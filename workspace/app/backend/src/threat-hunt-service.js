const { query } = require('./database');
const { sanitizeTenant } = require('./validators');
const { log: structuredLog } = require('./logger');

const VALID_QUERY_TYPES = ['kql', 'sql', 'regex', 'yara'];
const MAX_LIST_LIMIT = 200;

// Audit log helper — routes through the structured logger for PII redaction.
function logAuditEvent(config, tenant, action, details = {}, userId = null) {
  structuredLog('info', `audit.${action}`, {
    service: 'threat-hunt-service',
    tenant,
    action,
    userId,
    ...details,
  });
}

// Validate a regex pattern is safe to run against PostgreSQL ~* operator.
// Rejects patterns with catastrophic backtracking potential (nested quantifiers,
// excessive alternation) and enforces a length cap.
function isSafeRegex(pattern) {
  if (!pattern || pattern.length > 500) return false;
  // Reject nested quantifiers like (a+)+, (a*)+, (a{2,})*
  if (/(\([^)]*[+*][^)]*\))[+*{]/.test(pattern)) return false;
  // Reject excessive alternation (>20 alternatives)
  if ((pattern.match(/\|/g) || []).length > 20) return false;
  // Validate the pattern actually compiles
  try {
    new RegExp(pattern);
    return true;
  } catch {
    return false;
  }
}

async function listThreatHuntQueries(config, tenant, { limit = 50, offset = 0, queryType } = {}) {
  if (!config.databaseUrl) {
    return { data: [], total: 0 };
  }

  const cappedLimit = Math.min(Math.max(1, Number(limit) || 50), MAX_LIST_LIMIT);
  const cappedOffset = Math.max(0, Number(offset) || 0);
  const tenantSlug = sanitizeTenant(tenant);
  const conditions = ['tenant_slug = $1'];
  const params = [tenantSlug];
  let paramIdx = 2;

  if (queryType && VALID_QUERY_TYPES.includes(queryType)) {
    conditions.push(`query_type = $${paramIdx}`);
    params.push(queryType);
    paramIdx++;
  }

  const where = conditions.join(' AND ');

  const countResult = await query(
    config,
    `SELECT COUNT(*)::INT AS total FROM threat_hunt_queries WHERE ${where}`,
    params
  );

  const result = await query(
    config,
    `
      SELECT id, tenant_slug, name, description, query_type, query_text, data_source,
             last_run_at, last_result_count, created_by, created_at, updated_at
      FROM threat_hunt_queries
      WHERE ${where}
      ORDER BY updated_at DESC
      LIMIT $${paramIdx} OFFSET $${paramIdx + 1}
    `,
    [...params, cappedLimit, cappedOffset]
  );

  return {
    data: result?.rows || [],
    total: countResult?.rows?.[0]?.total || 0,
    limit: cappedLimit,
    offset: cappedOffset,
  };
}

async function createThreatHuntQuery(config, { tenant, name, description, queryType, queryText, dataSource, createdBy }) {
  if (!config.databaseUrl) {
    return null;
  }

  const tenantSlug = sanitizeTenant(tenant);
  const safeQueryType = VALID_QUERY_TYPES.includes(queryType) ? queryType : 'kql';

  const result = await query(
    config,
    `
      INSERT INTO threat_hunt_queries (tenant_slug, name, description, query_type, query_text, data_source, created_by)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING id, tenant_slug, name, description, query_type, query_text, data_source, last_run_at, last_result_count, created_by, created_at, updated_at
    `,
    [
      tenantSlug,
      String(name).slice(0, 255),
      description ? String(description).slice(0, 2000) : null,
      safeQueryType,
      String(queryText).slice(0, 10000),
      String(dataSource || 'siem_alerts').slice(0, 128),
      createdBy ? Number(createdBy) : null,
    ]
  );

  const created = result?.rows?.[0] || null;
  if (created) {
    logAuditEvent(config, tenantSlug, 'threat_hunt.created', { queryId: created.id, queryType: safeQueryType, name: String(name).slice(0, 255) }, createdBy);
  }
  return created;
}

async function updateThreatHuntQuery(config, tenant, queryId, updates) {
  if (!config.databaseUrl) {
    return null;
  }

  const tenantSlug = sanitizeTenant(tenant);
  const sets = ['updated_at = NOW()'];
  const params = [Number(queryId), tenantSlug];
  let paramIdx = 3;

  if (updates.name !== undefined) {
    sets.push(`name = $${paramIdx}`);
    params.push(String(updates.name).slice(0, 255));
    paramIdx++;
  }
  if (updates.description !== undefined) {
    sets.push(`description = $${paramIdx}`);
    params.push(updates.description ? String(updates.description).slice(0, 2000) : null);
    paramIdx++;
  }
  if (updates.queryType !== undefined && VALID_QUERY_TYPES.includes(updates.queryType)) {
    sets.push(`query_type = $${paramIdx}`);
    params.push(updates.queryType);
    paramIdx++;
  }
  if (updates.queryText !== undefined) {
    sets.push(`query_text = $${paramIdx}`);
    params.push(String(updates.queryText).slice(0, 10000));
    paramIdx++;
  }
  if (updates.dataSource !== undefined) {
    sets.push(`data_source = $${paramIdx}`);
    params.push(String(updates.dataSource).slice(0, 128));
    paramIdx++;
  }

  const result = await query(
    config,
    `
      UPDATE threat_hunt_queries SET ${sets.join(', ')}
      WHERE id = $1 AND tenant_slug = $2
      RETURNING id, tenant_slug, name, description, query_type, query_text, data_source, last_run_at, last_result_count, created_by, created_at, updated_at
    `,
    params
  );

  const updated = result?.rows?.[0] || null;
  if (updated) {
    logAuditEvent(config, tenantSlug, 'threat_hunt.updated', { queryId: Number(queryId), updatedFields: Object.keys(updates) });
  }
  return updated;
}

async function deleteThreatHuntQuery(config, tenant, queryId) {
  if (!config.databaseUrl) {
    return false;
  }

  const tenantSlug = sanitizeTenant(tenant);
  const result = await query(
    config,
    'DELETE FROM threat_hunt_queries WHERE id = $1 AND tenant_slug = $2 RETURNING id',
    [Number(queryId), tenantSlug]
  );

  const deleted = (result?.rowCount || 0) > 0;
  if (deleted) {
    logAuditEvent(config, tenantSlug, 'threat_hunt.deleted', { queryId: Number(queryId) });
  }
  return deleted;
}

async function executeThreatHuntQuery(config, tenant, queryId) {
  if (!config.databaseUrl) {
    return null;
  }

  const tenantSlug = sanitizeTenant(tenant);

  const huntResult = await query(
    config,
    'SELECT id, query_type, query_text, data_source FROM threat_hunt_queries WHERE id = $1 AND tenant_slug = $2',
    [Number(queryId), tenantSlug]
  );

  const hunt = huntResult?.rows?.[0];
  if (!hunt) {
    return null;
  }

  let results = [];
  let resultCount = 0;

  if (hunt.data_source === 'siem_alerts') {
    const searchText = String(hunt.query_text || '').trim();

    if (hunt.query_type === 'yara') {
      return {
        queryId: hunt.id,
        queryType: hunt.query_type,
        dataSource: hunt.data_source,
        resultCount: 0,
        results: [],
        executedAt: new Date().toISOString(),
        error: 'YARA query execution against SIEM alerts is not yet supported. YARA rules require file/binary scanning infrastructure.',
      };
    }

    if (hunt.query_type === 'sql') {
      return {
        queryId: hunt.id,
        queryType: hunt.query_type,
        dataSource: hunt.data_source,
        resultCount: 0,
        results: [],
        executedAt: new Date().toISOString(),
        error: 'Direct SQL execution is not supported for security reasons. Use KQL or regex query types instead.',
      };
    }

    if (hunt.query_type === 'regex') {
      if (!isSafeRegex(searchText)) {
        return {
          queryId: hunt.id,
          queryType: hunt.query_type,
          dataSource: hunt.data_source,
          resultCount: 0,
          results: [],
          executedAt: new Date().toISOString(),
          error: 'Regex pattern is invalid or too complex. Simplify the pattern and retry.',
        };
      }
      const alertResults = await query(
        config,
        `
          SELECT id, source, alert_id, rule_name, severity, category, source_ip, dest_ip, hostname, event_time
          FROM siem_alerts
          WHERE tenant_slug = $1
            AND (
              rule_name ~* $2
              OR alert_id ~* $2
              OR hostname ~* $2
              OR source_ip ~* $2
              OR dest_ip ~* $2
              OR category ~* $2
            )
          ORDER BY event_time DESC NULLS LAST
          LIMIT 100
        `,
        [tenantSlug, searchText]
      );
      results = alertResults?.rows || [];
    } else {
      const alertResults = await query(
        config,
        `
          SELECT id, source, alert_id, rule_name, severity, category, source_ip, dest_ip, hostname, event_time
          FROM siem_alerts
          WHERE tenant_slug = $1
            AND (
              rule_name ILIKE $2
              OR alert_id ILIKE $2
              OR hostname ILIKE $2
              OR source_ip ILIKE $2
              OR dest_ip ILIKE $2
              OR category ILIKE $2
            )
          ORDER BY event_time DESC NULLS LAST
          LIMIT 100
        `,
        [tenantSlug, `%${searchText.replace(/[%_\\]/g, '\\$&')}%`]
      );
      results = alertResults?.rows || [];
    }

    resultCount = results.length;
  }

  await query(
    config,
    'UPDATE threat_hunt_queries SET last_run_at = NOW(), last_result_count = $1 WHERE id = $2',
    [resultCount, hunt.id]
  );

  return {
    queryId: hunt.id,
    queryType: hunt.query_type,
    dataSource: hunt.data_source,
    resultCount,
    results,
    executedAt: new Date().toISOString(),
  };
}

module.exports = {
  listThreatHuntQueries,
  createThreatHuntQuery,
  updateThreatHuntQuery,
  deleteThreatHuntQuery,
  executeThreatHuntQuery,
};
