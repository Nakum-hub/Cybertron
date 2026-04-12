const { query } = require('./database');
const { sanitizeTenant } = require('./validators');
const { log: structuredLog } = require('./logger');
const { generateAlertTriageSuggestionWithAi } = require('./ai/siem-ai-service');

const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const VALID_RULE_TYPES = ['threshold', 'sequence', 'aggregation', 'anomaly'];
const VALID_ALERT_STATUSES = ['new', 'acknowledged', 'in_triage', 'escalated', 'resolved', 'dismissed'];
const ALERT_STATUS_TRANSITIONS = {
  'new':          ['acknowledged', 'in_triage', 'escalated', 'dismissed'],
  'acknowledged': ['in_triage', 'escalated', 'resolved', 'dismissed'],
  'in_triage':    ['escalated', 'resolved', 'dismissed'],
  'escalated':    ['resolved'],
  'resolved':     [],       // terminal
  'dismissed':    ['new'],  // can reopen by returning to 'new'
};
const MAX_LIST_LIMIT = 200;

// Audit log helper — routes through the structured logger for PII redaction.
function logAuditEvent(config, tenant, action, details = {}, userId = null) {
  structuredLog('info', `audit.${action}`, {
    service: 'siem-service',
    tenant,
    action,
    userId,
    ...details,
  });
}

async function listSiemAlerts(config, tenant, { limit = 50, offset = 0, severity, source, correlated, startTime, endTime, status, assignedTo, search } = {}) {
  if (!config.databaseUrl) {
    return { data: [], total: 0 };
  }

  const cappedLimit = Math.min(Math.max(1, Number(limit) || 50), MAX_LIST_LIMIT);
  const cappedOffset = Math.max(0, Number(offset) || 0);
  const tenantSlug = sanitizeTenant(tenant);
  const conditions = ['tenant_slug = $1'];
  const params = [tenantSlug];
  let paramIdx = 2;

  if (severity && VALID_SEVERITIES.includes(severity)) {
    conditions.push(`severity = $${paramIdx}`);
    params.push(severity);
    paramIdx++;
  }
  if (source) {
    conditions.push(`source = $${paramIdx}`);
    params.push(String(source).slice(0, 128));
    paramIdx++;
  }
  if (correlated !== undefined && correlated !== null) {
    conditions.push(`correlated = $${paramIdx}`);
    params.push(correlated === true || correlated === 'true');
    paramIdx++;
  }
  if (status && VALID_ALERT_STATUSES.includes(status)) {
    conditions.push(`status = $${paramIdx}`);
    params.push(status);
    paramIdx++;
  }
  if (assignedTo) {
    conditions.push(`assigned_to = $${paramIdx}`);
    params.push(Number(assignedTo));
    paramIdx++;
  }
  if (search) {
    const safeSearch = String(search).slice(0, 256).replace(/%/g, '');
    conditions.push(`(rule_name ILIKE $${paramIdx} OR alert_id ILIKE $${paramIdx} OR hostname ILIKE $${paramIdx} OR source_ip ILIKE $${paramIdx} OR dest_ip ILIKE $${paramIdx})`);
    params.push(`%${safeSearch}%`);
    paramIdx++;
  }
  if (startTime) {
    conditions.push(`event_time >= $${paramIdx}`);
    params.push(new Date(startTime).toISOString());
    paramIdx++;
  }
  if (endTime) {
    conditions.push(`event_time <= $${paramIdx}`);
    params.push(new Date(endTime).toISOString());
    paramIdx++;
  }

  const where = conditions.join(' AND ');

  const countResult = await query(
    config,
    `SELECT COUNT(*)::INT AS total FROM siem_alerts WHERE ${where}`,
    params
  );

  const result = await query(
    config,
    `
      SELECT id, tenant_slug, source, alert_id, rule_name, severity, category,
             raw_payload, source_ip, dest_ip, hostname, correlated, incident_id,
             status, assigned_to, acknowledged_at, acknowledged_by, resolved_at, notes,
             ingested_at, event_time
      FROM siem_alerts
      WHERE ${where}
      ORDER BY event_time DESC NULLS LAST, ingested_at DESC
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

async function ingestSiemAlert(config, { tenant, source, alertId, ruleName, severity, category, rawPayload, sourceIp, destIp, hostname, eventTime }) {
  if (!config.databaseUrl) {
    return null;
  }

  const tenantSlug = sanitizeTenant(tenant);
  const safeSeverity = VALID_SEVERITIES.includes(severity) ? severity : 'medium';

  const result = await query(
    config,
    `
      INSERT INTO siem_alerts (tenant_slug, source, alert_id, rule_name, severity, category, raw_payload, source_ip, dest_ip, hostname, event_time)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      ON CONFLICT (tenant_slug, source, alert_id) WHERE alert_id IS NOT NULL
      DO UPDATE SET
        rule_name = EXCLUDED.rule_name,
        severity = EXCLUDED.severity,
        category = EXCLUDED.category,
        raw_payload = EXCLUDED.raw_payload,
        source_ip = EXCLUDED.source_ip,
        dest_ip = EXCLUDED.dest_ip,
        hostname = EXCLUDED.hostname,
        event_time = EXCLUDED.event_time
      RETURNING id, tenant_slug, source, alert_id, rule_name, severity, category, source_ip, dest_ip, hostname, correlated, status, assigned_to, ingested_at, event_time
    `,
    [
      tenantSlug,
      String(source || 'unknown').slice(0, 128),
      alertId ? String(alertId).slice(0, 255) : null,
      ruleName ? String(ruleName).slice(0, 255) : null,
      safeSeverity,
      String(category || 'generic').slice(0, 64),
      rawPayload && typeof rawPayload === 'object' ? JSON.stringify(rawPayload) : '{}',
      sourceIp ? String(sourceIp).slice(0, 45) : null,
      destIp ? String(destIp).slice(0, 45) : null,
      hostname ? String(hostname).slice(0, 255) : null,
      eventTime ? new Date(eventTime).toISOString() : new Date().toISOString(),
    ]
  );

  const alert = result?.rows?.[0] || null;
  if (alert) {
    logAuditEvent(config, tenantSlug, 'siem_alert.ingested', { alertDbId: alert.id, alertId: alert.alert_id, severity: safeSeverity, source: alert.source });
  }
  return alert;
}

async function correlateAlertToIncident(config, tenant, alertId, incidentId) {
  if (!config.databaseUrl) {
    return null;
  }

  const tenantSlug = sanitizeTenant(tenant);
  const result = await query(
    config,
    `
      UPDATE siem_alerts
      SET correlated = TRUE, incident_id = $1
      WHERE id = $2 AND tenant_slug = $3
      RETURNING id, tenant_slug, source, alert_id, rule_name, severity, correlated, incident_id
    `,
    [Number(incidentId), Number(alertId), tenantSlug]
  );

  const correlated = result?.rows?.[0] || null;
  if (correlated) {
    logAuditEvent(config, tenantSlug, 'siem_alert.correlated', { alertId: Number(alertId), incidentId: Number(incidentId) });
  }
  return correlated;
}

async function getSiemAlertStats(config, tenant) {
  if (!config.databaseUrl) {
    return null;
  }

  const tenantSlug = sanitizeTenant(tenant);
  const result = await query(
    config,
    `
      SELECT
        COUNT(*)::INT AS total_alerts,
        COUNT(*) FILTER (WHERE correlated = FALSE)::INT AS uncorrelated,
        COUNT(*) FILTER (WHERE status = 'new')::INT AS new_count,
        COUNT(*) FILTER (WHERE status = 'acknowledged')::INT AS acknowledged_count,
        COUNT(*) FILTER (WHERE status = 'in_triage')::INT AS in_triage_count,
        COUNT(*) FILTER (WHERE status = 'escalated')::INT AS escalated_count,
        COUNT(*) FILTER (WHERE status = 'resolved')::INT AS resolved_count,
        COUNT(*) FILTER (WHERE status = 'dismissed')::INT AS dismissed_count,
        COUNT(*) FILTER (WHERE severity = 'critical')::INT AS critical_count,
        COUNT(*) FILTER (WHERE severity = 'high')::INT AS high_count,
        COUNT(*) FILTER (WHERE severity = 'medium')::INT AS medium_count,
        COUNT(*) FILTER (WHERE severity = 'low')::INT AS low_count,
        COUNT(*) FILTER (WHERE severity = 'info')::INT AS info_count,
        COUNT(DISTINCT source)::INT AS source_count,
        COUNT(DISTINCT assigned_to) FILTER (WHERE assigned_to IS NOT NULL)::INT AS assigned_analyst_count,
        MAX(event_time) AS latest_event_time
      FROM siem_alerts
      WHERE tenant_slug = $1
    `,
    [tenantSlug]
  );

  return result?.rows?.[0] || null;
}

async function listCorrelationRules(config, tenant, { activeOnly = true } = {}) {
  if (!config.databaseUrl) {
    return { data: [] };
  }

  const tenantSlug = sanitizeTenant(tenant);
  const conditions = ['tenant_slug = $1'];
  const params = [tenantSlug];

  if (activeOnly) {
    conditions.push('is_active = TRUE');
  }

  const result = await query(
    config,
    `
      SELECT id, tenant_slug, name, description, rule_type, conditions, severity_output, is_active, created_by, created_at
      FROM alert_correlation_rules
      WHERE ${conditions.join(' AND ')}
      ORDER BY created_at DESC
    `,
    params
  );

  return { data: result?.rows || [] };
}

async function createCorrelationRule(config, { tenant, name, description, ruleType, conditions, severityOutput, createdBy }) {
  if (!config.databaseUrl) {
    return null;
  }

  const tenantSlug = sanitizeTenant(tenant);
  const safeRuleType = VALID_RULE_TYPES.includes(ruleType) ? ruleType : 'threshold';

  const safeSeverityOutput = VALID_SEVERITIES.includes(severityOutput) ? severityOutput : 'high';

  const result = await query(
    config,
    `
      INSERT INTO alert_correlation_rules (tenant_slug, name, description, rule_type, conditions, severity_output, created_by)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING id, tenant_slug, name, description, rule_type, conditions, severity_output, is_active, created_by, created_at
    `,
    [
      tenantSlug,
      String(name).slice(0, 255),
      description ? String(description).slice(0, 2000) : null,
      safeRuleType,
      conditions && typeof conditions === 'object' ? JSON.stringify(conditions) : '{}',
      safeSeverityOutput,
      createdBy ? Number(createdBy) : null,
    ]
  );

  const rule = result?.rows?.[0] || null;
  if (rule) {
    logAuditEvent(config, tenantSlug, 'correlation_rule.created', { ruleId: rule.id, name: rule.name, ruleType: safeRuleType }, createdBy);
  }
  return rule;
}

async function updateCorrelationRule(config, tenant, ruleId, updates) {
  if (!config.databaseUrl) {
    return null;
  }

  const tenantSlug = sanitizeTenant(tenant);
  const sets = [];
  const params = [Number(ruleId), tenantSlug];
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
  if (updates.ruleType !== undefined && VALID_RULE_TYPES.includes(updates.ruleType)) {
    sets.push(`rule_type = $${paramIdx}`);
    params.push(updates.ruleType);
    paramIdx++;
  }
  if (updates.conditions !== undefined) {
    sets.push(`conditions = $${paramIdx}`);
    params.push(typeof updates.conditions === 'object' ? JSON.stringify(updates.conditions) : '{}');
    paramIdx++;
  }
  if (updates.isActive !== undefined) {
    sets.push(`is_active = $${paramIdx}`);
    params.push(Boolean(updates.isActive));
    paramIdx++;
  }

  if (sets.length === 0) {
    return null;
  }

  const result = await query(
    config,
    `
      UPDATE alert_correlation_rules SET ${sets.join(', ')}
      WHERE id = $1 AND tenant_slug = $2
      RETURNING id, tenant_slug, name, description, rule_type, conditions, severity_output, is_active, created_by, created_at
    `,
    params
  );

  const updated = result?.rows?.[0] || null;
  if (updated) {
    logAuditEvent(config, tenantSlug, 'correlation_rule.updated', { ruleId: updated.id, updatedFields: Object.keys(updates) });
  }
  return updated;
}

// --- Alert Lifecycle Operations ---

async function updateAlertStatus(config, tenant, alertId, { status, userId, notes } = {}) {
  if (!config.databaseUrl) return null;
  if (!VALID_ALERT_STATUSES.includes(status)) return null;

  const tenantSlug = sanitizeTenant(tenant);
  const id = Number(alertId);
  if (!Number.isFinite(id) || id <= 0) return null;

  // Fetch current status for state machine validation
  const current = await query(config,
    'SELECT status FROM siem_alerts WHERE id = $1 AND tenant_slug = $2',
    [id, tenantSlug]
  );
  if (!current?.rows?.length) return null;

  const currentStatus = current.rows[0].status;
  const allowed = ALERT_STATUS_TRANSITIONS[currentStatus] || [];
  if (!allowed.includes(status)) {
    const err = new Error(`Invalid status transition: ${currentStatus} -> ${status}. Allowed: ${allowed.join(', ') || 'none (terminal)'}`);
    err.code = 'invalid_status_transition';
    err.statusCode = 400;
    throw err;
  }

  const sets = ['status = $3'];
  const params = [id, tenantSlug, status];
  let paramIdx = 4;

  // Auto-set timestamps
  if (status === 'acknowledged') {
    sets.push(`acknowledged_at = NOW()`);
    if (userId) {
      sets.push(`acknowledged_by = $${paramIdx}`);
      params.push(Number(userId));
      paramIdx++;
    }
  }
  if (status === 'resolved') {
    sets.push(`resolved_at = NOW()`);
  }
  if (status === 'new') {
    sets.push('acknowledged_at = NULL');
    sets.push('acknowledged_by = NULL');
    sets.push('resolved_at = NULL');
  }

  if (notes !== undefined) {
    sets.push(`notes = $${paramIdx}`);
    params.push(notes ? String(notes).slice(0, 2000) : null);
    paramIdx++;
  }

  const result = await query(config,
    `UPDATE siem_alerts SET ${sets.join(', ')}
     WHERE id = $1 AND tenant_slug = $2
     RETURNING id, status, assigned_to, acknowledged_at, acknowledged_by, resolved_at, notes`,
    params
  );

  const updated = result?.rows?.[0] || null;
  if (updated) {
    logAuditEvent(config, tenantSlug, 'siem_alert.status_changed', {
      alertId: id, from: currentStatus, to: status,
    }, userId);
  }
  return updated;
}

async function assignAlert(config, tenant, alertId, { assignedTo, userId } = {}) {
  if (!config.databaseUrl) return null;

  const tenantSlug = sanitizeTenant(tenant);
  const id = Number(alertId);
  if (!Number.isFinite(id) || id <= 0) return null;
  const normalizedAssignedTo = assignedTo === null || assignedTo === undefined || assignedTo === ''
    ? null
    : Number(assignedTo);

  if (normalizedAssignedTo !== null) {
    if (!Number.isFinite(normalizedAssignedTo) || normalizedAssignedTo <= 0) {
      const err = new Error('assignedTo must be a valid analyst id');
      err.code = 'invalid_assignee';
      err.statusCode = 400;
      throw err;
    }

    const analystResult = await query(
      config,
      `
        SELECT id
        FROM users
        WHERE id = $1
          AND tenant_slug = $2
          AND is_active = TRUE
          AND role IN ('security_analyst', 'tenant_admin', 'super_admin')
      `,
      [normalizedAssignedTo, tenantSlug]
    );

    if (!analystResult?.rows?.length) {
      const err = new Error('assigned analyst not found in tenant');
      err.code = 'invalid_assignee';
      err.statusCode = 400;
      throw err;
    }
  }

  const result = await query(config,
    `UPDATE siem_alerts SET assigned_to = $3
     WHERE id = $1 AND tenant_slug = $2
     RETURNING id, status, assigned_to`,
    [id, tenantSlug, normalizedAssignedTo]
  );

  const updated = result?.rows?.[0] || null;
  if (updated) {
    logAuditEvent(config, tenantSlug, 'siem_alert.assigned', {
      alertId: id, assignedTo: normalizedAssignedTo,
    }, userId);
  }
  return updated;
}

async function escalateAlertToIncident(config, tenant, alertId, { userId, title, severity, priority } = {}) {
  if (!config.databaseUrl) return null;

  const tenantSlug = sanitizeTenant(tenant);
  const id = Number(alertId);
  if (!Number.isFinite(id) || id <= 0) return null;

  // Fetch alert for context and validate state machine
  const alertResult = await query(config,
    'SELECT id, rule_name, alert_id, severity, status, source_ip, dest_ip, hostname, source, raw_payload FROM siem_alerts WHERE id = $1 AND tenant_slug = $2',
    [id, tenantSlug]
  );
  if (!alertResult?.rows?.length) return null;

  const alert = alertResult.rows[0];

  // Enforce state machine: only alerts whose current status allows 'escalated' can be escalated
  const allowed = ALERT_STATUS_TRANSITIONS[alert.status] || [];
  if (!allowed.includes('escalated')) {
    const err = new Error(`Cannot escalate alert in '${alert.status}' status. Allowed transitions: ${allowed.join(', ') || 'none (terminal)'}`);
    err.code = 'invalid_status_transition';
    err.statusCode = 400;
    throw err;
  }
  const incidentTitle = title || `[Escalated] ${alert.rule_name || alert.alert_id || `Alert #${alert.id}`}`;
  const incidentSeverity = VALID_SEVERITIES.slice(0, 4).includes(severity) ? severity : (VALID_SEVERITIES.slice(0, 4).includes(alert.severity) ? alert.severity : 'medium');
  const incidentPriority = ['critical', 'high', 'medium', 'low'].includes(priority) ? priority : incidentSeverity;

  // Create incident from alert
  const incidentResult = await query(config,
    `INSERT INTO incidents (tenant_slug, title, severity, status, priority, source, detected_at, escalated_from_alert_id, raw_event)
     VALUES ($1, $2, $3, 'open', $4, $5, NOW(), $6, $7)
     RETURNING id`,
    [
      tenantSlug,
      incidentTitle,
      incidentSeverity,
      incidentPriority,
      alert.source || 'siem',
      id,
      JSON.stringify({
        escalatedFromAlert: id,
        alertRuleName: alert.rule_name,
        alertId: alert.alert_id,
        sourceIp: alert.source_ip,
        destIp: alert.dest_ip,
        hostname: alert.hostname,
      }),
    ]
  );

  const incidentId = incidentResult?.rows?.[0]?.id;
  if (!incidentId) return null;

  // Mark alert as escalated and correlate
  await query(config,
    `UPDATE siem_alerts SET status = 'escalated', correlated = TRUE, incident_id = $3
     WHERE id = $1 AND tenant_slug = $2`,
    [id, tenantSlug, incidentId]
  );

  // Create timeline entry
  await query(config,
    `INSERT INTO incident_timeline (tenant_slug, incident_id, event_type, message, actor_user_id)
     VALUES ($1, $2, 'escalated', $3, $4)`,
    [
      tenantSlug,
      incidentId,
      `Escalated from SIEM alert #${id} (${alert.rule_name || alert.alert_id || 'unnamed'})`,
      userId ? Number(userId) : null,
    ]
  );

  logAuditEvent(config, tenantSlug, 'siem_alert.escalated', {
    alertId: id, incidentId, title: incidentTitle,
  }, userId);

  return { alertId: id, incidentId, title: incidentTitle, severity: incidentSeverity, priority: incidentPriority };
}

// --- Bulk Alert Operations ---

async function bulkUpdateAlertStatus(config, tenant, { alertIds, status, userId, notes } = {}) {
  if (!config.databaseUrl) return { updated: 0, failed: 0, results: [] };
  if (!Array.isArray(alertIds) || alertIds.length === 0) return { updated: 0, failed: 0, results: [] };
  if (!VALID_ALERT_STATUSES.includes(status)) return { updated: 0, failed: 0, results: [] };

  const tenantSlug = sanitizeTenant(tenant);
  const safeIds = alertIds.slice(0, 100).map(Number).filter(id => Number.isFinite(id) && id > 0);
  if (safeIds.length === 0) return { updated: 0, failed: 0, results: [] };

  let updated = 0;
  let failed = 0;
  const results = [];

  for (const id of safeIds) {
    try {
      const result = await updateAlertStatus(config, tenant, id, { status, userId, notes });
      if (result) {
        updated++;
        results.push({ id, status: 'success', newStatus: result.status });
      } else {
        failed++;
        results.push({ id, status: 'failed', reason: 'not_found' });
      }
    } catch (err) {
      failed++;
      results.push({ id, status: 'failed', reason: err.code || err.message });
    }
  }

  logAuditEvent(config, tenantSlug, 'siem_alert.bulk_status_changed', {
    alertCount: safeIds.length, updated, failed, toStatus: status,
  }, userId);

  return { updated, failed, results };
}

// --- SLA Tracking ---

const DEFAULT_SLA_THRESHOLDS = {
  critical: { acknowledgeMinutes: 15, resolveMinutes: 240 },
  high:     { acknowledgeMinutes: 30, resolveMinutes: 480 },
  medium:   { acknowledgeMinutes: 60, resolveMinutes: 1440 },
  low:      { acknowledgeMinutes: 120, resolveMinutes: 4320 },
  info:     { acknowledgeMinutes: 480, resolveMinutes: 10080 },
};

async function getAlertSlaMetrics(config, tenant) {
  if (!config.databaseUrl) return null;

  const tenantSlug = sanitizeTenant(tenant);
  const result = await query(config,
    `
      SELECT
        COUNT(*) FILTER (WHERE status NOT IN ('resolved', 'dismissed'))::INT AS open_alerts,
        COUNT(*) FILTER (WHERE status = 'new')::INT AS unacknowledged_count,
        ROUND(AVG(EXTRACT(EPOCH FROM (acknowledged_at - ingested_at)) / 60)
          FILTER (WHERE acknowledged_at IS NOT NULL)::NUMERIC, 2) AS avg_time_to_ack_minutes,
        ROUND(PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (acknowledged_at - ingested_at)) / 60)
          FILTER (WHERE acknowledged_at IS NOT NULL)::NUMERIC, 2) AS median_time_to_ack_minutes,
        ROUND(AVG(EXTRACT(EPOCH FROM (resolved_at - ingested_at)) / 60)
          FILTER (WHERE status = 'resolved' AND resolved_at IS NOT NULL)::NUMERIC, 2) AS avg_time_to_resolve_minutes,
        ROUND(PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (resolved_at - ingested_at)) / 60)
          FILTER (WHERE status = 'resolved' AND resolved_at IS NOT NULL)::NUMERIC, 2) AS median_time_to_resolve_minutes,
        COUNT(*) FILTER (WHERE status = 'new' AND ingested_at < NOW() - INTERVAL '15 minutes' AND severity = 'critical')::INT AS critical_sla_breached,
        COUNT(*) FILTER (WHERE status = 'new' AND ingested_at < NOW() - INTERVAL '30 minutes' AND severity = 'high')::INT AS high_sla_breached,
        COUNT(*) FILTER (WHERE status = 'new' AND ingested_at < NOW() - INTERVAL '60 minutes' AND severity = 'medium')::INT AS medium_sla_breached,
        COUNT(*) FILTER (WHERE status = 'new' AND ingested_at < NOW() - INTERVAL '120 minutes' AND severity = 'low')::INT AS low_sla_breached
      FROM siem_alerts
      WHERE tenant_slug = $1
    `,
    [tenantSlug]
  );

  const row = result?.rows?.[0] || {};
  return {
    ...row,
    sla_thresholds: DEFAULT_SLA_THRESHOLDS,
    total_sla_breached: (row.critical_sla_breached || 0) + (row.high_sla_breached || 0) + (row.medium_sla_breached || 0) + (row.low_sla_breached || 0),
  };
}

// --- AI Triage Suggestions (rule-based, bounded, labeled) ---

function generateTriageSuggestion(alert) {
  if (!alert) return null;

  const suggestions = [];
  const severity = alert.severity || 'medium';
  const ruleName = (alert.rule_name || '').toLowerCase();
  const category = (alert.category || '').toLowerCase();
  const sourceIp = alert.source_ip || '';
  const destIp = alert.dest_ip || '';

  // Severity-based priority
  if (severity === 'critical') {
    suggestions.push({ action: 'escalate_immediately', confidence: 'high', reason: 'Critical severity alerts should be escalated to incident for immediate investigation.' });
  } else if (severity === 'high') {
    suggestions.push({ action: 'acknowledge_and_triage', confidence: 'high', reason: 'High severity alerts require prompt acknowledgment and triage.' });
  }

  // Pattern-based suggestions
  if (ruleName.includes('brute') || ruleName.includes('credential') || category.includes('authentication')) {
    suggestions.push({ action: 'check_auth_logs', confidence: 'medium', reason: 'Possible credential attack. Review authentication logs for the source IP.' });
    if (sourceIp) {
      suggestions.push({ action: 'block_source_ip', confidence: 'medium', reason: `Consider blocking source IP ${sourceIp} if confirmed malicious.` });
    }
  }

  if (ruleName.includes('malware') || ruleName.includes('trojan') || category.includes('malware')) {
    suggestions.push({ action: 'isolate_host', confidence: 'high', reason: 'Malware detection. Consider isolating the affected host for containment.' });
  }

  if (ruleName.includes('exfil') || ruleName.includes('data_leak') || category.includes('exfiltration')) {
    suggestions.push({ action: 'escalate_immediately', confidence: 'high', reason: 'Potential data exfiltration. Immediate escalation recommended.' });
    suggestions.push({ action: 'block_destination', confidence: 'medium', reason: `Review and potentially block destination ${destIp || 'address'}.` });
  }

  if (ruleName.includes('lateral') || category.includes('lateral_movement')) {
    suggestions.push({ action: 'map_attack_scope', confidence: 'medium', reason: 'Lateral movement detected. Map the scope of the attack across network segments.' });
  }

  if (ruleName.includes('scan') || ruleName.includes('recon') || category.includes('reconnaissance')) {
    suggestions.push({ action: 'monitor_follow_up', confidence: 'medium', reason: 'Reconnaissance activity. Monitor for follow-up exploitation attempts.' });
  }

  // Default if no specific pattern matched
  if (suggestions.length === 0) {
    suggestions.push({ action: 'review_and_classify', confidence: 'low', reason: 'Standard alert. Review context and classify as true/false positive.' });
  }

  return {
    alertId: alert.id,
    severity,
    suggestedPriority: severity === 'critical' ? 'critical' : severity === 'high' ? 'high' : 'medium',
    suggestions,
    automated: true,
    disclaimer: 'These are rule-based suggestions, not AI predictions. Always verify with full context before acting.',
  };
}

async function getAlertTriageSuggestion(config, tenant, alertId, context = {}) {
  if (!config.databaseUrl) return null;

  const tenantSlug = sanitizeTenant(tenant);
  const id = Number(alertId);
  if (!Number.isFinite(id) || id <= 0) return null;

  const result = await query(config,
    'SELECT id, rule_name, alert_id, severity, category, source_ip, dest_ip, hostname, status, raw_payload FROM siem_alerts WHERE id = $1 AND tenant_slug = $2',
    [id, tenantSlug]
  );

  if (!result?.rows?.length) return null;

  const alert = result.rows[0];
  const fallbackSuggestion = generateTriageSuggestion(alert);
  return generateAlertTriageSuggestionWithAi(
    {
      ...config,
      tenantSlug,
    },
    structuredLog,
    {
      tenant: tenantSlug,
      ...alert,
    },
    {
      ...context,
      tenantSlug,
    },
    fallbackSuggestion
  );
}

// --- Geo-IP Attack Map Data ---

async function getAttackMapData(config, tenant) {
  if (!config.databaseUrl) return null;

  const tenantSlug = sanitizeTenant(tenant);

  // Aggregate alerts by source_ip and dest_ip with geo-data from raw_payload
  const result = await query(config,
    `
      SELECT
        source_ip,
        dest_ip,
        severity,
        COUNT(*)::INT AS alert_count,
        MAX(event_time) AS latest_event_time,
        raw_payload->>'source_geo_lat' AS src_lat,
        raw_payload->>'source_geo_lon' AS src_lon,
        raw_payload->>'source_country' AS src_country,
        raw_payload->>'source_city' AS src_city,
        raw_payload->>'dest_geo_lat' AS dst_lat,
        raw_payload->>'dest_geo_lon' AS dst_lon,
        raw_payload->>'dest_country' AS dst_country,
        raw_payload->>'dest_city' AS dst_city
      FROM siem_alerts
      WHERE tenant_slug = $1
        AND source_ip IS NOT NULL
        AND event_time > NOW() - INTERVAL '7 days'
      GROUP BY source_ip, dest_ip, severity,
        raw_payload->>'source_geo_lat', raw_payload->>'source_geo_lon',
        raw_payload->>'source_country', raw_payload->>'source_city',
        raw_payload->>'dest_geo_lat', raw_payload->>'dest_geo_lon',
        raw_payload->>'dest_country', raw_payload->>'dest_city'
      ORDER BY alert_count DESC
      LIMIT 200
    `,
    [tenantSlug]
  );

  const nodes = new Map();
  const edges = [];

  for (const row of (result?.rows || [])) {
    const srcLat = Number.parseFloat(row.src_lat);
    const srcLon = Number.parseFloat(row.src_lon);
    const dstLat = Number.parseFloat(row.dst_lat);
    const dstLon = Number.parseFloat(row.dst_lon);
    const hasSourceGeo = Number.isFinite(srcLat) && Number.isFinite(srcLon);
    const hasDestGeo = Number.isFinite(dstLat) && Number.isFinite(dstLon);

    if (row.source_ip && hasSourceGeo) {
      const key = row.source_ip;
      if (!nodes.has(key)) {
        nodes.set(key, {
          ip: row.source_ip,
          lat: srcLat,
          lon: srcLon,
          country: row.src_country || 'Unknown',
          city: row.src_city || '',
          type: 'source',
          alertCount: 0,
        });
      }
      nodes.get(key).alertCount += row.alert_count;
    }

    if (row.dest_ip && hasDestGeo) {
      const key = row.dest_ip;
      if (!nodes.has(key)) {
        nodes.set(key, {
          ip: row.dest_ip,
          lat: dstLat,
          lon: dstLon,
          country: row.dst_country || 'Unknown',
          city: row.dst_city || '',
          type: 'destination',
          alertCount: 0,
        });
      }
      nodes.get(key).alertCount += row.alert_count;
    }

    if (row.source_ip && row.dest_ip && hasSourceGeo && hasDestGeo) {
      edges.push({
        source: row.source_ip,
        destination: row.dest_ip,
        severity: row.severity,
        alertCount: row.alert_count,
        latestEvent: row.latest_event_time,
      });
    }
  }

  // Top attacking countries summary
  const countrySummary = await query(config,
    `
      SELECT
        COALESCE(raw_payload->>'source_country', 'Unknown') AS country,
        COUNT(*)::INT AS attack_count,
        COUNT(DISTINCT source_ip)::INT AS unique_ips
      FROM siem_alerts
      WHERE tenant_slug = $1
        AND source_ip IS NOT NULL
        AND event_time > NOW() - INTERVAL '7 days'
      GROUP BY raw_payload->>'source_country'
      ORDER BY attack_count DESC
      LIMIT 20
    `,
    [tenantSlug]
  );

  return {
    nodes: Array.from(nodes.values()),
    edges: edges.slice(0, 500),
    countrySummary: countrySummary?.rows || [],
    timeRange: '7d',
    generatedAt: new Date().toISOString(),
  };
}

// --- Alert Notes Update ---

async function updateAlertNotes(config, tenant, alertId, { notes, userId } = {}) {
  if (!config.databaseUrl) return null;

  const tenantSlug = sanitizeTenant(tenant);
  const id = Number(alertId);
  if (!Number.isFinite(id) || id <= 0) return null;

  const safeNotes = notes ? String(notes).slice(0, 2000) : null;

  const result = await query(config,
    `UPDATE siem_alerts SET notes = $3
     WHERE id = $1 AND tenant_slug = $2
     RETURNING id, status, notes`,
    [id, tenantSlug, safeNotes]
  );

  const updated = result?.rows?.[0] || null;
  if (updated) {
    logAuditEvent(config, tenantSlug, 'siem_alert.notes_updated', {
      alertId: id,
    }, userId);
  }
  return updated;
}

// --- Alert Retention Cleanup ---
// Deletes resolved/dismissed alerts older than retentionDays (default 90).
// Returns the count of deleted alerts for audit logging.
async function cleanupStaleAlerts(config, tenant, { retentionDays = 90, batchSize = 1000 } = {}) {
  if (!config.databaseUrl) return { deleted: 0 };

  const tenantSlug = sanitizeTenant(tenant);
  const safeDays = Math.max(7, Math.min(retentionDays, 3650));
  const safeBatch = Math.max(1, Math.min(batchSize, 10_000));

  const result = await query(config,
    `
      DELETE FROM siem_alerts
      WHERE id IN (
        SELECT id FROM siem_alerts
        WHERE tenant_slug = $1
          AND status IN ('resolved', 'dismissed')
          AND ingested_at < NOW() - INTERVAL '1 day' * $2
        LIMIT $3
      )
      RETURNING id
    `,
    [tenantSlug, safeDays, safeBatch]
  );

  const deleted = result?.rowCount || 0;
  if (deleted > 0) {
    logAuditEvent(config, tenantSlug, 'siem_alert.retention_cleanup', {
      deletedCount: deleted,
      retentionDays: safeDays,
    });
  }
  return { deleted };
}

module.exports = {
  listSiemAlerts,
  ingestSiemAlert,
  correlateAlertToIncident,
  getSiemAlertStats,
  updateAlertStatus,
  assignAlert,
  escalateAlertToIncident,
  bulkUpdateAlertStatus,
  getAlertSlaMetrics,
  generateTriageSuggestion,
  getAlertTriageSuggestion,
  getAttackMapData,
  updateAlertNotes,
  listCorrelationRules,
  createCorrelationRule,
  updateCorrelationRule,
  cleanupStaleAlerts,
  VALID_ALERT_STATUSES,
  ALERT_STATUS_TRANSITIONS,
  DEFAULT_SLA_THRESHOLDS,
};
