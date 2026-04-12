const { query } = require('./database');

function clampLimit(value, fallback = 25, max = 200) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric <= 0) {
    return fallback;
  }

  return Math.max(1, Math.min(max, Math.floor(numeric)));
}

function normalizeTenant(value) {
  const input = String(value || 'global').trim().toLowerCase();
  if (!input) {
    return 'global';
  }

  return input.replace(/[^a-z0-9-]/g, '').slice(0, 64) || 'global';
}

async function listTenants(config, limit = 25) {
  const result = await query(
    config,
    `
      SELECT slug, name, created_at
      FROM tenants
      ORDER BY created_at DESC
      LIMIT $1
    `,
    [clampLimit(limit)]
  );

  if (!result) {
    return [];
  }

  return result.rows.map(row => ({
    slug: row.slug,
    name: row.name,
    createdAt: new Date(row.created_at).toISOString(),
  }));
}

async function listUsers(config, tenant, limit = 25) {
  const result = await query(
    config,
    `
      SELECT tenant_slug, email, display_name, role, is_active, created_at
      FROM users
      WHERE tenant_slug = $1
      ORDER BY created_at DESC
      LIMIT $2
    `,
    [normalizeTenant(tenant), clampLimit(limit)]
  );

  if (!result) {
    return [];
  }

  return result.rows.map(row => ({
    tenant: row.tenant_slug,
    email: row.email,
    displayName: row.display_name,
    role: row.role,
    active: Boolean(row.is_active),
    createdAt: new Date(row.created_at).toISOString(),
  }));
}

async function listServiceRequests(config, tenant, limit = 25) {
  let effectiveLimit = clampLimit(limit);
  let requesterEmail = '';

  if (limit && typeof limit === 'object') {
    effectiveLimit = clampLimit(limit.limit, 25, 200);
    requesterEmail = String(limit.requesterEmail || '').trim().toLowerCase();
  }

  const values = [normalizeTenant(tenant)];
  let whereClause = 'tenant_slug = $1';

  if (requesterEmail) {
    values.push(requesterEmail);
    whereClause += ` AND requester_email = $${values.length}`;
  }

  values.push(effectiveLimit);
  const result = await query(
    config,
    `
      SELECT
        id,
        tenant_slug,
        category,
        priority,
        status,
        subject,
        description,
        requester_email,
        created_at,
        updated_at
      FROM service_requests
      WHERE ${whereClause}
      ORDER BY created_at DESC
      LIMIT $${values.length}
    `,
    values
  );

  if (!result) {
    return [];
  }

  return result.rows.map(row => ({
    id: String(row.id),
    tenant: row.tenant_slug,
    category: row.category,
    priority: row.priority,
    status: row.status,
    subject: row.subject,
    description: row.description || null,
    requesterEmail: row.requester_email,
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString(),
  }));
}

async function listReports(config, tenant, limit = 25) {
  const result = await query(
    config,
    `
      SELECT
        id,
        report_type,
        report_date,
        storage_path,
        storage_provider,
        checksum_sha256,
        file_name,
        mime_type,
        size_bytes,
        created_at
      FROM reports
      WHERE tenant_slug = $1
      ORDER BY report_date DESC, created_at DESC
      LIMIT $2
    `,
    [normalizeTenant(tenant), clampLimit(limit)]
  );

  if (!result) {
    return [];
  }

  return result.rows.map(row => ({
    id: String(row.id),
    type: row.report_type,
    reportDate: row.report_date,
    storagePath: row.storage_path,
    storageProvider: row.storage_provider || 'local',
    fileName: row.file_name || null,
    mimeType: row.mime_type || null,
    sizeBytes: row.size_bytes === null ? null : Number(row.size_bytes),
    checksumSha256: row.checksum_sha256,
    createdAt: new Date(row.created_at).toISOString(),
  }));
}

async function listAuditLogs(config, tenant, { limit = 50, offset = 0, action, actorEmail, startDate, endDate } = {}) {
  const cappedLimit = clampLimit(limit, 50, 500);
  const cappedOffset = Math.max(0, Math.floor(Number(offset) || 0));
  const conditions = ['tenant_slug = $1'];
  const params = [normalizeTenant(tenant)];
  let paramIdx = 2;

  if (action) {
    conditions.push(`action = $${paramIdx}`);
    params.push(String(action).slice(0, 191));
    paramIdx++;
  }
  if (actorEmail) {
    conditions.push(`actor_email = $${paramIdx}`);
    params.push(String(actorEmail).slice(0, 191).toLowerCase());
    paramIdx++;
  }
  if (startDate) {
    conditions.push(`created_at >= $${paramIdx}`);
    params.push(String(startDate));
    paramIdx++;
  }
  if (endDate) {
    conditions.push(`created_at <= $${paramIdx}`);
    params.push(String(endDate));
    paramIdx++;
  }

  const where = conditions.join(' AND ');

  const countResult = await query(
    config,
    `SELECT COUNT(*)::INT AS total FROM audit_logs WHERE ${where}`,
    params
  );

  const result = await query(
    config,
    `
      SELECT id, action, actor_id, actor_email, target_type, target_id, ip_address, user_agent, trace_id, payload, created_at
      FROM audit_logs
      WHERE ${where}
      ORDER BY created_at DESC
      LIMIT $${paramIdx} OFFSET $${paramIdx + 1}
    `,
    [...params, cappedLimit, cappedOffset]
  );

  if (!result) {
    return { data: [], total: 0 };
  }

  return {
    data: result.rows.map(row => ({
      id: String(row.id),
      action: row.action,
      actorId: row.actor_id,
      actorEmail: row.actor_email,
      targetType: row.target_type,
      targetId: row.target_id,
      ipAddress: row.ip_address,
      userAgent: row.user_agent,
      traceId: row.trace_id,
      payload: row.payload || {},
      createdAt: new Date(row.created_at).toISOString(),
    })),
    total: countResult?.rows?.[0]?.total || 0,
    limit: cappedLimit,
    offset: cappedOffset,
  };
}

module.exports = {
  listTenants,
  listUsers,
  listServiceRequests,
  listReports,
  listAuditLogs,
};
