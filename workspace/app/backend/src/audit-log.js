const { query } = require('./database');
const { sanitizeTenant } = require('./validators');

function trimString(value, max = 512) {
  const input = String(value || '').trim();
  if (!input) {
    return null;
  }

  return input.slice(0, max);
}

async function appendAuditLog(config, entry = {}, executor = null) {
  if (!config.databaseUrl) {
    // SECURITY FIX: Log a warning instead of silently dropping audit events
    console.error(JSON.stringify({
      level: 'error',
      msg: 'audit_log_dropped',
      reason: 'no_database_url',
      action: entry.action || 'unknown',
      tenant: entry.tenantSlug || 'unknown',
      ts: new Date().toISOString(),
    }));
    return;
  }

  try {
    const runQuery =
      executor && typeof executor.query === 'function'
        ? (text, values) => executor.query(text, values)
        : (text, values) => query(config, text, values);

    await runQuery(
      `
        INSERT INTO audit_logs (
          tenant_slug,
          actor_id,
          actor_email,
          action,
          target_type,
          target_id,
          ip_address,
          user_agent,
          trace_id,
          payload
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)
      `,
      [
        sanitizeTenant(entry.tenantSlug || 'global'),
        trimString(entry.actorId, 191),
        trimString(entry.actorEmail, 191),
        trimString(entry.action, 191) || 'unspecified_action',
        trimString(entry.targetType, 64),
        trimString(entry.targetId, 191),
        trimString(entry.ipAddress, 64),
        trimString(entry.userAgent, 2048),
        trimString(entry.traceId, 128),
        JSON.stringify(entry.payload || {}),
      ]
    );
  } catch (err) {
    // SECURITY FIX: Log DB write failures instead of letting them propagate silently
    console.error(JSON.stringify({
      level: 'error',
      msg: 'audit_log_write_failed',
      error: err instanceof Error ? err.message : 'unknown',
      action: entry.action || 'unknown',
      tenant: entry.tenantSlug || 'unknown',
      ts: new Date().toISOString(),
    }));
  }
}

module.exports = {
  appendAuditLog,
};
