const { query } = require('../../database');
const { sanitizeTenant } = require('../../validators');

async function fetchComplianceMetrics(config, tenant) {
  if (!config.databaseUrl) {
    return null;
  }

  const tenantSlug = sanitizeTenant(tenant || 'global');
  const result = await query(
    config,
    `
      SELECT
        COUNT(*)::INT AS audit_events,
        COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours')::INT AS audit_events_24h,
        (
          SELECT COUNT(*)::INT
          FROM reports r
          WHERE r.tenant_slug = $1
        ) AS reports_total
      FROM audit_logs
      WHERE tenant_slug = $1
    `,
    [tenantSlug]
  );

  return result?.rows?.[0] || null;
}

module.exports = {
  fetchComplianceMetrics,
};
