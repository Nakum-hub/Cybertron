const { query } = require('../../database');
const { sanitizeTenant } = require('../../validators');

async function fetchThreatIntelMetrics(config, tenant) {
  if (!config.databaseUrl) {
    return null;
  }

  const tenantSlug = sanitizeTenant(tenant || 'global');
  const result = await query(
    config,
    `
      SELECT
        COUNT(*)::INT AS total_incidents,
        COUNT(*) FILTER (WHERE status IN ('open', 'investigating'))::INT AS active_incidents,
        COUNT(*) FILTER (WHERE severity IN ('critical', 'high'))::INT AS high_severity,
        MAX(detected_at) AS latest_detected_at
      FROM incidents
      WHERE tenant_slug = $1
    `,
    [tenantSlug]
  );

  return result?.rows?.[0] || null;
}

module.exports = {
  fetchThreatIntelMetrics,
};
