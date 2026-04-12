const { query } = require('../../database');
const { sanitizeTenant } = require('../../validators');

async function fetchRiskSignals(config, tenant) {
  if (!config.databaseUrl) {
    return null;
  }

  const tenantSlug = sanitizeTenant(tenant || 'global');
  const result = await query(
    config,
    `
      SELECT
        COUNT(*) FILTER (WHERE severity = 'critical')::INT AS critical_open,
        COUNT(*) FILTER (WHERE severity = 'high')::INT AS high_open,
        COUNT(*) FILTER (WHERE status IN ('open', 'investigating'))::INT AS active_incidents,
        (
          SELECT COUNT(*)::INT
          FROM iocs i
          WHERE i.tenant_slug = $1
            AND i.confidence >= 70
        ) AS high_conf_iocs
      FROM incidents
      WHERE tenant_slug = $1
        AND status IN ('open', 'investigating')
    `,
    [tenantSlug]
  );

  return result?.rows?.[0] || null;
}

module.exports = {
  fetchRiskSignals,
};
