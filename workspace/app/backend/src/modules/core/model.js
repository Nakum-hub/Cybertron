const { query } = require('../../database');
const { sanitizeTenant } = require('../../validators');

async function fetchCoreIdentityMetrics(config, tenant) {
  if (!config.databaseUrl) {
    return null;
  }

  const tenantSlug = sanitizeTenant(tenant || 'global');
  const result = await query(
    config,
    `
      SELECT
        COUNT(*)::INT AS total_users,
        COUNT(*) FILTER (WHERE is_active = TRUE)::INT AS active_users,
        MAX(last_login_at) AS latest_login_at
      FROM users
      WHERE tenant_slug = $1
    `,
    [tenantSlug]
  );

  return result?.rows?.[0] || null;
}

module.exports = {
  fetchCoreIdentityMetrics,
};
