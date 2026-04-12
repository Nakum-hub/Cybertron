const { sanitizeTenant } = require('../../validators');
const { fetchCoreIdentityMetrics } = require('./model');

async function getStatus(config, tenant) {
  const tenantSlug = sanitizeTenant(tenant || 'global');
  const metrics = await fetchCoreIdentityMetrics(config, tenantSlug);
  if (!metrics) {
    return {
      status: 'no_data',
      message: 'Database is not configured for core identity telemetry.',
      tenant: tenantSlug,
      evidence: {
        totalUsers: 0,
        activeUsers: 0,
      },
    };
  }

  const totalUsers = Number(metrics.total_users || 0);
  const activeUsers = Number(metrics.active_users || 0);
  return {
    status: totalUsers > 0 ? 'operational' : 'no_data',
    message: totalUsers > 0 ? undefined : 'No users available for this tenant.',
    tenant: tenantSlug,
    evidence: {
      totalUsers,
      activeUsers,
      latestLoginAt: metrics.latest_login_at ? new Date(metrics.latest_login_at).toISOString() : null,
    },
  };
}

module.exports = {
  getStatus,
};
