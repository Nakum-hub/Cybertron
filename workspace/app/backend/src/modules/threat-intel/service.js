const { sanitizeTenant } = require('../../validators');
const { fetchThreatIntelMetrics } = require('./model');

async function getStatus(config, tenant) {
  const tenantSlug = sanitizeTenant(tenant || 'global');
  const metrics = await fetchThreatIntelMetrics(config, tenantSlug);
  if (!metrics) {
    return {
      status: 'no_data',
      message: 'Database is not configured for threat intelligence telemetry.',
      tenant: tenantSlug,
      evidence: {
        totalIncidents: 0,
        activeIncidents: 0,
      },
    };
  }

  const totalIncidents = Number(metrics.total_incidents || 0);
  const activeIncidents = Number(metrics.active_incidents || 0);
  const highSeverity = Number(metrics.high_severity || 0);
  return {
    status: highSeverity > 0 ? 'degraded' : totalIncidents > 0 ? 'operational' : 'no_data',
    message: totalIncidents > 0 ? undefined : 'No incidents available for this tenant.',
    tenant: tenantSlug,
    evidence: {
      totalIncidents,
      activeIncidents,
      highSeverity,
      latestDetectedAt: metrics.latest_detected_at
        ? new Date(metrics.latest_detected_at).toISOString()
        : null,
    },
  };
}

module.exports = {
  getStatus,
};
