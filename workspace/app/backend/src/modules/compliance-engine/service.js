const { sanitizeTenant } = require('../../validators');
const { fetchComplianceMetrics } = require('./model');

async function getStatus(config, tenant) {
  const tenantSlug = sanitizeTenant(tenant || 'global');
  const metrics = await fetchComplianceMetrics(config, tenantSlug);
  if (!metrics) {
    return {
      status: 'no_data',
      message: 'Database is not configured for compliance telemetry.',
      tenant: tenantSlug,
      evidence: {
        auditEvents: 0,
        reportsTotal: 0,
      },
    };
  }

  const auditEvents = Number(metrics.audit_events || 0);
  const reportsTotal = Number(metrics.reports_total || 0);
  return {
    status: auditEvents > 0 || reportsTotal > 0 ? 'operational' : 'no_data',
    message: auditEvents > 0 || reportsTotal > 0 ? undefined : 'No compliance evidence found for this tenant.',
    tenant: tenantSlug,
    evidence: {
      auditEvents,
      auditEvents24h: Number(metrics.audit_events_24h || 0),
      reportsTotal,
    },
  };
}

module.exports = {
  getStatus,
};
