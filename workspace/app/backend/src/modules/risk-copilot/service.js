const { sanitizeTenant } = require('../../validators');
const { fetchRiskSignals } = require('./model');

function computePriorityScore(signals) {
  const criticalOpen = Number(signals.critical_open || 0);
  const highOpen = Number(signals.high_open || 0);
  const highConfidenceIocs = Number(signals.high_conf_iocs || 0);
  return criticalOpen * 30 + highOpen * 10 + Math.min(40, highConfidenceIocs);
}

function classifyPriority(score) {
  if (score >= 120) return 'critical';
  if (score >= 70) return 'high';
  if (score >= 30) return 'medium';
  return 'low';
}

async function getStatus(config, tenant) {
  const tenantSlug = sanitizeTenant(tenant || 'global');
  const signals = await fetchRiskSignals(config, tenantSlug);
  if (!signals) {
    return {
      status: 'no_data',
      message: 'Database is not configured for risk copilot.',
      tenant: tenantSlug,
      evidence: {
        activeIncidents: 0,
        priorityScore: 0,
        priorityClass: 'low',
      },
    };
  }

  const priorityScore = computePriorityScore(signals);
  const priorityClass = classifyPriority(priorityScore);
  return {
    status: Number(signals.active_incidents || 0) > 0 ? 'operational' : 'no_data',
    tenant: tenantSlug,
    evidence: {
      activeIncidents: Number(signals.active_incidents || 0),
      criticalOpen: Number(signals.critical_open || 0),
      highOpen: Number(signals.high_open || 0),
      highConfidenceIocs: Number(signals.high_conf_iocs || 0),
      priorityScore,
      priorityClass,
    },
  };
}

module.exports = {
  getStatus,
};
