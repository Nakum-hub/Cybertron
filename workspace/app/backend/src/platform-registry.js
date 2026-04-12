const { roleRank, normalizeRole, hasRoleAccess } = require('./security-policy');

const platformApps = [
  {
    id: 'threat-command',
    name: 'Threat Command',
    tagline: 'Real-time threat intelligence and SOC orchestration',
    description:
      'Unified command interface for threat triage, investigation workflows, and incident response playbooks.',
    path: '/platform/threat-command',
    requiredRole: 'executive_viewer',
    statusEndpoint: '/v1/apps/threat-command/status',
    capabilities: ['Alert prioritization', 'Incident timelines', 'Response orchestration'],
  },
  {
    id: 'identity-guardian',
    name: 'Identity Guardian',
    tagline: 'Adaptive identity trust and access governance',
    description:
      'Zero-trust policy controls, risk-adaptive authentication, and cross-tenant identity posture dashboards.',
    path: '/platform/identity-guardian',
    requiredRole: 'security_analyst',
    statusEndpoint: '/v1/apps/identity-guardian/status',
    capabilities: ['Risk-based access', 'Session trust analytics', 'SSO policy enforcement'],
  },
  {
    id: 'resilience-hq',
    name: 'Resilience HQ',
    tagline: 'Executive reliability and security KPI cockpit',
    description:
      'Board-level visibility into uptime, security posture, and resilience trajectories across all business units.',
    path: '/platform/resilience-hq',
    requiredRole: 'executive_viewer',
    statusEndpoint: '/v1/apps/resilience-hq/status',
    capabilities: ['Global KPI views', 'Business risk scorecards', 'Quarterly strategy snapshots'],
  },
  {
    id: 'risk-copilot',
    name: 'Risk Copilot',
    tagline: 'Risk-adaptive intelligence for prioritization and response planning',
    description:
      'Cross-domain risk signal aggregation with explainable prioritization, evidence lineage, and tenant-scoped decision trails.',
    path: '/platform/risk-copilot',
    requiredRole: 'executive_viewer',
    statusEndpoint: '/v1/apps/risk-copilot/status',
    capabilities: ['Risk score normalization', 'Priority recommendations', 'Evidence-backed advisory output'],
  },
];

function getAccessibleApps(role) {
  return platformApps.filter(app => hasRoleAccess(role, app.requiredRole));
}

function getAppById(appId) {
  return platformApps.find(app => app.id === appId);
}

module.exports = {
  roleRank,
  platformApps,
  normalizeRole,
  hasRoleAccess,
  getAccessibleApps,
  getAppById,
};
