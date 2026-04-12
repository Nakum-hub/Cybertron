const service = require('./service');
const { routes } = require('./routes');

const descriptor = {
  moduleId: 'compliance-engine',
  productKey: 'resilience-hq',
  name: 'Resilience HQ',
  tagline: 'Executive reliability and security KPI cockpit',
  description:
    'Board-level visibility into uptime, security posture, and resilience trajectories across all business units.',
  requiredRole: 'executive_viewer',
  path: '/platform/resilience-hq',
  capabilities: ['Global KPI views', 'Business risk scorecards', 'Quarterly strategy snapshots'],
};

module.exports = {
  descriptor,
  routes,
  service,
};
