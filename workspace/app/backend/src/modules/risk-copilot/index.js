const service = require('./service');
const { routes } = require('./routes');

const descriptor = {
  moduleId: 'risk-copilot',
  productKey: 'risk-copilot',
  name: 'Risk Copilot',
  tagline: 'AI-assisted risk prioritization and response sequencing',
  description:
    'Context-aware prioritization engine over incidents and IOC confidence to focus analyst effort where risk is highest.',
  requiredRole: 'executive_viewer',
  path: '/platform/risk-copilot',
  capabilities: ['Priority score generation', 'Analyst queue suggestions', 'Tenant-scoped risk trend tracking'],
};

module.exports = {
  descriptor,
  routes,
  service,
};
