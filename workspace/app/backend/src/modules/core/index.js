const service = require('./service');
const { routes } = require('./routes');

const descriptor = {
  moduleId: 'core',
  productKey: 'identity-guardian',
  name: 'Identity Guardian',
  tagline: 'Adaptive identity trust and access governance',
  description:
    'Zero-trust policy controls, risk-adaptive authentication, and cross-tenant identity posture dashboards.',
  requiredRole: 'security_analyst',
  path: '/platform/identity-guardian',
  capabilities: ['Risk-based access', 'Session trust analytics', 'SSO policy enforcement'],
};

module.exports = {
  descriptor,
  routes,
  service,
};
