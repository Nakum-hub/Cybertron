const service = require('./service');
const { routes } = require('./routes');

const descriptor = {
  moduleId: 'threat-intel',
  productKey: 'threat-command',
  name: 'Threat Command',
  tagline: 'Real-time threat intelligence and SOC orchestration',
  description:
    'Unified command interface for threat triage, investigation workflows, and incident response playbooks.',
  requiredRole: 'executive_viewer',
  path: '/platform/threat-command',
  capabilities: ['Alert prioritization', 'Incident timelines', 'Response orchestration'],
};

module.exports = {
  descriptor,
  routes,
  service,
};
