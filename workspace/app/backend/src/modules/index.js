const core = require('./core');
const threatIntel = require('./threat-intel');
const complianceEngine = require('./compliance-engine');
const riskCopilot = require('./risk-copilot');

const modules = [core, threatIntel, complianceEngine, riskCopilot];

function listRegisteredModules() {
  return modules.map(mod => mod.descriptor);
}

function getModuleByProductKey(productKey) {
  const normalized = String(productKey || '').trim().toLowerCase();
  return modules.find(mod => mod.descriptor.productKey === normalized) || null;
}

function getModuleById(moduleId) {
  const normalized = String(moduleId || '').trim().toLowerCase();
  return modules.find(mod => mod.descriptor.moduleId === normalized) || null;
}

function buildAppFromModule(moduleDescriptor) {
  return {
    id: moduleDescriptor.productKey,
    moduleId: moduleDescriptor.moduleId,
    name: moduleDescriptor.name,
    tagline: moduleDescriptor.tagline,
    description: moduleDescriptor.description,
    path: moduleDescriptor.path,
    requiredRole: moduleDescriptor.requiredRole,
    statusEndpoint: `/v1/apps/${moduleDescriptor.productKey}/status`,
    capabilities: moduleDescriptor.capabilities,
  };
}

module.exports = {
  modules,
  listRegisteredModules,
  getModuleById,
  getModuleByProductKey,
  buildAppFromModule,
};
