const modules = {
  riskCopilot: require('./modules/risk-copilot'),
  compliance: require('./modules/compliance'),
  threatIntel: require('./modules/threat-intel'),
};

function listAiModules() {
  return Object.values(modules).map(mod => ({
    moduleId: mod.moduleId,
    name: mod.name,
    status: mod.status,
    message: mod.message,
  }));
}

function getAiModule(moduleId) {
  const normalized = String(moduleId || '').toLowerCase().trim();
  if (normalized === 'risk-copilot') return modules.riskCopilot;
  if (normalized === 'compliance') return modules.compliance;
  if (normalized === 'threat-intel') return modules.threatIntel;
  return null;
}

module.exports = {
  listAiModules,
  getAiModule,
};
