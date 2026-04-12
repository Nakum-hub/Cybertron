const ROLE_ORDER = [
  'executive_viewer',
  'compliance_officer',
  'security_analyst',
  'tenant_admin',
  'super_admin',
];

const ROLE_ALIASES = {
  client: 'executive_viewer',
  viewer: 'executive_viewer',
  analyst: 'security_analyst',
  operator: 'compliance_officer',
  admin: 'tenant_admin',
  executive: 'super_admin',
  executive_viewer: 'executive_viewer',
  compliance_officer: 'compliance_officer',
  security_analyst: 'security_analyst',
  tenant_admin: 'tenant_admin',
  super_admin: 'super_admin',
};

const roleRank = ROLE_ORDER.reduce((acc, role, idx) => {
  acc[role] = idx + 1;
  return acc;
}, {});

function normalizeRole(value) {
  const normalized = String(value || '').toLowerCase().trim();
  const mapped = ROLE_ALIASES[normalized];
  return mapped || 'executive_viewer';
}

function hasRoleAccess(role, requiredRole) {
  const roleValue = roleRank[normalizeRole(role)];
  const requiredValue = roleRank[normalizeRole(requiredRole)];
  return Number.isFinite(roleValue) && Number.isFinite(requiredValue) && roleValue >= requiredValue;
}

function listRoles() {
  return [...ROLE_ORDER];
}

module.exports = {
  roleRank,
  listRoles,
  normalizeRole,
  hasRoleAccess,
};
