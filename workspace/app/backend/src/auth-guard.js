const { normalizeRole, hasRoleAccess } = require('./security-policy');
const { sanitizeTenant } = require('./validators');

function createAuthGuard(options) {
  const config = options.config;
  const sendError = options.sendError;
  const getSession = options.getSession;

  async function requireAuth(context, response, extraHeaders, message = 'Authentication required') {
    const session = await getSession(context);
    if (session) {
      return session;
    }

    sendError(
      response,
      context,
      config,
      401,
      'auth_required',
      message,
      {
        loginPath: '/v1/auth/login',
      },
      extraHeaders
    );
    return null;
  }

  function requireRole(session, requiredRole, context, response, extraHeaders, message) {
    if (hasRoleAccess(session?.user?.role, requiredRole)) {
      return true;
    }

    sendError(
      response,
      context,
      config,
      403,
      'access_denied',
      message || `Role ${requiredRole} is required for this endpoint.`,
      {
        requiredRole: normalizeRole(requiredRole),
        effectiveRole: normalizeRole(session?.user?.role),
      },
      extraHeaders
    );
    return false;
  }

  function resolveTenantScope(session, requestedTenant, options = {}) {
    const fallbackTenant = sanitizeTenant(session?.user?.tenant || requestedTenant || 'global');
    const targetTenant = sanitizeTenant(requestedTenant || fallbackTenant);

    if (!requestedTenant || targetTenant === fallbackTenant) {
      return fallbackTenant;
    }

    const allowCrossTenantRoles = Array.isArray(options.allowCrossTenantRoles)
      ? options.allowCrossTenantRoles
      : ['super_admin'];

    const role = normalizeRole(session?.user?.role);
    const canCrossTenant = allowCrossTenantRoles.some(required => hasRoleAccess(role, required));
    return canCrossTenant ? targetTenant : fallbackTenant;
  }

  function requireTenantScope(session, targetTenant, context, response, extraHeaders, options = {}) {
    const fallbackTenant = sanitizeTenant(session?.user?.tenant || 'global');
    const target = sanitizeTenant(targetTenant || fallbackTenant);
    const allowCrossTenantRoles = Array.isArray(options.allowCrossTenantRoles)
      ? options.allowCrossTenantRoles
      : ['super_admin'];

    if (target === fallbackTenant) {
      return true;
    }

    const role = normalizeRole(session?.user?.role);
    const canCrossTenant = allowCrossTenantRoles.some(required => hasRoleAccess(role, required));
    if (canCrossTenant) {
      return true;
    }

    sendError(
      response,
      context,
      config,
      403,
      'tenant_scope_denied',
      'Cross-tenant access is not allowed for this session.',
      {
        requestedTenant: target,
        effectiveTenant: fallbackTenant,
      },
      extraHeaders
    );
    return false;
  }

  return {
    requireAuth,
    requireRole,
    resolveTenantScope,
    requireTenantScope,
  };
}

module.exports = {
  createAuthGuard,
};
