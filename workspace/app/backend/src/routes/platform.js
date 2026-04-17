function registerRoutes(routerContext) {
  const register = routerContext?.register;
  if (typeof register !== 'function') {
    throw new Error('platform routes require routerContext.register(handler)');
  }

  const deps = routerContext.deps || {};
  const {
    config,
    sendJson,
    sendError,
    sendMethodNotAllowed,
    requireDatabaseConfigured,
    requireSession,
    resolveTenantForRequest,
    parseJsonBody,
    validateBodyShape,
    handleServiceFailure,
    actorMetaFromContext,
    sanitizeTenant,
    normalizeRole,
    hasRoleAccess,
    toSafeInteger,
    requireRole,
    requireProductAccess,
    resolveRequestedRoleScope,
    authGuard,
    listPlatformAppsForRole,
    resolveAccessibleAppForContext,
    buildAppStatus,
    listTenants,
    listTenantProducts,
    setTenantProductState,
    listTenantFeatureFlags,
    setTenantFeatureFlag,
    listUsers,
    listRegisteredModules,
    meterUsage,
  } = deps;

  register(async ({ context, response, baseExtraHeaders }) => {
    async function requireCrudProductGate(session, tenant, productKey, requiredRole, options = {}) {
      return requireProductAccess(
        context,
        response,
        baseExtraHeaders,
        session,
        tenant,
        productKey,
        requiredRole,
        options
      );
    }

    if (context.path === '/v1/platform/apps') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'Platform endpoints require authenticated session'
      );
      if (!session) {
        return true;
      }

      const effectiveRole = resolveRequestedRoleScope(
        session,
        context.url.searchParams.get('role'),
        context,
        response,
        baseExtraHeaders
      );
      if (!effectiveRole) {
        return true;
      }

      const tenant = await resolveTenantForRequest(
        context,
        response,
        baseExtraHeaders,
        session,
        context.url.searchParams.get('tenant')
      );
      if (!tenant) {
        return true;
      }

      const apps = await listPlatformAppsForRole(tenant, effectiveRole);
      await meterUsage(context, session, tenant, 'threat-command', 'platform.apps.list', 1, {
        appCount: apps.length,
        effectiveRole,
      });
      sendJson(response, context, config, 200, apps, baseExtraHeaders);
      return true;
    }

    if (/^\/v1\/apps\/[a-z0-9-]+\/status$/.test(context.path)) {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'Platform endpoints require authenticated session'
      );
      if (!session) {
        return true;
      }

      const appId = context.path.replace('/v1/apps/', '').replace('/status', '').toLowerCase();
      const effectiveRole = resolveRequestedRoleScope(
        session,
        context.url.searchParams.get('role'),
        context,
        response,
        baseExtraHeaders
      );
      if (!effectiveRole) {
        return true;
      }

      const tenant = await resolveTenantForRequest(
        context,
        response,
        baseExtraHeaders,
        session,
        context.url.searchParams.get('tenant')
      );
      if (!tenant) {
        return true;
      }

      const app = await resolveAccessibleAppForContext(appId, tenant, effectiveRole);
      if (!app) {
        sendError(
          response,
          context,
          config,
          403,
          'module_not_accessible',
          'Module is disabled, feature-gated, or not accessible for current role/tenant scope.',
          null,
          baseExtraHeaders
        );
        return true;
      }

      if (!hasRoleAccess(effectiveRole, app.requiredRole)) {
        sendError(
          response,
          context,
          config,
          403,
          'access_denied',
          'Role does not have access to this module',
          {
            requiredRole: app.requiredRole,
            effectiveRole,
            appId: app.id,
          },
          baseExtraHeaders
        );
        return true;
      }

      const gatedProduct = await requireCrudProductGate(session, tenant, app.id, app.requiredRole);
      if (!gatedProduct) {
        return true;
      }

      const payload = await buildAppStatus(app.id, tenant);
      await meterUsage(context, session, tenant, app.id, 'platform.app.status', 1, {
        effectiveRole,
      });
      sendJson(response, context, config, 200, payload, baseExtraHeaders);
      return true;
    }

    if (/^\/v1\/modules\/[a-z0-9-]+\/status$/.test(context.path)) {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'Module endpoints require authenticated session'
      );
      if (!session) {
        return true;
      }

      const moduleId = context.path.replace('/v1/modules/', '').replace('/status', '').toLowerCase();
      const effectiveRole = resolveRequestedRoleScope(
        session,
        context.url.searchParams.get('role'),
        context,
        response,
        baseExtraHeaders
      );
      if (!effectiveRole) {
        return true;
      }

      const tenant = await resolveTenantForRequest(
        context,
        response,
        baseExtraHeaders,
        session,
        context.url.searchParams.get('tenant')
      );
      if (!tenant) {
        return true;
      }

      const registeredModule = listRegisteredModules().find(
        item => String(item?.moduleId || '').toLowerCase() === moduleId
      );
      if (!registeredModule) {
        sendError(
          response,
          context,
          config,
          404,
          'module_not_found',
          'Module is not registered.',
          { moduleId },
          baseExtraHeaders
        );
        return true;
      }

      const accessibleApps = await listPlatformAppsForRole(tenant, effectiveRole);
      const app = accessibleApps.find(
        candidate => String(candidate?.moduleId || '').toLowerCase() === moduleId
      );
      if (!app) {
        sendError(
          response,
          context,
          config,
          403,
          'module_not_accessible',
          'Module is disabled, feature-gated, or not accessible for current role/tenant scope.',
          { moduleId },
          baseExtraHeaders
        );
        return true;
      }

      if (!hasRoleAccess(effectiveRole, app.requiredRole)) {
        sendError(
          response,
          context,
          config,
          403,
          'access_denied',
          'Role does not have access to this module',
          {
            requiredRole: app.requiredRole,
            effectiveRole,
            appId: app.id,
            moduleId,
          },
          baseExtraHeaders
        );
        return true;
      }

      const gatedProduct = await requireCrudProductGate(session, tenant, app.id, app.requiredRole);
      if (!gatedProduct) {
        return true;
      }

      const payload = await buildAppStatus(app.id, tenant);
      await meterUsage(context, session, tenant, app.id, 'platform.module.status', 1, {
        effectiveRole,
        moduleId,
      });
      sendJson(response, context, config, 200, payload, baseExtraHeaders);
      return true;
    }

    if (context.path === '/v1/tenants') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'Tenant catalog requires authenticated session'
      );
      if (!session) {
        return true;
      }

      const role = normalizeRole(session.user.role);
      const tenantSlug = sanitizeTenant(session.user.tenant || 'global');
      if (!config.databaseUrl || !hasRoleAccess(role, 'super_admin')) {
        sendJson(
          response,
          context,
          config,
          200,
          [
            {
              slug: tenantSlug,
              name: tenantSlug === 'global' ? 'Global Tenant' : `Tenant ${tenantSlug}`,
              createdAt: new Date().toISOString(),
            },
          ],
          baseExtraHeaders
        );
        return true;
      }

      const limit = toSafeInteger(context.url.searchParams.get('limit'), 25, 1, 200);
      const payload = await listTenants(config, limit);
      sendJson(response, context, config, 200, payload, baseExtraHeaders);
      return true;
    }

    if (/^\/v1\/tenants\/[a-z0-9-]+\/products$/.test(context.path)) {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'Tenant product registry requires authenticated session'
      );
      if (!session) {
        return true;
      }

      const tenantSlug = sanitizeTenant(context.path.split('/')[3] || 'global');
      if (
        !authGuard.requireTenantScope(session, tenantSlug, context, response, baseExtraHeaders, {
          allowCrossTenantRoles: ['super_admin'],
        })
      ) {
        return true;
      }

      const effectiveRole = resolveRequestedRoleScope(
        session,
        context.url.searchParams.get('role'),
        context,
        response,
        baseExtraHeaders
      );
      if (!effectiveRole) {
        return true;
      }

      const payload = await listTenantProducts(config, tenantSlug, effectiveRole);
      sendJson(response, context, config, 200, payload, baseExtraHeaders);
      return true;
    }

    if (/^\/v1\/tenants\/[a-z0-9-]+\/products\/[a-z0-9-]+$/.test(context.path)) {
      if (context.method !== 'PATCH') {
        sendMethodNotAllowed(response, context, config, ['PATCH'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'Tenant product updates require authenticated session'
      );
      if (!session) {
        return true;
      }
      if (!requireRole(session, 'tenant_admin', response, context, baseExtraHeaders)) {
        return true;
      }

      const tenantSlug = sanitizeTenant(context.path.split('/')[3] || 'global');
      if (
        !authGuard.requireTenantScope(session, tenantSlug, context, response, baseExtraHeaders, {
          allowCrossTenantRoles: ['super_admin'],
        })
      ) {
        return true;
      }

      const payload = await parseJsonBody(context, response, baseExtraHeaders);
      if (!payload) {
        return true;
      }
      if (
        !validateBodyShape(context, response, baseExtraHeaders, payload, {
          required: ['enabled'],
          optional: ['roleMin'],
        })
      ) {
        return true;
      }

      const productKey = context.path.split('/')[5];
      try {
        const result = await setTenantProductState(
          config,
          {
            productKey,
            tenant: tenantSlug,
            enabled: payload.enabled,
            roleMin: payload.roleMin,
          },
          actorMetaFromContext(context, session)
        );
        sendJson(response, context, config, 200, result, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (/^\/v1\/tenants\/[a-z0-9-]+\/feature-flags$/.test(context.path)) {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'Feature flag catalog requires authenticated session'
      );
      if (!session) {
        return true;
      }

      const tenantSlug = sanitizeTenant(context.path.split('/')[3] || 'global');
      if (
        !authGuard.requireTenantScope(session, tenantSlug, context, response, baseExtraHeaders, {
          allowCrossTenantRoles: ['super_admin'],
        })
      ) {
        return true;
      }
      if (!requireRole(session, 'executive_viewer', response, context, baseExtraHeaders)) {
        return true;
      }

      const payload = await listTenantFeatureFlags(config, tenantSlug);
      sendJson(response, context, config, 200, payload, baseExtraHeaders);
      return true;
    }

    if (/^\/v1\/tenants\/[a-z0-9-]+\/feature-flags\/[a-z0-9_:-]+$/.test(context.path)) {
      if (context.method !== 'PATCH') {
        sendMethodNotAllowed(response, context, config, ['PATCH'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'Feature flag updates require authenticated session'
      );
      if (!session) {
        return true;
      }
      if (!requireRole(session, 'tenant_admin', response, context, baseExtraHeaders)) {
        return true;
      }

      const tenantSlug = sanitizeTenant(context.path.split('/')[3] || 'global');
      if (
        !authGuard.requireTenantScope(session, tenantSlug, context, response, baseExtraHeaders, {
          allowCrossTenantRoles: ['super_admin'],
        })
      ) {
        return true;
      }

      const payload = await parseJsonBody(context, response, baseExtraHeaders);
      if (!payload) {
        return true;
      }
      if (
        !validateBodyShape(context, response, baseExtraHeaders, payload, {
          required: ['enabled'],
          optional: [],
        })
      ) {
        return true;
      }

      const flagKey = context.path.split('/')[5];
      try {
        const result = await setTenantFeatureFlag(
          config,
          {
            tenant: tenantSlug,
            flagKey,
            enabled: payload.enabled,
          },
          actorMetaFromContext(context, session)
        );
        sendJson(response, context, config, 200, result, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (context.path === '/v1/products') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'Products catalog requires authenticated session'
      );
      if (!session) {
        return true;
      }
      if (!requireRole(session, 'executive_viewer', response, context, baseExtraHeaders)) {
        return true;
      }

      const tenant = await resolveTenantForRequest(
        context,
        response,
        baseExtraHeaders,
        session,
        context.url.searchParams.get('tenant'),
        { allowCrossTenantRoles: ['super_admin'] }
      );
      if (!tenant) {
        return true;
      }

      const effectiveRole = resolveRequestedRoleScope(
        session,
        context.url.searchParams.get('role'),
        context,
        response,
        baseExtraHeaders
      );
      if (!effectiveRole) {
        return true;
      }

      const products = await listTenantProducts(config, tenant, effectiveRole);
      sendJson(response, context, config, 200, products, baseExtraHeaders);
      return true;
    }

    if (context.path === '/v1/modules') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'Module registry requires authenticated session'
      );
      if (!session) {
        return true;
      }
      if (!requireRole(session, 'executive_viewer', response, context, baseExtraHeaders)) {
        return true;
      }

      const tenant = await resolveTenantForRequest(
        context,
        response,
        baseExtraHeaders,
        session,
        context.url.searchParams.get('tenant'),
        { allowCrossTenantRoles: ['super_admin'] }
      );
      if (!tenant) {
        return true;
      }

      const role = resolveRequestedRoleScope(
        session,
        context.url.searchParams.get('role'),
        context,
        response,
        baseExtraHeaders
      );
      if (!role) {
        return true;
      }

      const apps = await listPlatformAppsForRole(tenant, role);
      sendJson(
        response,
        context,
        config,
        200,
        {
          modules: listRegisteredModules(),
          apps,
        },
        baseExtraHeaders
      );
      return true;
    }

    if (context.path === '/v1/users') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'User directory requires authenticated session'
      );
      if (!session) {
        return true;
      }
      if (!requireRole(session, 'tenant_admin', response, context, baseExtraHeaders, 'Tenant admin role required for user directory')) {
        return true;
      }

      const tenant = await resolveTenantForRequest(
        context,
        response,
        baseExtraHeaders,
        session,
        context.url.searchParams.get('tenant'),
        { allowCrossTenantRoles: ['super_admin'] }
      );
      if (!tenant) {
        return true;
      }

      const limit = toSafeInteger(context.url.searchParams.get('limit'), 25, 1, 200);
      const payload = await listUsers(config, tenant, limit);
      sendJson(response, context, config, 200, payload, baseExtraHeaders);
      return true;
    }

    if (context.path === '/v1/ai/modules') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'AI module catalog requires authenticated session'
      );
      if (!session) {
        return true;
      }
      if (!requireRole(session, 'executive_viewer', response, context, baseExtraHeaders)) {
        return true;
      }

      const tenant = await resolveTenantForRequest(
        context,
        response,
        baseExtraHeaders,
        session,
        context.url.searchParams.get('tenant'),
        { allowCrossTenantRoles: ['super_admin'] }
      );
      if (!tenant) {
        return true;
      }

      const role = resolveRequestedRoleScope(
        session,
        context.url.searchParams.get('role'),
        context,
        response,
        baseExtraHeaders
      );
      if (!role) {
        return true;
      }

      const apps = await listPlatformAppsForRole(tenant, role);
      sendJson(
        response,
        context,
        config,
        200,
        {
          modules: listRegisteredModules(),
          apps,
        },
        baseExtraHeaders
      );
      return true;
    }

    return false;
  });
}

module.exports = { registerRoutes };
