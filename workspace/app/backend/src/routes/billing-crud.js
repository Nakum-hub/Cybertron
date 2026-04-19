function registerRoutes(routerContext) {
  const register = routerContext?.register;
  if (typeof register !== 'function') {
    throw new Error('billing crud routes require routerContext.register(handler)');
  }

  const deps = routerContext.deps || {};
  const {
    config,
    sendJson,
    sendMethodNotAllowed,
    requireDatabaseConfigured,
    requireSession,
    resolveTenantForRequest,
    parseJsonBody,
    handleServiceFailure,
    actorMetaFromContext,
    toSafeInteger,
    requireRole,
    listUsageEvents,
    getCredits,
    getTenantPlan,
    setPlanForTenant,
    appendAuditLog,
  } = deps;

  register(async ({ context, response, baseExtraHeaders }) => {
    if (context.path === '/v1/billing/usage') {
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
        'Billing usage endpoint requires authenticated session'
      );
      if (!session) {
        return true;
      }

      if (!requireRole(session, 'security_analyst', response, context, baseExtraHeaders)) {
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

      const payload = await listUsageEvents(config, tenant, {
        limit: toSafeInteger(context.url.searchParams.get('limit'), 50, 1, 500),
        offset: toSafeInteger(context.url.searchParams.get('offset'), 0, 0, 50_000),
        productKey: context.url.searchParams.get('productKey') || undefined,
      });
      sendJson(response, context, config, 200, payload, baseExtraHeaders);
      return true;
    }

    if (context.path === '/v1/billing/credits') {
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
        'Billing credits endpoint requires authenticated session'
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

      const payload = await getCredits(config, tenant);
      sendJson(response, context, config, 200, payload, baseExtraHeaders);
      return true;
    }

    if (context.path === '/v1/billing/plan') {
      if (context.method === 'GET') {
        const session = await requireSession(
          context,
          response,
          baseExtraHeaders,
          'Session required to view billing plan'
        );
        if (!session) {
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

        try {
          const plan = await getTenantPlan(config, tenant);
          sendJson(response, context, config, 200, plan, baseExtraHeaders);
        } catch (error) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
        }
        return true;
      }

      if (context.method === 'PUT') {
        const session = await requireSession(
          context,
          response,
          baseExtraHeaders,
          'Session required to update billing plan'
        );
        if (!session) {
          return true;
        }

        if (
          !requireRole(
            session,
            'super_admin',
            response,
            context,
            baseExtraHeaders,
            'Super admin role required'
          )
        ) {
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

        const body = await parseJsonBody(context, response, baseExtraHeaders);
        if (!body) {
          return true;
        }

        try {
          const result = await setPlanForTenant(config, tenant, body.tier, body.expiresAt || null);
          await appendAuditLog(config, {
            tenantSlug: tenant,
            actorId: session.user.id,
            actorEmail: session.user.email,
            action: 'billing.plan_updated',
            targetType: 'tenant_plan',
            targetId: tenant,
            ...actorMetaFromContext(context, session),
            payload: { tier: body.tier },
          });
          sendJson(response, context, config, 200, result, baseExtraHeaders);
        } catch (error) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
        }
        return true;
      }

      sendMethodNotAllowed(response, context, config, ['GET', 'PUT'], baseExtraHeaders);
      return true;
    }

    return false;
  });
}

module.exports = { registerRoutes };
