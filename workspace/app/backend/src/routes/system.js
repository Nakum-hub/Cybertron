/**
 * System / health / metrics routes.
 *
 * Extracted from server.js so the main request handler stays lean.
 * Exports a single `registerRoutes(routerContext)` following the same
 * convention used by the module route files (risk-copilot, compliance-engine,
 * threat-intel).
 *
 * SECURITY: The full health payload (memory, version, auth-mode, dependency
 * details) is only returned to authenticated callers.  Unauthenticated
 * requests receive a minimal `{ status, checkedAt }` response so that
 * external monitors can still verify basic availability without leaking
 * internal diagnostics.
 */

function registerRoutes(routerContext) {
  const register = routerContext?.register;
  if (typeof register !== 'function') {
    throw new Error('system routes require routerContext.register(handler)');
  }

  const deps = routerContext.deps || {};
  const {
    config,
    sendJson,
    sendText,
    sendError,
    sendMethodNotAllowed,
    buildHealthPayload,
    buildReadinessPayload,
    buildPublicRuntimeConfig,
    buildMetricsPayload,
    buildPrometheusMetrics,
    getMetricsAuthorizationStatus,
    buildOpenApiSpec,
    getSessionFromContext,
    hasRoleAccess,
  } = deps;

  register(async ({ context, response, baseExtraHeaders }) => {
    // ─── GET / ── root info endpoint ──────────────────────────────────
    if (context.path === '/') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }

      sendJson(
        response,
        context,
        config,
        200,
        {
          service: 'cybertron-backend',
          environment: config.environment,
          version: config.appVersion,
          docs: '/v1/system/openapi',
        },
        baseExtraHeaders
      );
      return true;
    }

    // ─── GET /v1/system/health ────────────────────────────────────────
    // Full payload is auth-protected; unauthenticated callers get a
    // minimal { status, checkedAt } response.
    if (context.path === '/v1/system/health') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }

      const health = await buildHealthPayload();

      const session = await getSessionFromContext(context);
      if (session) {
        sendJson(response, context, config, 200, health, baseExtraHeaders);
      } else {
        sendJson(
          response,
          context,
          config,
          200,
          {
            status: health.status,
            checkedAt: health.checkedAt,
          },
          baseExtraHeaders
        );
      }
      return true;
    }

    // ─── GET /v1/system/liveness ──────────────────────────────────────
    if (context.path === '/v1/system/liveness') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }

      sendJson(
        response,
        context,
        config,
        200,
        {
          status: 'alive',
          checkedAt: new Date().toISOString(),
        },
        baseExtraHeaders
      );
      return true;
    }

    // ─── GET /v1/system/readiness ─────────────────────────────────────
    if (context.path === '/v1/system/readiness') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }

      const readiness = await buildReadinessPayload();
      sendJson(response, context, config, readiness.ready ? 200 : 503, readiness, baseExtraHeaders);
      return true;
    }

    // ─── GET /config  |  GET /v1/system/config ────────────────────────
    if (context.path === '/config' || context.path === '/v1/system/config') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }

      sendJson(response, context, config, 200, buildPublicRuntimeConfig(), baseExtraHeaders);
      return true;
    }

    // ─── GET /v1/system/metrics (JSON) ────────────────────────────────
    if (context.path === '/v1/system/metrics') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }

      const metricsAuthorization = getMetricsAuthorizationStatus(context);
      if (!metricsAuthorization.allowed) {
        sendError(
          response,
          context,
          config,
          metricsAuthorization.statusCode,
          metricsAuthorization.code,
          metricsAuthorization.message,
          null,
          baseExtraHeaders
        );
        return true;
      }

      sendJson(response, context, config, 200, buildMetricsPayload(), baseExtraHeaders);
      return true;
    }

    // ─── GET /v1/system/metrics/prometheus ────────────────────────────
    if (context.path === '/v1/system/metrics/prometheus') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }

      const metricsAuthorization = getMetricsAuthorizationStatus(context);
      if (!metricsAuthorization.allowed) {
        sendError(
          response,
          context,
          config,
          metricsAuthorization.statusCode,
          metricsAuthorization.code,
          metricsAuthorization.message,
          null,
          baseExtraHeaders
        );
        return true;
      }

      sendText(response, context, config, 200, buildPrometheusMetrics(), baseExtraHeaders);
      return true;
    }

    // ─── GET /v1/system/openapi ───────────────────────────────────────
    if (context.path === '/v1/system/openapi') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }

      const session = await getSessionFromContext(context);
      if (!session) {
        sendError(
          response,
          context,
          config,
          401,
          'auth_required',
          'Authenticated internal access is required for API documentation.',
          null,
          baseExtraHeaders
        );
        return true;
      }

      const role = session?.user?.role || 'executive_viewer';
      if (!hasRoleAccess(role, 'tenant_admin')) {
        sendError(
          response,
          context,
          config,
          403,
          'access_denied',
          'Tenant Admin role or higher is required for API documentation.',
          {
            requiredRole: 'tenant_admin',
            effectiveRole: role,
          },
          baseExtraHeaders
        );
        return true;
      }

      sendJson(response, context, config, 200, buildOpenApiSpec(config), baseExtraHeaders);
      return true;
    }

    // Not handled by this module.
    return false;
  });
}

module.exports = { registerRoutes };
