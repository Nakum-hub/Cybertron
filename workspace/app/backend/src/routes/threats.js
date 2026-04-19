function registerRoutes(routerContext) {
  const register = routerContext?.register;
  if (typeof register !== 'function') {
    throw new Error('threat routes require routerContext.register(handler)');
  }

  const deps = routerContext.deps || {};
  const {
    config,
    log,
    sendJson,
    sendNoContent,
    sendMethodNotAllowed,
    requireDatabaseConfigured,
    requireSession,
    resolveTenantForRequest,
    parseJsonBody,
    validateBodyShape,
    handleServiceFailure,
    actorMetaFromContext,
    normalizeRole,
    hasRoleAccess,
    toSafeInteger,
    requireRole,
    requireProductAccess,
    getSessionFromContext,
    buildThreatSummary,
    buildThreatIncidents,
    getConnectorsStatus,
    listIncidents,
    createIncident,
    updateIncident,
    listIncidentTimeline,
    listIocs,
    createIoc,
    linkIocToIncident,
    createServiceRequest,
    updateServiceRequest,
    listServiceRequestComments,
    listServiceRequests,
    notifyIncidentCreated,
    notifyIncidentUpdated,
    getTenantPlan,
    assertFeatureAllowed,
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

    async function requirePlanFeatureGate(tenant, featureKey, featureContext = {}) {
      try {
        const plan = await getTenantPlan(config, tenant);
        assertFeatureAllowed(plan, featureKey, featureContext);
        return plan;
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
        return null;
      }
    }

    if (context.path === '/v1/threats/summary') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }

      let session = await getSessionFromContext(context);
      if (config.requireAuthForThreatEndpoints && !session) {
        session = await requireSession(
          context,
          response,
          baseExtraHeaders,
          'Threat data requires authenticated session'
        );
      }
      if (config.requireAuthForThreatEndpoints && !session) {
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

      const summary = await buildThreatSummary(config, tenant, log);
      sendJson(response, context, config, 200, summary, baseExtraHeaders);
      return true;
    }

    if (context.path === '/v1/threats/incidents') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }

      let session = await getSessionFromContext(context);
      if (config.requireAuthForThreatEndpoints && !session) {
        session = await requireSession(
          context,
          response,
          baseExtraHeaders,
          'Threat data requires authenticated session'
        );
      }
      if (config.requireAuthForThreatEndpoints && !session) {
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

      const limit = toSafeInteger(context.url.searchParams.get('limit'), 6, 1, 10);
      const incidents = await buildThreatIncidents(config, tenant, limit, log);
      sendJson(response, context, config, 200, incidents, baseExtraHeaders);
      return true;
    }

    if (context.path === '/v1/connectors/status') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'Connector status requires authenticated session'
      );
      if (!session) {
        return true;
      }

      if (
        !requireRole(
          session,
          'analyst',
          response,
          context,
          baseExtraHeaders,
          'Analyst role required for connector status'
        )
      ) {
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

      const plan = await requirePlanFeatureGate(tenant, 'connectorAccess');
      if (!plan) {
        return true;
      }

      try {
        const status = await getConnectorsStatus(config, log);
        sendJson(response, context, config, 200, status, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (/^\/v1\/incidents\/[0-9]+\/timeline$/.test(context.path)) {
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
        'Incident timeline requires authentication'
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
        context.url.searchParams.get('tenant')
      );
      if (!tenant) {
        return true;
      }

      const product = await requireCrudProductGate(
        session,
        tenant,
        'threat-command',
        'executive_viewer'
      );
      if (!product) {
        return true;
      }

      const incidentId = context.path.split('/')[3];
      const limit = toSafeInteger(context.url.searchParams.get('limit'), 100, 1, 200);

      try {
        const timeline = await listIncidentTimeline(config, tenant, incidentId, limit);
        sendJson(response, context, config, 200, { incidentId, data: timeline }, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (/^\/v1\/incidents\/[0-9]+\/iocs\/[0-9]+$/.test(context.path)) {
      if (context.method !== 'POST') {
        sendMethodNotAllowed(response, context, config, ['POST'], baseExtraHeaders);
        return true;
      }

      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'Incident linking requires authentication'
      );
      if (!session) {
        return true;
      }

      if (!requireRole(session, 'security_analyst', response, context, baseExtraHeaders)) {
        return true;
      }

      const segments = context.path.split('/');
      const incidentId = segments[3];
      const iocId = segments[5];
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

      const threatCommandProduct = await requireCrudProductGate(
        session,
        tenant,
        'threat-command',
        'security_analyst'
      );
      if (!threatCommandProduct) {
        return true;
      }

      try {
        await linkIocToIncident(config, tenant, incidentId, iocId, actorMetaFromContext(context, session));
        sendNoContent(response, context, config, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (/^\/v1\/incidents\/[0-9]+$/.test(context.path)) {
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
        'Incident updates require authentication'
      );
      if (!session) {
        return true;
      }

      if (!requireRole(session, 'security_analyst', response, context, baseExtraHeaders)) {
        return true;
      }

      const payload = await parseJsonBody(context, response, baseExtraHeaders);
      if (!payload) {
        return true;
      }

      if (
        !validateBodyShape(context, response, baseExtraHeaders, payload, {
          required: [],
          optional: [
            'title',
            'severity',
            'status',
            'priority',
            'assignedTo',
            'blocked',
            'source',
            'detectedAt',
            'resolvedAt',
            'responseTimeMinutes',
            'timelineMessage',
          ],
        })
      ) {
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

      const threatCommandProduct = await requireCrudProductGate(
        session,
        tenant,
        'threat-command',
        'security_analyst'
      );
      if (!threatCommandProduct) {
        return true;
      }

      const incidentId = context.path.split('/')[3];

      try {
        const incident = await updateIncident(
          config,
          tenant,
          incidentId,
          payload,
          actorMetaFromContext(context, session)
        );
        notifyIncidentUpdated(tenant, incident);
        sendJson(response, context, config, 200, incident, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (context.path === '/v1/incidents') {
      if (context.method !== 'GET' && context.method !== 'POST') {
        sendMethodNotAllowed(response, context, config, ['GET', 'POST'], baseExtraHeaders);
        return true;
      }

      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'Incident API requires authentication'
      );
      if (!session) {
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

      if (context.method === 'GET') {
        if (!requireRole(session, 'executive_viewer', response, context, baseExtraHeaders)) {
          return true;
        }

        const threatCommandProduct = await requireCrudProductGate(
          session,
          tenant,
          'threat-command',
          'executive_viewer'
        );
        if (!threatCommandProduct) {
          return true;
        }

        const rawSeverity = context.url.searchParams.get('severity') || undefined;
        const rawStatus = context.url.searchParams.get('status') || undefined;
        const rawSearch =
          context.url.searchParams.get('search') || context.url.searchParams.get('q') || undefined;

        const validIncidentSeverities = ['critical', 'high', 'medium', 'low'];
        const validIncidentStatuses = ['open', 'investigating', 'resolved'];

        const options = {
          severity:
            rawSeverity && validIncidentSeverities.includes(rawSeverity.toLowerCase())
              ? rawSeverity.toLowerCase()
              : undefined,
          status:
            rawStatus && validIncidentStatuses.includes(rawStatus.toLowerCase())
              ? rawStatus.toLowerCase()
              : undefined,
          search: rawSearch ? String(rawSearch).slice(0, 500) : undefined,
          limit: toSafeInteger(context.url.searchParams.get('limit'), 25, 1, 100),
          offset: toSafeInteger(context.url.searchParams.get('offset'), 0, 0, 50_000),
        };

        try {
          const payload = await listIncidents(config, tenant, options);
          sendJson(response, context, config, 200, payload, baseExtraHeaders);
        } catch (error) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
        }
        return true;
      }

      if (!requireRole(session, 'security_analyst', response, context, baseExtraHeaders)) {
        return true;
      }

      const threatCommandProduct = await requireCrudProductGate(
        session,
        tenant,
        'threat-command',
        'security_analyst'
      );
      if (!threatCommandProduct) {
        return true;
      }

      const payload = await parseJsonBody(context, response, baseExtraHeaders);
      if (!payload) {
        return true;
      }

      if (
        !validateBodyShape(context, response, baseExtraHeaders, payload, {
          required: ['title', 'severity'],
          optional: [
            'status',
            'blocked',
            'source',
            'detectedAt',
            'resolvedAt',
            'responseTimeMinutes',
            'timelineMessage',
            'rawEvent',
          ],
        })
      ) {
        return true;
      }

      try {
        const incident = await createIncident(
          config,
          tenant,
          payload,
          actorMetaFromContext(context, session)
        );
        notifyIncidentCreated(tenant, incident);
        sendJson(response, context, config, 201, incident, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (context.path === '/v1/iocs') {
      if (context.method !== 'GET' && context.method !== 'POST') {
        sendMethodNotAllowed(response, context, config, ['GET', 'POST'], baseExtraHeaders);
        return true;
      }

      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'IOC vault requires authentication'
      );
      if (!session) {
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

      if (context.method === 'GET') {
        if (!requireRole(session, 'executive_viewer', response, context, baseExtraHeaders)) {
          return true;
        }

        const threatCommandProduct = await requireCrudProductGate(
          session,
          tenant,
          'threat-command',
          'executive_viewer'
        );
        if (!threatCommandProduct) {
          return true;
        }

        const rawIocType =
          context.url.searchParams.get('iocType') || context.url.searchParams.get('type') || undefined;
        const rawIocSearch =
          context.url.searchParams.get('search') || context.url.searchParams.get('q') || undefined;
        const rawMinConfidence = context.url.searchParams.get('minConfidence');
        const validIocTypes = ['ip', 'domain', 'url', 'hash'];

        const options = {
          iocType:
            rawIocType && validIocTypes.includes(rawIocType.toLowerCase())
              ? rawIocType.toLowerCase()
              : undefined,
          search: rawIocSearch ? String(rawIocSearch).slice(0, 500) : undefined,
          minConfidence: rawMinConfidence != null ? Number(rawMinConfidence) : undefined,
          limit: toSafeInteger(context.url.searchParams.get('limit'), 50, 1, 200),
          offset: toSafeInteger(context.url.searchParams.get('offset'), 0, 0, 50_000),
        };

        try {
          const payload = await listIocs(config, tenant, options);
          sendJson(response, context, config, 200, payload, baseExtraHeaders);
        } catch (error) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
        }
        return true;
      }

      if (!requireRole(session, 'security_analyst', response, context, baseExtraHeaders)) {
        return true;
      }

      const threatCommandProduct = await requireCrudProductGate(
        session,
        tenant,
        'threat-command',
        'security_analyst'
      );
      if (!threatCommandProduct) {
        return true;
      }

      const payload = await parseJsonBody(context, response, baseExtraHeaders);
      if (!payload) {
        return true;
      }

      if (
        !validateBodyShape(context, response, baseExtraHeaders, payload, {
          required: ['iocType', 'value'],
          optional: ['source', 'confidence', 'firstSeenAt', 'lastSeenAt', 'tags'],
        })
      ) {
        return true;
      }

      try {
        const ioc = await createIoc(config, tenant, payload, actorMetaFromContext(context, session));
        sendJson(response, context, config, 201, ioc, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (/^\/v1\/service-requests\/[0-9]+\/comments$/.test(context.path)) {
      if (context.method !== 'GET' && context.method !== 'POST') {
        sendMethodNotAllowed(response, context, config, ['GET', 'POST'], baseExtraHeaders);
        return true;
      }

      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'Service request comments require authentication'
      );
      if (!session) {
        return true;
      }

      if (!requireRole(session, 'executive_viewer', response, context, baseExtraHeaders)) {
        return true;
      }

      const requestId = context.path.split('/')[3];
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

      const threatCommandProduct = await requireCrudProductGate(
        session,
        tenant,
        'threat-command',
        'executive_viewer'
      );
      if (!threatCommandProduct) {
        return true;
      }

      if (context.method === 'GET') {
        const limit = toSafeInteger(context.url.searchParams.get('limit'), 100, 1, 200);
        try {
          const comments = await listServiceRequestComments(config, tenant, requestId, limit);
          sendJson(response, context, config, 200, { requestId, data: comments }, baseExtraHeaders);
        } catch (error) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
        }
        return true;
      }

      const payload = await parseJsonBody(context, response, baseExtraHeaders);
      if (!payload) {
        return true;
      }

      if (
        !validateBodyShape(context, response, baseExtraHeaders, payload, {
          required: ['comment'],
          optional: [],
        })
      ) {
        return true;
      }

      try {
        const updated = await updateServiceRequest(
          config,
          tenant,
          requestId,
          {
            comment: payload.comment,
          },
          actorMetaFromContext(context, session)
        );
        sendJson(
          response,
          context,
          config,
          200,
          {
            request: updated,
            message: 'Comment added.',
          },
          baseExtraHeaders
        );
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (/^\/v1\/service-requests\/[0-9]+$/.test(context.path)) {
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
        'Service request updates require authentication'
      );
      if (!session) {
        return true;
      }

      if (!requireRole(session, 'security_analyst', response, context, baseExtraHeaders)) {
        return true;
      }

      const payload = await parseJsonBody(context, response, baseExtraHeaders);
      if (!payload) {
        return true;
      }

      if (
        !validateBodyShape(context, response, baseExtraHeaders, payload, {
          required: [],
          optional: ['category', 'priority', 'status', 'subject', 'description', 'comment'],
        })
      ) {
        return true;
      }

      const requestId = context.path.split('/')[3];
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

      const threatCommandProduct = await requireCrudProductGate(
        session,
        tenant,
        'threat-command',
        'security_analyst'
      );
      if (!threatCommandProduct) {
        return true;
      }

      try {
        const updated = await updateServiceRequest(
          config,
          tenant,
          requestId,
          payload,
          actorMetaFromContext(context, session)
        );
        sendJson(response, context, config, 200, updated, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (context.path === '/v1/service-requests') {
      if (context.method !== 'GET' && context.method !== 'POST') {
        sendMethodNotAllowed(response, context, config, ['GET', 'POST'], baseExtraHeaders);
        return true;
      }

      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'Service request endpoints require authenticated session'
      );
      if (!session) {
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

      if (context.method === 'GET') {
        const threatCommandProduct = await requireCrudProductGate(
          session,
          tenant,
          'threat-command',
          'executive_viewer'
        );
        if (!threatCommandProduct) {
          return true;
        }

        const limit = toSafeInteger(context.url.searchParams.get('limit'), 25, 1, 200);
        const role = normalizeRole(session.user.role);
        const scopedFilter = hasRoleAccess(role, 'security_analyst')
          ? { limit }
          : { limit, requesterEmail: session.user.email || '' };

        const payload = await listServiceRequests(config, tenant, scopedFilter);
        sendJson(response, context, config, 200, payload, baseExtraHeaders);
        return true;
      }

      const payload = await parseJsonBody(context, response, baseExtraHeaders);
      if (!payload) {
        return true;
      }

      const threatCommandProduct = await requireCrudProductGate(
        session,
        tenant,
        'threat-command',
        'executive_viewer'
      );
      if (!threatCommandProduct) {
        return true;
      }

      if (
        !validateBodyShape(context, response, baseExtraHeaders, payload, {
          required: ['category', 'subject'],
          optional: ['requesterEmail', 'priority', 'description', 'comment'],
        })
      ) {
        return true;
      }

      try {
        const requestRecord = await createServiceRequest(
          config,
          tenant,
          payload,
          actorMetaFromContext(context, session)
        );
        sendJson(response, context, config, 201, requestRecord, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (context.path === '/v1/threats/iocs') {
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
        'IOC data requires authentication'
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
        context.url.searchParams.get('tenant')
      );
      if (!tenant) {
        return true;
      }

      const product = await requireCrudProductGate(
        session,
        tenant,
        'threat-command',
        'executive_viewer'
      );
      if (!product) {
        return true;
      }

      try {
        const payload = await listIocs(config, tenant, {
          limit: toSafeInteger(context.url.searchParams.get('limit'), 50, 1, 200),
          offset: toSafeInteger(context.url.searchParams.get('offset'), 0, 0, 50_000),
        });
        sendJson(response, context, config, 200, payload, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    return false;
  });
}

module.exports = { registerRoutes };
