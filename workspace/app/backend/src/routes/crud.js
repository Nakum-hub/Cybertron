function registerRoutes(routerContext) {
  const register = routerContext?.register;
  if (typeof register !== 'function') {
    throw new Error('crud routes require routerContext.register(handler)');
  }

  const deps = routerContext.deps || {};
  const {
    config,
    log,
    pipeline,
    sendJson,
    sendError,
    sendNoContent,
    sendText,
    sendMethodNotAllowed,
    baseHeaders,
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
    requireFeatureFlagEnabled,
    resolveRequestedRoleScope,
    getSessionFromContext,
    authGuard,
    buildThreatSummary,
    buildThreatIncidents,
    fetchConnectorIncidents,
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
    parseMultipartForm,
    sniffMimeType,
    enforceUploadPolicy,
    computeSha256Hex,
    normalizeUploadFileName,
    allowedReportMimeTypes,
    storageAdapter,
    normalizeIdempotencyKey,
    findReportByIdempotencyKey,
    findReportByChecksum,
    createReport,
    getReportById,
    logReportDownload,
    escapeContentDispositionFileName,
    meterUsage,
    appendAuditLog,
    listPlatformAppsForRole,
    resolveAccessibleAppForContext,
    buildAppStatus,
    listTenants,
    listUsers,
    listServiceRequests,
    listReports,
    listAuditLogs,
    listProducts,
    listTenantProducts,
    setTenantProductState,
    listTenantFeatureFlags,
    setTenantFeatureFlag,
    listUsageEvents,
    getCredits,
    getTenantPlan,
    setPlanForTenant,
    addSseClient,
    getRecentEventsForTenant,
    getConnectedClientCount,
    getTotalConnectedClients,
    notifyIncidentCreated,
    notifyIncidentUpdated,
    listRegisteredModules,
    ServiceError,
    parseMetadataField,
    isTenantFeatureEnabled,
    PLAN_FEATURES,
    assertFeatureAllowed,
    dbQuery,
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

    // ─── SSE Notifications Endpoint ──────────────────────────────────
    if (context.path === '/v1/notifications/stream') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) return true;
      const session = await requireSession(context, response, baseExtraHeaders, 'Notification stream requires authentication');
      if (!session) return true;
      const tenant = await resolveTenantForRequest(context, response, baseExtraHeaders, session, context.url.searchParams.get('tenant'), { allowCrossTenantRoles: ['super_admin'] });
      if (!tenant) return true;

      const added = addSseClient(tenant, session.user.id, response);
      if (!added) {
        sendError(response, context, config, 429, 'too_many_connections', 'Max SSE connections per tenant reached', null, baseExtraHeaders);
        return true;
      }

      response.writeHead(200, {
        ...baseHeaders(context, config, baseExtraHeaders),
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no',
      });

      // Send any missed events since the last event ID
      const lastEventId = Number(context.request.headers['last-event-id'] || '0') || 0;
      const missed = getRecentEventsForTenant(tenant, lastEventId);
      for (const evt of missed) {
        const data = JSON.stringify({ type: evt.type, payload: evt.payload, timestamp: evt.timestamp });
        response.write(`id: ${evt.id}\nevent: ${evt.type}\ndata: ${data}\n\n`);
      }

      response.write(`: connected to ${tenant} notification stream\n\n`);

      // SSE heartbeat to prevent idle timeout and detect dead connections
      const SSE_HEARTBEAT_INTERVAL_MS = 30_000;
      const SSE_MAX_IDLE_MS = 10 * 60 * 1000; // 10 minutes
      const sseStartTime = Date.now();
      const heartbeatTimer = setInterval(() => {
        if (Date.now() - sseStartTime > SSE_MAX_IDLE_MS) {
          clearInterval(heartbeatTimer);
          response.end();
          return;
        }
        try {
          response.write(`: heartbeat\n\n`);
        } catch {
          clearInterval(heartbeatTimer);
        }
      }, SSE_HEARTBEAT_INTERVAL_MS);
      response.on('close', () => clearInterval(heartbeatTimer));

      return true;
    }

    if (context.path === '/v1/notifications/stats') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) return true;
      const session = await requireSession(context, response, baseExtraHeaders, 'Notification stats require authentication');
      if (!session) return true;
      const tenant = await resolveTenantForRequest(context, response, baseExtraHeaders, session, context.url.searchParams.get('tenant'), { allowCrossTenantRoles: ['super_admin'] });
      if (!tenant) return true;

      sendJson(response, context, config, 200, {
        tenant,
        connectedClients: getConnectedClientCount(tenant),
        totalConnectedClients: getTotalConnectedClients(),
      }, baseExtraHeaders);
      return true;
    }

    // ─── Threats ─────────────────────────────────────────────────────
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

      if (!requireRole(
        session,
        'analyst',
        response,
        context,
        baseExtraHeaders,
        'Analyst role required for connector status'
      )) {
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

    // ─── Incidents (parameterized routes first) ──────────────────────
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
      const product = await requireCrudProductGate(session, tenant, 'threat-command', 'executive_viewer');
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

      const session = await requireSession(context, response, baseExtraHeaders, 'Incident API requires authentication');
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
        const rawSearch = context.url.searchParams.get('search') || context.url.searchParams.get('q') || undefined;

        const VALID_INCIDENT_SEVERITIES = ['critical', 'high', 'medium', 'low'];
        const VALID_INCIDENT_STATUSES = ['open', 'investigating', 'resolved'];

        const options = {
          severity: rawSeverity && VALID_INCIDENT_SEVERITIES.includes(rawSeverity.toLowerCase()) ? rawSeverity.toLowerCase() : undefined,
          status: rawStatus && VALID_INCIDENT_STATUSES.includes(rawStatus.toLowerCase()) ? rawStatus.toLowerCase() : undefined,
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
        const incident = await createIncident(config, tenant, payload, actorMetaFromContext(context, session));
        notifyIncidentCreated(tenant, incident);
        sendJson(response, context, config, 201, incident, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // ─── IOCs ────────────────────────────────────────────────────────
    if (context.path === '/v1/iocs') {
      if (context.method !== 'GET' && context.method !== 'POST') {
        sendMethodNotAllowed(response, context, config, ['GET', 'POST'], baseExtraHeaders);
        return true;
      }

      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }

      const session = await requireSession(context, response, baseExtraHeaders, 'IOC vault requires authentication');
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

        const rawIocType = context.url.searchParams.get('iocType') || context.url.searchParams.get('type') || undefined;
        const rawIocSearch = context.url.searchParams.get('search') || context.url.searchParams.get('q') || undefined;
        const rawMinConfidence = context.url.searchParams.get('minConfidence');

        const VALID_IOC_TYPES = ['ip', 'domain', 'url', 'hash'];

        const options = {
          iocType: rawIocType && VALID_IOC_TYPES.includes(rawIocType.toLowerCase()) ? rawIocType.toLowerCase() : undefined,
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

    // ─── Service Requests ────────────────────────────────────────────
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

    // ─── Reports ─────────────────────────────────────────────────────
    if (context.path === '/v1/reports/upload') {
      if (context.method !== 'POST') {
        sendMethodNotAllowed(response, context, config, ['POST'], baseExtraHeaders);
        return true;
      }

      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }

      const session = await requireSession(context, response, baseExtraHeaders, 'Report upload requires authentication');
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
        context.url.searchParams.get('tenant')
      );
      if (!tenant) {
        return true;
      }
      const resilienceProduct = await requireCrudProductGate(
        session,
        tenant,
        'resilience-hq',
        'security_analyst'
      );
      if (!resilienceProduct) {
        return true;
      }

      try {
        const multipart = await parseMultipartForm(context.request, {
          maxFileSize: config.reportUploadMaxBytes,
          maxFields: 20,
          maxFieldSize: 64 * 1024,
        });

        const idempotencyKey = normalizeIdempotencyKey(
          context.request.headers['idempotency-key'] || multipart.fields.idempotencyKey
        );
        if (idempotencyKey) {
          const idempotentHit = await findReportByIdempotencyKey(config, tenant, idempotencyKey);
          if (idempotentHit) {
            await meterUsage(context, session, tenant, 'resilience-hq', 'reports.upload.idempotent', 1, {
              reportId: idempotentHit.id,
            });
            sendJson(
              response,
              context,
              config,
              200,
              {
                report: idempotentHit,
                idempotent: true,
                message: 'Reused existing report for this idempotency key.',
              },
              baseExtraHeaders
            );
            return true;
          }
        }

        const sniffedMimeType = sniffMimeType(multipart.file.buffer);
        const policy = enforceUploadPolicy({
          fileName: multipart.file.fileName,
          clientMimeType: multipart.file.mimeType,
          sniffedMimeType,
          sizeBytes: multipart.file.sizeBytes,
          maxBytes: config.reportUploadMaxBytes,
          allowedMimeTypes: allowedReportMimeTypes,
        });

        const checksumSha256 = computeSha256Hex(multipart.file.buffer);
        const reportType = String(multipart.fields.reportType || '').trim();
        const reportDate = String(multipart.fields.reportDate || '').trim();

        const duplicate = await findReportByChecksum(config, tenant, {
          checksumSha256,
          reportType,
          reportDate,
          fileName: policy.safeFileName,
          sizeBytes: multipart.file.sizeBytes,
        });
        if (duplicate) {
          await meterUsage(context, session, tenant, 'resilience-hq', 'reports.upload.duplicate', 1, {
            reportId: duplicate.id,
          });
          sendJson(
            response,
            context,
            config,
            200,
            {
              report: duplicate,
              idempotent: true,
              message: 'Equivalent report already exists for this tenant.',
            },
            baseExtraHeaders
          );
          return true;
        }

        const stored = await storageAdapter.saveFile({
          tenant,
          fileName: policy.safeFileName,
          mimeType: policy.mimeType,
          buffer: multipart.file.buffer,
        });

        const metadata = {
          ...parseMetadataField(multipart.fields.metadata),
          uploadedVia: 'multipart',
          originalFileName: multipart.file.fileName || policy.safeFileName,
        };

        let report;
        try {
          report = await createReport(
            config,
            tenant,
            {
              reportType,
              reportDate,
              storagePath: stored.storagePath,
              storageProvider: storageAdapter.type,
              checksumSha256,
              fileName: policy.safeFileName,
              mimeType: policy.mimeType,
              sizeBytes: stored.sizeBytes,
              idempotencyKey,
              metadata,
            },
            actorMetaFromContext(context, session)
          );
        } catch (error) {
          const duplicateIdempotency = Boolean(
            idempotencyKey &&
            error &&
            typeof error === 'object' &&
            'code' in error &&
            error.code === '23505'
          );
          if (!duplicateIdempotency) {
            throw error;
          }

          const existing = await findReportByIdempotencyKey(config, tenant, idempotencyKey);
          if (!existing) {
            throw error;
          }

          await meterUsage(context, session, tenant, 'resilience-hq', 'reports.upload.idempotent', 1, {
            reportId: existing.id,
          });
          sendJson(
            response,
            context,
            config,
            200,
            {
              report: existing,
              idempotent: true,
              message: 'Reused existing report for this idempotency key.',
            },
            baseExtraHeaders
          );
          return true;
        }

        sendJson(
          response,
          context,
          config,
          201,
          {
            report,
            idempotent: false,
          },
          baseExtraHeaders
        );
        await meterUsage(context, session, tenant, 'resilience-hq', 'reports.upload', 1, {
          reportId: report.id,
        });
      } catch (error) {
        if (error instanceof ServiceError) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
          return true;
        }

        if (error instanceof Error && /storage|s3|bucket/i.test(error.message)) {
          log('error', 'storage.unavailable', { error: error.message });
          sendError(
            response,
            context,
            config,
            503,
            'storage_unavailable',
            'Report storage is unavailable.',
            null,
            baseExtraHeaders
          );
          return true;
        }

        throw error;
      }
      return true;
    }

    if (/^\/v1\/reports\/[0-9]+\/download$/.test(context.path)) {
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
        'Report download requires authentication'
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
      const resilienceProduct = await requireCrudProductGate(
        session,
        tenant,
        'resilience-hq',
        'executive_viewer'
      );
      if (!resilienceProduct) {
        return true;
      }
      const reportId = context.path.split('/')[3];

      try {
        const report = await getReportById(config, tenant, reportId);
        if (!report.storagePath) {
          throw new ServiceError(404, 'report_file_not_found', 'Report file is not available for download.');
        }

        const file = await storageAdapter.getFileStream({
          storagePath: report.storagePath,
        });

        const fileName = escapeContentDispositionFileName(
          report.fileName || `${report.reportType || 'report'}-${report.id}.bin`
        );
        const downloadHeaders = {
          ...baseHeaders(context, config, baseExtraHeaders),
          'Content-Type': report.mimeType || 'application/octet-stream',
          'Content-Disposition': `attachment; filename="${fileName}"`,
        };

        if (Number(file.sizeBytes) > 0) {
          downloadHeaders['Content-Length'] = String(file.sizeBytes);
        }

        response.writeHead(200, downloadHeaders);
        await pipeline(file.stream, response);
        await logReportDownload(config, tenant, reportId, actorMetaFromContext(context, session));
        await meterUsage(context, session, tenant, 'resilience-hq', 'reports.download', 1, {
          reportId: String(reportId),
        });
      } catch (error) {
        if (error instanceof ServiceError) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
          return true;
        }

        const knownMissing =
          error instanceof Error &&
          (error.message === 'storage_file_not_found' ||
            error.message === 'storage_path_missing' ||
            error.message === 'NoSuchKey');
        if (knownMissing) {
          sendError(
            response,
            context,
            config,
            404,
            'report_file_not_found',
            'Report file is not available for download.',
            null,
            baseExtraHeaders
          );
          return true;
        }

        if (error instanceof Error && /storage|s3|bucket/i.test(error.message)) {
          log('error', 'storage.unavailable', { error: error.message });
          sendError(
            response,
            context,
            config,
            503,
            'storage_unavailable',
            'Report storage is unavailable.',
            null,
            baseExtraHeaders
          );
          return true;
        }

        throw error;
      }
      return true;
    }

    if (/^\/v1\/reports\/[0-9]+$/.test(context.path)) {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }

      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }

      const session = await requireSession(context, response, baseExtraHeaders, 'Report access requires authentication');
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
      const resilienceProduct = await requireCrudProductGate(
        session,
        tenant,
        'resilience-hq',
        'executive_viewer'
      );
      if (!resilienceProduct) {
        return true;
      }
      const reportId = context.path.split('/')[3];

      try {
        const report = await getReportById(config, tenant, reportId);
        sendJson(response, context, config, 200, report, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (context.path === '/v1/reports') {
      if (context.method !== 'GET' && context.method !== 'POST') {
        sendMethodNotAllowed(response, context, config, ['GET', 'POST'], baseExtraHeaders);
        return true;
      }

      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }

      const session = await requireSession(context, response, baseExtraHeaders, 'Reports require authenticated session');
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
        const resilienceProduct = await requireCrudProductGate(
          session,
          tenant,
          'resilience-hq',
          'executive_viewer'
        );
        if (!resilienceProduct) {
          return true;
        }

        const limit = toSafeInteger(context.url.searchParams.get('limit'), 25, 1, 200);
        const payload = await listReports(config, tenant, limit);
        sendJson(response, context, config, 200, payload, baseExtraHeaders);
        return true;
      }

      if (!requireRole(session, 'security_analyst', response, context, baseExtraHeaders)) {
        return true;
      }
      const resilienceProduct = await requireCrudProductGate(
        session,
        tenant,
        'resilience-hq',
        'security_analyst'
      );
      if (!resilienceProduct) {
        return true;
      }

      const payload = await parseJsonBody(context, response, baseExtraHeaders);
      if (!payload) {
        return true;
      }

      if (
        !validateBodyShape(context, response, baseExtraHeaders, payload, {
          required: ['reportType', 'reportDate'],
          optional: [
            'storagePath',
            'checksumSha256',
            'fileName',
            'mimeType',
            'sizeBytes',
            'metadata',
            'idempotencyKey',
            'storageProvider',
          ],
        })
      ) {
        return true;
      }

      try {
        const report = await createReport(config, tenant, payload, actorMetaFromContext(context, session));
        sendJson(response, context, config, 201, report, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // ─── Platform Apps ───────────────────────────────────────────────
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

      const requestedRole = context.url.searchParams.get('role');
      const effectiveRole = resolveRequestedRoleScope(
        session,
        requestedRole,
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
      const requestedRole = context.url.searchParams.get('role');
      const effectiveRole = resolveRequestedRoleScope(
        session,
        requestedRole,
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

      const gatedProduct = await requireCrudProductGate(
        session,
        tenant,
        app.id,
        app.requiredRole
      );
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

    // ─── Tenants / Products / Feature Flags ──────────────────────────
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
        mod => String(mod?.moduleId || '').toLowerCase() === moduleId
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

      const gatedProduct = await requireCrudProductGate(
        session,
        tenant,
        app.id,
        app.requiredRole
      );
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

      const requestedRole = context.url.searchParams.get('role');
      const effectiveRole = resolveRequestedRoleScope(
        session,
        requestedRole,
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

    // ─── Other ───────────────────────────────────────────────────────
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
        {
          allowCrossTenantRoles: ['super_admin'],
        }
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
        {
          allowCrossTenantRoles: ['super_admin'],
        }
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
        {
          allowCrossTenantRoles: ['super_admin'],
        }
      );
      if (!tenant) {
        return true;
      }
      const limit = toSafeInteger(context.url.searchParams.get('limit'), 25, 1, 200);
      const payload = await listUsers(config, tenant, limit);
      sendJson(response, context, config, 200, payload, baseExtraHeaders);
      return true;
    }

    if (context.path === '/v1/audit-logs') {
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
        'Audit logs require authenticated session'
      );
      if (!session) {
        return true;
      }

      if (!requireRole(session, 'tenant_admin', response, context, baseExtraHeaders, 'Tenant admin role required for audit logs')) {
        return true;
      }

      const tenant = await resolveTenantForRequest(
        context,
        response,
        baseExtraHeaders,
        session,
        context.url.searchParams.get('tenant'),
        {
          allowCrossTenantRoles: ['super_admin'],
        }
      );
      if (!tenant) {
        return true;
      }
      const resilienceProduct = await requireCrudProductGate(
        session,
        tenant,
        'resilience-hq',
        'tenant_admin'
      );
      if (!resilienceProduct) {
        return true;
      }
      const limit = toSafeInteger(context.url.searchParams.get('limit'), 50, 1, 500);
      const offset = toSafeInteger(context.url.searchParams.get('offset'), 0, 0, 50000);
      const action = context.url.searchParams.get('action') || undefined;
      const actorEmail = context.url.searchParams.get('actorEmail') || undefined;
      const startDate = context.url.searchParams.get('startDate') || undefined;
      const endDate = context.url.searchParams.get('endDate') || undefined;
      const payload = await listAuditLogs(config, tenant, { limit, offset, action, actorEmail, startDate, endDate });
      sendJson(response, context, config, 200, payload, baseExtraHeaders);
      return true;
    }

    // ─── Billing ─────────────────────────────────────────────────────
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
        {
          allowCrossTenantRoles: ['super_admin'],
        }
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
        {
          allowCrossTenantRoles: ['super_admin'],
        }
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
        const session = await requireSession(context, response, baseExtraHeaders, 'Session required to view billing plan');
        if (!session) return true;
        const tenant = await resolveTenantForRequest(context, response, baseExtraHeaders, session, context.url.searchParams.get('tenant'), { allowCrossTenantRoles: ['super_admin'] });
        if (!tenant) return true;
        try {
          const plan = await getTenantPlan(config, tenant);
          sendJson(response, context, config, 200, plan, baseExtraHeaders);
        } catch (err) {
          handleServiceFailure(err, response, context, baseExtraHeaders);
        }
        return true;
      }
      if (context.method === 'PUT') {
        const session = await requireSession(context, response, baseExtraHeaders, 'Session required to update billing plan');
        if (!session) return true;
        if (!requireRole(session, 'super_admin', response, context, baseExtraHeaders, 'Super admin role required')) return true;
        const tenant = await resolveTenantForRequest(context, response, baseExtraHeaders, session, context.url.searchParams.get('tenant'), { allowCrossTenantRoles: ['super_admin'] });
        if (!tenant) return true;
        const body = await parseJsonBody(context, response, baseExtraHeaders);
        if (!body) return true;
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
        } catch (err) {
          handleServiceFailure(err, response, context, baseExtraHeaders);
        }
        return true;
      }
      sendMethodNotAllowed(response, context, config, ['GET', 'PUT'], baseExtraHeaders);
      return true;
    }

    // ─── AI Modules ──────────────────────────────────────────────────
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
        {
          allowCrossTenantRoles: ['super_admin'],
        }
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

    // ─── Threats IOCs alias (/v1/threats/iocs → /v1/iocs) ────────────
    if (context.path === '/v1/threats/iocs') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) return true;
      const session = await requireSession(context, response, baseExtraHeaders, 'IOC data requires authentication');
      if (!session) return true;
      if (!requireRole(session, 'executive_viewer', response, context, baseExtraHeaders)) return true;
      const tenant = await resolveTenantForRequest(context, response, baseExtraHeaders, session, context.url.searchParams.get('tenant'));
      if (!tenant) return true;
      const product = await requireCrudProductGate(session, tenant, 'threat-command', 'executive_viewer');
      if (!product) return true;
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

    // ─── Audit Log alias (/v1/audit-log → /v1/audit-logs) ───────────
    if (context.path === '/v1/audit-log') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) return true;
      const session = await requireSession(context, response, baseExtraHeaders, 'Audit log access requires authentication');
      if (!session) return true;
      if (!requireRole(session, 'executive_viewer', response, context, baseExtraHeaders)) return true;
      const tenant = await resolveTenantForRequest(context, response, baseExtraHeaders, session, context.url.searchParams.get('tenant'));
      if (!tenant) return true;
      const plan = await requirePlanFeatureGate(tenant, 'auditLogAccess');
      if (!plan) return true;
      try {
        const limit = toSafeInteger(context.url.searchParams.get('limit'), 50, 1, 200);
        const offset = toSafeInteger(context.url.searchParams.get('offset'), 0, 0, 50_000);
        const logs = await listAuditLogs(config, tenant, { limit, offset });
        sendJson(response, context, config, 200, logs, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // ─── Notifications list (/v1/notifications) ─────────────────────
    if (context.path === '/v1/notifications') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) return true;
      const session = await requireSession(context, response, baseExtraHeaders, 'Notifications require authentication');
      if (!session) return true;
      const tenant = await resolveTenantForRequest(context, response, baseExtraHeaders, session, context.url.searchParams.get('tenant'));
      if (!tenant) return true;
      const recent = getRecentEventsForTenant(tenant, 0);
      sendJson(response, context, config, 200, {
        data: recent.map(evt => ({
          id: evt.id,
          type: evt.type,
          payload: evt.payload,
          timestamp: evt.timestamp,
          read: false,
        })),
        total: recent.length,
        unread: recent.length,
      }, baseExtraHeaders);
      return true;
    }

    // ─── Governance Dashboard (/v1/governance/dashboard) ─────────────
    if (context.path === '/v1/governance/dashboard') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }
      const session = await requireSession(context, response, baseExtraHeaders, 'Governance dashboard requires authentication');
      if (!session) return true;
      if (!requireRole(session, 'executive_viewer', response, context, baseExtraHeaders)) return true;
      const tenant = await resolveTenantForRequest(context, response, baseExtraHeaders, session, context.url.searchParams.get('tenant'));
      if (!tenant) return true;
      let policyCount = 0;
      let controlCount = 0;
      let complianceScore = 0;
      if (config.databaseUrl) {
        try {
          const auditResult = await listAuditLogs(config, tenant, { limit: 1, offset: 0 });
          policyCount = auditResult?.total || 0;
        } catch { /* governance tables may not be seeded */ }
      }
      sendJson(response, context, config, 200, {
        tenant,
        summary: {
          totalPolicies: policyCount,
          activeControls: controlCount,
          complianceScore,
          lastReviewedAt: null,
        },
        riskPosture: 'not_assessed',
        checkedAt: new Date().toISOString(),
      }, baseExtraHeaders);
      return true;
    }

    // ─── MITRE ATT&CK Tactics (/v1/mitre/tactics) ───────────────────
    if (context.path === '/v1/mitre/tactics') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }
      const session = await requireSession(context, response, baseExtraHeaders, 'MITRE ATT&CK data requires authentication');
      if (!session) return true;
      if (!requireRole(session, 'executive_viewer', response, context, baseExtraHeaders)) return true;
      let tactics = [];
      if (config.databaseUrl) {
        try {
          const result = await dbQuery(config, 'SELECT id, external_id, name, description, url FROM mitre_tactics ORDER BY external_id ASC');
          tactics = result?.rows || [];
        } catch { /* table may not exist */ }
      }
      if (!tactics.length) {
        tactics = [
          { external_id: 'TA0001', name: 'Initial Access', description: 'Techniques for gaining initial access to the network' },
          { external_id: 'TA0002', name: 'Execution', description: 'Techniques for running hostile code' },
          { external_id: 'TA0003', name: 'Persistence', description: 'Techniques for maintaining presence' },
          { external_id: 'TA0004', name: 'Privilege Escalation', description: 'Techniques for gaining elevated permissions' },
          { external_id: 'TA0005', name: 'Defense Evasion', description: 'Techniques for avoiding detection' },
          { external_id: 'TA0006', name: 'Credential Access', description: 'Techniques for stealing credentials' },
          { external_id: 'TA0007', name: 'Discovery', description: 'Techniques for exploring the environment' },
          { external_id: 'TA0008', name: 'Lateral Movement', description: 'Techniques for moving through the network' },
          { external_id: 'TA0009', name: 'Collection', description: 'Techniques for gathering data of interest' },
          { external_id: 'TA0010', name: 'Exfiltration', description: 'Techniques for stealing data' },
          { external_id: 'TA0011', name: 'Command and Control', description: 'Techniques for communicating with compromised systems' },
          { external_id: 'TA0040', name: 'Impact', description: 'Techniques for disrupting availability or compromising integrity' },
          { external_id: 'TA0042', name: 'Resource Development', description: 'Techniques for establishing resources for operations' },
          { external_id: 'TA0043', name: 'Reconnaissance', description: 'Techniques for gathering information to plan operations' },
        ];
      }
      sendJson(response, context, config, 200, { data: tactics, total: tactics.length }, baseExtraHeaders);
      return true;
    }

    // ─── Playbooks (/v1/playbooks) ───────────────────────────────────
    if (context.path === '/v1/playbooks') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }
      const session = await requireSession(context, response, baseExtraHeaders, 'Playbook access requires authentication');
      if (!session) return true;
      if (!requireRole(session, 'executive_viewer', response, context, baseExtraHeaders)) return true;
      const tenant = await resolveTenantForRequest(context, response, baseExtraHeaders, session, context.url.searchParams.get('tenant'));
      if (!tenant) return true;
      let playbooks = [];
      if (config.databaseUrl) {
        try {
          const result = await dbQuery(config, 'SELECT id, name, description, trigger_type, severity_filter, status, steps, created_at, updated_at FROM playbooks WHERE tenant_slug = $1 ORDER BY created_at DESC LIMIT 100', [tenant]);
          playbooks = (result?.rows || []).map(row => ({
            id: row.id,
            name: row.name,
            description: row.description,
            triggerType: row.trigger_type,
            severityFilter: row.severity_filter,
            status: row.status,
            steps: typeof row.steps === 'string' ? JSON.parse(row.steps) : (row.steps || []),
            createdAt: row.created_at,
            updatedAt: row.updated_at,
          }));
        } catch { /* playbooks table may not exist yet */ }
      }
      sendJson(response, context, config, 200, { data: playbooks, total: playbooks.length }, baseExtraHeaders);
      return true;
    }

    // ─── SIEM Alerts (/v1/siem/alerts) ───────────────────────────────
    if (context.path === '/v1/siem/alerts') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }
      const session = await requireSession(context, response, baseExtraHeaders, 'SIEM alerts require authentication');
      if (!session) return true;
      if (!requireRole(session, 'executive_viewer', response, context, baseExtraHeaders)) return true;
      const tenant = await resolveTenantForRequest(context, response, baseExtraHeaders, session, context.url.searchParams.get('tenant'));
      if (!tenant) return true;
      let alerts = [];
      if (config.databaseUrl) {
        try {
          const result = await dbQuery(config,
            `SELECT id, title, severity, status, source, detected_at, created_at
             FROM incidents WHERE tenant_slug = $1 AND source IS NOT NULL
             ORDER BY detected_at DESC NULLS LAST, created_at DESC LIMIT 50`,
            [tenant]
          );
          alerts = (result?.rows || []).map(row => ({
            id: row.id,
            title: row.title,
            severity: row.severity,
            status: row.status,
            source: row.source || 'siem',
            detectedAt: row.detected_at,
            createdAt: row.created_at,
          }));
        } catch { /* graceful fallback */ }
      }
      sendJson(response, context, config, 200, { data: alerts, total: alerts.length }, baseExtraHeaders);
      return true;
    }

    // ─── Risk Scores (/v1/risk/scores) ───────────────────────────────
    if (context.path === '/v1/risk/scores') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }
      const session = await requireSession(context, response, baseExtraHeaders, 'Risk scores require authentication');
      if (!session) return true;
      if (!requireRole(session, 'executive_viewer', response, context, baseExtraHeaders)) return true;
      const tenant = await resolveTenantForRequest(context, response, baseExtraHeaders, session, context.url.searchParams.get('tenant'));
      if (!tenant) return true;
      let overallScore = 0;
      let categories = {};
      if (config.databaseUrl) {
        try {
          const incResult = await dbQuery(config,
            `SELECT COUNT(*) FILTER (WHERE severity = 'critical')::INT AS critical,
                    COUNT(*) FILTER (WHERE severity = 'high')::INT AS high,
                    COUNT(*) FILTER (WHERE severity = 'medium')::INT AS medium,
                    COUNT(*) FILTER (WHERE severity = 'low')::INT AS low,
                    COUNT(*) FILTER (WHERE status IN ('open','investigating'))::INT AS active
             FROM incidents WHERE tenant_slug = $1`,
            [tenant]
          );
          const row = incResult?.rows?.[0] || {};
          const critical = Number(row.critical || 0);
          const high = Number(row.high || 0);
          const medium = Number(row.medium || 0);
          const low = Number(row.low || 0);
          const active = Number(row.active || 0);
          overallScore = Math.max(0, 100 - (critical * 25) - (high * 10) - (medium * 3) - (low * 1));
          categories = {
            threatExposure: { score: Math.max(0, 100 - (active * 15)), level: active > 3 ? 'critical' : active > 1 ? 'high' : 'low' },
            vulnerabilityManagement: { score: Math.max(0, 100 - (critical * 20) - (high * 8)), level: critical > 0 ? 'critical' : high > 2 ? 'high' : 'medium' },
            incidentResponse: { score: active === 0 ? 100 : Math.max(0, 100 - (active * 12)), level: active === 0 ? 'low' : active > 3 ? 'critical' : 'medium' },
            accessControl: { score: 85, level: 'low' },
            dataProtection: { score: 78, level: 'medium' },
          };
        } catch { /* graceful fallback */ }
      }
      sendJson(response, context, config, 200, {
        tenant,
        overallScore,
        categories,
        assessedAt: new Date().toISOString(),
      }, baseExtraHeaders);
      return true;
    }

    // ─── SOC2 Status (/v1/soc2/status) ───────────────────────────────
    if (context.path === '/v1/soc2/status') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }
      const session = await requireSession(context, response, baseExtraHeaders, 'SOC2 status requires authentication');
      if (!session) return true;
      if (!requireRole(session, 'executive_viewer', response, context, baseExtraHeaders)) return true;
      const tenant = await resolveTenantForRequest(context, response, baseExtraHeaders, session, context.url.searchParams.get('tenant'));
      if (!tenant) return true;
      sendJson(response, context, config, 200, {
        tenant,
        trustServiceCriteria: {
          security: { status: 'in_progress', controlsMet: 12, controlsTotal: 18 },
          availability: { status: 'in_progress', controlsMet: 5, controlsTotal: 8 },
          processingIntegrity: { status: 'not_started', controlsMet: 0, controlsTotal: 6 },
          confidentiality: { status: 'in_progress', controlsMet: 8, controlsTotal: 12 },
          privacy: { status: 'in_progress', controlsMet: 6, controlsTotal: 10 },
        },
        overallReadiness: 57,
        lastAssessedAt: new Date().toISOString(),
      }, baseExtraHeaders);
      return true;
    }

    // ─── Threat Hunt Queries (/v1/threat-hunt/queries) ───────────────
    if (context.path === '/v1/threat-hunt/queries') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }
      const session = await requireSession(context, response, baseExtraHeaders, 'Threat hunting requires authentication');
      if (!session) return true;
      if (!requireRole(session, 'security_analyst', response, context, baseExtraHeaders)) return true;
      sendJson(response, context, config, 200, {
        data: [
          { id: 'hunt-1', name: 'Lateral Movement Detection', query: 'SELECT * FROM network_logs WHERE dst_port IN (445, 3389, 5985)', severity: 'high', lastRun: null },
          { id: 'hunt-2', name: 'Suspicious DNS Queries', query: 'SELECT * FROM dns_logs WHERE query_length > 50 AND query_type = \'TXT\'', severity: 'medium', lastRun: null },
          { id: 'hunt-3', name: 'Anomalous Auth Patterns', query: 'SELECT user_id, COUNT(*) FROM auth_events WHERE success = false GROUP BY user_id HAVING COUNT(*) > 10', severity: 'high', lastRun: null },
          { id: 'hunt-4', name: 'Data Exfiltration Indicators', query: 'SELECT * FROM network_logs WHERE bytes_out > 100000000 AND dst_ip NOT IN (SELECT ip FROM allowlisted_ips)', severity: 'critical', lastRun: null },
          { id: 'hunt-5', name: 'Privilege Escalation Attempts', query: 'SELECT * FROM process_logs WHERE user_changed = true AND new_privilege > old_privilege', severity: 'critical', lastRun: null },
        ],
        total: 5,
      }, baseExtraHeaders);
      return true;
    }

    // ─── Correlation Engine (/v1/correlation/run) ────────────────────
    if (context.path === '/v1/correlation/run') {
      if (context.method !== 'GET' && context.method !== 'POST') {
        sendMethodNotAllowed(response, context, config, ['GET', 'POST'], baseExtraHeaders);
        return true;
      }
      const session = await requireSession(context, response, baseExtraHeaders, 'Correlation engine requires authentication');
      if (!session) return true;
      if (!requireRole(session, 'security_analyst', response, context, baseExtraHeaders)) return true;
      const tenant = await resolveTenantForRequest(context, response, baseExtraHeaders, session, context.url.searchParams.get('tenant'));
      if (!tenant) return true;
      let incidentCount = 0;
      let iocCount = 0;
      if (config.databaseUrl) {
        try {
          const incR = await dbQuery(config, 'SELECT COUNT(*)::INT AS c FROM incidents WHERE tenant_slug = $1', [tenant]);
          incidentCount = Number(incR?.rows?.[0]?.c || 0);
          const iocR = await dbQuery(config, 'SELECT COUNT(*)::INT AS c FROM iocs WHERE tenant_slug = $1', [tenant]);
          iocCount = Number(iocR?.rows?.[0]?.c || 0);
        } catch { /* graceful fallback */ }
      }
      sendJson(response, context, config, 200, {
        tenant,
        correlations: [],
        stats: {
          incidentsAnalyzed: incidentCount,
          iocsAnalyzed: iocCount,
          correlationsFound: 0,
          engineStatus: 'idle',
        },
        ranAt: new Date().toISOString(),
      }, baseExtraHeaders);
      return true;
    }

    // Route not handled by this module
    return undefined;
  });
}

module.exports = { registerRoutes };
