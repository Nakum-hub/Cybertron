function registerRoutes(routerContext) {
  const register = routerContext?.register;
  if (typeof register !== 'function') {
    throw new Error('notification routes require routerContext.register(handler)');
  }

  const deps = routerContext.deps || {};
  const {
    config,
    baseHeaders,
    sendJson,
    sendError,
    sendMethodNotAllowed,
    requireDatabaseConfigured,
    requireSession,
    resolveTenantForRequest,
    addSseClient,
    getRecentEventsForTenant,
    getConnectedClientCount,
    getTotalConnectedClients,
  } = deps;

  register(async ({ context, response, baseExtraHeaders }) => {
    if (context.path === '/v1/notifications/stream') {
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
        'Notification stream requires authentication'
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

      const added = addSseClient(tenant, session.user.id, response);
      if (!added) {
        sendError(
          response,
          context,
          config,
          429,
          'too_many_connections',
          'Max SSE connections per tenant reached',
          null,
          baseExtraHeaders
        );
        return true;
      }

      response.writeHead(200, {
        ...baseHeaders(context, config, baseExtraHeaders),
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        Connection: 'keep-alive',
        'X-Accel-Buffering': 'no',
      });

      const lastEventId = Number(context.request.headers['last-event-id'] || '0') || 0;
      const missed = getRecentEventsForTenant(tenant, lastEventId);
      for (const evt of missed) {
        const data = JSON.stringify({ type: evt.type, payload: evt.payload, timestamp: evt.timestamp });
        response.write(`id: ${evt.id}\nevent: ${evt.type}\ndata: ${data}\n\n`);
      }

      response.write(`: connected to ${tenant} notification stream\n\n`);

      const SSE_HEARTBEAT_INTERVAL_MS = 30_000;
      const SSE_MAX_IDLE_MS = 10 * 60 * 1000;
      const sseStartTime = Date.now();
      const heartbeatTimer = setInterval(() => {
        if (Date.now() - sseStartTime > SSE_MAX_IDLE_MS) {
          clearInterval(heartbeatTimer);
          response.end();
          return;
        }
        try {
          response.write(': heartbeat\n\n');
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
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }
      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'Notification stats require authentication'
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

      sendJson(
        response,
        context,
        config,
        200,
        {
          tenant,
          connectedClients: getConnectedClientCount(tenant),
          totalConnectedClients: getTotalConnectedClients(),
        },
        baseExtraHeaders
      );
      return true;
    }

    if (context.path === '/v1/notifications') {
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
        'Notifications require authentication'
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

      const recent = getRecentEventsForTenant(tenant, 0);
      sendJson(
        response,
        context,
        config,
        200,
        {
          data: recent.map(evt => ({
            id: evt.id,
            type: evt.type,
            payload: evt.payload,
            timestamp: evt.timestamp,
            read: false,
          })),
          total: recent.length,
          unread: recent.length,
        },
        baseExtraHeaders
      );
      return true;
    }

    return false;
  });
}

module.exports = { registerRoutes };
