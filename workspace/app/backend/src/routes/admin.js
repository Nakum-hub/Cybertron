/**
 * P1-4/6/8/10: Admin API Routes
 *
 * Registers routes for:
 * - /v1/admin/users (GET)
 * - /v1/admin/invites (GET, POST, DELETE)
 * - /v1/admin/connectors (GET, PUT, POST test)
 * - /v1/billing/checkout (POST)
 * - /v1/billing/status (GET)
 * - /v1/billing/webhook (POST — Stripe)
 * - /v1/admin/api-keys (GET, POST, DELETE)
 */

const { createInvite, acceptInvite, listInvites, revokeInvite } = require('../invite-service');
const { createCheckoutSession, handleWebhookEvent, getSubscriptionStatus, resolvePriceId } = require('../stripe-service');
const { listConnectorConfigs, upsertConnectorConfig, deleteConnectorConfig, testConnectorConnection } = require('../connector-config-service');
const { createApiKey, listApiKeys, revokeApiKey } = require('../api-key-service');
const { getNotificationPreferences, upsertNotificationPreferences } = require('../notification-preferences-service');

function registerRoutes(routerContext) {
  const register = routerContext?.register;
  if (typeof register !== 'function') {
    throw new Error('admin routes require routerContext.register(handler)');
  }

  const deps = routerContext.deps || {};
  const {
    config,
    sendJson,
    sendError,
    sendNoContent,
    sendMethodNotAllowed,
    requireDatabaseConfigured,
    requireSession,
    resolveTenantForRequest,
    parseJsonBody,
    handleServiceFailure,
    requireRole,
    listUsers,
    listAuditLogs,
    appendAuditLog,
    actorMetaFromContext,
  } = deps;

  register(async ({ context, response, baseExtraHeaders }) => {

    // ─── Admin: List Users ─────────────────────────────────────────
    if (context.path === '/v1/admin/users') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) return true;
      const session = await requireSession(context, response, baseExtraHeaders, 'Admin access required');
      if (!session) return true;
      if (!requireRole(session, 'tenant_admin', response, context, baseExtraHeaders, 'Admin role required')) return true;
      const tenant = await resolveTenantForRequest(context, response, baseExtraHeaders, session, context.url.searchParams.get('tenant'));
      if (!tenant) return true;

      try {
        const users = await listUsers(config, tenant);
        sendJson(response, context, config, 200, { data: users }, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // ─── Admin: Workspace Invites ──────────────────────────────────
    if (/^\/v1\/admin\/invites(\/[0-9]+)?$/.test(context.path)) {
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) return true;
      const session = await requireSession(context, response, baseExtraHeaders, 'Admin access required');
      if (!session) return true;
      if (!requireRole(session, 'tenant_admin', response, context, baseExtraHeaders, 'Admin role required')) return true;
      const tenant = await resolveTenantForRequest(context, response, baseExtraHeaders, session, context.url.searchParams.get('tenant'));
      if (!tenant) return true;

      // GET /v1/admin/invites
      if (context.path === '/v1/admin/invites' && context.method === 'GET') {
        try {
          const invites = await listInvites(config, tenant);
          sendJson(response, context, config, 200, invites, baseExtraHeaders);
        } catch (error) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
        }
        return true;
      }

      // POST /v1/admin/invites
      if (context.path === '/v1/admin/invites' && context.method === 'POST') {
        const payload = await parseJsonBody(context, response, baseExtraHeaders);
        if (!payload) return true;
        try {
          const result = await createInvite(config, {
            tenant,
            email: payload.email,
            role: payload.role,
            invitedByUserId: session.user?.id,
          });
          await appendAuditLog(config, {
            tenantSlug: tenant,
            actorId: String(session.user?.id || ''),
            actorEmail: session.user?.email || null,
            action: 'admin.invite_created',
            targetType: 'invite',
            targetId: result.inviteId,
            ...actorMetaFromContext(context, session),
            payload: { email: payload.email, role: payload.role },
          });
          sendJson(response, context, config, 201, result, baseExtraHeaders);
        } catch (error) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
        }
        return true;
      }

      // DELETE /v1/admin/invites/:id
      if (/^\/v1\/admin\/invites\/[0-9]+$/.test(context.path) && context.method === 'DELETE') {
        const inviteId = context.path.split('/').pop();
        try {
          await revokeInvite(config, tenant, inviteId);
          sendNoContent(response, context, config, baseExtraHeaders);
        } catch (error) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
        }
        return true;
      }

      sendMethodNotAllowed(response, context, config, ['GET', 'POST', 'DELETE'], baseExtraHeaders);
      return true;
    }

    // ─── Invite Accept (public) ────────────────────────────────────
    if (context.path === '/v1/invites/accept' && context.method === 'POST') {
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) return true;
      const payload = await parseJsonBody(context, response, baseExtraHeaders);
      if (!payload) return true;
      try {
        const result = await acceptInvite(config, {
          token: payload.token,
          acceptingUserId: payload.userId,
        });
        sendJson(response, context, config, 200, result, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // ─── Admin: Connector Configs ──────────────────────────────────
    if (/^\/v1\/admin\/connectors/.test(context.path)) {
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) return true;
      const session = await requireSession(context, response, baseExtraHeaders, 'Admin access required');
      if (!session) return true;
      if (!requireRole(session, 'tenant_admin', response, context, baseExtraHeaders, 'Admin role required')) return true;
      const tenant = await resolveTenantForRequest(context, response, baseExtraHeaders, session, context.url.searchParams.get('tenant'));
      if (!tenant) return true;

      // GET /v1/admin/connectors
      if (context.path === '/v1/admin/connectors' && context.method === 'GET') {
        try {
          const configs_list = await listConnectorConfigs(config, tenant);
          sendJson(response, context, config, 200, configs_list, baseExtraHeaders);
        } catch (error) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
        }
        return true;
      }

      // PUT /v1/admin/connectors/:connector
      if (/^\/v1\/admin\/connectors\/[a-z]+$/.test(context.path) && context.method === 'PUT') {
        const connector = context.path.split('/').pop();
        const payload = await parseJsonBody(context, response, baseExtraHeaders);
        if (!payload) return true;
        try {
          const result = await upsertConnectorConfig(config, tenant, {
            connector,
            apiUrl: payload.apiUrl,
            apiToken: payload.apiToken,
            enabled: payload.enabled,
          });
          await appendAuditLog(config, {
            tenantSlug: tenant,
            actorId: String(session.user?.id || ''),
            actorEmail: session.user?.email || null,
            action: 'admin.connector_updated',
            targetType: 'connector',
            targetId: connector,
            ...actorMetaFromContext(context, session),
            payload: { connector, enabled: payload.enabled },
          });
          sendJson(response, context, config, 200, result, baseExtraHeaders);
        } catch (error) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
        }
        return true;
      }

      // POST /v1/admin/connectors/:connector/test
      if (/^\/v1\/admin\/connectors\/[a-z]+\/test$/.test(context.path) && context.method === 'POST') {
        const connector = context.path.split('/')[4];
        try {
          const result = await testConnectorConnection(config, tenant, connector);
          sendJson(response, context, config, 200, result, baseExtraHeaders);
        } catch (error) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
        }
        return true;
      }

      // DELETE /v1/admin/connectors/:connector
      if (/^\/v1\/admin\/connectors\/[a-z]+$/.test(context.path) && context.method === 'DELETE') {
        const connector = context.path.split('/').pop();
        try {
          await deleteConnectorConfig(config, tenant, connector);
          sendNoContent(response, context, config, baseExtraHeaders);
        } catch (error) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
        }
        return true;
      }

      sendMethodNotAllowed(response, context, config, ['GET', 'PUT', 'POST', 'DELETE'], baseExtraHeaders);
      return true;
    }

    // ─── Billing: Checkout and Status ──────────────────────────────
    if (context.path === '/v1/billing/checkout' && context.method === 'POST') {
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) return true;
      const session = await requireSession(context, response, baseExtraHeaders, 'Billing requires authentication');
      if (!session) return true;
      const tenant = await resolveTenantForRequest(context, response, baseExtraHeaders, session, context.url.searchParams.get('tenant'));
      if (!tenant) return true;
      const payload = await parseJsonBody(context, response, baseExtraHeaders);
      if (!payload) return true;
      try {
        const priceId = payload.priceId || resolvePriceId(config, payload.plan, payload.billingCycle);
        const result = await createCheckoutSession(config, {
          tenant,
          priceId,
          successUrl: payload.successUrl,
          cancelUrl: payload.cancelUrl,
        });
        sendJson(response, context, config, 200, result, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (context.path === '/v1/billing/status' && context.method === 'GET') {
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) return true;
      const session = await requireSession(context, response, baseExtraHeaders, 'Billing requires authentication');
      if (!session) return true;
      const tenant = await resolveTenantForRequest(context, response, baseExtraHeaders, session, context.url.searchParams.get('tenant'));
      if (!tenant) return true;
      try {
        const status = await getSubscriptionStatus(config, tenant);
        sendJson(response, context, config, 200, status, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // ─── Stripe Webhook (no auth — verified by signature) ──────────
    if (context.path === '/v1/billing/webhook' && context.method === 'POST') {
      try {
        const chunks = [];
        for await (const chunk of context.request) {
          chunks.push(chunk);
        }
        const rawBody = Buffer.concat(chunks).toString('utf8');
        const signature = context.request.headers['stripe-signature'] || '';
        const result = await handleWebhookEvent(config, rawBody, signature);
        sendJson(response, context, config, 200, result, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // ─── API Keys ──────────────────────────────────────────────────
    if (/^\/v1\/admin\/api-keys/.test(context.path)) {
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) return true;
      const session = await requireSession(context, response, baseExtraHeaders, 'API key management requires authentication');
      if (!session) return true;
      const tenant = await resolveTenantForRequest(context, response, baseExtraHeaders, session, context.url.searchParams.get('tenant'));
      if (!tenant) return true;

      // GET /v1/admin/api-keys
      if (context.path === '/v1/admin/api-keys' && context.method === 'GET') {
        try {
          const keys = await listApiKeys(config, tenant, session.user?.id);
          sendJson(response, context, config, 200, { data: keys }, baseExtraHeaders);
        } catch (error) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
        }
        return true;
      }

      // POST /v1/admin/api-keys
      if (context.path === '/v1/admin/api-keys' && context.method === 'POST') {
        const payload = await parseJsonBody(context, response, baseExtraHeaders);
        if (!payload) return true;
        try {
          const key = await createApiKey(config, {
            tenant,
            userId: session.user?.id,
            name: payload.name,
            scopes: payload.scopes,
            expiresIn: payload.expiresIn,
          });
          await appendAuditLog(config, {
            tenantSlug: tenant,
            actorId: String(session.user?.id || ''),
            actorEmail: session.user?.email || null,
            action: 'admin.api_key_created',
            targetType: 'api_key',
            targetId: key.id,
            ...actorMetaFromContext(context, session),
            payload: { name: payload.name },
          });
          sendJson(response, context, config, 201, key, baseExtraHeaders);
        } catch (error) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
        }
        return true;
      }

      // DELETE /v1/admin/api-keys/:id
      if (/^\/v1\/admin\/api-keys\/[0-9]+$/.test(context.path) && context.method === 'DELETE') {
        const keyId = context.path.split('/').pop();
        try {
          await revokeApiKey(config, keyId, session.user?.id);
          sendNoContent(response, context, config, baseExtraHeaders);
        } catch (error) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
        }
        return true;
      }

      sendMethodNotAllowed(response, context, config, ['GET', 'POST', 'DELETE'], baseExtraHeaders);
      return true;
    }

    // ─── Notification Preferences ───────────────────────────────────
    if (context.path === '/v1/notifications/preferences') {
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) return true;
      const session = await requireSession(context, response, baseExtraHeaders, 'Authentication required');
      if (!session) return true;

      // GET /v1/notifications/preferences
      if (context.method === 'GET') {
        try {
          const prefs = await getNotificationPreferences(config, session.user?.id);
          sendJson(response, context, config, 200, prefs, baseExtraHeaders);
        } catch (error) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
        }
        return true;
      }

      // PATCH /v1/notifications/preferences
      if (context.method === 'PATCH') {
        const payload = await parseJsonBody(context, response, baseExtraHeaders);
        if (!payload) return true;
        try {
          const prefs = await upsertNotificationPreferences(config, session.user?.id, payload);
          sendJson(response, context, config, 200, prefs, baseExtraHeaders);
        } catch (error) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
        }
        return true;
      }

      sendMethodNotAllowed(response, context, config, ['GET', 'PATCH'], baseExtraHeaders);
      return true;
    }

    return false;
  });
}

module.exports = { registerRoutes };
