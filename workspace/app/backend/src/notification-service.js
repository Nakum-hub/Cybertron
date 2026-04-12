'use strict';

/**
 * In-memory event bus for real-time notifications via SSE.
 * Manages connected clients per tenant and broadcasts typed events.
 */

const MAX_CLIENTS_PER_TENANT = 50;
const HEARTBEAT_INTERVAL_MS = 25_000;

/** @type {Map<string, Set<{res: object, userId: number, lastEventId: number}>>} */
const tenantClients = new Map();

let globalEventId = 0;

/** @type {Map<string, Array<{id: number, tenant: string, type: string, payload: object, timestamp: string}>>} */
const tenantRecentEvents = new Map();
const MAX_RECENT_EVENTS_PER_TENANT = 50;

function addClient(tenantSlug, userId, res) {
  if (!tenantClients.has(tenantSlug)) {
    tenantClients.set(tenantSlug, new Set());
  }
  const clients = tenantClients.get(tenantSlug);
  if (clients.size >= MAX_CLIENTS_PER_TENANT) {
    return false;
  }
  const client = { res, userId, lastEventId: globalEventId };
  clients.add(client);

  res.on('close', () => {
    clients.delete(client);
    if (clients.size === 0) {
      tenantClients.delete(tenantSlug);
    }
  });

  return true;
}

function broadcast(tenantSlug, eventType, payload) {
  globalEventId += 1;
  const event = {
    id: globalEventId,
    tenant: tenantSlug,
    type: eventType,
    payload,
    timestamp: new Date().toISOString(),
  };

  // Store events per-tenant to prevent noisy-tenant flooding
  if (!tenantRecentEvents.has(tenantSlug)) {
    tenantRecentEvents.set(tenantSlug, []);
  }
  const tenantEvents = tenantRecentEvents.get(tenantSlug);
  tenantEvents.push(event);
  if (tenantEvents.length > MAX_RECENT_EVENTS_PER_TENANT) {
    tenantEvents.splice(0, tenantEvents.length - MAX_RECENT_EVENTS_PER_TENANT);
  }

  const clients = tenantClients.get(tenantSlug);
  if (!clients || clients.size === 0) return 0;

  const data = JSON.stringify({ type: eventType, payload, timestamp: event.timestamp });
  const message = `id: ${globalEventId}\nevent: ${eventType}\ndata: ${data}\n\n`;

  let sent = 0;
  for (const client of clients) {
    try {
      client.res.write(message);
      client.lastEventId = globalEventId;
      sent += 1;
    } catch {
      clients.delete(client);
    }
  }
  return sent;
}

function getRecentEventsForTenant(tenantSlug, sinceId) {
  const tenantEvents = tenantRecentEvents.get(tenantSlug) || [];
  return tenantEvents.filter(e => e.id > sinceId);
}

function getConnectedClientCount(tenantSlug) {
  const clients = tenantClients.get(tenantSlug);
  return clients ? clients.size : 0;
}

function getTotalConnectedClients() {
  let total = 0;
  for (const clients of tenantClients.values()) {
    total += clients.size;
  }
  return total;
}

// Heartbeat to keep connections alive
const heartbeatTimer = setInterval(() => {
  const comment = `: heartbeat ${Date.now()}\n\n`;
  for (const clients of tenantClients.values()) {
    for (const client of clients) {
      try {
        client.res.write(comment);
      } catch {
        clients.delete(client);
      }
    }
  }
}, HEARTBEAT_INTERVAL_MS);

if (heartbeatTimer.unref) {
  heartbeatTimer.unref();
}

// ─── Convenience broadcasters ────────────────────────────────────

function notifyIncidentCreated(tenantSlug, incident) {
  broadcast(tenantSlug, 'incident.created', {
    id: incident.id,
    title: incident.title,
    severity: incident.severity,
  });
}

function notifyIncidentUpdated(tenantSlug, incident) {
  broadcast(tenantSlug, 'incident.updated', {
    id: incident.id,
    title: incident.title,
    status: incident.status,
    severity: incident.severity,
  });
}

function notifyAlertIngested(tenantSlug, alert) {
  broadcast(tenantSlug, 'alert.ingested', {
    id: alert.id,
    severity: alert.severity,
    source: alert.source,
    ruleName: alert.rule_name || alert.ruleName,
  });
}

function notifyComplianceStatusChanged(tenantSlug, frameworkId, controlId, status) {
  broadcast(tenantSlug, 'compliance.status_changed', {
    frameworkId,
    controlId,
    status,
  });
}

function notifyPlaybookExecuted(tenantSlug, execution) {
  broadcast(tenantSlug, 'playbook.executed', {
    id: execution.id,
    playbookId: execution.playbook_id || execution.playbookId,
    status: execution.status,
  });
}

function notifyAuditEvent(tenantSlug, action, targetType) {
  broadcast(tenantSlug, 'audit.event', {
    action,
    targetType,
  });
}

module.exports = {
  addClient,
  broadcast,
  getRecentEventsForTenant,
  getConnectedClientCount,
  getTotalConnectedClients,
  notifyIncidentCreated,
  notifyIncidentUpdated,
  notifyAlertIngested,
  notifyComplianceStatusChanged,
  notifyPlaybookExecuted,
  notifyAuditEvent,
};
