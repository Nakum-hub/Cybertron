'use strict';

const crypto = require('node:crypto');

const { getRedisClient } = require('./redis-client');

const REDIS_CHANNEL_PREFIX = 'cybertron:sse:events:';
const MAX_CLIENTS_PER_TENANT = 50;
const HEARTBEAT_INTERVAL_MS = 25_000;
const MAX_RECENT_EVENTS_PER_TENANT = 50;
const instanceId = crypto.randomUUID();

/** @type {Map<string, Set<{res: object, userId: number, lastEventId: number}>>} */
const tenantClients = new Map();
/** @type {Map<string, Array<{id: number, tenant: string, type: string, payload: object, timestamp: string}>>} */
const tenantRecentEvents = new Map();

let globalEventId = 0;
let subscriberReady = false;
let subscriberClient = null;
let runtimeConfig = null;
let runtimeLog = () => {};

function nextEventId() {
  globalEventId += 1;
  return globalEventId;
}

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

function storeRecentEvent(tenantSlug, event) {
  if (!tenantRecentEvents.has(tenantSlug)) {
    tenantRecentEvents.set(tenantSlug, []);
  }

  const tenantEvents = tenantRecentEvents.get(tenantSlug);
  tenantEvents.push(event);
  if (tenantEvents.length > MAX_RECENT_EVENTS_PER_TENANT) {
    tenantEvents.splice(0, tenantEvents.length - MAX_RECENT_EVENTS_PER_TENANT);
  }
}

function _localBroadcast(tenantSlug, eventType, payload, eventId) {
  const id = Number.isFinite(eventId) ? eventId : nextEventId();
  const event = {
    id,
    tenant: tenantSlug,
    type: eventType,
    payload,
    timestamp: new Date().toISOString(),
  };

  storeRecentEvent(tenantSlug, event);

  const clients = tenantClients.get(tenantSlug);
  if (!clients || clients.size === 0) {
    return 0;
  }

  const data = JSON.stringify({ type: eventType, payload, timestamp: event.timestamp });
  const message = `id: ${id}\nevent: ${eventType}\ndata: ${data}\n\n`;

  let sent = 0;
  for (const client of clients) {
    try {
      client.res.write(message);
      client.lastEventId = id;
      sent += 1;
    } catch {
      clients.delete(client);
    }
  }

  return sent;
}

async function initRedisSubscriber(config, log) {
  runtimeConfig = config;
  runtimeLog = log || (() => {});

  if (subscriberReady) {
    return;
  }

  try {
    const redis = await getRedisClient(config, runtimeLog);
    if (!redis || typeof redis.duplicate !== 'function') {
      return;
    }

    const subscriber = redis.duplicate();
    await subscriber.connect();
    await subscriber.pSubscribe(`${REDIS_CHANNEL_PREFIX}*`, (message, channel) => {
      try {
        const event = JSON.parse(message);
        if (event.originId === instanceId) {
          return;
        }

        const tenant =
          typeof channel === 'string' && channel.startsWith(REDIS_CHANNEL_PREFIX)
            ? channel.slice(REDIS_CHANNEL_PREFIX.length)
            : String(event.tenant || '').trim();
        if (!tenant) {
          return;
        }

        _localBroadcast(tenant, event.type, event.payload);
      } catch {
        // Ignore malformed relay events.
      }
    });

    subscriberClient = subscriber;
    subscriberReady = true;
    runtimeLog('info', 'sse.redis_subscriber_ready', {
      channelPattern: `${REDIS_CHANNEL_PREFIX}*`,
      instanceId,
    });
  } catch (error) {
    runtimeLog('warn', 'sse.redis_subscriber_failed', {
      error: error instanceof Error ? error.message : 'unknown',
    });
  }
}

async function publishToRedis(event) {
  if (!runtimeConfig) {
    return;
  }

  try {
    const redis = await getRedisClient(runtimeConfig, runtimeLog);
    if (!redis) {
      return;
    }

    await redis.publish(`${REDIS_CHANNEL_PREFIX}${event.tenant}`, JSON.stringify(event));
  } catch {
    // Redis relay is optional. Local broadcast already completed.
  }
}

function broadcast(tenantSlug, eventType, payload) {
  const sent = _localBroadcast(tenantSlug, eventType, payload);

  void publishToRedis({
    originId: instanceId,
    tenant: tenantSlug,
    type: eventType,
    payload,
  });

  return sent;
}

function getRecentEventsForTenant(tenantSlug, sinceId) {
  const tenantEvents = tenantRecentEvents.get(tenantSlug) || [];
  return tenantEvents.filter(event => event.id > sinceId);
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

async function closeNotificationBus() {
  const subscriber = subscriberClient;
  subscriberClient = null;
  subscriberReady = false;

  if (!subscriber) {
    return;
  }

  try {
    await subscriber.quit();
  } catch {
    try {
      subscriber.disconnect();
    } catch {
      // Ignore hard disconnect failures during shutdown.
    }
  }
}

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
  closeNotificationBus,
  getConnectedClientCount,
  getRecentEventsForTenant,
  getTotalConnectedClients,
  initRedisSubscriber,
  notifyAlertIngested,
  notifyAuditEvent,
  notifyComplianceStatusChanged,
  notifyIncidentCreated,
  notifyIncidentUpdated,
  notifyPlaybookExecuted,
};
