function normalizeSeverity(value) {
  const normalized = String(value || '').toLowerCase().trim();
  if (normalized === 'critical') return 'critical';
  if (normalized === 'high') return 'high';
  if (normalized === 'medium') return 'medium';
  if (normalized === 'low') return 'low';
  // HARDENING: Do not inflate unknown severity to 'medium'.
  // Unknown severity must remain unknown until analyst triages.
  return 'unknown';
}

// SSRF protection: block requests to private/internal IP ranges and localhost.
function isPrivateHostname(hostname) {
  if (!hostname) return true;
  const h = hostname.toLowerCase();

  // Block localhost
  if (h === 'localhost' || h === 'localhost.localdomain') return true;

  // Block IPv6 loopback
  if (h === '::1' || h === '[::1]') return true;

  // Block metadata endpoints (cloud provider SSRF vectors)
  if (h === '169.254.169.254' || h === 'metadata.google.internal') return true;

  // Block private IPv4 ranges
  const ipv4Match = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const [, a, b] = ipv4Match.map(Number);
    if (a === 10) return true;                          // 10.0.0.0/8
    if (a === 172 && b >= 16 && b <= 31) return true;   // 172.16.0.0/12
    if (a === 192 && b === 168) return true;             // 192.168.0.0/16
    if (a === 127) return true;                          // 127.0.0.0/8
    if (a === 0) return true;                            // 0.0.0.0/8
    if (a === 169 && b === 254) return true;             // link-local
  }

  return false;
}

function normalizeStatus(value) {
  const normalized = String(value || '').toLowerCase().trim();
  if (normalized === 'open') return 'open';
  if (normalized === 'investigating') return 'investigating';
  if (normalized === 'resolved') return 'resolved';
  return 'open';
}

function normalizeIncident(raw, sourceTag) {
  const idValue = raw?.id || raw?._id || raw?.caseId || raw?.event_id || raw?.uuid;
  const titleValue =
    raw?.title ||
    raw?.name ||
    raw?.description ||
    raw?.event_title ||
    raw?.alert ||
    'Unlabeled incident';

  const detectedAtValue =
    raw?.detectedAt || raw?.timestamp || raw?.createdAt || raw?.created_at || raw?.date;

  return {
    id: String(idValue || `${sourceTag}-${Date.now()}`),
    title: String(titleValue),
    severity: normalizeSeverity(raw?.severity || raw?.priority || raw?.level),
    detectedAt: new Date(detectedAtValue || Date.now()).toISOString(),
    status: normalizeStatus(raw?.status || raw?.state),
    source: sourceTag,
  };
}

async function fetchJson(url, options = {}) {
  // SSRF protection: reject private/internal IP addresses and hostnames
  const parsed = new URL(url);
  const hostname = parsed.hostname;
  if (isPrivateHostname(hostname)) {
    throw new Error(`SSRF blocked: request to private/internal address "${hostname}" is not allowed`);
  }

  const timeoutMs = Number(options.timeoutMs || 6_000);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      method: options.method || 'GET',
      headers: options.headers || {},
      body: options.body,
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(`Connector request failed (${response.status})`);
    }

    return response.json();
  } finally {
    clearTimeout(timeout);
  }
}

async function fetchWazuh(config, tenant, limit) {
  if (!config.wazuhApiUrl) {
    return [];
  }

  const url = `${config.wazuhApiUrl.replace(/\/$/, '')}/alerts?tenant=${encodeURIComponent(tenant)}&limit=${limit}`;
  const headers = config.wazuhApiToken
    ? {
        Authorization: `Bearer ${config.wazuhApiToken}`,
      }
    : {};

  const payload = await fetchJson(url, {
    headers,
    timeoutMs: config.connectorTimeoutMs,
  });

  const rows = Array.isArray(payload) ? payload : Array.isArray(payload?.data) ? payload.data : [];
  return rows.map(item => normalizeIncident(item, 'wazuh'));
}

async function fetchMisp(config, tenant, limit) {
  if (!config.mispApiUrl) {
    return [];
  }

  const url = `${config.mispApiUrl.replace(/\/$/, '')}/events/restSearch`;
  const headers = {
    'Content-Type': 'application/json',
    ...(config.mispApiKey ? { Authorization: config.mispApiKey } : {}),
  };

  const payload = await fetchJson(url, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      limit,
      page: 1,
      tags: [tenant],
    }),
    timeoutMs: config.connectorTimeoutMs,
  });

  const rows =
    Array.isArray(payload) ? payload : Array.isArray(payload?.response) ? payload.response : [];
  return rows.map(item => normalizeIncident(item, 'misp'));
}

async function fetchOpenCti(config, tenant, limit) {
  if (!config.openCtiApiUrl) {
    return [];
  }

  const url = `${config.openCtiApiUrl.replace(/\/$/, '')}/graphql`;
  const query = `query CybertronIncidents($tenant: String, $limit: Int!) {
    incidents(tenant: $tenant, first: $limit) {
      edges {
        node {
          id
          name
          createdAt
          severity
          status
        }
      }
    }
  }`;

  const payload = await fetchJson(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(config.openCtiApiToken ? { Authorization: `Bearer ${config.openCtiApiToken}` } : {}),
    },
    body: JSON.stringify({
      query,
      variables: {
        tenant,
        limit,
      },
    }),
    timeoutMs: config.connectorTimeoutMs,
  });

  const rows = payload?.data?.incidents?.edges?.map(edge => edge?.node).filter(Boolean) || [];
  return rows.map(item => normalizeIncident(item, 'opencti'));
}

async function fetchTheHive(config, tenant, limit) {
  if (!config.theHiveApiUrl) {
    return [];
  }

  const upperBound = Math.max(0, Number(limit) - 1);
  const url = `${config.theHiveApiUrl.replace(/\/$/, '')}/api/alert?range=0-${upperBound}&tenant=${encodeURIComponent(tenant)}`;

  const payload = await fetchJson(url, {
    headers: config.theHiveApiToken
      ? {
          Authorization: `Bearer ${config.theHiveApiToken}`,
        }
      : {},
    timeoutMs: config.connectorTimeoutMs,
  });

  const rows = Array.isArray(payload) ? payload : [];
  return rows.map(item => normalizeIncident(item, 'thehive'));
}

async function fetchConnectorIncidents(config, tenant, limit, log = () => {}) {
  const tasks = [
    { name: 'wazuh', fn: fetchWazuh },
    { name: 'misp', fn: fetchMisp },
    { name: 'opencti', fn: fetchOpenCti },
    { name: 'thehive', fn: fetchTheHive },
  ];

  // Fetch all connectors in parallel instead of sequentially
  const settled = await Promise.allSettled(
    tasks.map(task => task.fn(config, tenant, limit))
  );

  const results = [];
  for (let i = 0; i < settled.length; i++) {
    const outcome = settled[i];
    if (outcome.status === 'fulfilled' && outcome.value.length) {
      results.push(...outcome.value);
    } else if (outcome.status === 'rejected') {
      log('warn', 'connector.fetch_failed', {
        connector: tasks[i].name,
        error: outcome.reason instanceof Error ? outcome.reason.message : 'unknown connector failure',
      });
    }
  }

  results.sort((a, b) => new Date(b.detectedAt).getTime() - new Date(a.detectedAt).getTime());
  return results.slice(0, Math.max(1, Number(limit) || 1));
}

function hasConfiguredConnector(config) {
  return Boolean(config.wazuhApiUrl || config.mispApiUrl || config.openCtiApiUrl || config.theHiveApiUrl);
}

async function probeConnector(connector, config) {
  const timeoutMs = config.connectorTimeoutMs;

  if (connector.name === 'wazuh') {
    await fetchJson(`${config.wazuhApiUrl.replace(/\/$/, '')}/`, {
      headers: config.wazuhApiToken ? { Authorization: `Bearer ${config.wazuhApiToken}` } : {},
      timeoutMs,
    });
    return;
  }

  if (connector.name === 'misp') {
    await fetchJson(`${config.mispApiUrl.replace(/\/$/, '')}/servers/getVersion`, {
      headers: config.mispApiKey ? { Authorization: config.mispApiKey } : {},
      timeoutMs,
    });
    return;
  }

  if (connector.name === 'opencti') {
    await fetchJson(`${config.openCtiApiUrl.replace(/\/$/, '')}/graphql`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(config.openCtiApiToken ? { Authorization: `Bearer ${config.openCtiApiToken}` } : {}),
      },
      body: JSON.stringify({
        query: 'query HealthQuery { __typename }',
      }),
      timeoutMs,
    });
    return;
  }

  if (connector.name === 'thehive') {
    await fetchJson(`${config.theHiveApiUrl.replace(/\/$/, '')}/api/status`, {
      headers: config.theHiveApiToken ? { Authorization: `Bearer ${config.theHiveApiToken}` } : {},
      timeoutMs,
    });
  }
}

// --- Connector Health Cache (30s TTL to prevent external API abuse) ---
let _connectorStatusCache = null;
let _connectorStatusCacheTime = 0;
const CONNECTOR_STATUS_CACHE_TTL_MS = 30_000;

async function getConnectorStatus(config, log = () => {}) {
  const now = Date.now();
  if (_connectorStatusCache && (now - _connectorStatusCacheTime) < CONNECTOR_STATUS_CACHE_TTL_MS) {
    return _connectorStatusCache;
  }

  const connectors = [
    { name: 'wazuh', url: config.wazuhApiUrl },
    { name: 'misp', url: config.mispApiUrl },
    { name: 'opencti', url: config.openCtiApiUrl },
    { name: 'thehive', url: config.theHiveApiUrl },
  ];

  const checks = await Promise.all(
    connectors.map(async connector => {
      const configured = Boolean(connector.url);
      if (!configured) {
        return {
          name: connector.name,
          configured: false,
          status: 'not_configured',
          checkedAt: new Date().toISOString(),
          message: 'Connector URL is not configured.',
        };
      }

      const startedAt = Date.now();
      try {
        await probeConnector(connector, config);
        return {
          name: connector.name,
          configured: true,
          status: 'healthy',
          latencyMs: Date.now() - startedAt,
          checkedAt: new Date().toISOString(),
        };
      } catch (error) {
        const message = error instanceof Error ? error.message : 'connector probe failed';
        log('warn', 'connector.health_failed', {
          connector: connector.name,
          message,
        });
        return {
          name: connector.name,
          configured: true,
          status: 'unreachable',
          latencyMs: Date.now() - startedAt,
          checkedAt: new Date().toISOString(),
          message,
        };
      }
    })
  );

  _connectorStatusCache = checks;
  _connectorStatusCacheTime = Date.now();
  return checks;
}

module.exports = {
  fetchConnectorIncidents,
  hasConfiguredConnector,
  getConnectorStatus,
};
