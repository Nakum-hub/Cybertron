/**
 * URLhaus threat feed integration.
 * Fetches recent malicious URL data from abuse.ch URLhaus API.
 * Free, no authentication required, HTTPS only.
 * API docs: https://urlhaus-api.abuse.ch/
 */
const { ServiceError } = require('../auth-service');

const URLHAUS_RECENT_URL = 'https://urlhaus-api.abuse.ch/v1/urls/recent/';
const URLHAUS_PAYLOAD_URL = 'https://urlhaus-api.abuse.ch/v1/payload/';

function createTimeoutController(timeoutMs) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), Math.max(1, Number(timeoutMs) || 15_000));
  return { controller, timeout };
}

/**
 * Normalize a URLhaus entry into a standard threat indicator format.
 */
function normalizeUrlhausEntry(raw) {
  return {
    id: String(raw.id || raw.urlhaus_reference || `urlhaus-${Date.now()}`),
    url: String(raw.url || '').slice(0, 2048),
    urlStatus: String(raw.url_status || 'unknown').slice(0, 32),
    threat: String(raw.threat || 'malware_download').slice(0, 64),
    tags: Array.isArray(raw.tags) ? raw.tags.map(t => String(t).slice(0, 64)).slice(0, 10) : [],
    host: String(raw.host || '').slice(0, 255),
    dateAdded: raw.dateadded || raw.date_added || new Date().toISOString(),
    reporter: String(raw.reporter || 'unknown').slice(0, 128),
    source: 'urlhaus',
  };
}

/**
 * Fetch recent malicious URLs from URLhaus.
 * @param {object} config - Application config
 * @param {object} [options] - Fetch options
 * @param {number} [options.limit] - Max entries to return (default 100, max 1000)
 * @returns {Promise<{ entries: object[], count: number, fetchedAt: string }>}
 */
async function fetchRecentThreats(config, options = {}) {
  const limit = Math.min(1000, Math.max(1, Number(options.limit) || 100));
  const timeoutMs = Number(config.urlhausRequestTimeoutMs) || 15_000;

  const { controller, timeout } = createTimeoutController(timeoutMs);
  try {
    const response = await fetch(URLHAUS_RECENT_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `limit=${limit}`,
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new ServiceError(
        502,
        'urlhaus_feed_unavailable',
        `URLhaus API returned ${response.status}.`
      );
    }

    const rawBody = await response.text();
    if (rawBody.length > 5_000_000) {
      throw new ServiceError(502, 'urlhaus_feed_unavailable', 'URLhaus response exceeds maximum allowed size.');
    }

    const payload = JSON.parse(rawBody);
    const urls = Array.isArray(payload.urls) ? payload.urls : [];
    const entries = urls.slice(0, limit).map(normalizeUrlhausEntry);

    return {
      entries,
      count: entries.length,
      fetchedAt: new Date().toISOString(),
    };
  } catch (error) {
    if (error instanceof ServiceError) {
      throw error;
    }

    throw new ServiceError(502, 'urlhaus_feed_unavailable', 'Unable to fetch URLhaus feed.');
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Look up a specific URL in URLhaus to check if it's known-malicious.
 * @param {string} urlToCheck - The URL to look up
 * @param {object} config - Application config
 * @returns {Promise<{ found: boolean, threat: string|null, status: string|null, entry: object|null }>}
 */
async function lookupUrl(urlToCheck, config) {
  if (!urlToCheck || typeof urlToCheck !== 'string') {
    return { found: false, threat: null, status: null, entry: null };
  }

  const timeoutMs = Number(config.urlhausRequestTimeoutMs) || 10_000;
  const { controller, timeout } = createTimeoutController(timeoutMs);

  try {
    const response = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `url=${encodeURIComponent(urlToCheck)}`,
      signal: controller.signal,
    });

    if (!response.ok) {
      return { found: false, threat: null, status: null, entry: null };
    }

    const rawBody = await response.text();
    if (rawBody.length > 2_000_000) {
      return { found: false, threat: null, status: null, entry: null };
    }

    const payload = JSON.parse(rawBody);
    if (payload.query_status === 'no_results') {
      return { found: false, threat: null, status: null, entry: null };
    }

    return {
      found: true,
      threat: String(payload.threat || 'unknown').slice(0, 64),
      status: String(payload.url_status || 'unknown').slice(0, 32),
      entry: normalizeUrlhausEntry(payload),
    };
  } catch {
    return { found: false, threat: null, status: null, entry: null };
  } finally {
    clearTimeout(timeout);
  }
}

module.exports = {
  fetchRecentThreats,
  lookupUrl,
  normalizeUrlhausEntry,
};
