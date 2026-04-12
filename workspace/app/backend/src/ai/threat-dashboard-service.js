const { query, withClient } = require('../database');
const { sanitizeTenant, toSafeInteger } = require('../validators');
const { ServiceError } = require('../auth-service');
const { fetchNvdFeed } = require('./cve-fetcher');
const { parseNvdCvePayload } = require('./cve-parser');

function computeRelevanceScore(cve = {}) {
  const severityWeight = cve.severity === 'critical'
    ? 100
    : cve.severity === 'high'
      ? 75
      : cve.severity === 'medium'
        ? 45
        : 25;

  const cvss = Number(cve.cvssScore || 0);
  const scoreWeight = Number.isFinite(cvss) ? cvss * 5 : 0;

  const publishedAt = cve.publishedAt ? new Date(cve.publishedAt).getTime() : Date.now();
  const ageDays = Math.max(0, (Date.now() - publishedAt) / (1000 * 60 * 60 * 24));
  const recencyWeight = Math.max(0, 30 - ageDays);

  return Number((severityWeight + scoreWeight + recencyWeight).toFixed(2));
}

function computeBackoffMs(config, failureCount) {
  const baseMs = toSafeInteger(config.nvdSyncBackoffBaseMs, 30_000, 1_000, 24 * 60 * 60 * 1000);
  const maxMs = toSafeInteger(config.nvdSyncBackoffMaxMs, 15 * 60 * 1000, baseMs, 24 * 60 * 60 * 1000);
  const exponent = Math.max(0, Math.min(10, Number(failureCount || 1) - 1));
  return Math.min(maxMs, baseMs * (2 ** exponent));
}

function getFutureDateIso(msFromNow) {
  return new Date(Date.now() + Math.max(1_000, Number(msFromNow) || 1_000)).toISOString();
}

async function getSyncState(config) {
  const state = await query(
    config,
    `
      SELECT
        source,
        etag,
        last_modified,
        synced_at,
        last_success_at,
        last_attempt_at,
        last_error,
        failure_count,
        backoff_until,
        updated_at
      FROM cve_sync_state
      WHERE source = 'nvd'
      LIMIT 1
    `
  );

  if (!state?.rows?.length) {
    return {
      etag: null,
      lastModified: null,
      lastSuccessAt: null,
      lastAttemptAt: null,
      lastError: null,
      failureCount: 0,
      backoffUntil: null,
      updatedAt: null,
    };
  }

  return {
    etag: state.rows[0].etag || null,
    lastModified: state.rows[0].last_modified || null,
    lastSuccessAt: state.rows[0].last_success_at || null,
    lastAttemptAt: state.rows[0].last_attempt_at || null,
    lastError: state.rows[0].last_error || null,
    failureCount: Number(state.rows[0].failure_count || 0),
    backoffUntil: state.rows[0].backoff_until || null,
    updatedAt: state.rows[0].updated_at || null,
  };
}

async function writeSyncState(config, payload = {}) {
  await query(
    config,
    `
      INSERT INTO cve_sync_state (
        source,
        etag,
        last_modified,
        synced_at,
        last_success_at,
        last_attempt_at,
        last_error,
        failure_count,
        backoff_until,
        updated_at
      )
      VALUES ('nvd',$1,$2,NOW(),$3,$4,$5,$6,$7,NOW())
      ON CONFLICT (source)
      DO UPDATE SET
        etag = EXCLUDED.etag,
        last_modified = EXCLUDED.last_modified,
        synced_at = EXCLUDED.synced_at,
        last_success_at = EXCLUDED.last_success_at,
        last_attempt_at = EXCLUDED.last_attempt_at,
        last_error = EXCLUDED.last_error,
        failure_count = EXCLUDED.failure_count,
        backoff_until = EXCLUDED.backoff_until,
        updated_at = NOW()
    `,
    [
      payload.etag || null,
      payload.lastModified || null,
      payload.lastSuccessAt || null,
      payload.lastAttemptAt || null,
      payload.lastError || null,
      Number(payload.failureCount || 0),
      payload.backoffUntil || null,
    ]
  );
}

function throwIfBackoffActive(syncState) {
  if (!syncState?.backoffUntil) {
    return;
  }

  const backoffUntilMs = new Date(syncState.backoffUntil).getTime();
  if (Number.isNaN(backoffUntilMs) || backoffUntilMs <= Date.now()) {
    return;
  }

  const retryAfterSeconds = Math.max(1, Math.ceil((backoffUntilMs - Date.now()) / 1000));
  throw new ServiceError(
    429,
    'cve_sync_backoff_active',
    `CVE sync is in backoff window. Retry after ${retryAfterSeconds} second(s).`,
    {
      retryAfterSeconds,
    }
  );
}

async function recordSyncFailure(config, syncState, error) {
  const failureCount = Number(syncState?.failureCount || 0) + 1;
  const backoffUntil = getFutureDateIso(computeBackoffMs(config, failureCount));
  const errorMessage = error instanceof Error ? error.message : 'unknown sync failure';

  await writeSyncState(config, {
    etag: syncState?.etag || null,
    lastModified: syncState?.lastModified || null,
    lastSuccessAt: syncState?.lastSuccessAt || null,
    lastAttemptAt: new Date().toISOString(),
    lastError: errorMessage.slice(0, 500),
    failureCount,
    backoffUntil,
  });

  return {
    failureCount,
    backoffUntil,
  };
}

async function syncCveFeed(config, log, tenant, actorUserId = null) {
  const tenantSlug = sanitizeTenant(tenant || 'global');
  const previousState = await getSyncState(config);
  throwIfBackoffActive(previousState);

  let feed;
  try {
    feed = await fetchNvdFeed(config, previousState);
  } catch (error) {
    try {
      const failureState = await recordSyncFailure(config, previousState, error);
      log('warn', 'threat_intel.cve_sync.fetch_failed', {
        tenant: tenantSlug,
        failureCount: failureState.failureCount,
        backoffUntil: failureState.backoffUntil,
        error: error instanceof Error ? error.message : 'unknown fetch failure',
      });
    } catch (stateError) {
      log('warn', 'threat_intel.cve_sync.failure_state_write_failed', {
        tenant: tenantSlug,
        error: stateError instanceof Error ? stateError.message : 'unknown failure state write error',
      });
    }
    throw error;
  }

  if (feed.notModified) {
    await writeSyncState(config, {
      etag: feed.etag || previousState.etag || null,
      lastModified: feed.lastModified || previousState.lastModified || null,
      lastSuccessAt: new Date().toISOString(),
      lastAttemptAt: new Date().toISOString(),
      lastError: null,
      failureCount: 0,
      backoffUntil: null,
    });

    return {
      synced: false,
      notModified: true,
      source: 'nvd',
      cveCount: 0,
      tenant: tenantSlug,
    };
  }

  const parsed = parseNvdCvePayload(feed.payload || {});
  const maxCves = toSafeInteger(config.nvdSyncMaxEntries, 400, 1, 5000);
  const cves = parsed.slice(0, maxCves);

  try {
    await withClient(config, async client => {
      await client.query('BEGIN');
      try {
        for (const cve of cves) {
          await client.query(
            `
              INSERT INTO cves (
                cve_id,
                published_at,
                last_modified_at,
                cvss_score,
                severity,
                description,
                raw_json
              )
              VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb)
              ON CONFLICT (cve_id)
              DO UPDATE SET
                published_at = EXCLUDED.published_at,
                last_modified_at = EXCLUDED.last_modified_at,
                cvss_score = EXCLUDED.cvss_score,
                severity = EXCLUDED.severity,
                description = EXCLUDED.description,
                raw_json = EXCLUDED.raw_json
            `,
            [
              cve.cveId,
              cve.publishedAt,
              cve.lastModifiedAt,
              cve.cvssScore,
              cve.severity,
              cve.description,
              JSON.stringify(cve.rawJson || {}),
            ]
          );

          await client.query(
            `
              INSERT INTO tenant_cve_views (tenant_slug, cve_id, relevance_score)
              VALUES ($1,$2,$3)
              ON CONFLICT (tenant_slug, cve_id)
              DO UPDATE SET
                relevance_score = EXCLUDED.relevance_score,
                created_at = NOW()
            `,
            [tenantSlug, cve.cveId, computeRelevanceScore(cve)]
          );
        }

        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      }
    });

    await writeSyncState(config, {
      etag: feed.etag || previousState.etag || null,
      lastModified: feed.lastModified || previousState.lastModified || null,
      lastSuccessAt: new Date().toISOString(),
      lastAttemptAt: new Date().toISOString(),
      lastError: null,
      failureCount: 0,
      backoffUntil: null,
    });
  } catch (error) {
    const failureState = await recordSyncFailure(config, previousState, error);
    log('warn', 'threat_intel.cve_sync.persist_failed', {
      tenant: tenantSlug,
      failureCount: failureState.failureCount,
      backoffUntil: failureState.backoffUntil,
      error: error instanceof Error ? error.message : 'unknown cve persistence failure',
    });
    throw error;
  }

  log('info', 'threat_intel.cve_sync.complete', {
    tenant: tenantSlug,
    cveCount: cves.length,
  });

  return {
    synced: true,
    notModified: false,
    source: 'nvd',
    cveCount: cves.length,
    tenant: tenantSlug,
    actorUserId: actorUserId ? String(actorUserId) : null,
  };
}

async function listTenantCveFeed(config, tenant, options = {}) {
  const tenantSlug = sanitizeTenant(tenant || 'global');
  const limit = toSafeInteger(options.limit, 50, 1, 200);
  const offset = toSafeInteger(options.offset, 0, 0, 50_000);
  const severity = String(options.severity || '').trim().toLowerCase();

  const values = [tenantSlug];
  const where = ['tv.tenant_slug = $1'];
  if (severity) {
    values.push(severity);
    where.push(`c.severity = $${values.length}`);
  }

  const whereSql = where.join(' AND ');
  const count = await query(
    config,
    `
      SELECT COUNT(*)::INT AS total
      FROM tenant_cve_views tv
      INNER JOIN cves c ON c.cve_id = tv.cve_id
      WHERE ${whereSql}
    `,
    values
  );
  const total = Number(count?.rows?.[0]?.total || 0);

  values.push(limit, offset);
  const rows = await query(
    config,
    `
      SELECT
        tv.id,
        tv.tenant_slug,
        tv.relevance_score,
        tv.created_at AS viewed_at,
        c.cve_id,
        c.published_at,
        c.last_modified_at,
        c.cvss_score,
        c.severity,
        c.description
      FROM tenant_cve_views tv
      INNER JOIN cves c ON c.cve_id = tv.cve_id
      WHERE ${whereSql}
      ORDER BY tv.relevance_score DESC, c.published_at DESC NULLS LAST, tv.id DESC
      LIMIT $${values.length - 1}
      OFFSET $${values.length}
    `,
    values
  );

  const data = (rows?.rows || []).map(row => ({
    id: String(row.id),
    tenant: row.tenant_slug,
    cveId: row.cve_id,
    severity: row.severity,
    cvssScore: row.cvss_score === null ? null : Number(row.cvss_score),
    description: row.description || '',
    relevanceScore: Number(row.relevance_score || 0),
    publishedAt: row.published_at ? new Date(row.published_at).toISOString() : null,
    lastModifiedAt: row.last_modified_at ? new Date(row.last_modified_at).toISOString() : null,
    viewedAt: row.viewed_at ? new Date(row.viewed_at).toISOString() : null,
  }));

  return {
    data,
    pagination: {
      limit,
      offset,
      total,
      hasMore: offset + data.length < total,
    },
    message: data.length ? undefined : 'No CVE feed entries available. Run sync to ingest NVD data.',
  };
}

async function getCveRecord(config, cveId) {
  const normalizedId = String(cveId || '').trim().toUpperCase();
  if (!/^CVE-\d{4}-\d{4,}$/.test(normalizedId)) {
    throw new ServiceError(400, 'invalid_cve_id', 'CVE id is invalid.');
  }

  const result = await query(
    config,
    `
      SELECT cve_id, published_at, last_modified_at, cvss_score, severity, description
      FROM cves
      WHERE cve_id = $1
      LIMIT 1
    `,
    [normalizedId]
  );

  if (!result?.rows?.length) {
    throw new ServiceError(404, 'cve_not_found', 'CVE record was not found.');
  }

  const row = result.rows[0];
  return {
    cveId: row.cve_id,
    severity: row.severity,
    cvssScore: row.cvss_score === null ? null : Number(row.cvss_score),
    description: row.description || '',
    publishedAt: row.published_at ? new Date(row.published_at).toISOString() : null,
    lastModifiedAt: row.last_modified_at ? new Date(row.last_modified_at).toISOString() : null,
  };
}

async function saveCveSummary(config, payload = {}) {
  const tenantSlug = sanitizeTenant(payload.tenant || 'global');
  const cveId = String(payload.cveId || '').trim().toUpperCase();
  const summaryText = String(payload.summaryText || '').trim();
  const model = String(payload.model || 'unknown').trim().slice(0, 128) || 'unknown';

  if (!summaryText) {
    throw new ServiceError(400, 'invalid_cve_summary', 'CVE summary text is required.');
  }

  const result = await query(
    config,
    `
      INSERT INTO cve_summaries (tenant_slug, cve_id, summary_text, model)
      VALUES ($1,$2,$3,$4)
      RETURNING id, tenant_slug, cve_id, summary_text, model, created_at
    `,
    [tenantSlug, cveId, summaryText, model]
  );

  const row = result.rows[0];
  return {
    id: String(row.id),
    tenant: row.tenant_slug,
    cveId: row.cve_id,
    summaryText: row.summary_text,
    model: row.model,
    createdAt: new Date(row.created_at).toISOString(),
  };
}

async function getThreatDashboard(config, tenant, options = {}) {
  const tenantSlug = sanitizeTenant(tenant || 'global');
  const days = toSafeInteger(options.days, 30, 1, 180);

  const severityRows = await query(
    config,
    `
      SELECT c.severity, COUNT(*)::INT AS total
      FROM tenant_cve_views tv
      INNER JOIN cves c ON c.cve_id = tv.cve_id
      WHERE tv.tenant_slug = $1
      GROUP BY c.severity
    `,
    [tenantSlug]
  );

  const trendRows = await query(
    config,
    `
      SELECT
        TO_CHAR(DATE_TRUNC('day', c.published_at), 'YYYY-MM-DD') AS day,
        COUNT(*)::INT AS total
      FROM tenant_cve_views tv
      INNER JOIN cves c ON c.cve_id = tv.cve_id
      WHERE tv.tenant_slug = $1
        AND c.published_at >= NOW() - ($2::TEXT || ' days')::INTERVAL
      GROUP BY DATE_TRUNC('day', c.published_at)
      ORDER BY DATE_TRUNC('day', c.published_at) ASC
    `,
    [tenantSlug, String(days)]
  );

  const severityCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  for (const row of severityRows?.rows || []) {
    const key = String(row.severity || '').toLowerCase();
    if (Object.prototype.hasOwnProperty.call(severityCounts, key)) {
      severityCounts[key] = Number(row.total || 0);
    }
  }

  const trend = (trendRows?.rows || []).map(row => ({
    day: row.day,
    total: Number(row.total || 0),
  }));

  return {
    tenant: tenantSlug,
    severityCounts,
    trend,
    generatedAt: new Date().toISOString(),
    message:
      severityCounts.critical + severityCounts.high + severityCounts.medium + severityCounts.low > 0
        ? undefined
        : 'No tenant CVE telemetry available yet. Run CVE sync to populate dashboard.',
  };
}

module.exports = {
  syncCveFeed,
  listTenantCveFeed,
  getCveRecord,
  saveCveSummary,
  getThreatDashboard,
};
