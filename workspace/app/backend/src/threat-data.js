const { query } = require('./database');
const { fetchConnectorIncidents, hasConfiguredConnector } = require('./threat-connectors');
const { sanitizeTenant } = require('./validators');

const EMPTY_SUMMARY = {
  activeThreats: 0,
  blockedToday: 0,
  mttrMinutes: null,
  trustScore: 0,
  dataSource: 'none',
};

function clamp(min, value, max) {
  return Math.max(min, Math.min(max, value));
}

function normalizeIncidentStatus(value) {
  const normalized = String(value || '').toLowerCase().trim();
  if (normalized === 'open') return 'open';
  if (normalized === 'investigating') return 'investigating';
  if (normalized === 'resolved') return 'resolved';
  return 'open';
}

function normalizeIncidentSeverity(value) {
  const normalized = String(value || '').toLowerCase().trim();
  if (normalized === 'critical') return 'critical';
  if (normalized === 'high') return 'high';
  if (normalized === 'medium') return 'medium';
  if (normalized === 'low') return 'low';
  // HARDENING: Unknown severity stays unknown -- do not auto-inflate to medium.
  return 'unknown';
}

function normalizeIncidentRow(row) {
  return {
    id: String(row.id),
    title: String(row.title || 'Unlabeled incident'),
    severity: normalizeIncidentSeverity(row.severity),
    detectedAt: new Date(row.detected_at || row.detectedAt || Date.now()).toISOString(),
    status: normalizeIncidentStatus(row.status),
  };
}

function summarizeFromIncidents(incidents) {
  const activeThreats = incidents.filter(item => item.status !== 'resolved').length;
  const blockedToday = incidents.filter(
    item => item.status === 'resolved' && new Date(item.detectedAt).toDateString() === new Date().toDateString()
  ).length;

  const resolved = incidents.filter(item => item.status === 'resolved').length;
  const unresolvedRatio = incidents.length ? activeThreats / incidents.length : 0;
  const trustScore = incidents.length ? Math.round(clamp(0, (1 - unresolvedRatio) * 100, 100)) : 0;

  return {
    activeThreats,
    blockedToday,
    // HARDENING: MTTR cannot be computed from connector data (no resolution timestamps).
    // Report null instead of fabricating a number.
    mttrMinutes: null,
    trustScore,
    dataSource: 'connectors',
    dataQuality: {
      incidentCount: incidents.length,
      resolvedCount: resolved,
      mttrAvailable: false,
      mttrNote: 'MTTR requires database persistence with response_time_minutes. Connector data lacks resolution timing.',
    },
  };
}

async function loadSummaryFromDatabase(config, tenant) {
  const result = await query(
    config,
    `
      SELECT
        COUNT(*) FILTER (WHERE status IN ('open', 'investigating'))::INT AS active_threats,
        COUNT(*) FILTER (
          WHERE blocked = TRUE
          AND detected_at >= date_trunc('day', NOW())
        )::INT AS blocked_today,
        COALESCE(
          ROUND(AVG(response_time_minutes) FILTER (
            WHERE status = 'resolved' AND response_time_minutes IS NOT NULL
          )),
          0
        )::INT AS mttr_minutes,
        CASE
          WHEN COUNT(*) = 0 THEN 0
          ELSE GREATEST(
            0,
            LEAST(
              100,
              ROUND(
                100 - (
                  COUNT(*) FILTER (WHERE status IN ('open', 'investigating'))::DECIMAL
                  / GREATEST(COUNT(*), 1)
                ) * 100
              )
            )
          )::INT
        END AS trust_score,
        COUNT(*)::INT AS total_count
      FROM incidents
      WHERE tenant_slug = $1
    `,
    [tenant]
  );

  if (!result || !result.rows.length) {
    return null;
  }

  const row = result.rows[0];
  const mttrValue = Number(row.mttr_minutes || 0);
  return {
    summary: {
      activeThreats: Number(row.active_threats || 0),
      blockedToday: Number(row.blocked_today || 0),
      mttrMinutes: mttrValue > 0 ? mttrValue : null,
      trustScore: Number(row.trust_score || 0),
      dataSource: 'database',
      dataQuality: {
        incidentCount: Number(row.total_count || 0),
        mttrAvailable: mttrValue > 0,
        mttrNote: mttrValue > 0
          ? 'MTTR computed from AVG(response_time_minutes) of resolved incidents.'
          : 'No resolved incidents with response_time_minutes data.',
      },
    },
    totalCount: Number(row.total_count || 0),
  };
}

async function loadIncidentsFromDatabase(config, tenant, limit) {
  const result = await query(
    config,
    `
      SELECT
        id,
        title,
        severity,
        status,
        detected_at
      FROM incidents
      WHERE tenant_slug = $1
      ORDER BY detected_at DESC
      LIMIT $2
    `,
    [tenant, limit]
  );

  if (!result) {
    return null;
  }

  return result.rows.map(normalizeIncidentRow);
}

async function buildThreatIncidents(config, tenant, limit = 6, log = () => {}) {
  const normalizedLimit = clamp(1, Number(limit) || 6, 100);
  const normalizedTenant = sanitizeTenant(tenant);

  try {
    const databaseIncidents = await loadIncidentsFromDatabase(
      config,
      normalizedTenant,
      normalizedLimit
    );

    if (Array.isArray(databaseIncidents) && databaseIncidents.length) {
      return databaseIncidents;
    }

    if (hasConfiguredConnector(config)) {
      return fetchConnectorIncidents(config, normalizedTenant, normalizedLimit, log);
    }
  } catch (error) {
    log('warn', 'threat.incidents_fetch_failed', {
      tenant: normalizedTenant,
      error: error instanceof Error ? error.message : 'unknown error',
    });
  }

  return [];
}

async function buildThreatSummary(config, tenant, log = () => {}) {
  const normalizedTenant = sanitizeTenant(tenant);

  try {
    const dbSummary = await loadSummaryFromDatabase(config, normalizedTenant);
    if (dbSummary && dbSummary.totalCount > 0) {
      return dbSummary.summary;
    }

    if (hasConfiguredConnector(config)) {
      const connectorIncidents = await fetchConnectorIncidents(config, normalizedTenant, 200, log);
      if (connectorIncidents.length) {
        return summarizeFromIncidents(connectorIncidents);
      }
    }
  } catch (error) {
    log('warn', 'threat.summary_fetch_failed', {
      tenant: normalizedTenant,
      error: error instanceof Error ? error.message : 'unknown error',
    });
  }

  return EMPTY_SUMMARY;
}

module.exports = {
  buildThreatSummary,
  buildThreatIncidents,
};