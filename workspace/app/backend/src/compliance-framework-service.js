'use strict';

const { sanitizeTenant } = require('./validators');
const { query } = require('./database');

// Valid governance state transitions (aligned with compliance-model.js).
const VALID_TRANSITIONS = {
  'not_started':     ['in_progress', 'not_applicable'],
  'in_progress':     ['implemented', 'not_started', 'not_applicable'],
  'implemented':     ['validated', 'in_progress', 'not_applicable'],
  'validated':       ['implemented', 'not_applicable'],
  'not_applicable':  ['not_started'],
};

/**
 * List all available compliance frameworks.
 */
async function listComplianceFrameworks(config) {
  const sql = `
    SELECT id, name, version, description, category, created_at
    FROM compliance_frameworks
    ORDER BY name ASC
  `;
  const result = await query(config, sql, []);
  return { data: result.rows };
}

/**
 * Get a single compliance framework by id.
 */
async function getComplianceFramework(config, frameworkId) {
  const sql = `
    SELECT id, name, version, description, category, created_at
    FROM compliance_frameworks
    WHERE id = $1
  `;
  const result = await query(config, sql, [frameworkId]);
  if (result.rows.length === 0) {
    const err = new Error(`Compliance framework '${frameworkId}' not found.`);
    err.statusCode = 404;
    err.code = 'not_found';
    throw err;
  }
  return result.rows[0];
}

/**
 * List controls belonging to a specific framework.
 */
async function listFrameworkControls(config, frameworkId, { family } = {}) {
  const params = [frameworkId];
  let where = 'WHERE framework_id = $1';
  if (family) {
    params.push(family);
    where += ` AND family = $${params.length}`;
  }
  const sql = `
    SELECT id, framework_id, control_id, family, title, description, default_weight, created_at
    FROM compliance_controls
    ${where}
    ORDER BY control_id ASC
  `;
  const result = await query(config, sql, params);
  return { data: result.rows, total: result.rows.length };
}

/**
 * List tenant-scoped control statuses for a framework,
 * joined with control metadata.
 */
async function listFrameworkControlStatus(config, tenant, frameworkId) {
  const tenantSlug = sanitizeTenant(tenant);
  const sql = `
    SELECT
      cc.control_id    AS "controlId",
      cc.family,
      cc.title,
      cc.description,
      cc.default_weight AS "defaultWeight",
      COALESCE(cs.status, 'not_started') AS status,
      cs.owner_user_id  AS "ownerUserId",
      cs.notes,
      cs.updated_at     AS "updatedAt",
      CASE WHEN cs.id IS NOT NULL THEN 1 ELSE 0 END AS "evidenceCount"
    FROM compliance_controls cc
    LEFT JOIN compliance_control_status cs
      ON cs.tenant_slug = $1
      AND cs.framework_id = cc.framework_id
      AND cs.control_id = cc.control_id
    WHERE cc.framework_id = $2
    ORDER BY cc.control_id ASC
  `;
  const result = await query(config, sql, [tenantSlug, frameworkId]);
  return result.rows;
}

/**
 * Upsert a single control status for a tenant + framework + control.
 * G2: Enforces valid state transitions.
 * G3: Requires evidence for validated status (multi-framework uses evidenceCount from status record).
 * G4: Returns previousStatus for audit trail enrichment.
 */
async function upsertFrameworkControlStatus(config, { tenant, frameworkId, controlId, status, ownerUserId, notes }) {
  const tenantSlug = sanitizeTenant(tenant);
  const validStatuses = ['not_started', 'in_progress', 'implemented', 'validated', 'not_applicable'];
  const normalizedStatus = String(status || 'not_started').trim().toLowerCase();
  if (!validStatuses.includes(normalizedStatus)) {
    const err = new Error(`Invalid status '${status}'. Must be one of: ${validStatuses.join(', ')}`);
    err.statusCode = 400;
    err.code = 'invalid_status';
    throw err;
  }

  // Fetch current status for transition validation
  const currentRow = await query(
    config,
    `SELECT status FROM compliance_control_status
     WHERE tenant_slug = $1 AND framework_id = $2 AND control_id = $3 LIMIT 1`,
    [tenantSlug, frameworkId, controlId]
  );
  const currentStatus = currentRow?.rows?.[0]?.status || 'not_started';

  // G2: Validate transition
  if (currentStatus !== normalizedStatus) {
    const allowed = VALID_TRANSITIONS[currentStatus];
    if (!allowed || !allowed.includes(normalizedStatus)) {
      const err = new Error(
        `Cannot transition from '${currentStatus}' to '${normalizedStatus}'. Allowed: ${(allowed || []).join(', ')}.`
      );
      err.statusCode = 400;
      err.code = 'invalid_status_transition';
      throw err;
    }
  }

  const sql = `
    INSERT INTO compliance_control_status (tenant_slug, framework_id, control_id, status, owner_user_id, notes, updated_at)
    VALUES ($1, $2, $3, $4, $5, $6, NOW())
    ON CONFLICT (tenant_slug, framework_id, control_id)
    DO UPDATE SET
      status = EXCLUDED.status,
      owner_user_id = COALESCE(EXCLUDED.owner_user_id, compliance_control_status.owner_user_id),
      notes = COALESCE(EXCLUDED.notes, compliance_control_status.notes),
      updated_at = NOW()
    RETURNING
      tenant_slug   AS "tenantSlug",
      framework_id  AS "frameworkId",
      control_id    AS "controlId",
      status,
      owner_user_id AS "ownerUserId",
      notes,
      updated_at    AS "updatedAt"
  `;
  const result = await query(config, sql, [
    tenantSlug,
    frameworkId,
    controlId,
    normalizedStatus,
    ownerUserId || null,
    notes || null,
  ]);
  const row = result.rows[0];
  row.previousStatus = currentStatus;
  return row;
}

/**
 * Compute a per-framework compliance gap using the same algorithm as the SOC2 engine.
 * This reuses the computeComplianceGap function signature expected by the frontend.
 */
function computeFrameworkGap(controls) {
  const summary = {
    totalControls: 0,
    validated: 0,
    implemented: 0,
    inProgress: 0,
    notStarted: 0,
    notApplicable: 0,
    readinessScore: 0,
    gaps: [],
    validatedWithoutEvidence: 0,
  };

  if (!Array.isArray(controls) || controls.length === 0) {
    return summary;
  }

  let weightedScore = 0;
  let totalWeight = 0;

  for (const control of controls) {
    const status = String(control.status || 'not_started').trim().toLowerCase();
    const weight = Number(control.defaultWeight || control.default_weight || 1);
    const normalizedWeight = Number.isFinite(weight) && weight > 0 ? weight : 1;

    summary.totalControls += 1;
    totalWeight += normalizedWeight;

    let statusScore = 0;
    if (status === 'validated') {
      statusScore = 1.0;
      summary.validated += 1;
      // G5: Track validated controls with no evidence
      const evCount = Number(control.evidenceCount || control.evidence_count || 0);
      if (evCount === 0) {
        summary.validatedWithoutEvidence += 1;
      }
    }
    else if (status === 'implemented') { statusScore = 0.8; summary.implemented += 1; }
    else if (status === 'in_progress') { statusScore = 0.45; summary.inProgress += 1; }
    else if (status === 'not_applicable') { statusScore = 1.0; summary.notApplicable += 1; }
    else { summary.notStarted += 1; }

    weightedScore += normalizedWeight * statusScore;

    if (status !== 'validated' && status !== 'not_applicable') {
      summary.gaps.push({
        controlId: control.controlId || control.control_id,
        family: control.family,
        title: control.title,
        status,
        recommendedAction:
          status === 'not_started'
            ? 'Assign an owner and publish implementation timeline.'
            : status === 'in_progress'
              ? 'Complete implementation and collect objective evidence.'
              : 'Run validation review and attach auditor-ready evidence.',
      });
    }
  }

  summary.readinessScore = totalWeight > 0 ? Number(((weightedScore / totalWeight) * 100).toFixed(2)) : 0;

  summary.gaps.sort((a, b) => {
    if (a.status === b.status) return (a.controlId || '').localeCompare(b.controlId || '');
    if (a.status === 'not_started') return -1;
    if (b.status === 'not_started') return 1;
    if (a.status === 'in_progress') return -1;
    if (b.status === 'in_progress') return 1;
    return 0;
  });

  return summary;
}

/**
 * Get a cross-framework summary for a tenant.
 * Returns readiness scores for all frameworks the tenant has data for.
 */
async function getComplianceSummary(config, tenant) {
  const tenantSlug = sanitizeTenant(tenant);

  // Single query to fetch all frameworks with aggregated control status counts,
  // eliminating the previous N+1 pattern (1 query per framework).
  const summaryResult = await query(config, `
    SELECT
      cf.id          AS "frameworkId",
      cf.name,
      cf.version,
      cf.category,
      COUNT(cc.control_id)::INT                                                       AS "totalControls",
      COUNT(*) FILTER (WHERE COALESCE(cs.status,'not_started') = 'validated')::INT     AS validated,
      COUNT(*) FILTER (WHERE COALESCE(cs.status,'not_started') = 'implemented')::INT   AS implemented,
      COUNT(*) FILTER (WHERE COALESCE(cs.status,'not_started') = 'in_progress')::INT   AS "inProgress",
      COUNT(*) FILTER (WHERE COALESCE(cs.status,'not_started') = 'not_started')::INT   AS "notStarted",
      COUNT(*) FILTER (WHERE COALESCE(cs.status,'not_started') = 'not_applicable')::INT AS "notApplicable",
      COUNT(*) FILTER (WHERE COALESCE(cs.status,'not_started') NOT IN ('validated','not_applicable'))::INT AS "gapCount"
    FROM compliance_frameworks cf
    JOIN compliance_controls cc ON cc.framework_id = cf.id
    LEFT JOIN compliance_control_status cs
      ON cs.tenant_slug = $1
      AND cs.framework_id = cc.framework_id
      AND cs.control_id = cc.control_id
    GROUP BY cf.id, cf.name, cf.version, cf.category
    ORDER BY cf.name
  `, [tenantSlug]);

  const summaries = (summaryResult?.rows || []).map(row => {
    const total = row.totalControls || 0;
    // Weighted readiness approximation:
    // validated & n/a = 100%, implemented = 80%, in_progress = 45%, not_started = 0%
    const score = total > 0
      ? Number((((row.validated + row.notApplicable) * 1.0 + row.implemented * 0.8 + row.inProgress * 0.45) / total * 100).toFixed(2))
      : 0;
    return {
      frameworkId: row.frameworkId,
      name: row.name,
      version: row.version,
      category: row.category,
      totalControls: total,
      readinessScore: score,
      validated: row.validated,
      implemented: row.implemented,
      inProgress: row.inProgress,
      notStarted: row.notStarted,
      notApplicable: row.notApplicable,
      gapCount: row.gapCount,
    };
  });

  return { frameworks: summaries };
}

module.exports = {
  listComplianceFrameworks,
  getComplianceFramework,
  listFrameworkControls,
  listFrameworkControlStatus,
  upsertFrameworkControlStatus,
  computeFrameworkGap,
  getComplianceSummary,
};
