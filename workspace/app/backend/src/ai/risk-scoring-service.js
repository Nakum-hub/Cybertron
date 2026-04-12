const { query, withClient } = require('../database');
const { sanitizeTenant, toSafeInteger } = require('../validators');
const { ServiceError } = require('../auth-service');
const { computeRiskFinding, aggregateRiskPortfolio } = require('./risk-engine');

function normalizeActorUserId(value) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    return null;
  }
  return parsed;
}

function sanitizeCategory(value) {
  return String(value || '').trim().toLowerCase().slice(0, 64);
}

function sanitizeSeverity(value) {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'critical') return 'critical';
  if (normalized === 'high') return 'high';
  if (normalized === 'medium') return 'medium';
  if (normalized === 'low') return 'low';
  return '';
}

async function ingestAwsLogRecords(config, tenant, userId, records, contextMeta = {}) {
  const tenantSlug = sanitizeTenant(tenant || 'global');
  const actorUserId = normalizeActorUserId(userId);
  if (!Array.isArray(records) || records.length === 0) {
    throw new ServiceError(400, 'risk_ingest_empty', 'No AWS records were provided for ingestion.');
  }

  return withClient(config, async client => {
    await client.query('BEGIN');
    try {
      const jobResult = await client.query(
        `
          INSERT INTO aws_ingest_jobs (tenant_slug, user_id, status, meta_json)
          VALUES ($1,$2,'processing',$3::jsonb)
          RETURNING id, created_at
        `,
        [
          tenantSlug,
          actorUserId,
          JSON.stringify({
            recordCount: records.length,
            traceId: contextMeta.traceId || null,
          }),
        ]
      );

      const jobId = Number(jobResult.rows[0].id);
      const severityCounts = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
      };

      for (const record of records) {
        const finding = computeRiskFinding(record);
        severityCounts[finding.severity] += 1;
        await client.query(
          `
            INSERT INTO risk_findings (
              tenant_slug,
              asset_id,
              category,
              severity,
              score,
              details_json
            )
            VALUES ($1,$2,$3,$4,$5,$6::jsonb)
          `,
          [
            tenantSlug,
            finding.assetId,
            finding.category,
            finding.severity,
            finding.score,
            JSON.stringify(finding.detailsJson),
          ]
        );
      }

      await client.query(
        `
          UPDATE aws_ingest_jobs
          SET
            status = 'completed',
            updated_at = NOW(),
            meta_json = $2::jsonb
          WHERE id = $1
        `,
        [
          jobId,
          JSON.stringify({
            recordCount: records.length,
            insertedFindings: records.length,
            severityCounts,
          }),
        ]
      );

      await client.query('COMMIT');
      return {
        jobId: String(jobId),
        tenant: tenantSlug,
        recordCount: records.length,
        insertedFindings: records.length,
        severityCounts,
      };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    }
  });
}

async function listRiskFindings(config, tenant, options = {}) {
  const tenantSlug = sanitizeTenant(tenant || 'global');
  const limit = toSafeInteger(options.limit, 50, 1, 500);
  const offset = toSafeInteger(options.offset, 0, 0, 50_000);
  const severity = sanitizeSeverity(options.severity);
  const category = sanitizeCategory(options.category);

  const values = [tenantSlug];
  const where = ['tenant_slug = $1'];

  if (severity) {
    values.push(severity);
    where.push(`severity = $${values.length}`);
  }

  if (category) {
    values.push(category);
    where.push(`category = $${values.length}`);
  }

  const whereSql = where.join(' AND ');
  const count = await query(
    config,
    `SELECT COUNT(*)::INT AS total FROM risk_findings WHERE ${whereSql}`,
    values
  );
  const total = Number(count?.rows?.[0]?.total || 0);

  values.push(limit, offset);
  const result = await query(
    config,
    `
      SELECT
        id,
        tenant_slug,
        asset_id,
        category,
        severity,
        score,
        details_json,
        created_at,
        treatment_status,
        owner_user_id,
        reviewed_at,
        review_notes,
        residual_score
      FROM risk_findings
      WHERE ${whereSql}
      ORDER BY created_at DESC, id DESC
      LIMIT $${values.length - 1}
      OFFSET $${values.length}
    `,
    values
  );

  const data = (result?.rows || []).map(row => ({
    id: String(row.id),
    tenant: row.tenant_slug,
    assetId: row.asset_id || null,
    category: row.category,
    severity: row.severity,
    score: Number(row.score || 0),
    details: row.details_json || {},
    createdAt: new Date(row.created_at).toISOString(),
    treatmentStatus: row.treatment_status || 'open',
    ownerUserId: row.owner_user_id ? String(row.owner_user_id) : null,
    reviewedAt: row.reviewed_at ? new Date(row.reviewed_at).toISOString() : null,
    reviewNotes: row.review_notes || null,
    residualScore: row.residual_score != null ? Number(row.residual_score) : null,
  }));

  return {
    data,
    pagination: {
      limit,
      offset,
      total,
      hasMore: offset + data.length < total,
    },
    message: data.length
      ? undefined
      : 'No risk findings found. Upload AWS logs JSON to start risk scoring.',
  };
}

async function getRiskPortfolioSummary(config, tenant) {
  const tenantSlug = sanitizeTenant(tenant || 'global');
  const result = await query(
    config,
    `
      SELECT
        severity,
        AVG(score) AS avg_score,
        MAX(score) AS max_score,
        COUNT(*)::INT AS total
      FROM risk_findings
      WHERE tenant_slug = $1
      GROUP BY severity
    `,
    [tenantSlug]
  );

  // Build portfolio directly from SQL aggregates (R7 fix: previously used
  // synthetic flattened array that reported avg_score as highestScore).
  const portfolio = {
    totalFindings: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    averageScore: 0,
    highestScore: 0,
  };
  let scoreWeightedSum = 0;
  for (const row of result?.rows || []) {
    const count = Number(row.total || 0);
    const sev = String(row.severity || 'medium').trim().toLowerCase();
    const maxScore = Number(row.max_score || 0);
    const avgScore = Number(row.avg_score || 0);
    portfolio.totalFindings += count;
    if (sev === 'critical') portfolio.critical += count;
    else if (sev === 'high') portfolio.high += count;
    else if (sev === 'medium') portfolio.medium += count;
    else portfolio.low += count;
    scoreWeightedSum += avgScore * count;
    if (maxScore > portfolio.highestScore) portfolio.highestScore = maxScore;
  }
  portfolio.averageScore = portfolio.totalFindings > 0
    ? Number((scoreWeightedSum / portfolio.totalFindings).toFixed(2))
    : 0;
  portfolio.highestScore = Number(portfolio.highestScore.toFixed(2));

  // Treatment status distribution
  const treatmentResult = await query(
    config,
    `SELECT treatment_status, COUNT(*)::INT AS total
     FROM risk_findings WHERE tenant_slug = $1 GROUP BY treatment_status`,
    [tenantSlug]
  );
  const treatmentDistribution = {};
  for (const row of treatmentResult?.rows || []) {
    treatmentDistribution[row.treatment_status || 'open'] = Number(row.total || 0);
  }

  const latest = await query(
    config,
    `
      SELECT created_at
      FROM risk_findings
      WHERE tenant_slug = $1
      ORDER BY created_at DESC
      LIMIT 1
    `,
    [tenantSlug]
  );

  return {
    ...portfolio,
    treatmentDistribution,
    lastFindingAt: latest?.rows?.[0]?.created_at
      ? new Date(latest.rows[0].created_at).toISOString()
      : null,
  };
}

async function createRiskReportRecord(config, payload = {}) {
  const tenantSlug = sanitizeTenant(payload.tenant || 'global');
  const createdBy = normalizeActorUserId(payload.createdBy);
  const pdfStoragePath = String(payload.pdfStoragePath || '').trim();
  if (!pdfStoragePath) {
    throw new ServiceError(500, 'risk_report_path_missing', 'Risk report storage path is missing.');
  }

  const result = await query(
    config,
    `
      INSERT INTO risk_reports (tenant_slug, created_by, pdf_storage_path, summary_json)
      VALUES ($1,$2,$3,$4::jsonb)
      RETURNING id, tenant_slug, created_by, pdf_storage_path, summary_json, created_at
    `,
    [tenantSlug, createdBy, pdfStoragePath, JSON.stringify(payload.summaryJson || {})]
  );

  const row = result.rows[0];
  return {
    id: String(row.id),
    tenant: row.tenant_slug,
    createdBy: row.created_by ? String(row.created_by) : null,
    pdfStoragePath: row.pdf_storage_path,
    summary: row.summary_json || {},
    createdAt: new Date(row.created_at).toISOString(),
  };
}

async function getRiskReportRecord(config, tenant, reportId) {
  const tenantSlug = sanitizeTenant(tenant || 'global');
  const id = Number(reportId);
  if (!Number.isInteger(id) || id <= 0) {
    throw new ServiceError(400, 'invalid_risk_report_id', 'Risk report id is invalid.');
  }

  const result = await query(
    config,
    `
      SELECT id, tenant_slug, created_by, pdf_storage_path, summary_json, created_at
      FROM risk_reports
      WHERE tenant_slug = $1 AND id = $2
      LIMIT 1
    `,
    [tenantSlug, id]
  );

  if (!result?.rows?.length) {
    throw new ServiceError(404, 'risk_report_not_found', 'Risk report was not found.');
  }

  const row = result.rows[0];
  return {
    id: String(row.id),
    tenant: row.tenant_slug,
    createdBy: row.created_by ? String(row.created_by) : null,
    pdfStoragePath: row.pdf_storage_path,
    summary: row.summary_json || {},
    createdAt: new Date(row.created_at).toISOString(),
  };
}

const VALID_TREATMENT_STATUSES = new Set([
  'open', 'mitigating', 'mitigated', 'accepted', 'transferred', 'avoided',
]);

async function updateRiskFindingTreatment(config, tenant, findingId, payload = {}) {
  const tenantSlug = sanitizeTenant(tenant || 'global');
  const id = Number(findingId);
  if (!Number.isInteger(id) || id <= 0) {
    throw new ServiceError(400, 'invalid_finding_id', 'Risk finding id is invalid.');
  }

  const treatmentStatus = String(payload.treatmentStatus || '').trim().toLowerCase();
  if (!VALID_TREATMENT_STATUSES.has(treatmentStatus)) {
    throw new ServiceError(
      400,
      'invalid_treatment_status',
      `Treatment status must be one of: ${[...VALID_TREATMENT_STATUSES].join(', ')}.`
    );
  }

  const residualScore = payload.residualScore != null
    ? Math.max(0, Math.min(100, Number(payload.residualScore) || 0))
    : null;
  const ownerUserId = normalizeActorUserId(payload.ownerUserId);
  const reviewNotes = String(payload.reviewNotes || '').trim().slice(0, 4000) || null;

  // Verify finding exists and belongs to tenant
  const existing = await query(
    config,
    `SELECT id, treatment_status FROM risk_findings WHERE tenant_slug = $1 AND id = $2 LIMIT 1`,
    [tenantSlug, id]
  );
  if (!existing?.rows?.length) {
    throw new ServiceError(404, 'risk_finding_not_found', 'Risk finding was not found.');
  }
  const previousStatus = existing.rows[0].treatment_status || 'open';

  const setClauses = ['treatment_status = $3', 'reviewed_at = NOW()'];
  const params = [tenantSlug, id, treatmentStatus];

  if (residualScore !== null) {
    params.push(residualScore);
    setClauses.push(`residual_score = $${params.length}`);
  }
  if (ownerUserId) {
    params.push(ownerUserId);
    setClauses.push(`owner_user_id = $${params.length}`);
  }
  if (reviewNotes) {
    params.push(reviewNotes);
    setClauses.push(`review_notes = $${params.length}`);
  }

  const result = await query(
    config,
    `UPDATE risk_findings SET ${setClauses.join(', ')}
     WHERE tenant_slug = $1 AND id = $2
     RETURNING id, tenant_slug, asset_id, category, severity, score,
               treatment_status, owner_user_id, reviewed_at, review_notes,
               residual_score, details_json, created_at`,
    params
  );

  const row = result.rows[0];
  return {
    id: String(row.id),
    tenant: row.tenant_slug,
    assetId: row.asset_id || null,
    category: row.category,
    severity: row.severity,
    score: Number(row.score || 0),
    treatmentStatus: row.treatment_status,
    previousTreatmentStatus: previousStatus,
    ownerUserId: row.owner_user_id ? String(row.owner_user_id) : null,
    reviewedAt: row.reviewed_at ? new Date(row.reviewed_at).toISOString() : null,
    reviewNotes: row.review_notes || null,
    residualScore: row.residual_score != null ? Number(row.residual_score) : null,
    details: row.details_json || {},
    createdAt: new Date(row.created_at).toISOString(),
  };
}

module.exports = {
  ingestAwsLogRecords,
  listRiskFindings,
  getRiskPortfolioSummary,
  createRiskReportRecord,
  getRiskReportRecord,
  updateRiskFindingTreatment,
  VALID_TREATMENT_STATUSES,
};
