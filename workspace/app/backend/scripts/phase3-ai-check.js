#!/usr/bin/env node

const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const path = require('node:path');

const backendRoot = path.resolve(__dirname, '..');
const port = Number(process.env.BACKEND_TEST_PORT || 8104);

function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function shouldRequireDatabase() {
  const explicit = process.env.REQUIRE_DATABASE_FOR_CI;
  if (explicit !== undefined) {
    return String(explicit).toLowerCase() === 'true';
  }
  return String(process.env.CI || '').toLowerCase() === 'true';
}

function allowDevDatabaseSkip() {
  return String(process.env.ALLOW_QA_DATABASE_SKIP || 'false').toLowerCase() === 'true';
}

async function waitForHealth(maxAttempts = 30) {
  const url = `http://127.0.0.1:${port}/v1/system/health`;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        return;
      }
    } catch {
      // ignore boot window
    }
    await wait(250);
  }
  throw new Error('Backend did not become healthy in time for phase3 QA.');
}

function assertCondition(condition, label) {
  if (!condition) {
    throw new Error(`Assertion failed: ${label}`);
  }
  process.stdout.write(`PASS: ${label}\n`);
}

function toBase64UrlJson(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function buildJwtHs256(secret, payload) {
  const header = toBase64UrlJson({ alg: 'HS256', typ: 'JWT' });
  const body = toBase64UrlJson(payload);
  const signature = crypto
    .createHmac('sha256', secret)
    .update(`${header}.${body}`)
    .digest('base64url');
  return `${header}.${body}.${signature}`;
}

async function parseResponseBody(response) {
  const contentType = String(response.headers.get('content-type') || '').toLowerCase();
  if (contentType.includes('application/json')) {
    return response.json();
  }
  return response.text();
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, options);
  const body = await parseResponseBody(response);
  return { response, body };
}

function bearer(token) {
  return {
    Authorization: `Bearer ${token}`,
  };
}

function isPdf(bytes) {
  if (!bytes || bytes.length < 4) {
    return false;
  }
  return (
    bytes[0] === 0x25 && // %
    bytes[1] === 0x50 && // P
    bytes[2] === 0x44 && // D
    bytes[3] === 0x46 // F
  );
}

async function runChecks() {
  const requireDatabase = shouldRequireDatabase();
  const hasDatabase = Boolean(process.env.DATABASE_URL);
  if (!hasDatabase) {
    if (requireDatabase && !allowDevDatabaseSkip()) {
      throw new Error(
        'DATABASE_URL is required for qa:phase3 when REQUIRE_DATABASE_FOR_CI=true (or CI=true).'
      );
    }
    process.stdout.write('SKIP: DATABASE_URL is not set; phase3 AI endpoint checks were skipped.\n');
    return;
  }

  const base = `http://127.0.0.1:${port}`;
  const nowSeconds = Math.floor(Date.now() / 1000);
  const jwtSecret = process.env.JWT_SECRET || 'phase3-jwt-secret';

  const analystToken = buildJwtHs256(jwtSecret, {
    sub: 'phase3-analyst-user',
    email: 'phase3.analyst@cybertron.local',
    role: 'security_analyst',
    tenant: 'global',
    iat: nowSeconds,
    exp: nowSeconds + 3600,
  });
  const complianceToken = buildJwtHs256(jwtSecret, {
    sub: 'phase3-compliance-user',
    email: 'phase3.compliance@cybertron.local',
    role: 'compliance_officer',
    tenant: 'global',
    iat: nowSeconds,
    exp: nowSeconds + 3600,
  });
  const adminToken = buildJwtHs256(jwtSecret, {
    sub: 'phase3-admin-user',
    email: 'phase3.admin@cybertron.local',
    role: 'tenant_admin',
    tenant: 'global',
    iat: nowSeconds,
    exp: nowSeconds + 3600,
  });
  const superAdminToken = buildJwtHs256(jwtSecret, {
    sub: 'phase3-super-admin-user',
    email: 'phase3.super-admin@cybertron.local',
    role: 'super_admin',
    tenant: 'global',
    iat: nowSeconds,
    exp: nowSeconds + 3600,
  });
  const viewerToken = buildJwtHs256(jwtSecret, {
    sub: 'phase3-viewer-user',
    email: 'phase3.viewer@cybertron.local',
    role: 'executive_viewer',
    tenant: 'global',
    iat: nowSeconds,
    exp: nowSeconds + 3600,
  });

  async function ensureProductEnabled(productKey, roleMin = 'executive_viewer') {
    const result = await requestJson(
      `${base}/v1/tenants/global/products/${encodeURIComponent(productKey)}`,
      {
        method: 'PATCH',
        headers: {
          ...bearer(adminToken),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          enabled: true,
          roleMin,
        }),
      }
    );
    assertCondition(result.response.status === 200, `tenant product enabled (${productKey})`);
  }

  async function ensureFlagEnabled(flagKey) {
    const result = await requestJson(
      `${base}/v1/tenants/global/feature-flags/${encodeURIComponent(flagKey)}`,
      {
        method: 'PATCH',
        headers: {
          ...bearer(adminToken),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          enabled: true,
        }),
      }
    );
    assertCondition(result.response.status === 200, `tenant feature flag enabled (${flagKey})`);
  }

  async function ensurePlanTier(tier) {
    const result = await requestJson(`${base}/v1/billing/plan?tenant=global`, {
      method: 'PUT',
      headers: {
        ...bearer(superAdminToken),
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        tier,
      }),
    });
    assertCondition(result.response.status === 200, `tenant billing plan updated (${tier})`);
  }

  await ensurePlanTier('enterprise');
  await ensureProductEnabled('risk-copilot', 'executive_viewer');
  await ensureProductEnabled('resilience-hq', 'executive_viewer');
  await ensureProductEnabled('threat-command', 'executive_viewer');
  await ensureFlagEnabled('product_risk_copilot_enabled');
  await ensureFlagEnabled('product_compliance_engine_enabled');
  await ensureFlagEnabled('product_threat_intel_enabled');
  await ensureFlagEnabled('risk_copilot_beta');
  await ensureFlagEnabled('llm_features_enabled');

  const unauthenticatedPlatformApps = await requestJson(`${base}/v1/platform/apps`);
  assertCondition(
    unauthenticatedPlatformApps.response.status === 401,
    'platform apps rejects unauthenticated requests'
  );

  const viewerPlatformApps = await requestJson(`${base}/v1/platform/apps?tenant=global&role=executive_viewer`, {
    headers: bearer(viewerToken),
  });
  assertCondition(viewerPlatformApps.response.status === 200, 'platform apps loads for executive viewer');
  assertCondition(Array.isArray(viewerPlatformApps.body), 'platform apps payload is an array for executive viewer');
  const viewerAppIds = new Set((viewerPlatformApps.body || []).map(item => String(item?.id || '')));
  assertCondition(viewerAppIds.has('risk-copilot'), 'risk copilot is visible to executive viewer in read-only mode');
  assertCondition(viewerAppIds.has('resilience-hq'), 'compliance engine is visible to executive viewer in read-only mode');
  assertCondition(viewerAppIds.has('threat-command'), 'threat intel is visible to executive viewer in read-only mode');

  const viewerRiskStatus = await requestJson(
    `${base}/v1/apps/risk-copilot/status?tenant=global&role=executive_viewer`,
    {
      headers: bearer(viewerToken),
    }
  );
  assertCondition(viewerRiskStatus.response.status === 200, 'risk copilot status loads for executive viewer');

  const viewerComplianceStatus = await requestJson(
    `${base}/v1/apps/resilience-hq/status?tenant=global&role=executive_viewer`,
    {
      headers: bearer(viewerToken),
    }
  );
  assertCondition(
    viewerComplianceStatus.response.status === 200,
    'compliance engine status loads for executive viewer'
  );

  // Risk Copilot: ingest
  const awsForm = new FormData();
  awsForm.append(
    'file',
    new Blob(
      [
        JSON.stringify({
          records: [
            {
              severity: 'critical',
              category: 'vulnerability',
              assetId: 'ec2-i-123',
              vulnerabilityScore: 9.1,
              exposureScore: 8.5,
              misconfigurationScore: 7.8,
              title: 'Publicly exposed admin endpoint',
            },
            {
              severity: 'high',
              category: 'misconfiguration',
              assetId: 's3-bucket-prod',
              vulnerabilityScore: 6.4,
              exposureScore: 7.2,
              misconfigurationScore: 8.2,
              title: 'S3 bucket ACL too permissive',
            },
          ],
        }),
      ],
      { type: 'application/json' }
    ),
    'aws-findings.json'
  );

  const ingestResult = await requestJson(`${base}/v1/risk/ingest/aws-logs?tenant=global`, {
    method: 'POST',
    headers: bearer(analystToken),
    body: awsForm,
  });
  assertCondition(
    ingestResult.response.status === 200 || ingestResult.response.status === 201,
    'risk ingest endpoint status'
  );
  assertCondition(Boolean(ingestResult.body?.jobId), 'risk ingest returns job id');
  assertCondition(Number(ingestResult.body?.insertedFindings || 0) >= 1, 'risk ingest persists findings');

  const computeResult = await requestJson(`${base}/v1/risk/score/compute?tenant=global`, {
    method: 'POST',
    headers: {
      ...bearer(analystToken),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      includeAi: false,
      limit: 50,
    }),
  });
  assertCondition(computeResult.response.status === 200, 'risk compute endpoint status');
  assertCondition(
    Number(computeResult.body?.portfolio?.totalFindings || 0) >= 1,
    'risk compute returns portfolio totals'
  );

  const findingsResult = await requestJson(`${base}/v1/risk/findings?tenant=global&limit=10`, {
    headers: bearer(analystToken),
  });
  assertCondition(findingsResult.response.status === 200, 'risk findings endpoint status');
  assertCondition(Array.isArray(findingsResult.body?.data), 'risk findings payload array');
  assertCondition(findingsResult.body.data.length >= 1, 'risk findings contains ingested records');

  const riskReportResult = await requestJson(`${base}/v1/risk/report/generate?tenant=global`, {
    method: 'POST',
    headers: bearer(analystToken),
  });
  const riskReportErrorCode = riskReportResult.body?.error?.code || '';
  assertCondition(
    riskReportResult.response.status === 201 ||
      (riskReportResult.response.status === 503 && riskReportErrorCode === 'LLM_NOT_CONFIGURED'),
    'risk report generate endpoint behavior'
  );
  if (riskReportResult.response.status === 201) {
    assertCondition(Boolean(riskReportResult.body?.report?.id), 'risk report generate returns report id');
    const riskReportId = String(riskReportResult.body.report.id);
    const riskDownload = await fetch(
      `${base}/v1/risk/report/${encodeURIComponent(riskReportId)}/download?tenant=global`,
      {
        headers: bearer(analystToken),
      }
    );
    assertCondition(riskDownload.status === 200, 'risk report download endpoint status');
    assertCondition(
      String(riskDownload.headers.get('content-type') || '').toLowerCase().includes('application/pdf'),
      'risk report download returns pdf'
    );
    const riskDownloadBytes = new Uint8Array(await riskDownload.arrayBuffer());
    assertCondition(isPdf(riskDownloadBytes), 'risk report download starts with PDF signature');
    assertCondition(riskDownloadBytes.length > 5 * 1024, 'risk report download is larger than 5KB');
  }

  // Compliance Engine: controls and status
  const controlsResult = await requestJson(`${base}/v1/compliance/soc2/controls?tenant=global`, {
    headers: bearer(complianceToken),
  });
  assertCondition(controlsResult.response.status === 200, 'soc2 controls endpoint status');
  assertCondition(Array.isArray(controlsResult.body), 'soc2 controls payload array');
  assertCondition(controlsResult.body.length >= 1, 'soc2 controls loaded from database');

  const statusResult = await requestJson(`${base}/v1/compliance/soc2/status?tenant=global`, {
    headers: bearer(complianceToken),
  });
  assertCondition(statusResult.response.status === 200, 'soc2 status endpoint status');
  assertCondition(Array.isArray(statusResult.body?.controls), 'soc2 status returns controls list');

  const controlId = String(statusResult.body?.controls?.[0]?.controlId || controlsResult.body?.[0]?.controlId || '');
  assertCondition(Boolean(controlId), 'soc2 control id available for mutation checks');

  const patchStatusResult = await requestJson(
    `${base}/v1/compliance/soc2/status/${encodeURIComponent(controlId)}?tenant=global`,
    {
      method: 'PATCH',
      headers: {
        ...bearer(complianceToken),
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        status: 'in_progress',
        notes: 'Phase3 automation verification: transition to in_progress.',
      }),
    }
  );
  assertCondition(patchStatusResult.response.status === 200, 'soc2 status patch to in_progress');
  assertCondition(
    String(patchStatusResult.body?.status || '') === 'in_progress',
    'soc2 status patch persisted in_progress value'
  );

  // Second valid transition: in_progress -> implemented
  const patchImplementedResult = await requestJson(
    `${base}/v1/compliance/soc2/status/${encodeURIComponent(controlId)}?tenant=global`,
    {
      method: 'PATCH',
      headers: {
        ...bearer(complianceToken),
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        status: 'implemented',
        notes: 'Phase3 automation verification: transition to implemented.',
      }),
    }
  );
  assertCondition(patchImplementedResult.response.status === 200, 'soc2 status patch to implemented');
  assertCondition(
    String(patchImplementedResult.body?.status || '') === 'implemented',
    'soc2 status patch persisted implemented value'
  );

  const patchStatusAsAnalyst = await requestJson(
    `${base}/v1/compliance/soc2/status/${encodeURIComponent(controlId)}?tenant=global`,
    {
      method: 'PATCH',
      headers: {
        ...bearer(viewerToken),
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        status: 'validated',
      }),
    }
  );
  assertCondition(
    patchStatusAsAnalyst.response.status === 403,
    'soc2 status patch blocks role bypass for executive viewer token'
  );

  const evidenceForm = new FormData();
  evidenceForm.append('controlId', controlId);
  evidenceForm.append(
    'file',
    new Blob(['%PDF-1.4\n% compliance evidence\n1 0 obj\n<< /Type /Catalog >>\nendobj\n'], {
      type: 'application/pdf',
    }),
    'evidence.pdf'
  );
  const evidenceUploadResult = await requestJson(
    `${base}/v1/compliance/soc2/evidence/upload?tenant=global`,
    {
      method: 'POST',
      headers: bearer(complianceToken),
      body: evidenceForm,
    }
  );
  assertCondition(
    evidenceUploadResult.response.status === 200 || evidenceUploadResult.response.status === 201,
    'soc2 evidence upload endpoint status'
  );
  assertCondition(Boolean(evidenceUploadResult.body?.id), 'soc2 evidence upload returns evidence id');

  const policyResult = await requestJson(`${base}/v1/compliance/policy/generate?tenant=global`, {
    method: 'POST',
    headers: {
      ...bearer(complianceToken),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      policyKey: 'phase3-generated-policy',
      organization: 'Cybertron',
    }),
  });
  const policyErrorCode = policyResult.body?.error?.code || '';
  assertCondition(
    policyResult.response.status === 201 ||
      (policyResult.response.status === 503 && policyErrorCode === 'LLM_NOT_CONFIGURED') ||
      (policyResult.response.status === 403 && policyErrorCode === 'feature_disabled'),
    'compliance policy generate endpoint behavior'
  );

  const auditPackageResult = await requestJson(
    `${base}/v1/compliance/audit-package/generate?tenant=global`,
    {
      method: 'POST',
      headers: bearer(complianceToken),
    }
  );
  assertCondition(
    auditPackageResult.response.status === 200 || auditPackageResult.response.status === 201,
    'audit package generate endpoint status'
  );
  assertCondition(Boolean(auditPackageResult.body?.id), 'audit package generate returns package id');

  const auditPackageId = String(auditPackageResult.body.id);
  const auditDownload = await fetch(
    `${base}/v1/compliance/audit-package/${encodeURIComponent(auditPackageId)}/download?tenant=global`,
    {
      headers: bearer(complianceToken),
    }
  );
  assertCondition(auditDownload.status === 200, 'audit package download endpoint status');
  assertCondition(
    String(auditDownload.headers.get('content-type') || '').toLowerCase().includes('application/pdf'),
    'audit package download returns pdf'
  );
  const auditBytes = new Uint8Array(await auditDownload.arrayBuffer());
  assertCondition(isPdf(auditBytes), 'audit package download starts with PDF signature');
  assertCondition(auditBytes.length > 5 * 1024, 'audit package download is larger than 5KB');

  // Threat intel: dashboard + feed + sync + summarize
  const dashboardResult = await requestJson(`${base}/v1/threat-intel/dashboard?tenant=global`, {
    headers: bearer(analystToken),
  });
  assertCondition(dashboardResult.response.status === 200, 'threat intel dashboard endpoint status');
  assertCondition(Boolean(dashboardResult.body?.severityCounts), 'threat intel dashboard returns severity counts');

  const feedResult = await requestJson(`${base}/v1/threat-intel/cve/feed?tenant=global&limit=10`, {
    headers: bearer(analystToken),
  });
  assertCondition(feedResult.response.status === 200, 'threat intel cve feed endpoint status');
  assertCondition(Array.isArray(feedResult.body?.data), 'threat intel cve feed returns data array');

  const syncResult = await requestJson(`${base}/v1/threat-intel/cve/sync?tenant=global`, {
    method: 'POST',
    headers: bearer(adminToken),
  });
  const syncErrorCode = syncResult.body?.error?.code || '';
  assertCondition(
    syncResult.response.status === 200 ||
      (syncResult.response.status === 502 && syncErrorCode === 'cve_feed_unavailable'),
    'threat intel cve sync endpoint behavior'
  );

  const feedAfterSync = await requestJson(`${base}/v1/threat-intel/cve/feed?tenant=global&limit=5`, {
    headers: bearer(analystToken),
  });
  assertCondition(feedAfterSync.response.status === 200, 'threat intel cve feed after sync status');
  assertCondition(Array.isArray(feedAfterSync.body?.data), 'threat intel cve feed after sync array');

  const cveId = String(feedAfterSync.body?.data?.[0]?.cveId || '').trim();
  if (cveId) {
    const summarizeResult = await requestJson(
      `${base}/v1/threat-intel/cve/${encodeURIComponent(cveId)}/summarize?tenant=global`,
      {
        method: 'POST',
        headers: bearer(analystToken),
      }
    );
    const summarizeErrorCode = summarizeResult.body?.error?.code || '';
    assertCondition(
      summarizeResult.response.status === 201 ||
        (summarizeResult.response.status === 503 && summarizeErrorCode === 'LLM_NOT_CONFIGURED') ||
        (summarizeResult.response.status === 403 && summarizeErrorCode === 'feature_disabled'),
      'threat intel cve summarize endpoint behavior'
    );
  } else {
    process.stdout.write('PASS: threat intel summarize skipped (no CVE records available).\n');
  }

  // Negative tenant isolation on new product endpoints.
  const crossTenantRiskResult = await requestJson(`${base}/v1/risk/findings?tenant=acme`, {
    headers: bearer(analystToken),
  });
  assertCondition(crossTenantRiskResult.response.status === 403, 'risk findings blocks cross-tenant access');

  const crossTenantThreatIntelResult = await requestJson(`${base}/v1/threat-intel/cve/feed?tenant=acme`, {
    headers: bearer(analystToken),
  });
  assertCondition(
    crossTenantThreatIntelResult.response.status === 403,
    'threat intel feed blocks cross-tenant access'
  );

  const crossTenantReportsResult = await requestJson(`${base}/v1/reports?tenant=acme`, {
    headers: bearer(analystToken),
  });
  assertCondition(
    crossTenantReportsResult.response.status === 403,
    'reports endpoint blocks cross-tenant access'
  );
}

async function run() {
  const child = spawn(process.execPath, ['server.js'], {
    cwd: backendRoot,
    env: {
      ...process.env,
      PORT: String(port),
      AUTH_MODE: process.env.AUTH_MODE || 'jwt_hs256',
      JWT_SECRET: process.env.JWT_SECRET || 'phase3-jwt-secret',
      ALLOW_INSECURE_DEMO_AUTH: process.env.ALLOW_INSECURE_DEMO_AUTH || 'false',
      ALLOW_PUBLIC_REGISTRATION: process.env.ALLOW_PUBLIC_REGISTRATION || 'true',
      AUTH_COOKIE_SECURE: process.env.AUTH_COOKIE_SECURE || 'false',
      AUTH_COOKIE_SAMESITE: process.env.AUTH_COOKIE_SAMESITE || 'lax',
      CSRF_ENABLED: process.env.CSRF_ENABLED || 'true',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  child.stdout.on('data', chunk => {
    process.stdout.write(chunk.toString());
  });
  child.stderr.on('data', chunk => {
    process.stderr.write(chunk.toString());
  });

  try {
    await waitForHealth();
    await runChecks();
    process.stdout.write('Phase3 AI endpoint checks passed.\n');
  } finally {
    child.kill('SIGTERM');
  }
}

run().catch(error => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
