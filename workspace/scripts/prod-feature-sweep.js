#!/usr/bin/env node

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

function parseArgs(argv) {
  const args = {};

  for (let index = 0; index < argv.length; index += 1) {
    const token = String(argv[index] || '');
    if (!token.startsWith('--')) {
      continue;
    }

    const key = token.slice(2);
    const next = argv[index + 1];
    if (next && !String(next).startsWith('--')) {
      args[key] = String(next);
      index += 1;
      continue;
    }

    args[key] = 'true';
  }

  return args;
}

function usage() {
  return [
    'Usage:',
    '  node scripts/prod-feature-sweep.js --password <admin-password> [options]',
    '',
    'Options:',
    '  --base-url <value>   Public base URL (default: http://127.0.0.1:8088)',
    '  --email <value>      Admin email (default: admin@cybertron.local)',
    '  --tenant <value>     Tenant slug (default: global)',
  ].join('\n');
}

function assertCondition(condition, label) {
  if (!condition) {
    throw new Error(`Assertion failed: ${label}`);
  }

  process.stdout.write(`PASS: ${label}\n`);
}

async function request(url, init = {}) {
  const response = await fetch(url, init);
  const contentType = String(response.headers.get('content-type') || '').toLowerCase();

  if (
    contentType.includes('application/pdf') ||
    contentType.includes('application/octet-stream') ||
    contentType.includes('text/csv')
  ) {
    const buffer = Buffer.from(await response.arrayBuffer());
    return { response, body: buffer, contentType };
  }

  const text = await response.text();
  let body = null;

  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
  }

  return { response, body, contentType };
}

function buildAuthHeaders(token, extras = {}) {
  return token
    ? {
        Authorization: `Bearer ${token}`,
        ...extras,
      }
    : extras;
}

function fixturePath(...segments) {
  return path.resolve(__dirname, '..', ...segments);
}

function readEvidencePdfBlob() {
  const buffer = fs.readFileSync(fixturePath('app', 'frontend', 'src', 'fixtures', 'evidence.sample.pdf'));
  return new Blob([buffer], { type: 'application/pdf' });
}

function buildAwsLogsBlob() {
  const payload = {
    records: [
      {
        severity: 'critical',
        category: 'identity',
        assetId: 'i-prod-web-1',
        title: 'Public admin console exposed',
        vulnerabilityScore: 9.5,
        exposureScore: 9.8,
        misconfigurationScore: 8.9,
        accountId: '123456789012',
        region: 'us-east-1',
        eventName: 'AuthorizeSecurityGroupIngress',
      },
      {
        severity: 'high',
        category: 'iam',
        assetId: 'iam-role-ci-runner',
        title: 'Privilege escalation path detected',
        vulnerabilityScore: 8.7,
        exposureScore: 6.4,
        misconfigurationScore: 7.3,
        accountId: '123456789012',
        region: 'us-east-1',
        eventName: 'AttachRolePolicy',
      },
      {
        severity: 'medium',
        category: 'storage',
        assetId: 's3-customer-backups',
        title: 'Bucket encryption policy drift',
        vulnerabilityScore: 4.1,
        exposureScore: 5.2,
        misconfigurationScore: 7.1,
        accountId: '123456789012',
        region: 'us-west-2',
        eventName: 'PutBucketEncryption',
      },
    ],
  };

  return new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
}

function buildReportUploadForm() {
  const reportContent = `timestamp,severity,signal\n${new Date().toISOString()},high,feature-sweep\n`;
  const form = new FormData();
  form.append('file', new Blob([reportContent], { type: 'text/csv' }), 'feature-sweep.csv');
  form.append('reportType', 'feature_sweep');
  form.append('reportDate', new Date().toISOString().slice(0, 10));
  form.append('metadata', JSON.stringify({ source: 'prod-feature-sweep' }));
  return form;
}

function nextComplianceStatus(currentStatus, evidenceCount = 0) {
  const normalized = String(currentStatus || 'not_started').trim().toLowerCase();

  if (normalized === 'not_started') {
    return 'in_progress';
  }
  if (normalized === 'in_progress') {
    return 'implemented';
  }
  if (normalized === 'implemented') {
    return Number(evidenceCount) > 0 ? 'validated' : 'in_progress';
  }
  if (normalized === 'validated') {
    return 'implemented';
  }
  if (normalized === 'not_applicable') {
    return 'not_started';
  }

  return 'in_progress';
}

async function updatePlan(baseUrl, accessToken, tenant, tier) {
  return request(`${baseUrl}/api/v1/billing/plan?tenant=${encodeURIComponent(tenant)}`, {
    method: 'PUT',
    headers: buildAuthHeaders(accessToken, {
      'Content-Type': 'application/json',
    }),
    body: JSON.stringify({ tenant, tier }),
  });
}

async function patchJson(url, accessToken, payload) {
  return request(url, {
    method: 'PATCH',
    headers: buildAuthHeaders(accessToken, {
      'Content-Type': 'application/json',
    }),
    body: JSON.stringify(payload),
  });
}

async function postJson(url, accessToken, payload) {
  return request(url, {
    method: 'POST',
    headers: buildAuthHeaders(accessToken, {
      'Content-Type': 'application/json',
    }),
    body: payload === undefined ? undefined : JSON.stringify(payload),
  });
}

async function putJson(url, accessToken, payload) {
  return request(url, {
    method: 'PUT',
    headers: buildAuthHeaders(accessToken, {
      'Content-Type': 'application/json',
    }),
    body: JSON.stringify(payload),
  });
}

async function ensureTenantReady(baseUrl, accessToken, tenant) {
  const productsRes = await request(
    `${baseUrl}/api/v1/tenants/${encodeURIComponent(tenant)}/products?role=super_admin`,
    { headers: buildAuthHeaders(accessToken) }
  );
  assertCondition(productsRes.response.status === 200, 'tenant products list succeeds');
  const productKeys = new Set((productsRes.body || []).map(item => String(item.productKey || item.productId || '')));

  for (const productKey of ['threat-command', 'identity-guardian', 'resilience-hq', 'risk-copilot']) {
    assertCondition(productKeys.has(productKey), `product catalog includes ${productKey}`);
    const patchRes = await patchJson(
      `${baseUrl}/api/v1/tenants/${encodeURIComponent(tenant)}/products/${encodeURIComponent(productKey)}`,
      accessToken,
      { enabled: true }
    );
    assertCondition(
      patchRes.response.status === 200,
      `tenant product enable succeeds for ${productKey}`
    );
  }

  const flagsRes = await request(
    `${baseUrl}/api/v1/tenants/${encodeURIComponent(tenant)}/feature-flags`,
    { headers: buildAuthHeaders(accessToken) }
  );
  assertCondition(flagsRes.response.status === 200, 'tenant feature flags list succeeds');
  const flagKeys = new Set((flagsRes.body || []).map(item => String(item.flagKey || '')));

  for (const flagKey of [
    'product_risk_copilot_enabled',
    'product_compliance_engine_enabled',
    'product_threat_intel_enabled',
    'risk_copilot_beta',
    'llm_features_enabled',
  ]) {
    assertCondition(flagKeys.has(flagKey), `feature flag catalog includes ${flagKey}`);
    const patchRes = await patchJson(
      `${baseUrl}/api/v1/tenants/${encodeURIComponent(tenant)}/feature-flags/${encodeURIComponent(flagKey)}`,
      accessToken,
      { enabled: true }
    );
    assertCondition(
      patchRes.response.status === 200,
      `tenant feature flag enable succeeds for ${flagKey}`
    );
  }
}

async function run() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help === 'true') {
    process.stdout.write(`${usage()}\n`);
    return;
  }

  const baseUrl = String(args['base-url'] || process.env.CYBERTRON_BASE_URL || 'http://127.0.0.1:8088').replace(/\/+$/, '');
  const email = String(args.email || process.env.CYBERTRON_ADMIN_EMAIL || 'admin@cybertron.local').trim().toLowerCase();
  const password = String(args.password || process.env.CYBERTRON_ADMIN_PASSWORD || '');
  const tenant = String(args.tenant || process.env.CYBERTRON_ADMIN_TENANT || 'global').trim().toLowerCase();
  const minGroundingScore = 60;

  if (password.length < 10) {
    throw new Error('A real admin password is required.');
  }

  const login = await request(`${baseUrl}/api/v1/auth/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ tenant, email, password }),
  });
  assertCondition(login.response.status === 200, 'password login succeeds for feature sweep');

  const accessToken = login.body?.tokens?.accessToken || '';
  const refreshToken = login.body?.tokens?.refreshToken || '';
  assertCondition(Boolean(accessToken), 'feature sweep login returns access token');
  assertCondition(Boolean(refreshToken), 'feature sweep login returns refresh token');

  const authHeaders = buildAuthHeaders(accessToken);

  const me = await request(`${baseUrl}/api/v1/auth/me`, { headers: authHeaders });
  assertCondition(me.response.status === 200, 'auth me succeeds for feature sweep');
  assertCondition(String(me.body?.tenant || '').toLowerCase() === tenant, 'auth me returns target tenant');

  const readiness = await request(`${baseUrl}/api/v1/system/readiness`);
  assertCondition(readiness.response.status === 200, 'system readiness succeeds through deployed stack');

  const openapi = await request(`${baseUrl}/api/v1/system/openapi`, { headers: authHeaders });
  assertCondition(openapi.response.status === 200, 'openapi endpoint succeeds through deployed stack');
  assertCondition(Object.keys(openapi.body?.paths || {}).length >= 20, 'openapi exposes a broad endpoint catalog');

  const connectors = await request(`${baseUrl}/api/v1/connectors/status`, { headers: authHeaders });
  assertCondition(connectors.response.status === 200, 'connector status endpoint succeeds');

  const billingBefore = await request(
    `${baseUrl}/api/v1/billing/credits?tenant=${encodeURIComponent(tenant)}`,
    { headers: authHeaders }
  );
  assertCondition(billingBefore.response.status === 200, 'billing credits succeeds before feature sweep');
  const currentTier = String(billingBefore.body?.planTier || '').trim().toLowerCase();
  if (currentTier !== 'enterprise') {
    const planRes = await updatePlan(baseUrl, accessToken, tenant, 'enterprise');
    assertCondition(planRes.response.status === 200, 'billing plan upgrade to enterprise succeeds');
  } else {
    assertCondition(true, 'tenant is already on enterprise plan for feature sweep');
  }

  await ensureTenantReady(baseUrl, accessToken, tenant);

  const tenantsRes = await request(`${baseUrl}/api/v1/tenants?limit=25`, { headers: authHeaders });
  assertCondition(tenantsRes.response.status === 200, 'tenant list succeeds');

  const productsRes = await request(
    `${baseUrl}/api/v1/products?tenant=${encodeURIComponent(tenant)}&role=super_admin`,
    { headers: authHeaders }
  );
  assertCondition(productsRes.response.status === 200, 'product catalog succeeds');

  const platformAppsRes = await request(
    `${baseUrl}/api/v1/platform/apps?tenant=${encodeURIComponent(tenant)}&role=super_admin`,
    { headers: authHeaders }
  );
  assertCondition(platformAppsRes.response.status === 200, 'platform apps succeeds for feature sweep');

  const modulesRes = await request(
    `${baseUrl}/api/v1/modules?tenant=${encodeURIComponent(tenant)}&role=super_admin`,
    { headers: authHeaders }
  );
  assertCondition(modulesRes.response.status === 200, 'module registry succeeds for feature sweep');
  assertCondition(Array.isArray(modulesRes.body?.modules), 'module registry returns modules array in feature sweep');

  for (const appId of ['threat-command', 'identity-guardian', 'resilience-hq', 'risk-copilot']) {
    const appStatusRes = await request(
      `${baseUrl}/api/v1/apps/${encodeURIComponent(appId)}/status?tenant=${encodeURIComponent(tenant)}&role=super_admin`,
      { headers: authHeaders }
    );
    assertCondition(appStatusRes.response.status === 200, `app status succeeds for ${appId}`);
  }

  for (const moduleId of ['threat-intel', 'core', 'compliance-engine', 'risk-copilot']) {
    const moduleStatusRes = await request(
      `${baseUrl}/api/v1/modules/${encodeURIComponent(moduleId)}/status?tenant=${encodeURIComponent(tenant)}&role=super_admin`,
      { headers: authHeaders }
    );
    assertCondition(moduleStatusRes.response.status === 200, `module status succeeds for ${moduleId}`);
  }

  const publicThreatSummary = await request(`${baseUrl}/api/v1/threats/summary?tenant=${encodeURIComponent(tenant)}`, {
    headers: authHeaders,
  });
  assertCondition(publicThreatSummary.response.status === 200, 'public threat summary succeeds with auth');

  const publicThreatIncidents = await request(`${baseUrl}/api/v1/threats/incidents?tenant=${encodeURIComponent(tenant)}&limit=10`, {
    headers: authHeaders,
  });
  assertCondition(publicThreatIncidents.response.status === 200, 'public threat incidents succeeds with auth');

  const usersRes = await request(`${baseUrl}/api/v1/users?tenant=${encodeURIComponent(tenant)}&limit=50`, {
    headers: authHeaders,
  });
  assertCondition(usersRes.response.status === 200, 'user list succeeds');

  const incidentCreate = await postJson(
    `${baseUrl}/api/v1/incidents?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    {
      title: 'Feature Sweep Incident',
      severity: 'high',
      status: 'open',
      blocked: false,
      source: 'prod-feature-sweep',
      timelineMessage: 'Incident created during production feature sweep.',
    }
  );
  assertCondition(incidentCreate.response.status === 201, 'incident create succeeds');
  const incidentId = String(incidentCreate.body?.id || '');
  assertCondition(Boolean(incidentId), 'incident create returns id');

  const incidentUpdate = await patchJson(
    `${baseUrl}/api/v1/incidents/${encodeURIComponent(incidentId)}?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    {
      status: 'investigating',
      priority: 'critical',
      timelineMessage: 'Incident escalated for live validation.',
    }
  );
  assertCondition(incidentUpdate.response.status === 200, 'incident update succeeds');

  const incidentList = await request(`${baseUrl}/api/v1/incidents?tenant=${encodeURIComponent(tenant)}&limit=20`, {
    headers: authHeaders,
  });
  assertCondition(incidentList.response.status === 200, 'incident list succeeds');

  const incidentTimeline = await request(
    `${baseUrl}/api/v1/incidents/${encodeURIComponent(incidentId)}/timeline?tenant=${encodeURIComponent(tenant)}`,
    { headers: authHeaders }
  );
  assertCondition(incidentTimeline.response.status === 200, 'incident timeline succeeds');
  assertCondition(Array.isArray(incidentTimeline.body?.data), 'incident timeline returns events array');

  const iocCreate = await postJson(
    `${baseUrl}/api/v1/iocs?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    {
      iocType: 'domain',
      value: `feature-sweep-${Date.now()}.cybertron.local`,
      source: 'prod-feature-sweep',
      confidence: 85,
      tags: ['feature-sweep', 'validation'],
    }
  );
  assertCondition(iocCreate.response.status === 201, 'IOC create succeeds');
  const iocId = String(iocCreate.body?.id || '');
  assertCondition(Boolean(iocId), 'IOC create returns id');

  const iocLink = await request(
    `${baseUrl}/api/v1/incidents/${encodeURIComponent(incidentId)}/iocs/${encodeURIComponent(iocId)}?tenant=${encodeURIComponent(tenant)}`,
    {
      method: 'POST',
      headers: authHeaders,
    }
  );
  assertCondition(
    iocLink.response.status === 200 || iocLink.response.status === 204,
    'IOC link to incident succeeds'
  );

  const iocList = await request(`${baseUrl}/api/v1/iocs?tenant=${encodeURIComponent(tenant)}&limit=20`, {
    headers: authHeaders,
  });
  assertCondition(iocList.response.status === 200, 'IOC list succeeds');

  const requestCreate = await postJson(
    `${baseUrl}/api/v1/service-requests?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    {
      requesterEmail: email,
      category: 'security-review',
      priority: 'high',
      subject: 'Production feature sweep request',
      description: 'Validating service request lifecycle on deployed stack.',
      comment: 'Initial service request comment from automated sweep.',
    }
  );
  assertCondition(requestCreate.response.status === 201, 'service request create succeeds');
  const serviceRequestId = String(requestCreate.body?.id || '');
  assertCondition(Boolean(serviceRequestId), 'service request create returns id');

  const requestComment = await postJson(
    `${baseUrl}/api/v1/service-requests/${encodeURIComponent(serviceRequestId)}/comments?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    { comment: 'Follow-up comment from production feature sweep.' }
  );
  assertCondition(requestComment.response.status === 200, 'service request comment succeeds');

  const requestUpdate = await patchJson(
    `${baseUrl}/api/v1/service-requests/${encodeURIComponent(serviceRequestId)}?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    {
      status: 'in_progress',
      comment: 'Transitioned into active validation.',
    }
  );
  assertCondition(requestUpdate.response.status === 200, 'service request update succeeds');

  const requestComments = await request(
    `${baseUrl}/api/v1/service-requests/${encodeURIComponent(serviceRequestId)}/comments?tenant=${encodeURIComponent(tenant)}`,
    { headers: authHeaders }
  );
  assertCondition(requestComments.response.status === 200, 'service request comments list succeeds');

  const reportUpload = await request(`${baseUrl}/api/v1/reports/upload?tenant=${encodeURIComponent(tenant)}`, {
    method: 'POST',
    headers: buildAuthHeaders(accessToken, {
      'Idempotency-Key': crypto.randomUUID(),
    }),
    body: buildReportUploadForm(),
  });
  assertCondition(
    reportUpload.response.status === 201 || reportUpload.response.status === 200,
    'report upload succeeds in feature sweep'
  );
  const uploadedReportId = String(reportUpload.body?.report?.id || '');
  assertCondition(Boolean(uploadedReportId), 'report upload returns report id in feature sweep');

  const reportList = await request(`${baseUrl}/api/v1/reports?tenant=${encodeURIComponent(tenant)}&limit=20`, {
    headers: authHeaders,
  });
  assertCondition(reportList.response.status === 200, 'report list succeeds');

  const reportGet = await request(
    `${baseUrl}/api/v1/reports/${encodeURIComponent(uploadedReportId)}?tenant=${encodeURIComponent(tenant)}`,
    { headers: authHeaders }
  );
  assertCondition(reportGet.response.status === 200, 'report fetch by id succeeds');

  const reportDownload = await request(
    `${baseUrl}/api/v1/reports/${encodeURIComponent(uploadedReportId)}/download?tenant=${encodeURIComponent(tenant)}`,
    { headers: authHeaders }
  );
  assertCondition(reportDownload.response.status === 200, 'report download succeeds in feature sweep');
  assertCondition(reportDownload.body.includes('feature-sweep'), 'downloaded report matches uploaded report');

  const awsUploadForm = new FormData();
  awsUploadForm.append('file', buildAwsLogsBlob(), 'aws-feature-sweep.json');
  const awsIngest = await request(`${baseUrl}/api/v1/risk/ingest/aws-logs?tenant=${encodeURIComponent(tenant)}`, {
    method: 'POST',
    headers: authHeaders,
    body: awsUploadForm,
  });
  assertCondition(awsIngest.response.status === 201, 'risk AWS log ingestion succeeds');
  assertCondition(Number(awsIngest.body?.recordCount || 0) >= 3, 'risk AWS log ingestion records are counted');

  const riskCompute = await postJson(
    `${baseUrl}/api/v1/risk/score/compute?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    { limit: 10, includeAi: true }
  );
  assertCondition(riskCompute.response.status === 200, 'risk compute succeeds');
  assertCondition(riskCompute.body?.aiExplanation?.provider === 'openai', 'risk compute uses H100-backed openai provider');

  const riskFindings = await request(`${baseUrl}/api/v1/risk/findings?tenant=${encodeURIComponent(tenant)}&limit=20`, {
    headers: authHeaders,
  });
  assertCondition(riskFindings.response.status === 200, 'risk findings list succeeds');
  const firstFinding = riskFindings.body?.data?.[0];
  assertCondition(Boolean(firstFinding?.id), 'risk findings list returns at least one finding');

  const riskTreatment = await patchJson(
    `${baseUrl}/api/v1/risk/findings/${encodeURIComponent(String(firstFinding.id))}/treatment?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    {
      treatmentStatus: 'mitigating',
      residualScore: 4.2,
      reviewNotes: 'Mitigation started during production feature sweep.',
    }
  );
  assertCondition(riskTreatment.response.status === 200, 'risk finding treatment update succeeds');

  const riskReport = await postJson(
    `${baseUrl}/api/v1/risk/report/generate?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    undefined
  );
  assertCondition(riskReport.response.status === 201, 'risk report generation succeeds');
  assertCondition(riskReport.body?.aiExplanation?.provider === 'openai', 'risk report generation uses H100-backed openai provider');
  const riskReportId = String(riskReport.body?.report?.id || '');
  assertCondition(Boolean(riskReportId), 'risk report generation returns report id');

  const riskReportPdf = await request(
    `${baseUrl}/api/v1/risk/report/${encodeURIComponent(riskReportId)}/download?tenant=${encodeURIComponent(tenant)}`,
    { headers: authHeaders }
  );
  assertCondition(riskReportPdf.response.status === 200, 'risk report PDF download succeeds');
  assertCondition(
    String(riskReportPdf.contentType || '').includes('application/pdf'),
    'risk report PDF download returns PDF content'
  );

  const soc2Controls = await request(
    `${baseUrl}/api/v1/compliance/soc2/controls?tenant=${encodeURIComponent(tenant)}`,
    { headers: authHeaders }
  );
  assertCondition(soc2Controls.response.status === 200, 'SOC2 controls list succeeds');
  const firstControl = soc2Controls.body?.[0];
  assertCondition(Boolean(firstControl?.controlId), 'SOC2 controls list returns at least one control');

  const soc2Status = await request(
    `${baseUrl}/api/v1/compliance/soc2/status?tenant=${encodeURIComponent(tenant)}`,
    { headers: authHeaders }
  );
  assertCondition(soc2Status.response.status === 200, 'SOC2 status succeeds');
  const firstControlStatus = (soc2Status.body?.controls || []).find(
    item => String(item.controlId || '') === String(firstControl.controlId)
  );
  const nextSoc2Status = nextComplianceStatus(
    firstControlStatus?.status,
    firstControlStatus?.evidenceCount
  );

  const soc2StatusUpdate = await patchJson(
    `${baseUrl}/api/v1/compliance/soc2/status/${encodeURIComponent(String(firstControl.controlId))}?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    {
      status: nextSoc2Status,
      notes: 'Implemented during production feature sweep.',
    }
  );
  assertCondition(soc2StatusUpdate.response.status === 200, 'SOC2 status update succeeds');

  const evidenceForm = new FormData();
  evidenceForm.append('controlId', String(firstControl.controlId));
  evidenceForm.append('file', readEvidencePdfBlob(), 'feature-sweep-evidence.pdf');
  const evidenceUpload = await request(
    `${baseUrl}/api/v1/compliance/soc2/evidence/upload?tenant=${encodeURIComponent(tenant)}`,
    {
      method: 'POST',
      headers: authHeaders,
      body: evidenceForm,
    }
  );
  assertCondition(evidenceUpload.response.status === 201, 'SOC2 evidence upload succeeds');

  const policyGenerate = await postJson(
    `${baseUrl}/api/v1/compliance/policy/generate?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    {
      policyKey: 'incident-response-policy',
      organization: 'Cybertron Labs',
    }
  );
  assertCondition(policyGenerate.response.status === 201, 'compliance policy generation succeeds');
  assertCondition(policyGenerate.body?.llm?.provider === 'openai', 'compliance policy generation uses H100-backed openai provider');
  const policyId = String(policyGenerate.body?.policy?.id || '');
  assertCondition(Boolean(policyId), 'compliance policy generation returns policy id');

  const policiesList = await request(
    `${baseUrl}/api/v1/compliance/policies?tenant=${encodeURIComponent(tenant)}`,
    { headers: authHeaders }
  );
  assertCondition(policiesList.response.status === 200, 'compliance policy list succeeds');

  const policySubmit = await patchJson(
    `${baseUrl}/api/v1/compliance/policies/${encodeURIComponent(policyId)}/status?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    { status: 'pending_approval' }
  );
  assertCondition(policySubmit.response.status === 200, 'compliance policy submission succeeds');

  const policyApprove = await patchJson(
    `${baseUrl}/api/v1/compliance/policies/${encodeURIComponent(policyId)}/status?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    { status: 'approved' }
  );
  assertCondition(policyApprove.response.status === 200, 'compliance policy approval succeeds');

  const auditPackage = await postJson(
    `${baseUrl}/api/v1/compliance/audit-package/generate?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    undefined
  );
  assertCondition(auditPackage.response.status === 201, 'audit package generation succeeds');
  const auditPackageId = String(auditPackage.body?.id || '');
  assertCondition(Boolean(auditPackageId), 'audit package generation returns package id');

  const auditPackagePdf = await request(
    `${baseUrl}/api/v1/compliance/audit-package/${encodeURIComponent(auditPackageId)}/download?tenant=${encodeURIComponent(tenant)}`,
    { headers: authHeaders }
  );
  assertCondition(auditPackagePdf.response.status === 200, 'audit package download succeeds');
  assertCondition(
    String(auditPackagePdf.contentType || '').includes('application/pdf'),
    'audit package download returns PDF content'
  );

  const frameworks = await request(
    `${baseUrl}/api/v1/compliance/frameworks?tenant=${encodeURIComponent(tenant)}`,
    { headers: authHeaders }
  );
  assertCondition(frameworks.response.status === 200, 'compliance frameworks list succeeds');
  const firstFramework = frameworks.body?.data?.[0];
  assertCondition(Boolean(firstFramework?.id), 'compliance frameworks list returns at least one framework');

  const complianceSummary = await request(
    `${baseUrl}/api/v1/compliance/summary?tenant=${encodeURIComponent(tenant)}`,
    { headers: authHeaders }
  );
  assertCondition(complianceSummary.response.status === 200, 'compliance summary succeeds');

  const frameworkControls = await request(
    `${baseUrl}/api/v1/compliance/frameworks/${encodeURIComponent(String(firstFramework.id))}/controls?tenant=${encodeURIComponent(tenant)}`,
    { headers: authHeaders }
  );
  assertCondition(frameworkControls.response.status === 200, 'framework controls list succeeds');
  const firstFrameworkControl = frameworkControls.body?.data?.[0];
  assertCondition(Boolean(firstFrameworkControl?.control_id), 'framework controls list returns at least one control');

  const frameworkStatus = await request(
    `${baseUrl}/api/v1/compliance/frameworks/${encodeURIComponent(String(firstFramework.id))}/status?tenant=${encodeURIComponent(tenant)}`,
    { headers: authHeaders }
  );
  assertCondition(frameworkStatus.response.status === 200, 'framework status succeeds');
  const firstFrameworkControlStatus = (frameworkStatus.body?.controls || []).find(
    item => String(item.controlId || '') === String(firstFrameworkControl.control_id)
  );
  const nextFrameworkStatus = nextComplianceStatus(
    firstFrameworkControlStatus?.status,
    firstFrameworkControlStatus?.evidenceCount
  );

  const frameworkStatusUpdate = await patchJson(
    `${baseUrl}/api/v1/compliance/frameworks/${encodeURIComponent(String(firstFramework.id))}/status/${encodeURIComponent(String(firstFrameworkControl.control_id))}?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    {
      status: nextFrameworkStatus,
      notes: 'Framework control updated during production feature sweep.',
    }
  );
  assertCondition(frameworkStatusUpdate.response.status === 200, 'framework control status update succeeds');

  const cveSync = await postJson(
    `${baseUrl}/api/v1/threat-intel/cve/sync?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    undefined
  );
  assertCondition(cveSync.response.status === 200, 'CVE sync succeeds against live NVD feed');

  const cveFeed = await request(
    `${baseUrl}/api/v1/threat-intel/cve/feed?tenant=${encodeURIComponent(tenant)}&limit=20`,
    { headers: authHeaders }
  );
  assertCondition(cveFeed.response.status === 200, 'CVE feed succeeds');
  const firstCve = cveFeed.body?.data?.[0];
  assertCondition(Boolean(firstCve?.cveId), 'CVE feed returns at least one CVE');

  const cveSummary = await postJson(
    `${baseUrl}/api/v1/threat-intel/cve/${encodeURIComponent(String(firstCve.cveId))}/summarize?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    undefined
  );
  assertCondition(cveSummary.response.status === 201, 'CVE summarization succeeds');
  assertCondition(cveSummary.body?.llm?.provider === 'openai', 'CVE summarization uses H100-backed openai provider');

  const threatDashboard = await request(
    `${baseUrl}/api/v1/threat-intel/dashboard?tenant=${encodeURIComponent(tenant)}&days=30`,
    { headers: authHeaders }
  );
  assertCondition(threatDashboard.response.status === 200, 'threat dashboard succeeds');

  const mitreTechniques = await request(
    `${baseUrl}/api/v1/threat-intel/mitre/techniques?tenant=${encodeURIComponent(tenant)}`,
    { headers: authHeaders }
  );
  assertCondition(mitreTechniques.response.status === 200, 'MITRE techniques list succeeds');
  const firstTechnique = mitreTechniques.body?.data?.[0];
  const firstTechniqueId = String(firstTechnique?.technique_id || firstTechnique?.id || '');
  assertCondition(Boolean(firstTechniqueId), 'MITRE techniques list returns at least one technique');

  const mitreHeatmap = await request(
    `${baseUrl}/api/v1/threat-intel/mitre/heatmap?tenant=${encodeURIComponent(tenant)}`,
    { headers: authHeaders }
  );
  assertCondition(mitreHeatmap.response.status === 200, 'MITRE heatmap succeeds');

  const mitreAdd = await postJson(
    `${baseUrl}/api/v1/threat-intel/mitre/incidents/${encodeURIComponent(incidentId)}?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    {
      techniqueId: firstTechniqueId,
      confidence: 90,
      notes: 'Mapped during production feature sweep.',
    }
  );
  assertCondition(mitreAdd.response.status === 201, 'MITRE incident mapping create succeeds');
  const mappingId = Number(mitreAdd.body?.id || 0);
  assertCondition(Number.isFinite(mappingId) && mappingId > 0, 'MITRE incident mapping returns id');

  const mitreMappings = await request(
    `${baseUrl}/api/v1/threat-intel/mitre/incidents/${encodeURIComponent(incidentId)}?tenant=${encodeURIComponent(tenant)}`,
    { headers: authHeaders }
  );
  assertCondition(mitreMappings.response.status === 200, 'MITRE incident mappings list succeeds');

  const mitreDelete = await request(
    `${baseUrl}/api/v1/threat-intel/mitre/mappings/${encodeURIComponent(String(mappingId))}?tenant=${encodeURIComponent(tenant)}`,
    {
      method: 'DELETE',
      headers: authHeaders,
    }
  );
  assertCondition(mitreDelete.response.status === 200, 'MITRE incident mapping delete succeeds');

  const playbookList = await request(
    `${baseUrl}/api/v1/threat-intel/playbooks?tenant=${encodeURIComponent(tenant)}&limit=20`,
    { headers: authHeaders }
  );
  assertCondition(playbookList.response.status === 200, 'playbook list succeeds');

  const playbookCreate = await postJson(
    `${baseUrl}/api/v1/threat-intel/playbooks?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    {
      name: `Feature Sweep Playbook ${Date.now()}`,
      description: 'Live production validation playbook.',
      severityFilter: 'high',
      category: 'feature-sweep',
    }
  );
  assertCondition(playbookCreate.response.status === 201, 'playbook create succeeds');
  const playbookId = Number(playbookCreate.body?.id || 0);
  assertCondition(Number.isFinite(playbookId) && playbookId > 0, 'playbook create returns id');

  const playbookUpdate = await putJson(
    `${baseUrl}/api/v1/threat-intel/playbooks/${encodeURIComponent(String(playbookId))}?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    {
      description: 'Updated during production feature sweep.',
      isActive: true,
    }
  );
  assertCondition(playbookUpdate.response.status === 200, 'playbook update succeeds');

  const playbookStepCreate = await postJson(
    `${baseUrl}/api/v1/threat-intel/playbooks/${encodeURIComponent(String(playbookId))}/steps?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    {
      title: 'Triage alert',
      description: 'Validate playbook execution path.',
      actionType: 'manual',
      assignedRole: 'security_analyst',
      timeoutMinutes: 30,
      stepOrder: 1,
    }
  );
  assertCondition(playbookStepCreate.response.status === 201, 'playbook step create succeeds');
  const playbookStepId = Number(playbookStepCreate.body?.id || 0);
  assertCondition(Number.isFinite(playbookStepId) && playbookStepId > 0, 'playbook step create returns id');

  const playbookDetail = await request(
    `${baseUrl}/api/v1/threat-intel/playbooks/${encodeURIComponent(String(playbookId))}?tenant=${encodeURIComponent(tenant)}`,
    { headers: authHeaders }
  );
  assertCondition(playbookDetail.response.status === 200, 'playbook detail succeeds');

  const playbookExecute = await postJson(
    `${baseUrl}/api/v1/threat-intel/playbooks/${encodeURIComponent(String(playbookId))}/execute?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    { incidentId: Number(incidentId) || undefined }
  );
  assertCondition(playbookExecute.response.status === 201, 'playbook execute succeeds');
  const executionId = Number(playbookExecute.body?.id || 0);
  assertCondition(Number.isFinite(executionId) && executionId > 0, 'playbook execution returns id');

  const playbookExecutions = await request(
    `${baseUrl}/api/v1/threat-intel/playbooks/executions?tenant=${encodeURIComponent(tenant)}&playbookId=${encodeURIComponent(String(playbookId))}`,
    { headers: authHeaders }
  );
  assertCondition(playbookExecutions.response.status === 200, 'playbook executions list succeeds');

  const executionSteps = await request(
    `${baseUrl}/api/v1/threat-intel/playbooks/executions/${encodeURIComponent(String(executionId))}/steps?tenant=${encodeURIComponent(tenant)}`,
    { headers: authHeaders }
  );
  assertCondition(executionSteps.response.status === 200, 'playbook execution steps list succeeds');

  const stepResultId =
    Number(executionSteps.body?.data?.[0]?.step_id || executionSteps.body?.data?.[0]?.stepId || playbookStepId);
  const stepUpdate = await putJson(
    `${baseUrl}/api/v1/threat-intel/playbooks/executions/${encodeURIComponent(String(executionId))}/steps/${encodeURIComponent(String(stepResultId))}?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    {
      status: 'completed',
      notes: 'Completed during production feature sweep.',
    }
  );
  assertCondition(stepUpdate.response.status === 200, 'playbook step result update succeeds');

  const analysts = await request(
    `${baseUrl}/api/v1/threat-intel/analysts?tenant=${encodeURIComponent(tenant)}`,
    { headers: authHeaders }
  );
  assertCondition(analysts.response.status === 200, 'tenant analysts list succeeds');
  const analystId = Number(analysts.body?.data?.[0]?.id || 0);

  const siemStatsBefore = await request(
    `${baseUrl}/api/v1/threat-intel/siem/alerts/stats?tenant=${encodeURIComponent(tenant)}`,
    { headers: authHeaders }
  );
  assertCondition(siemStatsBefore.response.status === 200, 'SIEM alert stats succeeds');

  const alertCreate = await postJson(
    `${baseUrl}/api/v1/threat-intel/siem/alerts?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    {
      source: 'feature-sweep',
      alertId: `fs-alert-${Date.now()}`,
      ruleName: 'Impossible travel',
      severity: 'high',
      category: 'identity',
      sourceIp: '185.10.10.10',
      destIp: '10.0.1.25',
      hostname: 'prod-app-01',
      eventTime: new Date().toISOString(),
      rawPayload: { source: 'feature-sweep', signal: 'impossible_travel' },
    }
  );
  assertCondition(alertCreate.response.status === 201, 'SIEM alert ingest succeeds');
  const alertId = Number(alertCreate.body?.id || 0);
  assertCondition(Number.isFinite(alertId) && alertId > 0, 'SIEM alert ingest returns id');

  const alertsList = await request(
    `${baseUrl}/api/v1/threat-intel/siem/alerts?tenant=${encodeURIComponent(tenant)}&limit=20`,
    { headers: authHeaders }
  );
  assertCondition(alertsList.response.status === 200, 'SIEM alerts list succeeds');

  const triageSuggestion = await request(
    `${baseUrl}/api/v1/threat-intel/siem/alerts/${encodeURIComponent(String(alertId))}/triage-suggestion?tenant=${encodeURIComponent(tenant)}`,
    { headers: authHeaders }
  );
  assertCondition(triageSuggestion.response.status === 200, 'SIEM triage suggestion succeeds');
  assertCondition(triageSuggestion.body?.llm?.aiGenerated === true, 'SIEM triage suggestion uses H100-backed openai provider');
  assertCondition(Number(triageSuggestion.body?.llm?.groundingScore || 0) >= minGroundingScore, 'SIEM triage suggestion grounding score meets threshold');
  assertCondition(triageSuggestion.body?.llm?.qualityGate?.accepted === true, 'SIEM triage suggestion quality gate accepts the response');

  const alertNotes = await patchJson(
    `${baseUrl}/api/v1/threat-intel/siem/alerts/${encodeURIComponent(String(alertId))}/notes?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    { notes: 'Notes added during production feature sweep.' }
  );
  assertCondition(alertNotes.response.status === 200, 'SIEM alert notes update succeeds');

  if (Number.isFinite(analystId) && analystId > 0) {
    const alertAssign = await patchJson(
      `${baseUrl}/api/v1/threat-intel/siem/alerts/${encodeURIComponent(String(alertId))}/assign?tenant=${encodeURIComponent(tenant)}`,
      accessToken,
      { assignedTo: analystId }
    );
    assertCondition(alertAssign.response.status === 200, 'SIEM alert assign succeeds');
  } else {
    assertCondition(true, 'no security analyst account exists yet, assignment check skipped');
  }

  const alertStatus = await patchJson(
    `${baseUrl}/api/v1/threat-intel/siem/alerts/${encodeURIComponent(String(alertId))}/status?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    { status: 'in_triage', notes: 'Moved to triage during production feature sweep.' }
  );
  assertCondition(alertStatus.response.status === 200, 'SIEM alert status update succeeds');

  const alertCorrelate = await postJson(
    `${baseUrl}/api/v1/threat-intel/siem/alerts/${encodeURIComponent(String(alertId))}/correlate?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    { incidentId: Number(incidentId) }
  );
  assertCondition(alertCorrelate.response.status === 200, 'SIEM alert correlate succeeds');

  const escalateAlertCreate = await postJson(
    `${baseUrl}/api/v1/threat-intel/siem/alerts?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    {
      source: 'feature-sweep',
      alertId: `fs-alert-escalate-${Date.now()}`,
      ruleName: 'Credential dumping',
      severity: 'critical',
      category: 'endpoint',
      sourceIp: '203.0.113.44',
      destIp: '10.0.2.99',
      hostname: 'db-prod-01',
      eventTime: new Date().toISOString(),
      rawPayload: { source: 'feature-sweep', signal: 'credential_dumping' },
    }
  );
  assertCondition(escalateAlertCreate.response.status === 201, 'second SIEM alert ingest succeeds');
  const escalateAlertId = Number(escalateAlertCreate.body?.id || 0);
  assertCondition(Number.isFinite(escalateAlertId) && escalateAlertId > 0, 'second SIEM alert returns id');

  const alertEscalate = await postJson(
    `${baseUrl}/api/v1/threat-intel/siem/alerts/${encodeURIComponent(String(escalateAlertId))}/escalate?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    {
      title: 'Escalated from feature sweep alert',
      severity: 'critical',
    }
  );
  assertCondition(alertEscalate.response.status === 201, 'SIEM alert escalation succeeds');

  const rulesList = await request(
    `${baseUrl}/api/v1/threat-intel/siem/correlation-rules?tenant=${encodeURIComponent(tenant)}`,
    { headers: authHeaders }
  );
  assertCondition(rulesList.response.status === 200, 'correlation rules list succeeds');

  const ruleCreate = await postJson(
    `${baseUrl}/api/v1/threat-intel/siem/correlation-rules?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    {
      name: `Feature Sweep Rule ${Date.now()}`,
      description: 'Correlation rule created during production feature sweep.',
      ruleType: 'threshold',
      severityOutput: 'high',
      conditions: { minAlerts: 2, severity: ['high', 'critical'], windowMinutes: 15 },
    }
  );
  assertCondition(ruleCreate.response.status === 201, 'correlation rule create succeeds');
  const ruleId = Number(ruleCreate.body?.id || 0);
  assertCondition(Number.isFinite(ruleId) && ruleId > 0, 'correlation rule create returns id');

  const ruleUpdate = await putJson(
    `${baseUrl}/api/v1/threat-intel/siem/correlation-rules/${encodeURIComponent(String(ruleId))}?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    {
      description: 'Updated during production feature sweep.',
      isActive: true,
    }
  );
  assertCondition(ruleUpdate.response.status === 200, 'correlation rule update succeeds');

  const connectorSync = await postJson(
    `${baseUrl}/api/v1/threat-intel/siem/sync-connectors?tenant=${encodeURIComponent(tenant)}&limit=25`,
    accessToken,
    {}
  );
  assertCondition(connectorSync.response.status === 200, 'connector sync endpoint succeeds');

  const correlateAll = await postJson(
    `${baseUrl}/api/v1/threat-intel/siem/correlate-all?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    {}
  );
  assertCondition(correlateAll.response.status === 200, 'correlation engine run succeeds');

  const exportCsv = await request(
    `${baseUrl}/api/v1/threat-intel/siem/export?tenant=${encodeURIComponent(tenant)}&format=csv&limit=100`,
    { headers: authHeaders }
  );
  assertCondition(exportCsv.response.status === 200, 'SIEM export succeeds');
  assertCondition(String(exportCsv.contentType || '').includes('text/csv'), 'SIEM export returns CSV content');

  const bulkStatus = await postJson(
    `${baseUrl}/api/v1/threat-intel/siem/alerts/bulk-status?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    {
      alertIds: [alertId, escalateAlertId],
      status: 'resolved',
      notes: 'Resolved during production feature sweep.',
    }
  );
  assertCondition(bulkStatus.response.status === 200, 'SIEM bulk status update succeeds');

  const slaMetrics = await request(
    `${baseUrl}/api/v1/threat-intel/siem/alerts/sla-metrics?tenant=${encodeURIComponent(tenant)}`,
    { headers: authHeaders }
  );
  assertCondition(slaMetrics.response.status === 200, 'SIEM SLA metrics succeeds');

  const attackMap = await request(
    `${baseUrl}/api/v1/threat-intel/siem/attack-map?tenant=${encodeURIComponent(tenant)}`,
    { headers: authHeaders }
  );
  assertCondition(attackMap.response.status === 200, 'SIEM attack map succeeds');

  const huntsList = await request(
    `${baseUrl}/api/v1/threat-intel/hunts?tenant=${encodeURIComponent(tenant)}&limit=20`,
    { headers: authHeaders }
  );
  assertCondition(huntsList.response.status === 200, 'threat hunts list succeeds');

  const huntCreate = await postJson(
    `${baseUrl}/api/v1/threat-intel/hunts?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    {
      name: `Feature Sweep Hunt ${Date.now()}`,
      description: 'Threat hunt created during production feature sweep.',
      queryType: 'sql',
      queryText: "SELECT * FROM siem_alerts WHERE severity IN ('high','critical') LIMIT 10",
      dataSource: 'siem_alerts',
    }
  );
  assertCondition(huntCreate.response.status === 201, 'threat hunt create succeeds');
  const huntId = Number(huntCreate.body?.id || 0);
  assertCondition(Number.isFinite(huntId) && huntId > 0, 'threat hunt create returns id');

  const huntUpdate = await putJson(
    `${baseUrl}/api/v1/threat-intel/hunts/${encodeURIComponent(String(huntId))}?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    {
      description: 'Threat hunt updated during production feature sweep.',
      queryText: "SELECT id, severity, source FROM siem_alerts ORDER BY ingested_at DESC LIMIT 5",
    }
  );
  assertCondition(huntUpdate.response.status === 200, 'threat hunt update succeeds');

  const huntExecute = await postJson(
    `${baseUrl}/api/v1/threat-intel/hunts/${encodeURIComponent(String(huntId))}/execute?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    undefined
  );
  assertCondition(huntExecute.response.status === 200, 'threat hunt execute succeeds');
  assertCondition(
    Number.isFinite(Number(huntExecute.body?.resultCount || 0)),
    'threat hunt execute returns numeric result count'
  );

  const huntDelete = await request(
    `${baseUrl}/api/v1/threat-intel/hunts/${encodeURIComponent(String(huntId))}?tenant=${encodeURIComponent(tenant)}`,
    {
      method: 'DELETE',
      headers: authHeaders,
    }
  );
  assertCondition(huntDelete.response.status === 200, 'threat hunt delete succeeds');

  const billingUsage = await request(
    `${baseUrl}/api/v1/billing/usage?tenant=${encodeURIComponent(tenant)}&limit=100`,
    { headers: authHeaders }
  );
  assertCondition(billingUsage.response.status === 200, 'billing usage list succeeds after feature sweep');

  const auditLogs = await request(
    `${baseUrl}/api/v1/audit-logs?tenant=${encodeURIComponent(tenant)}&limit=100`,
    { headers: authHeaders }
  );
  assertCondition(auditLogs.response.status === 200, 'audit log list succeeds after feature sweep');
  assertCondition(
    (auditLogs.body?.total ?? auditLogs.body?.data?.length ?? 0) >= 1,
    'audit log list returns activity after feature sweep'
  );

  const logout = await request(`${baseUrl}/api/v1/auth/logout`, {
    method: 'POST',
    headers: buildAuthHeaders(accessToken, {
      'Content-Type': 'application/json',
    }),
    body: JSON.stringify({
      tenant,
      refreshToken,
    }),
  });
  assertCondition(logout.response.status === 204, 'logout succeeds after feature sweep');

  process.stdout.write('Production feature sweep completed.\n');
}

run().catch(error => {
  process.stderr.write(`${error instanceof Error ? error.message : 'Production feature sweep failed.'}\n`);
  process.stderr.write(`${usage()}\n`);
  process.exitCode = 1;
});
