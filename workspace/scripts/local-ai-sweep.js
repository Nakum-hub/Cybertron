#!/usr/bin/env node

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
    '  node scripts/local-ai-sweep.js --email <admin-email> --password <admin-password> --tenant <tenant> [options]',
    '',
    'Options:',
    '  --base-url <value>             Base URL with frontend proxy or backend host (default: http://127.0.0.1:3000)',
    '  --min-grounding-score <value>  Minimum accepted grounding score (default: 60)',
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

async function postJson(url, accessToken, payload) {
  return request(url, {
    method: 'POST',
    headers: buildAuthHeaders(accessToken, {
      'Content-Type': 'application/json',
    }),
    body: payload === undefined ? undefined : JSON.stringify(payload),
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

async function putJson(url, accessToken, payload) {
  return request(url, {
    method: 'PUT',
    headers: buildAuthHeaders(accessToken, {
      'Content-Type': 'application/json',
    }),
    body: JSON.stringify(payload),
  });
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

async function ensureTenantReady(baseUrl, accessToken, tenant) {
  const productsRes = await request(
    `${baseUrl}/api/v1/tenants/${encodeURIComponent(tenant)}/products?role=tenant_admin`,
    { headers: buildAuthHeaders(accessToken) }
  );
  assertCondition(productsRes.response.status === 200, 'tenant products list succeeds for local AI sweep');
  const productKeys = new Set((productsRes.body || []).map(item => String(item.productKey || item.productId || '')));

  for (const productKey of ['threat-command', 'resilience-hq', 'risk-copilot']) {
    assertCondition(productKeys.has(productKey), `product catalog includes ${productKey}`);
    const patchRes = await patchJson(
      `${baseUrl}/api/v1/tenants/${encodeURIComponent(tenant)}/products/${encodeURIComponent(productKey)}`,
      accessToken,
      { enabled: true }
    );
    assertCondition(patchRes.response.status === 200, `tenant product enable succeeds for ${productKey}`);
  }

  const flagsRes = await request(
    `${baseUrl}/api/v1/tenants/${encodeURIComponent(tenant)}/feature-flags`,
    { headers: buildAuthHeaders(accessToken) }
  );
  assertCondition(flagsRes.response.status === 200, 'tenant feature flags list succeeds for local AI sweep');
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
    assertCondition(patchRes.response.status === 200, `tenant feature flag enable succeeds for ${flagKey}`);
  }
}

async function ensureEnterprisePlan(baseUrl, accessToken, tenant) {
  const planRes = await request(
    `${baseUrl}/api/v1/billing/plan?tenant=${encodeURIComponent(tenant)}`,
    { headers: buildAuthHeaders(accessToken) }
  );
  assertCondition(planRes.response.status === 200, 'tenant billing plan lookup succeeds for local AI sweep');

  if (String(planRes.body?.tier || '').toLowerCase() === 'enterprise') {
    process.stdout.write('PASS: tenant billing plan is already enterprise for local AI sweep\n');
    return;
  }

  const planUpdate = await putJson(
    `${baseUrl}/api/v1/billing/plan?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    {
      tenant,
      tier: 'enterprise',
    }
  );
  if (planUpdate.response.status !== 200) {
    const message =
      planUpdate.body?.error?.message ||
      planUpdate.body?.message ||
      'Billing plan upgrade failed.';
    throw new Error(
      `Local AI sweep needs an enterprise-capable session for tenant ${tenant}. ` +
      `Billing plan upgrade returned ${planUpdate.response.status}: ${message}`
    );
  }

  assertCondition(
    String(planUpdate.body?.tier || '').toLowerCase() === 'enterprise',
    'tenant billing plan upgrades to enterprise for local AI sweep'
  );
}

async function run() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help === 'true') {
    process.stdout.write(`${usage()}\n`);
    return;
  }

  const baseUrl = String(args['base-url'] || process.env.CYBERTRON_BASE_URL || 'http://127.0.0.1:3000').replace(/\/+$/, '');
  const email = String(args.email || process.env.CYBERTRON_ADMIN_EMAIL || '').trim().toLowerCase();
  const password = String(args.password || process.env.CYBERTRON_ADMIN_PASSWORD || '');
  const tenant = String(args.tenant || process.env.CYBERTRON_ADMIN_TENANT || '').trim().toLowerCase();
  const minGroundingScore = Math.max(
    0,
    Math.min(100, Number(args['min-grounding-score'] || process.env.CYBERTRON_MIN_GROUNDING_SCORE || 60))
  );

  if (!email || !tenant || password.length < 10) {
    throw new Error('Valid --email, --tenant, and --password arguments are required.');
  }

  const login = await request(`${baseUrl}/api/v1/auth/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      tenant,
      email,
      password,
    }),
  });
  assertCondition(login.response.status === 200, 'local AI sweep login succeeds');
  const accessToken = login.body?.tokens?.accessToken || '';
  assertCondition(Boolean(accessToken), 'local AI sweep login returns access token');

  await ensureEnterprisePlan(baseUrl, accessToken, tenant);
  await ensureTenantReady(baseUrl, accessToken, tenant);

  const runtime = await request(
    `${baseUrl}/api/v1/threat-intel/ai/runtime?tenant=${encodeURIComponent(tenant)}`,
    { headers: buildAuthHeaders(accessToken) }
  );
  assertCondition(runtime.response.status === 200, 'AI runtime endpoint succeeds');
  assertCondition(runtime.body?.reachable === true, 'AI runtime reports reachable local model');
  assertCondition(String(runtime.body?.provider || '') === 'openai', 'AI runtime provider is openai-compatible');
  assertCondition(String(runtime.body?.model || '') === 'cybertron-local', 'AI runtime model is cybertron-local');

  const awsUploadForm = new FormData();
  awsUploadForm.append('file', buildAwsLogsBlob(), 'aws-local-ai-sweep.json');
  const riskIngest = await request(`${baseUrl}/api/v1/risk/ingest/aws-logs?tenant=${encodeURIComponent(tenant)}`, {
    method: 'POST',
    headers: buildAuthHeaders(accessToken),
    body: awsUploadForm,
  });
  assertCondition(riskIngest.response.status === 201, 'risk ingest succeeds for local AI sweep');

  const riskCompute = await postJson(
    `${baseUrl}/api/v1/risk/score/compute?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    { limit: 20, includeAi: true }
  );
  assertCondition(riskCompute.response.status === 200, 'risk AI compute succeeds');
  const riskAi = riskCompute.body?.aiExplanation || {};
  assertCondition(riskAi.aiGenerated === true, 'risk AI compute returns AI-generated analysis');
  assertCondition(Number(riskAi.groundingScore || 0) >= minGroundingScore, 'risk AI grounding score meets threshold');
  assertCondition(riskAi.qualityGate?.accepted === true, 'risk AI quality gate accepts the response');
  assertCondition(
    Array.isArray(riskAi.mitigationSuggestions) && riskAi.mitigationSuggestions.length >= 3,
    'risk AI returns multiple mitigation actions'
  );
  assertCondition(
    String(riskAi.explanation || '').includes('i-prod-web-1') ||
      String(riskAi.explanation || '').includes('iam-role-ci-runner'),
    'risk AI explanation references real ingested asset IDs'
  );

  const soc2Controls = await request(
    `${baseUrl}/api/v1/compliance/soc2/controls?tenant=${encodeURIComponent(tenant)}`,
    { headers: buildAuthHeaders(accessToken) }
  );
  assertCondition(soc2Controls.response.status === 200, 'SOC2 controls list succeeds for local AI sweep');
  const firstControl = soc2Controls.body?.[0];
  assertCondition(Boolean(firstControl?.controlId), 'SOC2 controls list returns at least one control');

  const policyGenerate = await postJson(
    `${baseUrl}/api/v1/compliance/policy/generate?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    {
      policyKey: 'incident-response-policy',
      organization: 'Cybertron Labs',
    }
  );
  assertCondition(policyGenerate.response.status === 201, 'policy generation succeeds');
  const policy = policyGenerate.body?.policy || {};
  const policyLlm = policyGenerate.body?.llm || {};
  assertCondition(policyLlm.aiGenerated === true, 'policy generation returns AI-generated draft');
  assertCondition(Number(policyLlm.groundingScore || 0) >= minGroundingScore, 'policy grounding score meets threshold');
  assertCondition(policyLlm.qualityGate?.accepted === true, 'policy AI quality gate accepts the response');
  assertCondition(String(policy.content || '').includes('Mapped Controls'), 'policy draft includes mapped controls section');
  assertCondition(String(policy.content || '').includes(String(firstControl.controlId)), 'policy draft references real control IDs');

  const cveSync = await postJson(
    `${baseUrl}/api/v1/threat-intel/cve/sync?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    undefined
  );
  assertCondition(cveSync.response.status === 200, 'CVE sync succeeds for local AI sweep');

  const cveFeed = await request(
    `${baseUrl}/api/v1/threat-intel/cve/feed?tenant=${encodeURIComponent(tenant)}&limit=10`,
    { headers: buildAuthHeaders(accessToken) }
  );
  assertCondition(cveFeed.response.status === 200, 'CVE feed succeeds for local AI sweep');
  const firstCve = cveFeed.body?.data?.[0];
  assertCondition(Boolean(firstCve?.cveId), 'CVE feed returns at least one CVE');

  const cveSummary = await postJson(
    `${baseUrl}/api/v1/threat-intel/cve/${encodeURIComponent(firstCve.cveId)}/summarize?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    undefined
  );
  assertCondition(cveSummary.response.status === 201, 'CVE summarize succeeds for local AI sweep');
  const summary = cveSummary.body?.summary || {};
  const summaryLlm = cveSummary.body?.llm || {};
  assertCondition(summaryLlm.aiGenerated === true, 'CVE summarize returns AI-generated result');
  assertCondition(Number(summaryLlm.groundingScore || 0) >= minGroundingScore, 'CVE summary grounding score meets threshold');
  assertCondition(summaryLlm.qualityGate?.accepted === true, 'CVE summary quality gate accepts the response');
  assertCondition(String(summary.summaryText || '').includes(firstCve.cveId), 'CVE summary references the real CVE ID');
  assertCondition(String(summary.summaryText || '').includes('Evidence basis'), 'CVE summary includes evidence basis section');

  process.stdout.write('Local AI sweep completed.\n');
}

run().catch(error => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});
