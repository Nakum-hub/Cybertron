#!/usr/bin/env node

const crypto = require('node:crypto');
const { findComposeServiceContainer, readContainerEnv } = require('./docker-compose-runtime');

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
    '  node scripts/prod-stack-smoke.js --password <admin-password> --metrics-token <token> [options]',
    '',
    'Options:',
    '  --base-url <value>     Public base URL (default: http://127.0.0.1:8088)',
    '  --email <value>        Admin email (default: admin@cybertron.local)',
    '  --tenant <value>       Tenant slug (default: global)',
    '  --expect-storage-provider <value>  Assert uploaded reports use this storage provider (e.g. local, s3)',
  ].join('\n');
}

function assertCondition(condition, label) {
  if (!condition) {
    throw new Error(`Assertion failed: ${label}`);
  }

  process.stdout.write(`PASS: ${label}\n`);
}

async function requestJson(url, init = {}) {
  const response = await fetch(url, init);
  const text = await response.text();
  let body = null;

  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
  }

  return { response, body };
}

function buildReportUploadForm() {
  const reportContent = `date,severity,signal\n${new Date().toISOString()},high,docker-smoke\n`;
  const form = new FormData();
  form.append('file', new Blob([reportContent], { type: 'text/csv' }), 'docker-smoke.csv');
  form.append('reportType', 'docker_smoke');
  form.append('reportDate', new Date().toISOString().slice(0, 10));
  form.append('metadata', JSON.stringify({ source: 'prod-stack-smoke' }));
  return form;
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
  const expectedStorageProvider = String(args['expect-storage-provider'] || process.env.CYBERTRON_EXPECT_STORAGE_PROVIDER || '').trim().toLowerCase();
  let metricsToken = String(args['metrics-token'] || process.env.METRICS_AUTH_TOKEN || '');

  if (!metricsToken) {
    try {
      const backendContainer = findComposeServiceContainer('backend');
      const containerEnv = readContainerEnv(backendContainer);
      metricsToken = String(containerEnv.METRICS_AUTH_TOKEN || '');
    } catch {
      // fall through to explicit validation below
    }
  }

  if (password.length < 10) {
    throw new Error('A real admin password is required.');
  }

  if (!metricsToken) {
    throw new Error('A real metrics bearer token is required.');
  }

  const login = await requestJson(`${baseUrl}/api/v1/auth/login`, {
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
  assertCondition(login.response.status === 200, 'password login succeeds through frontend proxy');

  const accessToken = login.body?.tokens?.accessToken || '';
  const refreshToken = login.body?.tokens?.refreshToken || '';
  assertCondition(Boolean(accessToken), 'login returns access token');
  assertCondition(Boolean(refreshToken), 'login returns refresh token');

  const authHeaders = {
    Authorization: `Bearer ${accessToken}`,
  };

  const me = await requestJson(`${baseUrl}/api/v1/auth/me`, {
    headers: authHeaders,
  });
  assertCondition(me.response.status === 200, 'auth me succeeds through proxy');
  assertCondition(String(me.body?.email || '').toLowerCase() === email, 'auth me returns bootstrapped admin email');

  const fullHealth = await requestJson(`${baseUrl}/api/v1/system/health`, {
    headers: authHeaders,
  });
  assertCondition(fullHealth.response.status === 200, 'authenticated health succeeds through proxy');
  assertCondition(typeof fullHealth.body?.version === 'string', 'authenticated health returns full payload');
  assertCondition(fullHealth.body?.dependencies?.storage?.status === 'healthy', 'storage dependency is healthy in authenticated health payload');

  const threatSummary = await requestJson(`${baseUrl}/api/v1/threats/summary?tenant=${encodeURIComponent(tenant)}`, {
    headers: authHeaders,
  });
  assertCondition(threatSummary.response.status === 200, 'threat summary succeeds through proxy');
  assertCondition(Number.isFinite(threatSummary.body?.activeThreats), 'threat summary returns numeric fields');

  const platformApps = await requestJson(`${baseUrl}/api/v1/platform/apps?tenant=${encodeURIComponent(tenant)}`, {
    headers: authHeaders,
  });
  assertCondition(platformApps.response.status === 200, 'platform apps succeeds through proxy');
  assertCondition(Array.isArray(platformApps.body), 'platform apps returns array');
  assertCondition(platformApps.body.length >= 1, 'platform apps returns at least one enabled app');

  const moduleRegistry = await requestJson(`${baseUrl}/api/v1/modules?tenant=${encodeURIComponent(tenant)}`, {
    headers: authHeaders,
  });
  assertCondition(moduleRegistry.response.status === 200, 'module registry succeeds through proxy');
  assertCondition(Array.isArray(moduleRegistry.body?.modules), 'module registry returns modules array');
  assertCondition(Array.isArray(moduleRegistry.body?.apps), 'module registry returns apps array');

  const accessibleModuleIds = new Set(
    (moduleRegistry.body?.apps || [])
      .map(app => String(app?.moduleId || '').trim().toLowerCase())
      .filter(Boolean)
  );
  assertCondition(accessibleModuleIds.size >= 1, 'module registry exposes at least one accessible module');

  for (const moduleId of accessibleModuleIds) {
    const moduleStatus = await requestJson(
      `${baseUrl}/api/v1/modules/${encodeURIComponent(moduleId)}/status?tenant=${encodeURIComponent(tenant)}`,
      {
        headers: authHeaders,
      }
    );
    assertCondition(moduleStatus.response.status === 200, `module status succeeds for ${moduleId}`);
    assertCondition(
      typeof moduleStatus.body?.appId === 'string',
      `module status identifies backing app for ${moduleId}`
    );
    assertCondition(typeof moduleStatus.body?.status === 'string', `module status returns runtime state for ${moduleId}`);
  }

  const metrics = await requestJson(`${baseUrl}/api/v1/system/metrics`, {
    headers: {
      Authorization: `Bearer ${metricsToken}`,
    },
  });
  assertCondition(metrics.response.status === 200, 'metrics endpoint accepts bearer token');
  assertCondition(metrics.body?.service === 'cybertron-backend', 'metrics payload identifies backend service');

  const billing = await requestJson(`${baseUrl}/api/v1/billing/credits?tenant=${encodeURIComponent(tenant)}`, {
    headers: authHeaders,
  });
  assertCondition(billing.response.status === 200, 'billing credits succeeds through proxy');
  const currentPlanTier = String(billing.body?.planTier || '').trim().toLowerCase();
  if (currentPlanTier === 'free') {
    assertCondition(true, 'bootstrapped tenant starts on the free plan');

    const blockedResilienceStatus = await requestJson(
      `${baseUrl}/api/v1/apps/resilience-hq/status?tenant=${encodeURIComponent(tenant)}`,
      {
        headers: authHeaders,
      }
    );
    assertCondition(blockedResilienceStatus.response.status === 403, 'starter plan blocks resilience-hq app status');

    const blockedUpload = await requestJson(`${baseUrl}/api/v1/reports/upload?tenant=${encodeURIComponent(tenant)}`, {
      method: 'POST',
      headers: {
        ...authHeaders,
        'Idempotency-Key': crypto.randomUUID(),
      },
      body: buildReportUploadForm(),
    });
    assertCondition(blockedUpload.response.status === 403, 'starter plan blocks report upload through proxy');
    assertCondition(
      blockedUpload.body?.error?.code === 'plan_upgrade_required',
      'starter plan upload denial returns plan upgrade guidance'
    );

    const upgradePlan = await requestJson(`${baseUrl}/api/v1/billing/plan`, {
      method: 'PUT',
      headers: {
        ...authHeaders,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        tenant,
        tier: 'enterprise',
      }),
    });
    assertCondition(upgradePlan.response.status === 200, 'billing plan upgrade succeeds through proxy');
    assertCondition(upgradePlan.body?.tier === 'enterprise', 'billing plan upgrade applies enterprise tier');
  } else {
    assertCondition(
      currentPlanTier === 'enterprise' || currentPlanTier === 'pro',
      'tenant already has a paid plan on repeated production smoke runs'
    );
  }

  const resilienceStatus = await requestJson(
    `${baseUrl}/api/v1/apps/resilience-hq/status?tenant=${encodeURIComponent(tenant)}`,
    {
      headers: authHeaders,
    }
  );
  assertCondition(resilienceStatus.response.status === 200, 'resilience-hq app status succeeds after plan upgrade');

  const upload = await requestJson(`${baseUrl}/api/v1/reports/upload?tenant=${encodeURIComponent(tenant)}`, {
    method: 'POST',
    headers: {
      ...authHeaders,
      'Idempotency-Key': crypto.randomUUID(),
    },
    body: buildReportUploadForm(),
  });
  assertCondition(upload.response.status === 201 || upload.response.status === 200, 'report upload succeeds through proxy after plan upgrade');

  const reportId = upload.body?.report?.id;
  assertCondition(Boolean(reportId), 'report upload returns report id');
  if (expectedStorageProvider) {
    assertCondition(
      String(upload.body?.report?.storageProvider || '').trim().toLowerCase() === expectedStorageProvider,
      `report upload uses ${expectedStorageProvider} storage provider`
    );
  }

  const download = await fetch(`${baseUrl}/api/v1/reports/${encodeURIComponent(String(reportId))}/download?tenant=${encodeURIComponent(tenant)}`, {
    headers: authHeaders,
  });
  const downloadBody = await download.text();
  assertCondition(download.status === 200, 'report download succeeds through proxy');
  assertCondition(downloadBody.includes('docker-smoke'), 'downloaded report matches uploaded file');

  const logout = await requestJson(`${baseUrl}/api/v1/auth/logout`, {
    method: 'POST',
    headers: {
      ...authHeaders,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      refreshToken,
      tenant,
    }),
  });
  assertCondition(logout.response.status === 204, 'logout succeeds through proxy');

  const meAfterLogout = await requestJson(`${baseUrl}/api/v1/auth/me`, {
    headers: authHeaders,
  });
  assertCondition(meAfterLogout.response.status === 401, 'revoked access token is rejected after logout');

  process.stdout.write('Production stack smoke completed.\n');
}

run().catch(error => {
  process.stderr.write(`${error instanceof Error ? error.message : 'Production stack smoke failed.'}\n`);
  process.stderr.write(`${usage()}\n`);
  process.exitCode = 1;
});
