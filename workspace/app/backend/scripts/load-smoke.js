#!/usr/bin/env node

const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const path = require('node:path');

const backendRoot = path.resolve(__dirname, '..');
const port = Number(process.env.BACKEND_LOAD_TEST_PORT || 8102);
const concurrency = Number(process.env.LOAD_CONCURRENCY || 30);
const DEFAULT_DURATION_MS = 5 * 60 * 1000;
const MIN_DURATION_MS = 5 * 60 * 1000;
const MAX_DURATION_MS = 15 * 60 * 1000;
const allowShortLoad = String(process.env.LOAD_ALLOW_SHORT || 'false').toLowerCase() === 'true';

function clampDurationMs(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return DEFAULT_DURATION_MS;
  }

  if (allowShortLoad) {
    return Math.max(1_000, Math.round(parsed));
  }

  return Math.min(MAX_DURATION_MS, Math.max(MIN_DURATION_MS, Math.round(parsed)));
}

const durationMs = clampDurationMs(process.env.LOAD_DURATION_MS);

function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
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

function buildTenantSlug(prefix = 'load') {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, '-');
}

async function waitForHealth(maxAttempts = 50) {
  const url = `http://127.0.0.1:${port}/v1/system/health`;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        return;
      }
    } catch {
      // backend still starting
    }

    await wait(200);
  }

  throw new Error('Backend did not become healthy in time for load test.');
}

function percentile(values, percentileRank) {
  if (!values.length) {
    return 0;
  }

  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.min(sorted.length - 1, Math.floor((percentileRank / 100) * sorted.length));
  return sorted[index];
}

function summarizeLatency(values) {
  return {
    avg: values.length ? Math.round(values.reduce((a, b) => a + b, 0) / values.length) : 0,
    p95: percentile(values, 95),
    p99: percentile(values, 99),
  };
}

async function fetchDemoToken(base, tenant = 'global', role = 'security_analyst') {
  const response = await fetch(`${base}/v1/auth/login?tenant=${encodeURIComponent(tenant)}&role=${encodeURIComponent(role)}&redirect=/platform`, {
    redirect: 'manual',
  });

  if (response.status !== 302) {
    return null;
  }

  const location = response.headers.get('location') || '';
  const token = new URL(location, `${base}/`).searchParams.get('token');
  return token || null;
}

function buildLoadTestCredentials() {
  const stamp = Date.now();
  return {
    tenant: buildTenantSlug('load'),
    email: `load.${stamp}@cybertron.local`,
    password: `LoadTest!${stamp}`,
  };
}

async function registerAndLogin(base, credentials) {
  const register = await fetch(`${base}/v1/auth/register`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      tenant: credentials.tenant,
      email: credentials.email,
      password: credentials.password,
      role: 'security_analyst',
      displayName: 'Load Runner',
    }),
  });

  if (register.status !== 201 && register.status !== 409) {
    return null;
  }

  const login = await fetch(`${base}/v1/auth/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      tenant: credentials.tenant,
      email: credentials.email,
      password: credentials.password,
    }),
  });

  if (login.status !== 200) {
    return null;
  }

  const payload = await login.json();
  const accessToken = payload?.tokens?.accessToken;
  const refreshToken = payload?.tokens?.refreshToken;

  if (!accessToken || !refreshToken) {
    return null;
  }

  return {
    credentials,
    accessToken,
    refreshToken,
  };
}

async function rotateRefreshToken(base, authState) {
  if (!authState?.refreshToken) {
    return 0;
  }

  const response = await fetch(`${base}/v1/auth/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      grantType: 'refresh_token',
      refreshToken: authState.refreshToken,
    }),
  });

  if (response.status === 200) {
    const payload = await response.json();
    if (payload?.tokens?.accessToken) {
      authState.accessToken = payload.tokens.accessToken;
    }
    if (payload?.tokens?.refreshToken) {
      authState.refreshToken = payload.tokens.refreshToken;
    }
  }

  return response.status;
}

async function updateTenantPlan(base, token, tenant, tier) {
  return fetch(`${base}/v1/billing/plan?tenant=${encodeURIComponent(tenant)}`, {
    method: 'PUT',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ tier }),
  });
}

async function uploadReport(base, token, tenant, suffix = 'load') {
  if (!token) {
    return { status: 401, reportId: null };
  }

  const uploadBody = new FormData();
  uploadBody.append('reportType', 'load_smoke');
  uploadBody.append('reportDate', new Date().toISOString().slice(0, 10));
  uploadBody.append(
    'file',
    new Blob([`%PDF-1.4\nload-smoke-${suffix}`], { type: 'application/pdf' }),
    `load-smoke-${suffix}.pdf`
  );

  const upload = await fetch(`${base}/v1/reports/upload?tenant=${encodeURIComponent(tenant)}`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
    },
    body: uploadBody,
  });

  let reportId = null;
  if (upload.status === 201 || upload.status === 200) {
    try {
      const payload = await upload.json();
      reportId = payload?.report?.id ? String(payload.report.id) : null;
    } catch {
      reportId = null;
    }
  }

  return {
    status: upload.status,
    reportId,
  };
}

async function seedDownloadTarget(base, token, tenant) {
  if (!token || !process.env.DATABASE_URL) {
    return null;
  }

  const result = await uploadReport(base, token, tenant, 'seed');
  if (result.status !== 201 && result.status !== 200) {
    return null;
  }

  return result.reportId;
}

async function runLoad() {
  const base = `http://127.0.0.1:${port}`;
  const timings = [];
  const endpointStats = {};
  let success = 0;
  let failure = 0;

  const loadCredentials = process.env.DATABASE_URL ? buildLoadTestCredentials() : null;
  const demoToken = await fetchDemoToken(base);
  const dbBackedAuth = process.env.DATABASE_URL
    ? await registerAndLogin(base, loadCredentials)
    : null;
  const activeTenant = dbBackedAuth?.credentials?.tenant || 'global';
  const authState = dbBackedAuth || (demoToken ? { accessToken: demoToken, refreshToken: null } : null);
  if (dbBackedAuth?.credentials?.tenant) {
    const nowSeconds = Math.floor(Date.now() / 1000);
    const superAdminToken = buildJwtHs256(process.env.JWT_SECRET || 'load-test-jwt-secret', {
      sub: `load-super-admin-${activeTenant}`,
      email: `load.super.admin.${activeTenant}@cybertron.local`,
      role: 'super_admin',
      tenant: activeTenant,
      iat: nowSeconds,
      exp: nowSeconds + 3600,
    });
    const upgradePlan = await updateTenantPlan(base, superAdminToken, activeTenant, 'pro');
    if (upgradePlan.status !== 200) {
      throw new Error(`Failed to upgrade load-test tenant plan: ${upgradePlan.status}`);
    }
  }
  let activeReportId = await seedDownloadTarget(base, authState?.accessToken || null, activeTenant);
  let refreshLock = Promise.resolve(0);

  const healthTarget = {
    name: 'health',
    expected: new Set([200]),
    execute: async () => {
      const response = await fetch(`${base}/v1/system/health`);
      return response.status;
    },
  };
  const threatSummaryTarget = {
    name: 'threat_summary',
    expected: authState?.accessToken ? new Set([200]) : new Set([200, 401]),
    execute: async () => {
      const response = await fetch(`${base}/v1/threats/summary?tenant=${encodeURIComponent(activeTenant)}`, {
        headers: authState?.accessToken ? { Authorization: `Bearer ${authState.accessToken}` } : undefined,
      });
      return response.status;
    },
  };
  const threatIncidentsTarget = {
    name: 'threat_incidents',
    expected: authState?.accessToken ? new Set([200]) : new Set([200, 401]),
    execute: async () => {
      const response = await fetch(
        `${base}/v1/threats/incidents?tenant=${encodeURIComponent(activeTenant)}&limit=10`,
        {
          headers: authState?.accessToken ? { Authorization: `Bearer ${authState.accessToken}` } : undefined,
        }
      );
      return response.status;
    },
  };
  const targets = [
    healthTarget,
    healthTarget,
    healthTarget,
    healthTarget,
    threatSummaryTarget,
    threatSummaryTarget,
    threatSummaryTarget,
    threatSummaryTarget,
    threatIncidentsTarget,
    threatIncidentsTarget,
    threatIncidentsTarget,
    threatIncidentsTarget,
  ];

  if (dbBackedAuth?.credentials) {
    targets.push({
      name: 'auth_refresh',
      expected: new Set([200]),
      execute: async () => {
        refreshLock = refreshLock.then(() => rotateRefreshToken(base, authState));
        return refreshLock;
      },
    });
  } else {
    targets.push({
      name: 'auth_login',
      expected: new Set([302, 503]),
      execute: async () => {
        const response = await fetch(`${base}/v1/auth/login?tenant=global&role=executive_viewer&redirect=/platform`, {
          redirect: 'manual',
        });
        return response.status;
      },
    });
  }

  if (process.env.DATABASE_URL && authState?.accessToken) {
    targets.push({
      name: 'report_upload',
      expected: new Set([201, 200]),
      execute: async () => {
        const result = await uploadReport(base, authState.accessToken, activeTenant, String(Date.now()));
        if (result.reportId) {
          activeReportId = result.reportId;
        }
        return result.status;
      },
    });
  }

  if (activeReportId && authState?.accessToken) {
    targets.push({
      name: 'report_download',
      expected: new Set([200]),
      execute: async () => {
        const response = await fetch(
          `${base}/v1/reports/${activeReportId}/download?tenant=${encodeURIComponent(activeTenant)}`,
          {
            headers: { Authorization: `Bearer ${authState.accessToken}` },
          }
        );
        return response.status;
      },
    });
  }

  const endAt = Date.now() + durationMs;
  let cursor = 0;

  async function workerLoop() {
    while (Date.now() < endAt) {
      const target = targets[cursor % targets.length];
      cursor += 1;

      const startedAt = Date.now();
      try {
        const statusCode = await target.execute();
        const elapsed = Date.now() - startedAt;
        timings.push(elapsed);

        endpointStats[target.name] = endpointStats[target.name] || { total: 0, failures: 0 };
        endpointStats[target.name].total += 1;
        endpointStats[target.name].timings = endpointStats[target.name].timings || [];
        endpointStats[target.name].timings.push(elapsed);

        if (target.expected.has(statusCode)) {
          success += 1;
        } else {
          failure += 1;
          endpointStats[target.name].failures += 1;
        }
      } catch {
        const elapsed = Date.now() - startedAt;
        timings.push(elapsed);
        failure += 1;
        endpointStats[target.name] = endpointStats[target.name] || { total: 0, failures: 0 };
        endpointStats[target.name].total += 1;
        endpointStats[target.name].timings = endpointStats[target.name].timings || [];
        endpointStats[target.name].timings.push(elapsed);
        endpointStats[target.name].failures += 1;
      }
    }
  }

  await Promise.all(Array.from({ length: Math.max(1, concurrency) }, () => workerLoop()));

  const totalRequests = success + failure;
  const errorRate = totalRequests > 0 ? (failure / totalRequests) * 100 : 0;
  const overallLatency = summarizeLatency(timings);
  const interactiveLatency = summarizeLatency(
    ['health', 'threat_summary', 'threat_incidents', 'auth_refresh']
      .flatMap(name => endpointStats[name]?.timings || [])
  );
  const reportPipelineLatency = summarizeLatency(
    ['report_upload', 'report_download']
      .flatMap(name => endpointStats[name]?.timings || [])
  );

  process.stdout.write(
    `Load results: durationMs=${durationMs} success=${success} failure=${failure} errorRate=${errorRate.toFixed(2)}%\n`
  );
  process.stdout.write(
    `Latency: overall avg=${overallLatency.avg}ms p95=${overallLatency.p95}ms p99=${overallLatency.p99}ms\n`
  );
  process.stdout.write(
    `Latency SLOs: interactive avg=${interactiveLatency.avg}ms p95=${interactiveLatency.p95}ms p99=${interactiveLatency.p99}ms`
      + `, report_pipeline avg=${reportPipelineLatency.avg}ms p95=${reportPipelineLatency.p95}ms p99=${reportPipelineLatency.p99}ms\n`
  );
  process.stdout.write(`Endpoint stats: ${JSON.stringify(endpointStats)}\n`);

  if (errorRate > 2) {
    throw new Error(`Load test failed: error rate ${errorRate.toFixed(2)}% exceeds 2%`);
  }

  if (interactiveLatency.p95 > 700) {
    throw new Error(`Load test failed: interactive p95 latency ${interactiveLatency.p95}ms exceeds 700ms`);
  }

  if (reportPipelineLatency.p95 > 2500) {
    throw new Error(
      `Load test failed: report pipeline p95 latency ${reportPipelineLatency.p95}ms exceeds 2500ms`
    );
  }
}

async function run() {
  const usingDatabase = Boolean(process.env.DATABASE_URL);
  const requireDatabase =
    process.env.LOAD_REQUIRE_DATABASE !== undefined
      ? String(process.env.LOAD_REQUIRE_DATABASE).toLowerCase() === 'true'
      : process.env.REQUIRE_DATABASE_FOR_CI !== undefined
        ? String(process.env.REQUIRE_DATABASE_FOR_CI).toLowerCase() === 'true'
        : String(process.env.CI || '').toLowerCase() === 'true';

  if (requireDatabase && !usingDatabase) {
    throw new Error(
      'DATABASE_URL is required for load checks when LOAD_REQUIRE_DATABASE=true or REQUIRE_DATABASE_FOR_CI=true.'
    );
  }

  if (!usingDatabase) {
    process.stdout.write(
      'WARN: DATABASE_URL is not set; load profile skips DB-backed auth refresh and report upload/download targets.\n'
    );
  }

  const env = {
    ...process.env,
    PORT: String(port),
    RATE_LIMIT_MAX_REQUESTS: process.env.RATE_LIMIT_MAX_REQUESTS || '50000',
    RATE_LIMIT_WINDOW_MS: process.env.RATE_LIMIT_WINDOW_MS || '60000',
    AUTH_RATE_LIMIT_MAX_REQUESTS: process.env.AUTH_RATE_LIMIT_MAX_REQUESTS || '50000',
    AUTH_IDENTITY_RATE_LIMIT_MAX_REQUESTS: process.env.AUTH_IDENTITY_RATE_LIMIT_MAX_REQUESTS || '50000',
    REPORT_RATE_LIMIT_MAX_REQUESTS: process.env.REPORT_RATE_LIMIT_MAX_REQUESTS || '50000',
    MAX_CONCURRENT_REQUESTS: process.env.MAX_CONCURRENT_REQUESTS || '10000',
  };

  if (usingDatabase) {
    env.AUTH_MODE = process.env.AUTH_MODE || 'jwt_hs256';
    env.JWT_SECRET = process.env.JWT_SECRET || 'load-test-jwt-secret';
    env.ALLOW_PUBLIC_REGISTRATION = process.env.ALLOW_PUBLIC_REGISTRATION || 'true';
    env.ALLOW_INSECURE_DEMO_AUTH = process.env.ALLOW_INSECURE_DEMO_AUTH || 'false';
  }

  const child = spawn(process.execPath, ['server.js'], {
    cwd: backendRoot,
    env,
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
    await runLoad();
    process.stdout.write('Backend load smoke passed.\n');
  } finally {
    child.kill('SIGTERM');
  }
}

run().catch(error => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
