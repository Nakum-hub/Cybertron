#!/usr/bin/env node

const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const path = require('node:path');

const backendRoot = path.resolve(__dirname, '..');
const port = Number(process.env.BACKEND_TEST_PORT || 8101);

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

function readCookieAttributes(setCookieValue) {
  const value = String(setCookieValue || '');
  return {
    hasHttpOnly: /;\s*httponly/i.test(value),
    sameSite: /;\s*samesite=([^;]+)/i.exec(value)?.[1]?.toLowerCase() || '',
    hasSecure: /;\s*secure/i.test(value),
  };
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
      // ignore while server is booting
    }

    await wait(200);
  }

  throw new Error('Backend did not become healthy in time.');
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

function buildTenantSlug(prefix = 'smoke') {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, '-');
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

async function registerAndLogin(base) {
  const stamp = Date.now();
  const credentials = {
    tenant: buildTenantSlug('smoke'),
    email: `smoke.${stamp}@cybertron.local`,
    password: `SmokePass!${stamp}`,
  };

  const register = await fetch(`${base}/v1/auth/register`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      ...credentials,
      role: 'executive_viewer',
      displayName: 'Smoke Check',
    }),
  });
  assertCondition(register.status === 201, 'register user status code');

  const login = await fetch(`${base}/v1/auth/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(credentials),
  });
  assertCondition(login.status === 200, 'auth password login status code');

  const payload = await login.json();
  const accessToken = payload?.tokens?.accessToken || '';
  const refreshToken = payload?.tokens?.refreshToken || '';

  assertCondition(Boolean(accessToken), 'auth password login returned access token');
  assertCondition(Boolean(refreshToken), 'auth password login returned refresh token');

  const setCookie = login.headers.getSetCookie ? login.headers.getSetCookie() : [];
  assertCondition(Array.isArray(setCookie) && setCookie.length >= 2, 'auth login returns auth cookies');
  const accessCookie = setCookie.find(cookie => cookie.startsWith('ct_access=')) || '';
  const refreshCookie = setCookie.find(cookie => cookie.startsWith('ct_refresh=')) || '';
  const csrfCookie = setCookie.find(cookie => cookie.startsWith('ct_csrf=')) || '';
  assertCondition(Boolean(accessCookie), 'access cookie returned');
  assertCondition(Boolean(refreshCookie), 'refresh cookie returned');
  assertCondition(Boolean(csrfCookie), 'csrf cookie returned');

  const accessCookieAttrs = readCookieAttributes(accessCookie);
  assertCondition(accessCookieAttrs.hasHttpOnly, 'access cookie uses HttpOnly');
  assertCondition(['lax', 'strict', 'none'].includes(accessCookieAttrs.sameSite), 'access cookie has SameSite');

  return {
    credentials,
    user: payload?.user || null,
    accessToken,
    refreshToken,
  };
}

async function runChecks() {
  const requireDatabase = shouldRequireDatabase();
  const hasDatabase = Boolean(process.env.DATABASE_URL);
  const hasRedis = Boolean(process.env.REDIS_URL);
  const isStrictDeps =
    String(process.env.STRICT_DEPENDENCIES || 'false').toLowerCase() === 'true';
  // Readiness requires DB/Redis only in strict mode when URLs are configured.
  // In non-strict mode (default), readiness is 200 as long as storage is healthy.
  const expectedReady = isStrictDeps ? hasDatabase && hasRedis : true;
  if (requireDatabase && !hasDatabase && !allowDevDatabaseSkip()) {
    throw new Error(
      'DATABASE_URL is required for smoke checks when REQUIRE_DATABASE_FOR_CI=true (or CI=true).'
    );
  }

  const base = `http://127.0.0.1:${port}`;

  const health = await fetch(`${base}/v1/system/health`);
  const healthBody = await health.json();
  assertCondition(health.status === 200, 'health status code');
  assertCondition(typeof healthBody.status === 'string', 'health payload.status');
  assertCondition(typeof healthBody.checkedAt === 'string', 'health payload.checkedAt');
  // Note: version is intentionally omitted from unauthenticated health responses (security by design)

  const readiness = await fetch(`${base}/v1/system/readiness`);
  const readinessBody = await readiness.json();
  assertCondition(
    readiness.status === (expectedReady ? 200 : 503),
    'readiness status code reflects dependency requirements'
  );
  assertCondition(readinessBody.ready === expectedReady, 'readiness payload.ready reflects dependency state');

  const liveness = await fetch(`${base}/v1/system/liveness`);
  const livenessBody = await liveness.json();
  assertCondition(liveness.status === 200, 'liveness status code');
  assertCondition(livenessBody.status === 'alive', 'liveness payload.status');

  const runtimeConfig = await fetch(`${base}/api/config`);
  const runtimeConfigBody = await runtimeConfig.json();
  assertCondition(runtimeConfig.status === 200, 'runtime config status code');
  assertCondition(typeof runtimeConfigBody.API_BASE_URL === 'string', 'runtime config API_BASE_URL');
  assertCondition(typeof runtimeConfigBody.authTokenPath === 'string', 'runtime config authTokenPath');
  assertCondition(runtimeConfigBody.authTransport === 'cookie', 'runtime config auth transport cookie');
  assertCondition(runtimeConfigBody.csrfEnabled === true, 'runtime config csrf enabled');

  const summary = await fetch(`${base}/v1/threats/summary?tenant=global`);
  const summaryBody = await summary.json();
  assertCondition(summary.status === 200, 'threat summary status code');
  assertCondition(Number.isFinite(summaryBody.activeThreats), 'threat summary activeThreats');

  const appsUnauthorized = await fetch(`${base}/v1/platform/apps?tenant=global`);
  assertCondition(appsUnauthorized.status === 401, 'platform apps requires authentication');

  const nowSeconds = Math.floor(Date.now() / 1000);
  const analystToken = buildJwtHs256(process.env.JWT_SECRET || 'smoke-jwt-secret', {
    sub: 'smoke-analyst-user',
    email: 'smoke.analyst@cybertron.local',
    role: 'security_analyst',
    tenant: 'global',
    iat: nowSeconds,
    exp: nowSeconds + 3600,
  });
  const adminToken = buildJwtHs256(process.env.JWT_SECRET || 'smoke-jwt-secret', {
    sub: 'smoke-admin-user',
    email: 'smoke.admin@cybertron.local',
    role: 'tenant_admin',
    tenant: 'global',
    iat: nowSeconds,
    exp: nowSeconds + 3600,
  });

  if (!hasDatabase) {
    const apps = await fetch(`${base}/v1/platform/apps?tenant=global`, {
      headers: {
        Authorization: `Bearer ${analystToken}`,
      },
    });
    const appsBody = await apps.json();
    assertCondition(apps.status === 200, 'platform apps status code with auth');
    assertCondition(Array.isArray(appsBody), 'platform apps payload array with auth');

    const probeAppId = appsBody[0]?.id || 'threat-command';
    const appStatus = await fetch(`${base}/v1/apps/${encodeURIComponent(probeAppId)}/status?tenant=global`, {
      headers: {
        Authorization: `Bearer ${analystToken}`,
      },
    });
    if (appsBody.length > 0) {
      const appStatusBody = await appStatus.json();
      assertCondition(appStatus.status === 200, 'app status status code with auth');
      assertCondition(appStatusBody.appId === probeAppId, 'app status appId');
    } else {
      assertCondition(
        appStatus.status === 403 || appStatus.status === 404,
        'app status is denied when tenant has no enabled products'
      );
    }
  }

  const meUnauthorized = await fetch(`${base}/v1/auth/me`);
  assertCondition(meUnauthorized.status === 401, 'auth me unauthorized without token');

  if (hasDatabase) {
    const auth = await registerAndLogin(base);
    const tenant = auth.credentials.tenant;
    const nowSeconds = Math.floor(Date.now() / 1000);
    const analystToken = buildJwtHs256(process.env.JWT_SECRET || 'smoke-jwt-secret', {
      sub: `smoke-analyst-${tenant}`,
      email: `smoke.analyst.${tenant}@cybertron.local`,
      role: 'security_analyst',
      tenant,
      iat: nowSeconds,
      exp: nowSeconds + 3600,
    });
    const superAdminToken = buildJwtHs256(process.env.JWT_SECRET || 'smoke-jwt-secret', {
      sub: `smoke-super-admin-${tenant}`,
      email: `smoke.super.admin.${tenant}@cybertron.local`,
      role: 'super_admin',
      tenant,
      iat: nowSeconds,
      exp: nowSeconds + 3600,
    });

    const apps = await fetch(`${base}/v1/platform/apps?tenant=${encodeURIComponent(tenant)}`, {
      headers: {
        Authorization: `Bearer ${analystToken}`,
      },
    });
    const appsBody = await apps.json();
    assertCondition(apps.status === 200, 'platform apps status code with auth');
    assertCondition(Array.isArray(appsBody), 'platform apps payload array with auth');
    assertCondition(appsBody.length >= 1, 'platform apps payload non-empty with auth when database is configured');

    const probeAppId = appsBody[0]?.id || 'threat-command';
    const appStatus = await fetch(
      `${base}/v1/apps/${encodeURIComponent(probeAppId)}/status?tenant=${encodeURIComponent(tenant)}`,
      {
        headers: {
          Authorization: `Bearer ${analystToken}`,
        },
      }
    );
    const appStatusBody = await appStatus.json();
    assertCondition(appStatus.status === 200, 'app status status code with auth');
    assertCondition(appStatusBody.appId === probeAppId, 'app status appId');

    const meAuthorized = await fetch(`${base}/v1/auth/me`, {
      headers: {
        Authorization: `Bearer ${auth.accessToken}`,
      },
    });
    const meBody = await meAuthorized.json();
    assertCondition(meAuthorized.status === 200, 'auth me status code with token');
    assertCondition(typeof meBody.email === 'string', 'auth me payload email');

    const billingCredits = await fetch(`${base}/v1/billing/credits?tenant=${encodeURIComponent(tenant)}`, {
      headers: {
        Authorization: `Bearer ${auth.accessToken}`,
      },
    });
    const billingCreditsBody = await billingCredits.json();
    assertCondition(billingCredits.status === 200, 'billing credits status code');
    assertCondition(billingCreditsBody.planTier === 'free', 'default self-service tenant starts on free plan');
    assertCondition(billingCreditsBody.quotaEnforced === true, 'free plan quota is enforced');

    const products = await fetch(`${base}/v1/products?tenant=${encodeURIComponent(tenant)}`, {
      headers: {
        Authorization: `Bearer ${auth.accessToken}`,
      },
    });
    const productsBody = await products.json();
    assertCondition(products.status === 200, 'products list status code');
    assertCondition(Array.isArray(productsBody), 'products list payload array');
    const riskCopilotProduct = (productsBody || []).find(product => product?.productKey === 'risk-copilot');
    assertCondition(Boolean(riskCopilotProduct), 'risk copilot product is listed in tenant catalog');
    assertCondition(
      riskCopilotProduct?.planAllowed === false,
      'risk copilot is plan-blocked for default free-tier customer catalog'
    );
    assertCondition(riskCopilotProduct?.planTier === 'free', 'risk copilot product reports free plan tier');

    const freeTierRiskStatus = await fetch(
      `${base}/v1/apps/risk-copilot/status?tenant=${encodeURIComponent(tenant)}&role=executive_viewer`,
      {
        headers: {
          Authorization: `Bearer ${auth.accessToken}`,
        },
      }
    );
    assertCondition(
      freeTierRiskStatus.status === 403,
      'risk copilot app status is blocked for default free-tier customer'
    );

    const aiModules = await fetch(`${base}/v1/ai/modules`, {
      headers: {
        Authorization: `Bearer ${auth.accessToken}`,
      },
    });
    const aiModulesBody = await aiModules.json();
    assertCondition(aiModules.status === 200, 'ai modules catalog status code');
    assertCondition(Array.isArray(aiModulesBody.modules), 'ai modules payload list');

    const logout = await fetch(`${base}/v1/auth/logout`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${auth.accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        tenant: auth.credentials.tenant,
        refreshToken: auth.refreshToken,
      }),
    });
    assertCondition(logout.status === 204, 'auth logout status code with token');

    const meAfterLogout = await fetch(`${base}/v1/auth/me`, {
      headers: {
        Authorization: `Bearer ${auth.accessToken}`,
      },
    });
    assertCondition(meAfterLogout.status === 401, 'auth me unauthorized after logout');

    const upgradePlan = await updateTenantPlan(base, superAdminToken, tenant, 'pro');
    const upgradePlanBody = await upgradePlan.json();
    assertCondition(upgradePlan.status === 200, 'billing plan upgrade status code');
    assertCondition(upgradePlanBody.tier === 'pro', 'billing plan upgrade applied');

    const formData = new FormData();
    formData.append('reportType', 'smoke_report');
    formData.append('reportDate', new Date().toISOString().slice(0, 10));
    formData.append('metadata', JSON.stringify({ source: 'backend-smoke-check' }));
    formData.append('idempotencyKey', 'smoke-upload-check-key');
    formData.append(
      'file',
      new Blob(['%PDF-1.4\n% smoke\n1 0 obj\n<< /Type /Catalog >>\nendobj\n'], {
        type: 'application/pdf',
      }),
      'smoke.pdf'
    );

    const upload = await fetch(`${base}/v1/reports/upload?tenant=${encodeURIComponent(tenant)}`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${analystToken}`,
      },
      body: formData,
    });

    const uploadBody = await upload.json();
    assertCondition(upload.status === 201 || upload.status === 200, 'report upload status code');
    assertCondition(Boolean(uploadBody?.report?.id), 'report upload returns report id');

    const reportId = String(uploadBody.report.id);
    const download = await fetch(
      `${base}/v1/reports/${reportId}/download?tenant=${encodeURIComponent(tenant)}`,
      {
        headers: {
          Authorization: `Bearer ${analystToken}`,
        },
      }
    );
    assertCondition(download.status === 200, 'report download status code');
    const contentDisposition = download.headers.get('content-disposition') || '';
    assertCondition(
      contentDisposition.toLowerCase().includes('attachment'),
      'report download has attachment content-disposition'
    );
    const fileBytes = new Uint8Array(await download.arrayBuffer());
    assertCondition(fileBytes.length > 0, 'report download returned binary bytes');
  } else {
    process.stdout.write(
      'SKIP: DATABASE_URL is not set; DB-backed auth and report upload/download checks were skipped.\n'
    );
  }

  const loginMethodMismatch = await fetch(`${base}/v1/auth/login`, {
    method: 'PUT',
  });
  assertCondition(loginMethodMismatch.status === 405, 'auth login rejects unsupported method');

  const openapi = await fetch(`${base}/v1/system/openapi`);
  const openapiBody = await openapi.json();
  assertCondition(openapi.status === 401, 'openapi rejects unauthenticated access');
  assertCondition(openapiBody?.error?.code === 'auth_required', 'openapi unauthenticated response code');

  const openapiViewer = await fetch(`${base}/v1/system/openapi`, {
    headers: {
      Authorization: `Bearer ${analystToken}`,
    },
  });
  const openapiViewerBody = await openapiViewer.json();
  assertCondition(openapiViewer.status === 403, 'openapi rejects non-admin access');
  assertCondition(openapiViewerBody?.error?.code === 'access_denied', 'openapi non-admin response code');

  const openapiAdmin = await fetch(`${base}/v1/system/openapi`, {
    headers: {
      Authorization: `Bearer ${adminToken}`,
    },
  });
  const openapiAdminBody = await openapiAdmin.json();
  assertCondition(openapiAdmin.status === 200, 'openapi status code for tenant admin');
  assertCondition(openapiAdminBody.openapi === '3.0.3', 'openapi version');

  const prometheusMetrics = await fetch(`${base}/v1/system/metrics/prometheus`);
  const prometheusText = await prometheusMetrics.text();
  assertCondition(prometheusMetrics.status === 200, 'prometheus metrics status code');
  assertCondition(
    prometheusText.includes('cybertron_requests_total'),
    'prometheus metrics contains request counter'
  );

  const notFound = await fetch(`${base}/v1/unknown/path`);
  assertCondition(notFound.status === 404, 'unknown route returns 404');
}

async function run() {
  const requireDatabase = shouldRequireDatabase();
  const hasDatabase = Boolean(process.env.DATABASE_URL);
  if (requireDatabase && !hasDatabase && !allowDevDatabaseSkip()) {
    throw new Error(
      'DATABASE_URL is required for smoke checks when REQUIRE_DATABASE_FOR_CI=true (or CI=true).'
    );
  }

  const child = spawn(process.execPath, ['server.js'], {
    cwd: backendRoot,
    env: {
      ...process.env,
      PORT: String(port),
      AUTH_MODE: process.env.AUTH_MODE || 'jwt_hs256',
      JWT_SECRET: process.env.JWT_SECRET || 'smoke-jwt-secret',
      ALLOW_INSECURE_DEMO_AUTH: process.env.ALLOW_INSECURE_DEMO_AUTH || 'false',
      ALLOW_PUBLIC_REGISTRATION:
        process.env.ALLOW_PUBLIC_REGISTRATION || (hasDatabase ? 'true' : 'false'),
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
    process.stdout.write('Backend smoke checks passed.\n');
  } finally {
    child.kill('SIGTERM');
  }
}

run().catch(error => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
