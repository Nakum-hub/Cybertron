#!/usr/bin/env node

const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const path = require('node:path');
const { Client } = require('pg');

const backendRoot = path.resolve(__dirname, '..');
const port = Number(process.env.BACKEND_RED_TEAM_PORT || 8102);
const configuredReportRateLimitMax = Number(process.env.REPORT_RATE_LIMIT_MAX_REQUESTS || '6');
const reportRateLimitMaxForChecks =
  Number.isFinite(configuredReportRateLimitMax) && configuredReportRateLimitMax > 0
    ? Math.floor(configuredReportRateLimitMax)
    : 6;

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

function buildTenantSlug(prefix = 'redteam') {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, '-');
}

function hashAccessToken(token) {
  return crypto.createHash('sha256').update(String(token || '')).digest('hex');
}

async function fetchRevocationRecord(tokenHash) {
  if (!process.env.DATABASE_URL || !tokenHash) {
    return null;
  }

  const client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DB_SSL_MODE === 'disable' ? false : undefined,
  });
  await client.connect();
  try {
    const result = await client.query(
      `
        SELECT tenant_slug, user_id::text AS user_id, user_subject, token_hash
        FROM auth_access_token_revocations
        WHERE token_hash = $1
        LIMIT 1
      `,
      [tokenHash]
    );
    return result.rows[0] || null;
  } finally {
    await client.end();
  }
}

function toCookieHeader(setCookies = []) {
  return setCookies
    .map(cookie => String(cookie).split(';')[0].trim())
    .filter(Boolean)
    .join('; ');
}

function readCookieValue(setCookies, cookieName) {
  const matched = setCookies.find(cookie => String(cookie).startsWith(`${cookieName}=`)) || '';
  return String(matched).split(';')[0].split('=').slice(1).join('=') || '';
}

async function waitForHealth(maxAttempts = 40) {
  const url = `http://127.0.0.1:${port}/v1/system/health`;

  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        return;
      }
    } catch {
      // Server still booting.
    }

    await wait(200);
  }

  throw new Error('Backend did not become healthy in time for red-team checks.');
}

function uniqueCredentials(prefix, tenant = 'global') {
  const stamp = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  return {
    tenant,
    email: `${prefix}.${stamp}@cybertron.local`,
    password: `RedTeam!${stamp}`,
  };
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

async function registerAndLogin(base, prefix, role = 'security_analyst', tenant = buildTenantSlug(prefix)) {
  const credentials = uniqueCredentials(prefix, tenant);

  const register = await fetch(`${base}/v1/auth/register`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      ...credentials,
      role,
      displayName: `${prefix} user`,
    }),
  });
  assertCondition(register.status === 201, `${prefix} register succeeds`);

  const login = await fetch(`${base}/v1/auth/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(credentials),
  });
  assertCondition(login.status === 200, `${prefix} login succeeds`);

  const payload = await login.json();
  const accessToken = payload?.tokens?.accessToken || '';
  const refreshToken = payload?.tokens?.refreshToken || '';
  assertCondition(Boolean(accessToken), `${prefix} access token present`);
  assertCondition(Boolean(refreshToken), `${prefix} refresh token present`);

  return {
    credentials,
    accessToken,
    refreshToken,
    setCookies: login.headers.getSetCookie ? login.headers.getSetCookie() : [],
  };
}

async function runChecks() {
  const base = `http://127.0.0.1:${port}`;
  const hasDatabase = Boolean(process.env.DATABASE_URL);
  const requireDatabase = shouldRequireDatabase();

  if (requireDatabase && !hasDatabase && !allowDevDatabaseSkip()) {
    throw new Error(
      'DATABASE_URL is required for red-team checks when REQUIRE_DATABASE_FOR_CI=true (or CI=true).'
    );
  }

  const headerProbe = await fetch(`${base}/v1/system/health`);
  assertCondition(
    headerProbe.headers.get('x-content-type-options') === 'nosniff',
    'security header x-content-type-options present'
  );
  assertCondition(
    headerProbe.headers.get('x-frame-options') === 'DENY',
    'security header x-frame-options present'
  );
  assertCondition(
    String(headerProbe.headers.get('content-security-policy') || '').includes("default-src 'none'"),
    'security header content-security-policy present'
  );

  const allowedPreflight = await fetch(`${base}/v1/auth/login`, {
    method: 'OPTIONS',
    headers: {
      Origin: 'http://localhost:3000',
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'Content-Type,Authorization',
    },
  });
  assertCondition(allowedPreflight.status === 204, 'preflight allows trusted origin');
  assertCondition(
    String(allowedPreflight.headers.get('access-control-allow-methods') || '').includes('POST'),
    'preflight advertises required methods'
  );
  assertCondition(
    String(allowedPreflight.headers.get('access-control-allow-headers') || '')
      .toLowerCase()
      .includes('authorization'),
    'preflight advertises authorization header support'
  );
  assertCondition(
    String(allowedPreflight.headers.get('access-control-allow-credentials') || '').toLowerCase() ===
      'false',
    'preflight credentials disabled for cross-origin requests'
  );

  const blockedOrigin = await fetch(`${base}/v1/system/health`, {
    headers: {
      Origin: 'http://evil.example',
    },
  });
  assertCondition(blockedOrigin.status === 403, 'origin validation blocks unknown origin');

  const blockedPreflight = await fetch(`${base}/v1/auth/login`, {
    method: 'OPTIONS',
    headers: {
      Origin: 'http://evil.example',
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'Content-Type',
    },
  });
  assertCondition(blockedPreflight.status === 403, 'preflight blocks unknown origin');

  const runtimeConfig = await fetch(`${base}/api/config`);
  const runtimeConfigBody = await runtimeConfig.json();
  assertCondition(runtimeConfig.status === 200, 'runtime config endpoint responds');
  assertCondition(
    !Object.prototype.hasOwnProperty.call(runtimeConfigBody, 'jwtSecret'),
    'runtime config does not expose jwtSecret'
  );
  assertCondition(
    !Object.keys(runtimeConfigBody).some(key => /secret|password/i.test(key)),
    'runtime config does not expose secret-like keys'
  );
  assertCondition(runtimeConfigBody.authTransport === 'cookie', 'runtime config advertises cookie auth');

  const connectorsUnauthorized = await fetch(`${base}/v1/connectors/status`);
  assertCondition(connectorsUnauthorized.status === 401, 'protected connector status denies unauthenticated access');

  const platformAppsUnauthorized = await fetch(`${base}/v1/platform/apps`);
  assertCondition(platformAppsUnauthorized.status === 401, 'platform apps denies unauthenticated access');

  const metricsUnauthorized = await fetch(`${base}/v1/system/metrics`);
  assertCondition(metricsUnauthorized.status === 401, 'metrics endpoint denies unauthenticated access');

  const metricsAuthorized = await fetch(`${base}/v1/system/metrics`, {
    headers: {
      Authorization: `Bearer ${process.env.METRICS_AUTH_TOKEN || 'red-team-metrics-token'}`,
    },
  });
  assertCondition(metricsAuthorized.status === 200, 'metrics endpoint accepts configured auth token');

  const logoutUnknownField = await fetch(`${base}/v1/auth/logout`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      unknownField: 'x',
    }),
  });
  assertCondition(logoutUnknownField.status === 400, 'request body unknown fields are rejected');

  let authLimited = false;
  for (let attempt = 0; attempt < 10; attempt += 1) {
    const response = await fetch(`${base}/v1/auth/password/forgot`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        tenant: 'global',
        email: 'attacker@example.com',
      }),
    });

    if (response.status === 429) {
      authLimited = true;
      break;
    }
  }
  assertCondition(authLimited, 'auth abuse limiter blocks repeated auth endpoint attempts');

  let reportLimited = false;
  for (let attempt = 0; attempt < reportRateLimitMaxForChecks + 4; attempt += 1) {
    const response = await fetch(`${base}/v1/reports?tenant=global`, {
      method: 'GET',
    });

    if (response.status === 429) {
      reportLimited = true;
      break;
    }
  }
  assertCondition(reportLimited, 'report abuse limiter blocks repeated report endpoint attempts');

  const nowSeconds = Math.floor(Date.now() / 1000);
  const jwtSecret = process.env.JWT_SECRET || 'red-team-jwt-secret';
  const jwtToken = buildJwtHs256(jwtSecret, {
    sub: 'redteam-user-001',
    email: 'redteam.user@cybertron.local',
    role: 'security_analyst',
    tenant: 'global',
    iat: nowSeconds,
    exp: nowSeconds + 900,
  });
  const jwtMeBeforeLogout = await fetch(`${base}/v1/auth/me`, {
    headers: {
      Authorization: `Bearer ${jwtToken}`,
    },
  });
  assertCondition(jwtMeBeforeLogout.status === 200, 'jwt token is accepted before logout');

  const jwtLogout = await fetch(`${base}/v1/auth/logout`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${jwtToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ tenant: 'global' }),
  });
  assertCondition(jwtLogout.status === 204, 'jwt logout succeeds');

  const jwtMeAfterLogout = await fetch(`${base}/v1/auth/me`, {
    headers: {
      Authorization: `Bearer ${jwtToken}`,
    },
  });
  assertCondition(jwtMeAfterLogout.status === 401, 'jwt token replay is blocked after logout');
  if (hasDatabase) {
    const jwtRevocation = await fetchRevocationRecord(hashAccessToken(jwtToken));
    assertCondition(Boolean(jwtRevocation), 'jwt logout persists revocation row');
    assertCondition(jwtRevocation.user_id === null, 'jwt logout leaves numeric user_id null for string subject');
    assertCondition(jwtRevocation.user_subject === 'redteam-user-001', 'jwt logout persists string subject');
  }

  const traversalAttempt = await fetch(`${base}/v1/reports/../../windows/system32`);
  assertCondition(traversalAttempt.status === 404, 'path traversal style route is rejected');

  const sqliProbeToken = buildJwtHs256(jwtSecret, {
    sub: 'redteam-sqli-probe',
    email: 'redteam.sqli@cybertron.local',
    role: 'security_analyst',
    tenant: 'global',
    iat: nowSeconds,
    exp: nowSeconds + 900,
  });
  const sqliLikeRole = await fetch(`${base}/v1/platform/apps?role=' OR 1=1 --&tenant=global`, {
    headers: {
      Authorization: `Bearer ${sqliProbeToken}`,
    },
  });
  assertCondition(
    sqliLikeRole.status === 200 || sqliLikeRole.status === 403,
    'malicious role query input does not bypass platform endpoint controls'
  );

  if (hasDatabase) {
    const invalidLoginPayload = await fetch(`${base}/v1/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        tenant: 'global',
        email: 'analyst.global@cybertron.local',
        password: 'bad-password',
        injected: 'unexpected-field',
      }),
    });
    assertCondition(invalidLoginPayload.status === 400, 'login rejects unknown payload fields');

    let identityLimited = false;
    for (let attempt = 0; attempt < 12; attempt += 1) {
      const response = await fetch(`${base}/v1/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          tenant: 'global',
          email: 'identity.limit@cybertron.local',
          password: 'bad-password',
        }),
      });

      if (response.status === 429) {
        identityLimited = true;
        break;
      }
    }
    assertCondition(identityLimited, 'auth identity limiter blocks repeated account-targeted attempts');

    const inviteProtectedTenant = buildTenantSlug('protected');
    const ownerCredentials = uniqueCredentials('owner', inviteProtectedTenant);
    const ownerRegister = await fetch(`${base}/v1/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        ...ownerCredentials,
        role: 'executive_viewer',
        displayName: 'Owner user',
      }),
    });
    assertCondition(ownerRegister.status === 201, 'first self-service workspace registration succeeds');

    const joinAttemptCredentials = uniqueCredentials('joiner', inviteProtectedTenant);
    const joinAttemptRegister = await fetch(`${base}/v1/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        ...joinAttemptCredentials,
        role: 'executive_viewer',
        displayName: 'Join attempt',
      }),
    });
    const joinAttemptBody = await joinAttemptRegister.json();
    assertCondition(joinAttemptRegister.status === 403, 'public self-service cannot join an existing workspace');
    assertCondition(
      joinAttemptBody?.error?.code === 'tenant_join_invite_required',
      'existing workspace self-service join returns tenant_join_invite_required'
    );

    const sharedEmail = `shared.${Date.now()}@cybertron.local`;
    const workspaceLimitTenantA = buildTenantSlug('workspace-a');
    const workspaceLimitTenantB = buildTenantSlug('workspace-b');
    const workspaceLimitFirst = await fetch(`${base}/v1/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        tenant: workspaceLimitTenantA,
        email: sharedEmail,
        password: `WorkspaceA!${Date.now()}`,
        role: 'executive_viewer',
        displayName: 'Workspace A owner',
      }),
    });
    assertCondition(workspaceLimitFirst.status === 201, 'first workspace for shared email succeeds');

    const workspaceLimitSecond = await fetch(`${base}/v1/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        tenant: workspaceLimitTenantB,
        email: sharedEmail,
        password: `WorkspaceB!${Date.now()}`,
        role: 'executive_viewer',
        displayName: 'Workspace B owner',
      }),
    });
    const workspaceLimitBody = await workspaceLimitSecond.json();
    assertCondition(workspaceLimitSecond.status === 409, 'same email cannot create a second self-service workspace');
    assertCondition(
      workspaceLimitBody?.error?.code === 'self_service_workspace_limit_reached',
      'second workspace returns self_service_workspace_limit_reached'
    );

    const sharedFingerprint = `fp-${Date.now()}-route-shared-device`;
    const fingerprintTenantA = buildTenantSlug('fingerprint-a');
    const fingerprintTenantB = buildTenantSlug('fingerprint-b');
    const fingerprintRegisterFirst = await fetch(`${base}/v1/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Cybertron-Public-Fingerprint': sharedFingerprint,
      },
      body: JSON.stringify({
        tenant: fingerprintTenantA,
        email: `fingerprint.a.${Date.now()}@cybertron.local`,
        password: `FingerprintA!${Date.now()}`,
        role: 'executive_viewer',
        displayName: 'Fingerprint A owner',
      }),
    });
    assertCondition(
      fingerprintRegisterFirst.status === 201,
      'first workspace for shared fingerprint succeeds'
    );

    const fingerprintRegisterSecond = await fetch(`${base}/v1/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Cybertron-Public-Fingerprint': sharedFingerprint,
      },
      body: JSON.stringify({
        tenant: fingerprintTenantB,
        email: `fingerprint.b.${Date.now()}@cybertron.local`,
        password: `FingerprintB!${Date.now()}`,
        role: 'executive_viewer',
        displayName: 'Fingerprint B owner',
      }),
    });
    const fingerprintRegisterBody = await fingerprintRegisterSecond.json();
    assertCondition(
      fingerprintRegisterSecond.status === 429,
      'same fingerprint cannot create a second free workspace through register route'
    );
    assertCondition(
      fingerprintRegisterBody?.error?.code === 'workspace_creation_device_limit_reached',
      'shared fingerprint returns workspace_creation_device_limit_reached'
    );

    const missingWorkspaceRegister = await fetch(`${base}/v1/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email: `missing.workspace.${Date.now()}@cybertron.local`,
        password: `MissingWorkspace!${Date.now()}`,
        role: 'executive_viewer',
        displayName: 'Missing Workspace',
      }),
    });
    const missingWorkspaceRegisterBody = await missingWorkspaceRegister.json();
    assertCondition(missingWorkspaceRegister.status === 400, 'register rejects missing workspace slug');
    assertCondition(
      missingWorkspaceRegisterBody?.error?.code === 'workspace_slug_required',
      'missing workspace slug returns workspace_slug_required'
    );

    const reservedWorkspaceRegister = await fetch(`${base}/v1/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        tenant: 'global',
        email: `reserved.workspace.${Date.now()}@cybertron.local`,
        password: `ReservedWorkspace!${Date.now()}`,
        role: 'executive_viewer',
        displayName: 'Reserved Workspace',
      }),
    });
    const reservedWorkspaceRegisterBody = await reservedWorkspaceRegister.json();
    assertCondition(reservedWorkspaceRegister.status === 403, 'register rejects reserved internal workspace slug');
    assertCondition(
      reservedWorkspaceRegisterBody?.error?.code === 'reserved_workspace_slug',
      'reserved workspace slug returns reserved_workspace_slug'
    );

    const oauthInitMissingWorkspace = await fetch(`${base}/v1/auth/oauth/google`, {
      redirect: 'manual',
    });
    assertCondition(oauthInitMissingWorkspace.status === 302, 'oauth init redirects on missing workspace slug');
    assertCondition(
      String(oauthInitMissingWorkspace.headers.get('location') || '').includes('workspace_slug_required'),
      'oauth init missing workspace routes to workspace_slug_required'
    );

    const oauthInitReservedWorkspace = await fetch(`${base}/v1/auth/oauth/google?tenant=global`, {
      redirect: 'manual',
    });
    assertCondition(oauthInitReservedWorkspace.status === 302, 'oauth init redirects on reserved workspace slug');
    assertCondition(
      String(oauthInitReservedWorkspace.headers.get('location') || '').includes('reserved_workspace_slug'),
      'oauth init reserved workspace routes to reserved_workspace_slug'
    );

    const customerTenant = buildTenantSlug('customer');
    const cookieAuth = await registerAndLogin(base, 'customer-admin', 'executive_viewer', customerTenant);
    const cookieUserRoleToken = buildJwtHs256(jwtSecret, {
      sub: `redteam-viewer-${customerTenant}`,
      email: `redteam.viewer.${customerTenant}@cybertron.local`,
      role: 'executive_viewer',
      tenant: customerTenant,
      iat: nowSeconds,
      exp: nowSeconds + 3600,
    });
    const customerSuperAdminToken = buildJwtHs256(jwtSecret, {
      sub: `redteam-super-admin-${customerTenant}`,
      email: `redteam.super.admin.${customerTenant}@cybertron.local`,
      role: 'super_admin',
      tenant: customerTenant,
      iat: nowSeconds,
      exp: nowSeconds + 3600,
    });
    const customerAnalystToken = buildJwtHs256(jwtSecret, {
      sub: `redteam-analyst-${customerTenant}`,
      email: `redteam.analyst.${customerTenant}@cybertron.local`,
      role: 'security_analyst',
      tenant: customerTenant,
      iat: nowSeconds,
      exp: nowSeconds + 3600,
    });
    const customerMe = await fetch(`${base}/v1/auth/me`, {
      headers: {
        Authorization: `Bearer ${cookieAuth.accessToken}`,
      },
    });
    assertCondition(customerMe.status === 200, 'cookie-auth self-service user can load profile');
    const customerMeBody = await customerMe.json();
    const customerUserId = String(customerMeBody?.id || customerMeBody?.user?.id || '');
    assertCondition(Boolean(customerUserId), 'cookie-auth self-service user returns numeric user id');
    const tenantAdminAcmeToken = buildJwtHs256(jwtSecret, {
      sub: 'redteam-tenant-admin-acme',
      email: 'redteam.tenant.admin@cybertron.local',
      role: 'tenant_admin',
      tenant: 'acme',
      iat: nowSeconds,
      exp: nowSeconds + 3600,
    });

    const upgradedPlan = await updateTenantPlan(base, customerSuperAdminToken, customerTenant, 'pro');
    const upgradedPlanBody = await upgradedPlan.json();
    assertCondition(upgradedPlan.status === 200, 'super admin can upgrade customer tenant plan for report checks');
    assertCondition(upgradedPlanBody.tier === 'pro', 'customer tenant plan upgraded to pro');

    const roleMismatchBody = new FormData();
    roleMismatchBody.append('reportType', 'role_mismatch');
    roleMismatchBody.append('reportDate', new Date().toISOString().slice(0, 10));
    roleMismatchBody.append(
      'file',
      new Blob(['%PDF-1.4\nrole mismatch'], { type: 'application/pdf' }),
      'viewer.pdf'
    );
    const roleMismatch = await fetch(`${base}/v1/reports/upload?tenant=${encodeURIComponent(customerTenant)}`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${cookieUserRoleToken}`,
      },
      body: roleMismatchBody,
    });
    assertCondition(roleMismatch.status === 403, 'executive viewer role cannot upload report files');

    const forbiddenMimeBody = new FormData();
    forbiddenMimeBody.append('reportType', 'forbidden_mime');
    forbiddenMimeBody.append('reportDate', new Date().toISOString().slice(0, 10));
    forbiddenMimeBody.append('file', new Blob(['hello-world'], { type: 'text/plain' }), 'notes.txt');
    const forbiddenMime = await fetch(
      `${base}/v1/reports/upload?tenant=${encodeURIComponent(customerTenant)}`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${customerAnalystToken}`,
        },
        body: forbiddenMimeBody,
      }
    );
    assertCondition(forbiddenMime.status === 415, 'forbidden mime type upload is rejected');

    const oversizedBody = new FormData();
    oversizedBody.append('reportType', 'oversized_upload');
    oversizedBody.append('reportDate', new Date().toISOString().slice(0, 10));
    oversizedBody.append(
      'file',
      new Blob([Buffer.alloc(4096, 0x41)], { type: 'application/pdf' }),
      'oversized.pdf'
    );
    const oversized = await fetch(`${base}/v1/reports/upload?tenant=${encodeURIComponent(customerTenant)}`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${customerAnalystToken}`,
      },
      body: oversizedBody,
    });
    assertCondition(oversized.status === 413, 'oversized upload is rejected');

    const allowedBody = new FormData();
    allowedBody.append('reportType', 'tenant_scope');
    allowedBody.append('reportDate', new Date().toISOString().slice(0, 10));
    allowedBody.append(
      'file',
      new Blob(['%PDF-1.4\ntenant scope'], { type: 'application/pdf' }),
      'tenant-scope.pdf'
    );
    const allowedUpload = await fetch(`${base}/v1/reports/upload?tenant=${encodeURIComponent(customerTenant)}`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${customerAnalystToken}`,
      },
      body: allowedBody,
    });
    const allowedUploadBody = await allowedUpload.json();
    assertCondition(
      allowedUpload.status === 201 || allowedUpload.status === 200,
      'valid upload succeeds in red-team checks'
    );
    const uploadedReportId = String(allowedUploadBody?.report?.id || '');
    assertCondition(Boolean(uploadedReportId), 'valid upload returns report id');

    const tenantMismatchToken = buildJwtHs256(jwtSecret, {
      sub: 'redteam-tenant-mismatch',
      email: 'redteam.tenant@cybertron.local',
      role: 'security_analyst',
      tenant: 'acme',
      iat: nowSeconds,
      exp: nowSeconds + 3600,
    });

    const tenantMismatchDownload = await fetch(`${base}/v1/reports/${uploadedReportId}/download?tenant=acme`, {
      headers: {
        Authorization: `Bearer ${tenantMismatchToken}`,
      },
    });
    assertCondition(
      tenantMismatchDownload.status === 404 || tenantMismatchDownload.status === 403,
      'tenant mismatch cannot download another tenant report'
    );

    const unauthorizedDownload = await fetch(
      `${base}/v1/reports/${uploadedReportId}/download?tenant=${encodeURIComponent(customerTenant)}`
    );
    assertCondition(unauthorizedDownload.status === 401, 'download without auth is rejected');

    const crossTenantThreatSummary = await fetch(
      `${base}/v1/threats/summary?tenant=${encodeURIComponent(customerTenant)}`,
      {
        headers: {
          Authorization: `Bearer ${tenantAdminAcmeToken}`,
        },
      }
    );
    assertCondition(
      crossTenantThreatSummary.status === 403 || crossTenantThreatSummary.status === 404,
      'cross-tenant threat summary read is denied'
    );

    const crossTenantThreatIncidents = await fetch(
      `${base}/v1/threats/incidents?tenant=${encodeURIComponent(customerTenant)}`,
      {
        headers: {
          Authorization: `Bearer ${tenantAdminAcmeToken}`,
        },
      }
    );
    assertCondition(
      crossTenantThreatIncidents.status === 403 || crossTenantThreatIncidents.status === 404,
      'cross-tenant threat incidents read is denied'
    );

    const crossTenantIncidents = await fetch(`${base}/v1/incidents?tenant=${encodeURIComponent(customerTenant)}`, {
      headers: {
        Authorization: `Bearer ${tenantAdminAcmeToken}`,
      },
    });
    assertCondition(
      crossTenantIncidents.status === 403 || crossTenantIncidents.status === 404,
      'cross-tenant incidents read is denied'
    );

    const crossTenantUsers = await fetch(`${base}/v1/users?tenant=${encodeURIComponent(customerTenant)}`, {
      headers: {
        Authorization: `Bearer ${tenantAdminAcmeToken}`,
      },
    });
    assertCondition(
      crossTenantUsers.status === 403 || crossTenantUsers.status === 404,
      'cross-tenant users read is denied'
    );

    const crossTenantReports = await fetch(`${base}/v1/reports?tenant=${encodeURIComponent(customerTenant)}`, {
      headers: {
        Authorization: `Bearer ${tenantAdminAcmeToken}`,
      },
    });
    assertCondition(
      crossTenantReports.status === 403 || crossTenantReports.status === 404,
      'cross-tenant reports read is denied'
    );

    const cookieHeader = toCookieHeader(cookieAuth.setCookies);
    const csrfToken = readCookieValue(cookieAuth.setCookies, 'ct_csrf');
    assertCondition(Boolean(cookieHeader), 'login returned auth cookies for csrf checks');
    assertCondition(Boolean(csrfToken), 'csrf cookie token present');

    const csrfDenied = await fetch(`${base}/v1/auth/logout`, {
      method: 'POST',
      headers: {
        Cookie: cookieHeader,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        tenant: customerTenant,
      }),
    });
    assertCondition(csrfDenied.status === 403, 'mutation with auth cookies requires csrf header');

    const csrfAllowed = await fetch(`${base}/v1/auth/logout`, {
      method: 'POST',
      headers: {
        Cookie: cookieHeader,
        'x-csrf-token': csrfToken,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        tenant: customerTenant,
      }),
    });
    assertCondition(csrfAllowed.status === 204, 'csrf header allows cookie-auth mutation');
      const cookieRevocation = await fetchRevocationRecord(hashAccessToken(cookieAuth.accessToken));
      assertCondition(Boolean(cookieRevocation), 'cookie logout persists revocation row');
      assertCondition(cookieRevocation.user_id === customerUserId, 'cookie logout persists numeric user_id');
      assertCondition(
        cookieRevocation.user_subject === customerUserId,
        'cookie logout persists user_subject alongside numeric user_id'
      );
  } else {
    process.stdout.write(
      'SKIP: DATABASE_URL is not set; DB-backed red-team checks for tenant/report/auth workflows were skipped.\n'
    );
  }
}

async function run() {
  const hasDatabase = Boolean(process.env.DATABASE_URL);
  const requireDatabase = shouldRequireDatabase();
  if (requireDatabase && !hasDatabase && !allowDevDatabaseSkip()) {
    throw new Error(
      'DATABASE_URL is required for red-team checks when REQUIRE_DATABASE_FOR_CI=true (or CI=true).'
    );
  }

  if (!hasDatabase) {
    process.stdout.write(
      'WARN: Running red-team checks without DATABASE_URL. DB-backed attack paths will be skipped.\n'
    );
  }

  const child = spawn(process.execPath, ['server.js'], {
    cwd: backendRoot,
    env: {
      ...process.env,
      PORT: String(port),
      AUTH_MODE: process.env.AUTH_MODE || 'jwt_hs256',
      JWT_SECRET: process.env.JWT_SECRET || 'red-team-jwt-secret',
      ALLOW_INSECURE_DEMO_AUTH: process.env.ALLOW_INSECURE_DEMO_AUTH || 'false',
      ALLOW_PUBLIC_REGISTRATION:
        process.env.ALLOW_PUBLIC_REGISTRATION || (hasDatabase ? 'true' : 'false'),
      METRICS_REQUIRE_AUTH: process.env.METRICS_REQUIRE_AUTH || 'true',
      METRICS_AUTH_TOKEN: process.env.METRICS_AUTH_TOKEN || 'red-team-metrics-token',
      AUTH_RATE_LIMIT_MAX_REQUESTS: process.env.AUTH_RATE_LIMIT_MAX_REQUESTS || (hasDatabase ? '100' : '5'),
      AUTH_IDENTITY_RATE_LIMIT_MAX_REQUESTS:
        process.env.AUTH_IDENTITY_RATE_LIMIT_MAX_REQUESTS || '5',
      REPORT_RATE_LIMIT_MAX_REQUESTS: String(reportRateLimitMaxForChecks),
      REPORT_RATE_LIMIT_WINDOW_MS: process.env.REPORT_RATE_LIMIT_WINDOW_MS || '60000',
      REPORT_UPLOAD_MAX_BYTES: process.env.REPORT_UPLOAD_MAX_BYTES || '1024',
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
    process.stdout.write('Backend red-team checks passed.\n');
  } finally {
    child.kill('SIGTERM');
  }
}

run().catch(error => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
