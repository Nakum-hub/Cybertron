#!/usr/bin/env node

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const WORKSPACE_ROOT = path.resolve(__dirname, '..');
const DEFAULT_BASE_URL = String(process.env.CYBERTRON_BASE_URL || 'http://127.0.0.1:3000').replace(/\/+$/, '');
const DEFAULT_ADMIN_EMAIL = String(process.env.CYBERTRON_ADMIN_EMAIL || 'admin@cybertron.local').trim().toLowerCase();
const DEFAULT_ADMIN_TENANT = String(process.env.CYBERTRON_ADMIN_TENANT || 'global').trim().toLowerCase();
const DEFAULT_USERS_PER_PLAN = 15;
const DEFAULT_PASSWORD = String(process.env.CYBERTRON_AUDIT_PASSWORD || 'CybertronAudit2026!');

const PLAN_FEATURES = {
  free: {
    label: 'Starter',
    maxTeamMembers: 3,
    modules: ['threat-command'],
    reportUpload: false,
  },
  pro: {
    label: 'Pro',
    maxTeamMembers: 10,
    modules: ['threat-command', 'identity-guardian', 'resilience-hq'],
    reportUpload: true,
  },
  enterprise: {
    label: 'Enterprise',
    maxTeamMembers: 999999,
    modules: [
      'threat-command',
      'identity-guardian',
      'resilience-hq',
      'risk-copilot',
      'compliance-engine',
      'threat-intel',
    ],
    reportUpload: true,
  },
};

const ROLE_RANK = {
  executive_viewer: 1,
  compliance_officer: 2,
  security_analyst: 3,
  tenant_admin: 4,
  super_admin: 5,
};

const ROLE_ORDER = [
  'executive_viewer',
  'compliance_officer',
  'security_analyst',
  'tenant_admin',
  'super_admin',
];

const APP_REQUIREMENTS = {
  'threat-command': 'executive_viewer',
  'identity-guardian': 'security_analyst',
  'resilience-hq': 'executive_viewer',
  'risk-copilot': 'executive_viewer',
};

const PUBLIC_ROUTE_PROBES = [
  { key: 'landing', path: '/', expected: ['CYBERTRON'] },
  { key: 'account', path: '/account?mode=login', expected: ['Account Center', 'Secure Login'] },
  { key: 'about', path: '/about', expected: ['Building the Future of', 'Cyber Operations'] },
  { key: 'blog', path: '/blog', expected: ['Security Insights'] },
  { key: 'pricing', path: '/pricing', expected: ['Affordable Cyber Defense'] },
  { key: 'privacy', path: '/legal/privacy', expected: ['Privacy Policy'] },
  { key: 'terms', path: '/legal/terms', expected: ['Terms of Service'] },
  { key: 'cookies', path: '/legal/cookies', expected: ['Cookie Policy'] },
  { key: 'status', path: '/status', expected: ['Cybertron Runtime Health'] },
];

const AUTH_ROUTE_PROBES = [
  {
    key: 'account',
    path: user => '/account',
    expected: ['Account Center'],
  },
  {
    key: 'platform',
    path: user => `/platform?tenant=${encodeURIComponent(user.tenant)}&role=${encodeURIComponent(user.role)}`,
    expectedAny: ['Multi-App Operations Shell', 'Platform Workspace'],
  },
  {
    key: 'threat-intel-product',
    path: user => `/products/threat-intel?tenant=${encodeURIComponent(user.tenant)}&role=${encodeURIComponent(user.role)}`,
    expected: ['Threat intelligence and SOC workflows driven by real feeds and playbooks'],
  },
  {
    key: 'risk-copilot-product',
    path: user => `/products/risk-copilot?tenant=${encodeURIComponent(user.tenant)}&role=${encodeURIComponent(user.role)}`,
    expected: ['AI-assisted risk prioritization backed by live tenant findings'],
  },
  {
    key: 'compliance-engine-product',
    path: user => `/products/compliance-engine?tenant=${encodeURIComponent(user.tenant)}&role=${encodeURIComponent(user.role)}`,
    expected: ['Compliance and resilience oversight with live framework and policy state'],
  },
];

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
    '  node scripts/plan-access-audit.js --password <super-admin-password> [options]',
    '',
    'Options:',
    `  --base-url <value>         Frontend base URL (default: ${DEFAULT_BASE_URL})`,
    `  --email <value>            Super admin email (default: ${DEFAULT_ADMIN_EMAIL})`,
    `  --tenant <value>           Super admin tenant (default: ${DEFAULT_ADMIN_TENANT})`,
    `  --users-per-plan <value>   User accounts to create per plan (default: ${DEFAULT_USERS_PER_PLAN})`,
    `  --password-template <value> Password assigned to generated audit users (default: ${DEFAULT_PASSWORD})`,
    '  --skip-browser             Skip Playwright page audit',
    '  --help                     Show this help text',
  ].join('\n');
}

function normalizeBoolean(value, fallback = false) {
  if (value === undefined || value === null || value === '') {
    return fallback;
  }

  const normalized = String(value).trim().toLowerCase();
  if (normalized === 'true') {
    return true;
  }
  if (normalized === 'false') {
    return false;
  }
  return fallback;
}

function toPositiveInteger(value, fallback) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
}

function nowStamp() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function buildUrl(baseUrl, relativePath) {
  return new URL(relativePath, `${baseUrl}/`).toString();
}

function buildAuthHeaders(accessToken, extras = {}) {
  return accessToken
    ? {
        Authorization: `Bearer ${accessToken}`,
        ...extras,
      }
    : extras;
}

async function request(url, init = {}) {
  const response = await fetch(url, init);
  const contentType = String(response.headers.get('content-type') || '').toLowerCase();
  let body = null;

  if (
    contentType.includes('application/pdf') ||
    contentType.includes('application/octet-stream') ||
    contentType.includes('image/png')
  ) {
    body = Buffer.from(await response.arrayBuffer());
    return { response, body, contentType };
  }

  const text = await response.text();
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
  }

  return { response, body, contentType };
}

function extractErrorCode(body) {
  if (!body || typeof body !== 'object') {
    return '';
  }
  return String(body.error?.code || body.code || '').trim();
}

function extractErrorMessage(body) {
  if (!body || typeof body !== 'object') {
    return typeof body === 'string' ? body : '';
  }
  return String(body.error?.message || body.message || '').trim();
}

function roleAllowed(actualRole, requiredRole) {
  return Number(ROLE_RANK[actualRole] || 0) >= Number(ROLE_RANK[requiredRole] || 0);
}

function expectedAppIdsFor(planTier, role) {
  const plan = PLAN_FEATURES[planTier] || PLAN_FEATURES.free;
  return Object.keys(APP_REQUIREMENTS)
    .filter(appId => plan.modules.includes(appId))
    .filter(appId => roleAllowed(role, APP_REQUIREMENTS[appId]))
    .sort();
}

function uniqueSorted(values) {
  return [...new Set(values.filter(Boolean))].sort();
}

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

async function login(baseUrl, email, password, tenant) {
  const result = await request(buildUrl(baseUrl, '/api/v1/auth/login'), {
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

  return {
    status: result.response.status,
    body: result.body,
    accessToken: result.body?.tokens?.accessToken || '',
    refreshToken: result.body?.tokens?.refreshToken || '',
  };
}

async function registerUser(baseUrl, accessToken, payload) {
  return request(buildUrl(baseUrl, '/api/v1/auth/register'), {
    method: 'POST',
    headers: buildAuthHeaders(accessToken, {
      'Content-Type': 'application/json',
    }),
    body: JSON.stringify(payload),
  });
}

async function getJson(baseUrl, pathName, accessToken) {
  return request(buildUrl(baseUrl, pathName), {
    method: 'GET',
    headers: buildAuthHeaders(accessToken),
  });
}

async function putJson(baseUrl, pathName, accessToken, payload) {
  return request(buildUrl(baseUrl, pathName), {
    method: 'PUT',
    headers: buildAuthHeaders(accessToken, {
      'Content-Type': 'application/json',
    }),
    body: JSON.stringify(payload),
  });
}

async function patchJson(baseUrl, pathName, accessToken, payload) {
  return request(buildUrl(baseUrl, pathName), {
    method: 'PATCH',
    headers: buildAuthHeaders(accessToken, {
      'Content-Type': 'application/json',
    }),
    body: JSON.stringify(payload),
  });
}

async function postJson(baseUrl, pathName, accessToken, payload) {
  return request(buildUrl(baseUrl, pathName), {
    method: 'POST',
    headers: buildAuthHeaders(accessToken, {
      'Content-Type': 'application/json',
    }),
    body: payload === undefined ? undefined : JSON.stringify(payload),
  });
}

async function postForm(baseUrl, pathName, accessToken, formData, extraHeaders = {}) {
  return request(buildUrl(baseUrl, pathName), {
    method: 'POST',
    headers: buildAuthHeaders(accessToken, extraHeaders),
    body: formData,
  });
}

async function ensureAllProductsEnabled(baseUrl, accessToken, tenant) {
  const productsRes = await getJson(
    baseUrl,
    `/api/v1/tenants/${encodeURIComponent(tenant)}/products?role=super_admin`,
    accessToken
  );

  if (productsRes.response.status !== 200 || !Array.isArray(productsRes.body)) {
    return {
      status: productsRes.response.status,
      updatedProducts: [],
      failedProducts: [],
      body: productsRes.body,
    };
  }

  const updatedProducts = [];
  const failedProducts = [];

  for (const product of productsRes.body) {
    const productKey = String(product.productKey || product.productId || '').trim();
    if (!productKey) {
      continue;
    }

    const patchRes = await patchJson(
      baseUrl,
      `/api/v1/tenants/${encodeURIComponent(tenant)}/products/${encodeURIComponent(productKey)}`,
      accessToken,
      { enabled: true }
    );

    if (patchRes.response.status === 200) {
      updatedProducts.push(productKey);
      continue;
    }

    failedProducts.push({
      productKey,
      status: patchRes.response.status,
      code: extractErrorCode(patchRes.body),
      message: extractErrorMessage(patchRes.body),
    });
  }

  return {
    status: 200,
    updatedProducts: uniqueSorted(updatedProducts),
    failedProducts,
  };
}

async function ensureAllFeatureFlagsEnabled(baseUrl, accessToken, tenant) {
  const flagsRes = await getJson(
    baseUrl,
    `/api/v1/tenants/${encodeURIComponent(tenant)}/feature-flags`,
    accessToken
  );

  if (flagsRes.response.status !== 200 || !Array.isArray(flagsRes.body)) {
    return {
      status: flagsRes.response.status,
      updatedFlags: [],
      failedFlags: [],
      body: flagsRes.body,
    };
  }

  const updatedFlags = [];
  const failedFlags = [];

  for (const flag of flagsRes.body) {
    const flagKey = String(flag.flagKey || '').trim();
    if (!flagKey) {
      continue;
    }

    const patchRes = await patchJson(
      baseUrl,
      `/api/v1/tenants/${encodeURIComponent(tenant)}/feature-flags/${encodeURIComponent(flagKey)}`,
      accessToken,
      { enabled: true }
    );

    if (patchRes.response.status === 200) {
      updatedFlags.push(flagKey);
      continue;
    }

    failedFlags.push({
      flagKey,
      status: patchRes.response.status,
      code: extractErrorCode(patchRes.body),
      message: extractErrorMessage(patchRes.body),
    });
  }

  return {
    status: 200,
    updatedFlags: uniqueSorted(updatedFlags),
    failedFlags,
  };
}

function createAuditUsers(tenant, usersPerPlan, passwordTemplate) {
  const users = [];
  const replicasPerRole = Math.max(1, Math.ceil(usersPerPlan / ROLE_ORDER.length));
  let ordinal = 0;

  for (const role of ROLE_ORDER) {
    for (let replica = 1; replica <= replicasPerRole; replica += 1) {
      if (ordinal >= usersPerPlan) {
        break;
      }
      ordinal += 1;
      users.push({
        planOrdinal: ordinal,
        tenant,
        role,
        replica,
        email: `${tenant}.${role}.${replica}@cybertron.dev`,
        displayName: `${tenant} ${role.replace(/_/g, ' ')} ${replica}`,
        password: passwordTemplate,
        primary: replica === 1,
      });
    }
  }

  return users;
}

function buildRiskLogForm(tenant, role) {
  const payload = {
    records: [
      {
        severity: 'high',
        category: 'identity',
        assetId: `${tenant}-${role}-asset`,
        title: 'Plan audit AWS log ingestion probe',
        vulnerabilityScore: 8.2,
        exposureScore: 6.8,
        misconfigurationScore: 7.4,
        accountId: '123456789012',
        region: 'us-east-1',
        eventName: 'AttachRolePolicy',
      },
    ],
  };

  const form = new FormData();
  form.append('file', new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }), `${tenant}-${role}-aws-logs.json`);
  return form;
}

function buildReportForm(tenant, role) {
  const payload = JSON.stringify({
    source: 'plan-access-audit',
    tenant,
    role,
    generatedAt: new Date().toISOString(),
  });
  const form = new FormData();
  form.append('file', new Blob([payload], { type: 'application/json' }), `${tenant}-${role}-audit.json`);
  form.append('reportType', 'plan_access_audit');
  form.append('reportDate', new Date().toISOString().slice(0, 10));
  form.append('metadata', JSON.stringify({ source: 'plan-access-audit', tenant, role }));
  return form;
}

function probeDefinitions(context) {
  const { tenant, role, planTier } = context;
  const modules = new Set((PLAN_FEATURES[planTier] || PLAN_FEATURES.free).modules);
  const reportUploadAllowed = Boolean((PLAN_FEATURES[planTier] || PLAN_FEATURES.free).reportUpload);

  return [
    {
      key: 'billing_usage',
      expected: roleAllowed(role, 'security_analyst'),
      run: accessToken => getJson(baseUrlGlobal, `/api/v1/billing/usage?tenant=${encodeURIComponent(tenant)}&limit=1`, accessToken),
    },
    {
      key: 'incidents_list',
      expected: modules.has('threat-command') && roleAllowed(role, 'executive_viewer'),
      run: accessToken => getJson(baseUrlGlobal, `/api/v1/incidents?tenant=${encodeURIComponent(tenant)}&limit=1`, accessToken),
    },
    {
      key: 'iocs_list',
      expected: modules.has('threat-command') && roleAllowed(role, 'executive_viewer'),
      run: accessToken => getJson(baseUrlGlobal, `/api/v1/iocs?tenant=${encodeURIComponent(tenant)}&limit=1`, accessToken),
    },
    {
      key: 'ioc_create',
      expected: modules.has('threat-command') && roleAllowed(role, 'security_analyst'),
      run: accessToken =>
        postJson(baseUrlGlobal, `/api/v1/iocs?tenant=${encodeURIComponent(tenant)}`, accessToken, {
          iocType: 'domain',
          value: `${crypto.randomUUID()}.audit.cybertron.dev`,
          source: 'plan-access-audit',
          confidence: 50,
        }),
    },
    {
      key: 'users_list',
      expected: roleAllowed(role, 'tenant_admin'),
      run: accessToken => getJson(baseUrlGlobal, `/api/v1/users?tenant=${encodeURIComponent(tenant)}&limit=1`, accessToken),
    },
    {
      key: 'feature_flags_list',
      expected: roleAllowed(role, 'executive_viewer'),
      run: accessToken => getJson(baseUrlGlobal, `/api/v1/tenants/${encodeURIComponent(tenant)}/feature-flags`, accessToken),
    },
    {
      key: 'feature_flag_patch',
      expected: roleAllowed(role, 'tenant_admin'),
      run: accessToken =>
        patchJson(
          baseUrlGlobal,
          `/api/v1/tenants/${encodeURIComponent(tenant)}/feature-flags/risk_copilot_beta`,
          accessToken,
          { enabled: true }
        ),
    },
    {
      key: 'audit_logs',
      expected: modules.has('resilience-hq') && roleAllowed(role, 'tenant_admin'),
      run: accessToken => getJson(baseUrlGlobal, `/api/v1/audit-logs?tenant=${encodeURIComponent(tenant)}&limit=1`, accessToken),
    },
    {
      key: 'report_upload',
      expected: reportUploadAllowed && roleAllowed(role, 'security_analyst'),
      run: accessToken =>
        postForm(
          baseUrlGlobal,
          `/api/v1/reports/upload?tenant=${encodeURIComponent(tenant)}`,
          accessToken,
          buildReportForm(tenant, role),
          { 'Idempotency-Key': crypto.randomUUID() }
        ),
    },
    {
      key: 'soc2_controls',
      expected: modules.has('compliance-engine') && roleAllowed(role, 'executive_viewer'),
      inferred: true,
      run: accessToken => getJson(baseUrlGlobal, `/api/v1/compliance/soc2/controls?tenant=${encodeURIComponent(tenant)}`, accessToken),
    },
    {
      key: 'threat_intel_dashboard',
      expected: modules.has('threat-intel') && roleAllowed(role, 'executive_viewer'),
      run: accessToken => getJson(baseUrlGlobal, `/api/v1/threat-intel/dashboard?tenant=${encodeURIComponent(tenant)}`, accessToken),
    },
    {
      key: 'risk_ingest_aws_logs',
      expected: modules.has('risk-copilot') && roleAllowed(role, 'security_analyst'),
      run: accessToken =>
        postForm(
          baseUrlGlobal,
          `/api/v1/risk/ingest/aws-logs?tenant=${encodeURIComponent(tenant)}`,
          accessToken,
          buildRiskLogForm(tenant, role)
        ),
    },
  ];
}

let baseUrlGlobal = DEFAULT_BASE_URL;

function normalizeProbeStatus(status) {
  return status === 201 ? 201 : status;
}

function isAllowedStatus(status) {
  return status === 200 || status === 201;
}

function isDeniedStatus(status) {
  return status === 401 || status === 403;
}

function addIssue(report, issue) {
  report.issues.push({
    id: crypto.randomUUID(),
    ...issue,
  });
}

async function deepAuditUser(report, planReport, user) {
  const loginResult = await login(baseUrlGlobal, user.email, user.password, user.tenant);
  const audit = {
    user: {
      email: user.email,
      role: user.role,
      tenant: user.tenant,
      replica: user.replica,
      primary: user.primary,
    },
    login: {
      status: loginResult.status,
      success: loginResult.status === 200,
      errorCode: extractErrorCode(loginResult.body),
      errorMessage: extractErrorMessage(loginResult.body),
    },
    profile: null,
    billingPlan: null,
    billingCredits: null,
    platformApps: null,
    moduleRegistry: null,
    appStatuses: {},
    probes: {},
    issues: [],
  };

  if (loginResult.status !== 200 || !loginResult.accessToken) {
    const issue = {
      severity: 'high',
      type: 'login_failure',
      plan: planReport.planTier,
      tenant: user.tenant,
      role: user.role,
      email: user.email,
      message: `Login failed for ${user.email}: ${loginResult.status} ${audit.login.errorCode || audit.login.errorMessage || ''}`.trim(),
    };
    audit.issues.push(issue);
    addIssue(report, issue);
    return audit;
  }

  const accessToken = loginResult.accessToken;

  const [profileRes, planRes, creditsRes, appsRes, modulesRes] = await Promise.all([
    getJson(baseUrlGlobal, '/api/v1/auth/me', accessToken),
    getJson(baseUrlGlobal, `/api/v1/billing/plan?tenant=${encodeURIComponent(user.tenant)}`, accessToken),
    getJson(baseUrlGlobal, `/api/v1/billing/credits?tenant=${encodeURIComponent(user.tenant)}`, accessToken),
    getJson(
      baseUrlGlobal,
      `/api/v1/platform/apps?tenant=${encodeURIComponent(user.tenant)}&role=${encodeURIComponent(user.role)}`,
      accessToken
    ),
    getJson(
      baseUrlGlobal,
      `/api/v1/modules?tenant=${encodeURIComponent(user.tenant)}&role=${encodeURIComponent(user.role)}`,
      accessToken
    ),
  ]);

  audit.profile = {
    status: profileRes.response.status,
    body: profileRes.body,
  };
  audit.billingPlan = {
    status: planRes.response.status,
    body: planRes.body,
  };
  audit.billingCredits = {
    status: creditsRes.response.status,
    body: creditsRes.body,
  };
  audit.platformApps = {
    status: appsRes.response.status,
    appIds: Array.isArray(appsRes.body)
      ? uniqueSorted(appsRes.body.map(item => String(item.id || '').trim()))
      : [],
    rawCount: Array.isArray(appsRes.body) ? appsRes.body.length : 0,
  };
  audit.moduleRegistry = {
    status: modulesRes.response.status,
    appIds:
      modulesRes.body && Array.isArray(modulesRes.body.apps)
        ? uniqueSorted(modulesRes.body.apps.map(item => String(item.id || '').trim()))
        : [],
    moduleIds:
      modulesRes.body && Array.isArray(modulesRes.body.modules)
        ? uniqueSorted(modulesRes.body.modules.map(item => String(item.moduleId || '').trim()))
        : [],
  };

  const expectedAppIds = expectedAppIdsFor(planReport.planTier, user.role);
  const actualAppIds = audit.platformApps.appIds;
  audit.platformApps.expectedAppIds = expectedAppIds;
  audit.moduleRegistry.expectedAppIds = expectedAppIds;

  if (appsRes.response.status !== 200) {
    const issue = {
      severity: 'high',
      type: 'platform_apps_failure',
      plan: planReport.planTier,
      tenant: user.tenant,
      role: user.role,
      email: user.email,
      message: `Platform apps list failed with status ${appsRes.response.status}.`,
    };
    audit.issues.push(issue);
    addIssue(report, issue);
  } else if (JSON.stringify(actualAppIds) !== JSON.stringify(expectedAppIds)) {
    const issue = {
      severity: 'high',
      type: 'app_access_mismatch',
      plan: planReport.planTier,
      tenant: user.tenant,
      role: user.role,
      email: user.email,
      message: `Expected app ids ${expectedAppIds.join(', ') || '(none)'}, got ${actualAppIds.join(', ') || '(none)'}.`,
    };
    audit.issues.push(issue);
    addIssue(report, issue);
  }

  if (modulesRes.response.status !== 200) {
    const issue = {
      severity: 'high',
      type: 'module_registry_failure',
      plan: planReport.planTier,
      tenant: user.tenant,
      role: user.role,
      email: user.email,
      message: `Module registry failed with status ${modulesRes.response.status}.`,
    };
    audit.issues.push(issue);
    addIssue(report, issue);
  }

  for (const appId of Object.keys(APP_REQUIREMENTS)) {
    const statusRes = await getJson(
      baseUrlGlobal,
      `/api/v1/apps/${encodeURIComponent(appId)}/status?tenant=${encodeURIComponent(user.tenant)}&role=${encodeURIComponent(user.role)}`,
      accessToken
    );
    const shouldAllow = expectedAppIds.includes(appId);
    const normalizedStatus = normalizeProbeStatus(statusRes.response.status);
    audit.appStatuses[appId] = {
      status: normalizedStatus,
      code: extractErrorCode(statusRes.body),
      message: extractErrorMessage(statusRes.body),
      expectedAllowed: shouldAllow,
    };

    if ((shouldAllow && normalizedStatus !== 200) || (!shouldAllow && !isDeniedStatus(normalizedStatus))) {
      const issue = {
        severity: 'high',
        type: 'app_status_mismatch',
        plan: planReport.planTier,
        tenant: user.tenant,
        role: user.role,
        email: user.email,
        message: `App status mismatch for ${appId}: expected ${shouldAllow ? '200' : '403'}, got ${normalizedStatus}.`,
      };
      audit.issues.push(issue);
      addIssue(report, issue);
    }
  }

  for (const probe of probeDefinitions({
    tenant: user.tenant,
    role: user.role,
    planTier: planReport.planTier,
  })) {
    const result = await probe.run(accessToken);
    const status = normalizeProbeStatus(result.response.status);
    const code = extractErrorCode(result.body);
    const message = extractErrorMessage(result.body);

    audit.probes[probe.key] = {
      status,
      code,
      message,
      expectedAllowed: probe.expected,
      inferred: probe.inferred === true,
    };

    if (status >= 500) {
      const issue = {
        severity: 'critical',
        type: 'server_error',
        plan: planReport.planTier,
        tenant: user.tenant,
        role: user.role,
        email: user.email,
        message: `Endpoint ${probe.key} returned ${status}.`,
      };
      audit.issues.push(issue);
      addIssue(report, issue);
      continue;
    }

    if (probe.expected && !isAllowedStatus(status)) {
      const issue = {
        severity: probe.inferred ? 'medium' : 'high',
        type: 'expected_access_denied',
        plan: planReport.planTier,
        tenant: user.tenant,
        role: user.role,
        email: user.email,
        message: `Endpoint ${probe.key} should be allowed but returned ${status}${code ? ` (${code})` : ''}.`,
      };
      audit.issues.push(issue);
      addIssue(report, issue);
      continue;
    }

    if (!probe.expected && isAllowedStatus(status)) {
      const issue = {
        severity: probe.inferred ? 'medium' : 'high',
        type: 'unexpected_access_allowed',
        plan: planReport.planTier,
        tenant: user.tenant,
        role: user.role,
        email: user.email,
        message: `Endpoint ${probe.key} should be blocked but returned ${status}.`,
      };
      audit.issues.push(issue);
      addIssue(report, issue);
    }
  }

  return audit;
}

async function smokeAuditUser(report, planReport, user, baselineAppIds) {
  const loginResult = await login(baseUrlGlobal, user.email, user.password, user.tenant);
  const smoke = {
    user: {
      email: user.email,
      role: user.role,
      tenant: user.tenant,
      replica: user.replica,
    },
    loginStatus: loginResult.status,
    platformApps: null,
    issues: [],
  };

  if (loginResult.status !== 200 || !loginResult.accessToken) {
    const issue = {
      severity: 'high',
      type: 'duplicate_login_failure',
      plan: planReport.planTier,
      tenant: user.tenant,
      role: user.role,
      email: user.email,
      message: `Duplicate smoke login failed with status ${loginResult.status}.`,
    };
    smoke.issues.push(issue);
    addIssue(report, issue);
    return smoke;
  }

  const appsRes = await getJson(
    baseUrlGlobal,
    `/api/v1/platform/apps?tenant=${encodeURIComponent(user.tenant)}&role=${encodeURIComponent(user.role)}`,
    loginResult.accessToken
  );

  smoke.platformApps = {
    status: appsRes.response.status,
    appIds: Array.isArray(appsRes.body)
      ? uniqueSorted(appsRes.body.map(item => String(item.id || '').trim()))
      : [],
  };

  if (appsRes.response.status !== 200) {
    const issue = {
      severity: 'high',
      type: 'duplicate_platform_apps_failure',
      plan: planReport.planTier,
      tenant: user.tenant,
      role: user.role,
      email: user.email,
      message: `Duplicate platform app listing failed with status ${appsRes.response.status}.`,
    };
    smoke.issues.push(issue);
    addIssue(report, issue);
    return smoke;
  }

  if (JSON.stringify(smoke.platformApps.appIds) !== JSON.stringify(baselineAppIds)) {
    const issue = {
      severity: 'high',
      type: 'duplicate_access_inconsistency',
      plan: planReport.planTier,
      tenant: user.tenant,
      role: user.role,
      email: user.email,
      message: `Duplicate user app ids ${smoke.platformApps.appIds.join(', ') || '(none)'} differ from baseline ${baselineAppIds.join(', ') || '(none)'}.`,
    };
    smoke.issues.push(issue);
    addIssue(report, issue);
  }

  return smoke;
}

async function runPlanAudit(report, accessToken, planTier, usersPerPlan, passwordTemplate) {
  const tenant = `audit-${planTier}-${Date.now().toString(36)}-${crypto.randomUUID().slice(0, 6)}`;
  const planReport = {
    planTier,
    tenant,
    usersRequested: usersPerPlan,
    usersProvisioned: [],
    provisioningFailures: [],
    products: null,
    featureFlags: null,
    finalPlan: null,
    primaryAudits: [],
    duplicateAudits: [],
    limitProbe: null,
  };

  const users = createAuditUsers(tenant, usersPerPlan, passwordTemplate);

  const setEnterprise = await putJson(
    baseUrlGlobal,
    `/api/v1/billing/plan?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    { tenant, tier: 'enterprise' }
  );

  if (setEnterprise.response.status !== 200) {
    addIssue(report, {
      severity: 'critical',
      type: 'plan_seed_failure',
      plan: planTier,
      tenant,
      message: `Failed to seed tenant ${tenant} with enterprise plan before provisioning (${setEnterprise.response.status}).`,
    });
    planReport.finalPlan = {
      status: setEnterprise.response.status,
      body: setEnterprise.body,
    };
    return planReport;
  }

  for (const user of users) {
    const registerRes = await registerUser(baseUrlGlobal, accessToken, {
      tenant,
      email: user.email,
      password: user.password,
      displayName: user.displayName,
      role: user.role,
    });

    if (registerRes.response.status === 201) {
      planReport.usersProvisioned.push(cloneJson(user));
      continue;
    }

    planReport.provisioningFailures.push({
      user: cloneJson(user),
      status: registerRes.response.status,
      code: extractErrorCode(registerRes.body),
      message: extractErrorMessage(registerRes.body),
    });
    addIssue(report, {
      severity: 'high',
      type: 'provisioning_failure',
      plan: planTier,
      tenant,
      role: user.role,
      email: user.email,
      message: `Failed to provision ${user.email}: ${registerRes.response.status} ${extractErrorCode(registerRes.body) || extractErrorMessage(registerRes.body)}`.trim(),
    });
  }

  planReport.products = await ensureAllProductsEnabled(baseUrlGlobal, accessToken, tenant);
  for (const failure of planReport.products.failedProducts || []) {
    addIssue(report, {
      severity: 'medium',
      type: 'product_enable_failure',
      plan: planTier,
      tenant,
      message: `Failed to enable product ${failure.productKey}: ${failure.status} ${failure.code || failure.message}`.trim(),
    });
  }

  planReport.featureFlags = await ensureAllFeatureFlagsEnabled(baseUrlGlobal, accessToken, tenant);
  for (const failure of planReport.featureFlags.failedFlags || []) {
    addIssue(report, {
      severity: 'medium',
      type: 'feature_flag_enable_failure',
      plan: planTier,
      tenant,
      message: `Failed to enable feature flag ${failure.flagKey}: ${failure.status} ${failure.code || failure.message}`.trim(),
    });
  }

  const setFinalPlan = await putJson(
    baseUrlGlobal,
    `/api/v1/billing/plan?tenant=${encodeURIComponent(tenant)}`,
    accessToken,
    { tenant, tier: planTier }
  );

  planReport.finalPlan = {
    status: setFinalPlan.response.status,
    body: setFinalPlan.body,
  };

  if (setFinalPlan.response.status !== 200 || String(setFinalPlan.body?.tier || '').trim().toLowerCase() !== planTier) {
    addIssue(report, {
      severity: 'critical',
      type: 'plan_downgrade_failure',
      plan: planTier,
      tenant,
      message: `Failed to apply final plan ${planTier}.`,
    });
  }

  const primaryUsers = planReport.usersProvisioned.filter(user => user.primary);
  const duplicateUsers = planReport.usersProvisioned.filter(user => !user.primary);
  const primaryBaselines = new Map();

  for (const user of primaryUsers) {
    const audit = await deepAuditUser(report, planReport, user);
    planReport.primaryAudits.push(audit);
    if (audit.platformApps?.appIds) {
      primaryBaselines.set(user.role, cloneJson(audit.platformApps.appIds));
    }
  }

  for (const user of duplicateUsers) {
    const baselineAppIds = primaryBaselines.get(user.role) || expectedAppIdsFor(planTier, user.role);
    const smoke = await smokeAuditUser(report, planReport, user, baselineAppIds);
    planReport.duplicateAudits.push(smoke);
  }

  const extraUser = {
    tenant,
    email: `${tenant}.limit-probe@cybertron.dev`,
    password: passwordTemplate,
    displayName: `${tenant} limit probe`,
    role: 'executive_viewer',
  };
  const limitProbeRes = await registerUser(baseUrlGlobal, accessToken, extraUser);
  planReport.limitProbe = {
    attempted: true,
    expectedBlocked: planTier !== 'enterprise',
    status: limitProbeRes.response.status,
    code: extractErrorCode(limitProbeRes.body),
    message: extractErrorMessage(limitProbeRes.body),
  };

  if (planTier !== 'enterprise' && limitProbeRes.response.status !== 403) {
    addIssue(report, {
      severity: 'high',
      type: 'team_limit_not_enforced',
      plan: planTier,
      tenant,
      message: `Team member limit probe was expected to fail after downgrade to ${planTier}, but returned ${limitProbeRes.response.status}.`,
    });
  }

  if (planTier === 'enterprise' && limitProbeRes.response.status !== 201) {
    addIssue(report, {
      severity: 'medium',
      type: 'enterprise_limit_probe_failure',
      plan: planTier,
      tenant,
      message: `Enterprise limit probe should have succeeded, but returned ${limitProbeRes.response.status}.`,
    });
  }

  return planReport;
}

async function runBrowserAudit(report, outputDir) {
  const playwrightPath = path.resolve(WORKSPACE_ROOT, 'app', 'frontend', 'node_modules', 'playwright');
  const browserReport = {
    attempted: true,
    publicRoutes: [],
    authenticatedRoutes: [],
    skipped: false,
    reason: '',
  };

  let chromium;
  try {
    ({ chromium } = require(playwrightPath));
  } catch (error) {
    browserReport.skipped = true;
    browserReport.reason = error instanceof Error ? error.message : 'Playwright is unavailable.';
    addIssue(report, {
      severity: 'medium',
      type: 'browser_audit_skipped',
      message: `Browser audit skipped: ${browserReport.reason}`,
    });
    return browserReport;
  }

  const screenshotDir = path.join(outputDir, 'screenshots');
  ensureDir(screenshotDir);

  let browser;
  try {
    browser = await chromium.launch({ headless: true });
  } catch (error) {
    browserReport.skipped = true;
    browserReport.reason = error instanceof Error ? error.message : 'Chromium launch failed.';
    addIssue(report, {
      severity: 'medium',
      type: 'browser_launch_failure',
      message: `Browser audit skipped: ${browserReport.reason}`,
    });
    return browserReport;
  }

  try {
    for (const probe of PUBLIC_ROUTE_PROBES) {
      const page = await browser.newPage({ viewport: { width: 1440, height: 1100 } });
      const pageErrors = [];
      page.on('pageerror', error => {
        pageErrors.push(error.message);
      });
      page.on('console', message => {
        if (message.type() === 'error') {
          pageErrors.push(message.text());
        }
      });

      await page.goto(buildUrl(baseUrlGlobal, probe.path), { waitUntil: 'networkidle' });
      const bodyText = await page.locator('body').innerText();
      const matched = probe.expected.every(fragment => bodyText.includes(fragment));
      const routeResult = {
        key: probe.key,
        path: probe.path,
        matched,
        errors: uniqueSorted(pageErrors),
      };

      if (!matched || pageErrors.length) {
        const screenshotPath = path.join(screenshotDir, `public-${probe.key}.png`);
        await page.screenshot({ path: screenshotPath, fullPage: true });
        routeResult.screenshot = screenshotPath;
        addIssue(report, {
          severity: 'high',
          type: 'public_route_failure',
          route: probe.path,
          message: `Public route ${probe.path} did not render expected content cleanly.`,
        });
      }

      browserReport.publicRoutes.push(routeResult);
      await page.close();
    }

    for (const planReport of report.planAudits) {
      for (const audit of planReport.primaryAudits) {
        if (!audit.login?.success) {
          continue;
        }

        const user = audit.user;
        const context = await browser.newContext({ viewport: { width: 1440, height: 1100 } });
        const page = await context.newPage();
        const pageErrors = [];
        page.on('pageerror', error => {
          pageErrors.push(error.message);
        });
        page.on('console', message => {
          if (message.type() === 'error') {
            pageErrors.push(message.text());
          }
        });

        await page.goto(
          buildUrl(
            baseUrlGlobal,
            `/account?mode=login&tenant=${encodeURIComponent(user.tenant)}&returnTo=${encodeURIComponent('/account')}`
          ),
          { waitUntil: 'networkidle' }
        );
        await page.getByPlaceholder('acme-security').fill(user.tenant);
        await page.getByPlaceholder('name@company.com').fill(user.email);
        await page.getByPlaceholder('Enter a strong password').fill(DEFAULT_PASSWORD);
        await page.getByRole('button', { name: 'Secure Login' }).click();
        await page.waitForURL(url => url.pathname === '/account', { timeout: 20_000 });

        for (const probe of AUTH_ROUTE_PROBES) {
          const routeErrors = [];
          pageErrors.length = 0;
          await page.goto(buildUrl(baseUrlGlobal, probe.path(user)), { waitUntil: 'networkidle' });
          const bodyText = await page.locator('body').innerText();
          const expectedAll = probe.expected ? probe.expected.every(fragment => bodyText.includes(fragment)) : true;
          const expectedAny = probe.expectedAny ? probe.expectedAny.some(fragment => bodyText.includes(fragment)) : true;
          routeErrors.push(...pageErrors);
          const matched = expectedAll && expectedAny;

          const routeResult = {
            plan: planReport.planTier,
            role: user.role,
            email: user.email,
            key: probe.key,
            path: probe.path(user),
            matched,
            errors: uniqueSorted(routeErrors),
          };

          if (!matched || routeErrors.length) {
            const screenshotPath = path.join(
              screenshotDir,
              `${planReport.planTier}-${user.role}-${probe.key}.png`
            );
            await page.screenshot({ path: screenshotPath, fullPage: true });
            routeResult.screenshot = screenshotPath;
            addIssue(report, {
              severity: 'high',
              type: 'authenticated_route_failure',
              plan: planReport.planTier,
              role: user.role,
              email: user.email,
              route: probe.path(user),
              message: `Authenticated route ${probe.path(user)} did not render expected content cleanly.`,
            });
          }

          browserReport.authenticatedRoutes.push(routeResult);
        }

        await context.close();
      }
    }
  } finally {
    await browser.close();
  }

  return browserReport;
}

function buildMarkdownReport(report) {
  const lines = [];
  lines.push('# Plan Access Audit');
  lines.push('');
  lines.push(`- Generated at: ${report.generatedAt}`);
  lines.push(`- Base URL: ${report.baseUrl}`);
  lines.push(`- Super admin: ${report.admin.email} (${report.admin.tenant})`);
  lines.push(`- Users requested per plan: ${report.usersPerPlan}`);
  lines.push(`- Total issues: ${report.issues.length}`);
  lines.push('');

  lines.push('## Plans');
  lines.push('');
  lines.push('| Plan | Tenant | Provisioned | Final Plan Status | Limit Probe |');
  lines.push('| --- | --- | ---: | --- | --- |');
  for (const planReport of report.planAudits) {
    const limitProbe = planReport.limitProbe
      ? `${planReport.limitProbe.status}${planReport.limitProbe.code ? ` (${planReport.limitProbe.code})` : ''}`
      : 'n/a';
    lines.push(
      `| ${planReport.planTier} | ${planReport.tenant} | ${planReport.usersProvisioned.length} | ${planReport.finalPlan?.status || 'n/a'} | ${limitProbe} |`
    );
  }
  lines.push('');

  lines.push('## Primary Access Matrix');
  lines.push('');
  lines.push('| Plan | Role | Expected Apps | Actual Apps |');
  lines.push('| --- | --- | --- | --- |');
  for (const planReport of report.planAudits) {
    for (const audit of planReport.primaryAudits) {
      lines.push(
        `| ${planReport.planTier} | ${audit.user.role} | ${(audit.platformApps?.expectedAppIds || []).join(', ') || '(none)'} | ${(audit.platformApps?.appIds || []).join(', ') || '(none)'} |`
      );
    }
  }
  lines.push('');

  lines.push('## Findings');
  lines.push('');
  if (!report.issues.length) {
    lines.push('- No issues were recorded by the automated audit.');
  } else {
    for (const issue of report.issues) {
      const scope = [issue.plan, issue.role, issue.route].filter(Boolean).join(' / ');
      lines.push(`- [${String(issue.severity || 'info').toUpperCase()}] ${issue.type}${scope ? ` (${scope})` : ''}: ${issue.message}`);
    }
  }
  lines.push('');

  if (report.browserAudit?.attempted) {
    lines.push('## Browser Audit');
    lines.push('');
    if (report.browserAudit.skipped) {
      lines.push(`- Skipped: ${report.browserAudit.reason}`);
    } else {
      lines.push(`- Public routes checked: ${report.browserAudit.publicRoutes.length}`);
      lines.push(`- Authenticated routes checked: ${report.browserAudit.authenticatedRoutes.length}`);
    }
    lines.push('');
  }

  return `${lines.join('\n')}\n`;
}

async function run() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help === 'true') {
    process.stdout.write(`${usage()}\n`);
    return;
  }

  const baseUrl = String(args['base-url'] || DEFAULT_BASE_URL).replace(/\/+$/, '');
  const email = String(args.email || DEFAULT_ADMIN_EMAIL).trim().toLowerCase();
  const tenant = String(args.tenant || DEFAULT_ADMIN_TENANT).trim().toLowerCase();
  const password = String(args.password || process.env.CYBERTRON_ADMIN_PASSWORD || '').trim();
  const usersPerPlan = toPositiveInteger(args['users-per-plan'], DEFAULT_USERS_PER_PLAN);
  const passwordTemplate = String(args['password-template'] || DEFAULT_PASSWORD).trim() || DEFAULT_PASSWORD;
  const skipBrowser = normalizeBoolean(args['skip-browser'], false);

  if (password.length < 10) {
    throw new Error('A real super admin password is required.');
  }

  baseUrlGlobal = baseUrl;

  const outputDir = path.resolve(
    WORKSPACE_ROOT,
    '.runtime',
    'plan-access-audit',
    nowStamp()
  );
  ensureDir(outputDir);

  const report = {
    generatedAt: new Date().toISOString(),
    baseUrl,
    admin: {
      email,
      tenant,
    },
    usersPerPlan,
    planAudits: [],
    browserAudit: null,
    issues: [],
  };

  const adminLogin = await login(baseUrl, email, password, tenant);
  if (adminLogin.status !== 200 || !adminLogin.accessToken) {
    throw new Error(
      `Super admin login failed (${adminLogin.status}) ${extractErrorCode(adminLogin.body) || extractErrorMessage(adminLogin.body)}`
    );
  }

  const adminProfile = await getJson(baseUrl, '/api/v1/auth/me', adminLogin.accessToken);
  if (adminProfile.response.status !== 200) {
    throw new Error(`Unable to verify super admin profile (${adminProfile.response.status}).`);
  }
  const effectiveRole = String(adminProfile.body?.role || '').trim();
  if (effectiveRole !== 'super_admin') {
    throw new Error(`Expected a super_admin session but received role "${effectiveRole || 'unknown'}".`);
  }

  for (const planTier of Object.keys(PLAN_FEATURES)) {
    const planReport = await runPlanAudit(
      report,
      adminLogin.accessToken,
      planTier,
      usersPerPlan,
      passwordTemplate
    );
    report.planAudits.push(planReport);
  }

  if (!skipBrowser) {
    report.browserAudit = await runBrowserAudit(report, outputDir);
  } else {
    report.browserAudit = {
      attempted: false,
      skipped: true,
      reason: 'Skipped by --skip-browser.',
      publicRoutes: [],
      authenticatedRoutes: [],
    };
  }

  const jsonPath = path.join(outputDir, 'report.json');
  const markdownPath = path.join(outputDir, 'report.md');
  fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2));
  fs.writeFileSync(markdownPath, buildMarkdownReport(report));

  process.stdout.write(`Plan access audit report written to ${jsonPath}\n`);
  process.stdout.write(`Markdown summary written to ${markdownPath}\n`);

  if (report.issues.length) {
    process.stdout.write(`Audit completed with ${report.issues.length} issue(s).\n`);
    return;
  }

  process.stdout.write('Audit completed with no recorded issues.\n');
}

run().catch(error => {
  process.stderr.write(`${error instanceof Error ? error.stack || error.message : String(error)}\n`);
  process.exitCode = 1;
});
