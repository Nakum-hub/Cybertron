#!/usr/bin/env node

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const workspaceRoot = path.resolve(__dirname, '..');
const backendConfigPath = path.join(workspaceRoot, 'app', 'backend', 'src', 'config.js');
const defaultEnvFilePath = path.join(workspaceRoot, '.env');

const DEFAULT_LOCAL_ADMIN_EMAIL = 'admin@cybertron.local';
const DEFAULT_LOCAL_ADMIN_PASSWORD = 'Cyb3rtron!H100!2026';
const DEFAULT_LOCAL_ADMIN_TENANT = 'global';

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
    '  node scripts/go-live-readiness.js --env-file <path> [options]',
    '',
    'Options:',
    '  --env-file <path>       Production env file to validate (default: workspace/.env)',
    '  --base-url <value>      Online deployment base URL for live sweeps (required unless --skip-live)',
    '  --email <value>         Production admin email for live sweeps',
    '  --password <value>      Production admin password for live sweeps',
    '  --tenant <value>        Admin tenant slug for live sweeps (default: global)',
    '  --skip-live             Skip smoke / AI sweep / feature sweep execution',
  ].join('\n');
}

function assertCondition(condition, label, details = '') {
  if (!condition) {
    const suffix = details ? `\n${details}` : '';
    throw new Error(`FAIL: ${label}${suffix}`);
  }

  process.stdout.write(`PASS: ${label}\n`);
}

function warn(label, details = '') {
  const suffix = details ? `\n${details}` : '';
  process.stdout.write(`WARN: ${label}${suffix}\n`);
}

function readEnvFile(filePath) {
  const source = fs.readFileSync(filePath, 'utf8');
  const values = {};

  for (const rawLine of source.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) {
      continue;
    }

    const separatorIndex = line.indexOf('=');
    if (separatorIndex === -1) {
      continue;
    }

    const key = line.slice(0, separatorIndex).trim();
    const value = line.slice(separatorIndex + 1).trim();
    values[key] = value.replace(/^"(.*)"$/, '$1').replace(/^'(.*)'$/, '$1');
  }

  return values;
}

function toBoolean(value, fallback = false) {
  if (value === undefined || value === null || value === '') {
    return fallback;
  }

  const normalized = String(value).trim().toLowerCase();
  if (normalized === 'true') return true;
  if (normalized === 'false') return false;
  return fallback;
}

function parseUrl(value) {
  try {
    return new URL(String(value || ''));
  } catch {
    return null;
  }
}

function firstNonEmpty(...values) {
  for (const candidate of values) {
    const normalized = String(candidate || '').trim();
    if (normalized) {
      return normalized;
    }
  }

  return '';
}

function isHttpsUrl(value) {
  const parsed = parseUrl(value);
  return parsed?.protocol === 'https:';
}

function isLocalLikeUrl(value) {
  const parsed = parseUrl(value);
  const hostname = String(parsed?.hostname || '').toLowerCase().trim();
  return (
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname === 'host.docker.internal' ||
    hostname === 'minio' ||
    hostname.endsWith('.local')
  );
}

function extractUrlPassword(value) {
  const parsed = parseUrl(value);
  return parsed ? decodeURIComponent(parsed.password || '') : '';
}

function containsReservedDemoMarker(value) {
  const normalized = String(value || '').toLowerCase();
  return (
    /change[\W_]*me/.test(normalized) ||
    /replace[\W_]*me/.test(normalized) ||
    normalized.includes('placeholder') ||
    normalized.includes('example.com') ||
    normalized.includes('example.org') ||
    normalized.includes('cybertron-local') ||
    normalized.includes('local-docker') ||
    normalized.includes('dev-jwt-secret') ||
    normalized.includes('http://127.0.0.1') ||
    normalized.includes('http://localhost')
  );
}

function isWeakSecret(value) {
  const normalized = String(value || '').trim();
  if (!normalized) {
    return true;
  }

  return normalized.length < 24 || containsReservedDemoMarker(normalized);
}

function runNodeScript(scriptPath, args, env) {
  return spawnSync(process.execPath, [scriptPath, ...args], {
    cwd: workspaceRoot,
    encoding: 'utf8',
    env,
  });
}

function runBackendConfigValidation(env) {
  const validationScript = [
    `const { config, validateRuntimeConfig } = require(${JSON.stringify(backendConfigPath)});`,
    'const result = validateRuntimeConfig(config);',
    'process.stdout.write(JSON.stringify(result));',
  ].join('\n');

  const result = spawnSync(process.execPath, ['-e', validationScript], {
    cwd: workspaceRoot,
    encoding: 'utf8',
    env,
  });

  if ((result.status ?? 1) !== 0) {
    throw new Error(`FAIL: Backend runtime config validation bootstrap failed\n${result.stderr || result.stdout || 'Unknown validation error'}`);
  }

  return JSON.parse(result.stdout || '{}');
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

async function assertDefaultAdminCredentialsBlocked(baseUrl) {
  const login = await requestJson(`${baseUrl.replace(/\/+$/, '')}/api/v1/auth/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      tenant: DEFAULT_LOCAL_ADMIN_TENANT,
      email: DEFAULT_LOCAL_ADMIN_EMAIL,
      password: DEFAULT_LOCAL_ADMIN_PASSWORD,
    }),
  });

  assertCondition(
    login.response.status !== 200,
    'default local bootstrap admin credentials are rejected by the online deployment',
    'Rotate the default bootstrap admin account before any internet-facing launch.'
  );
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help === 'true') {
    process.stdout.write(`${usage()}\n`);
    return;
  }

  const envFile = path.resolve(args['env-file'] || defaultEnvFilePath);
  const skipLive = args['skip-live'] === 'true';
  const baseUrl = String(args['base-url'] || '').trim();
  const adminEmail = String(args.email || '').trim().toLowerCase();
  const adminPassword = String(args.password || '').trim();
  const tenant = String(args.tenant || DEFAULT_LOCAL_ADMIN_TENANT).trim().toLowerCase();

  assertCondition(fs.existsSync(envFile), 'go-live env file exists', envFile);
  assertCondition(
    !/\.local(\.|$)/i.test(path.basename(envFile)),
    'internet deploy is not using a .local env template',
    `Refusing to certify local validation template for internet launch: ${envFile}`
  );
  assertCondition(
    !/\.example$/i.test(path.basename(envFile)),
    'internet deploy is not using an example env template directly',
    `Copy the production template to a real env file with rotated secrets before launch: ${envFile}`
  );

  const fileEnv = readEnvFile(envFile);
  const env = {
    ...process.env,
    ...fileEnv,
  };

  assertCondition(
    String(env.NODE_ENV || '').trim().toLowerCase() === 'production',
    'NODE_ENV is production in the go-live env'
  );

  const validation = runBackendConfigValidation(env);
  assertCondition(
    validation.ok === true,
    'backend runtime config validation passes for the go-live env',
    [
      ...(validation.errors || []).map(item => `- ${item}`),
      ...(validation.warnings || []).length > 0 ? ['Warnings:'] : [],
      ...((validation.warnings || []).map(item => `- ${item}`)),
    ].join('\n')
  );

  assertCondition(
    toBoolean(env.LOCAL_PRODUCTION_VALIDATION, false) === false,
    'LOCAL_PRODUCTION_VALIDATION is disabled for internet deployment'
  );
  assertCondition(
    !containsReservedDemoMarker(env.APP_VERSION || ''),
    'APP_VERSION does not contain local/dev markers'
  );
  assertCondition(
    !containsReservedDemoMarker(env.FRONTEND_ORIGIN || ''),
    'FRONTEND_ORIGIN does not use example/local placeholder values'
  );
  assertCondition(
    String(env.REPORT_STORAGE_DRIVER || '').trim().toLowerCase() === 's3',
    'internet deployment uses S3-backed report storage',
    'Online deployments must not rely on local container filesystem storage for evidence and reports.'
  );
  assertCondition(
    String(env.LLM_PROVIDER || '').trim().toLowerCase() !== 'none',
    'LLM_PROVIDER is configured for online deployment'
  );
  const databasePassword = firstNonEmpty(env.POSTGRES_PASSWORD, extractUrlPassword(env.DATABASE_URL));
  const redisPassword = firstNonEmpty(env.REDIS_PASSWORD, extractUrlPassword(env.REDIS_URL));
  assertCondition(
    !isWeakSecret(databasePassword),
    'database credential is non-placeholder and sufficiently strong'
  );
  assertCondition(
    !isWeakSecret(redisPassword),
    'Redis credential is non-placeholder and sufficiently strong'
  );
  assertCondition(
    !isWeakSecret(env.METRICS_AUTH_TOKEN),
    'METRICS_AUTH_TOKEN is non-placeholder and sufficiently strong'
  );
  assertCondition(
    String(env.DB_SSL_MODE || '').trim().toLowerCase() !== 'disable',
    'DB_SSL_MODE is not disabled for internet deployment'
  );
  assertCondition(
    !isLocalLikeUrl(env.DATABASE_URL),
    'DATABASE_URL is not pointing at a local-only host'
  );
  assertCondition(
    !isLocalLikeUrl(env.REDIS_URL),
    'REDIS_URL is not pointing at a local-only host'
  );

  if (String(env.REPORT_STORAGE_S3_ENDPOINT || '').trim()) {
    assertCondition(
      isHttpsUrl(env.REPORT_STORAGE_S3_ENDPOINT),
      'REPORT_STORAGE_S3_ENDPOINT uses https for internet deployment'
    );
    assertCondition(
      !isLocalLikeUrl(env.REPORT_STORAGE_S3_ENDPOINT),
      'REPORT_STORAGE_S3_ENDPOINT is not pointing at a local-only host'
    );
  }

  if (String(env.LLM_PROVIDER || '').trim().toLowerCase() === 'openai') {
    assertCondition(
      isHttpsUrl(env.OPENAI_BASE_URL),
      'OPENAI_BASE_URL uses https for internet deployment'
    );
    assertCondition(
      !isLocalLikeUrl(env.OPENAI_BASE_URL),
      'OPENAI_BASE_URL is not pointing at a local-only host'
    );
    assertCondition(
      !isWeakSecret(env.OPENAI_API_KEY),
      'OPENAI_API_KEY is non-placeholder and sufficiently strong'
    );
  }

  if (String(env.OIDC_ISSUER_URL || '').trim()) {
    assertCondition(isHttpsUrl(env.OIDC_ISSUER_URL), 'OIDC_ISSUER_URL uses https');
  }

  for (const [key, value] of Object.entries({
    WAZUH_API_URL: env.WAZUH_API_URL,
    MISP_API_URL: env.MISP_API_URL,
    OPENCTI_API_URL: env.OPENCTI_API_URL,
    THEHIVE_API_URL: env.THEHIVE_API_URL,
  })) {
    if (!String(value || '').trim()) {
      continue;
    }
    assertCondition(isHttpsUrl(value), `${key} uses https`);
    assertCondition(!isLocalLikeUrl(value), `${key} is not pointing at a local-only host`);
  }

  if (!String(env.WAZUH_API_URL || env.MISP_API_URL || env.OPENCTI_API_URL || env.THEHIVE_API_URL || '').trim()) {
    warn(
      'no external threat connectors are configured',
      'Threat intel is still real via NVD, but live SOC ingestion breadth will remain limited until at least one connector is configured.'
    );
  } else {
    const connectorReadinessResult = runNodeScript(
      path.join(workspaceRoot, 'scripts', 'connector-readiness.js'),
      ['--env-file', envFile, '--require-healthy', '--json'],
      process.env
    );
    assertCondition(
      (connectorReadinessResult.status ?? 1) === 0,
      'configured threat connectors are healthy for internet deployment',
      `${connectorReadinessResult.stdout || ''}${connectorReadinessResult.stderr || ''}`.trim()
    );
  }

  if (toBoolean(env.ALLOW_PUBLIC_REGISTRATION, false)) {
    warn(
      'ALLOW_PUBLIC_REGISTRATION is enabled',
      'Invite-only onboarding is safer for an initial internet launch unless abuse controls and customer provisioning workflows are fully ready.'
    );
  }

  if (skipLive) {
    process.stdout.write('Go-live readiness checks passed without executing live sweeps.\n');
    return;
  }

  assertCondition(Boolean(baseUrl), 'base URL is provided for live go-live sweeps');
  assertCondition(Boolean(adminEmail), 'production admin email is provided for live go-live sweeps');
  assertCondition(Boolean(adminPassword), 'production admin password is provided for live go-live sweeps');
  assertCondition(
    adminEmail !== DEFAULT_LOCAL_ADMIN_EMAIL,
    'production admin email is not the local bootstrap default'
  );
  assertCondition(
    adminPassword !== DEFAULT_LOCAL_ADMIN_PASSWORD,
    'production admin password is not the local bootstrap default'
  );

  await assertDefaultAdminCredentialsBlocked(baseUrl);

  const smokeResult = runNodeScript(
    path.join(workspaceRoot, 'scripts', 'prod-stack-smoke.js'),
    [
      '--base-url',
      baseUrl,
      '--email',
      adminEmail,
      '--password',
      adminPassword,
      '--tenant',
      tenant,
      '--expect-storage-provider',
      's3',
    ],
    process.env
  );
  assertCondition(
    (smokeResult.status ?? 1) === 0,
    'production smoke passes for the target online deployment',
    `${smokeResult.stdout || ''}${smokeResult.stderr || ''}`.trim()
  );

  const aiSweepResult = runNodeScript(
    path.join(workspaceRoot, 'scripts', 'prod-ai-quality-sweep.js'),
    [
      '--base-url',
      baseUrl,
      '--email',
      adminEmail,
      '--password',
      adminPassword,
      '--tenant',
      tenant,
    ],
    process.env
  );
  assertCondition(
    (aiSweepResult.status ?? 1) === 0,
    'production AI quality sweep passes for the target online deployment',
    `${aiSweepResult.stdout || ''}${aiSweepResult.stderr || ''}`.trim()
  );

  const featureSweepResult = runNodeScript(
    path.join(workspaceRoot, 'scripts', 'prod-feature-sweep.js'),
    [
      '--base-url',
      baseUrl,
      '--email',
      adminEmail,
      '--password',
      adminPassword,
      '--tenant',
      tenant,
    ],
    process.env
  );
  assertCondition(
    (featureSweepResult.status ?? 1) === 0,
    'production feature sweep passes for the target online deployment',
    `${featureSweepResult.stdout || ''}${featureSweepResult.stderr || ''}`.trim()
  );

  process.stdout.write('Go-live readiness checks passed.\n');
}

main().catch(error => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
