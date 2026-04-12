#!/usr/bin/env node

const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const workspaceRoot = path.resolve(__dirname, '..');
const scriptPath = path.resolve(__dirname, 'connector-readiness.js');

function assertCondition(condition, label, details = '') {
  if (!condition) {
    const suffix = details ? `\n${details}` : '';
    throw new Error(`FAIL: ${label}${suffix}`);
  }

  process.stdout.write(`PASS: ${label}\n`);
}

async function writeFile(filePath, content) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, content, 'utf8');
}

function runCheck(args = []) {
  const result = spawnSync(process.execPath, [scriptPath, ...args], {
    cwd: workspaceRoot,
    encoding: 'utf8',
    env: process.env,
  });

  return {
    status: result.status ?? 1,
    output: `${result.stdout || ''}${result.stderr || ''}`,
  };
}

function buildBaseEnv() {
  return [
    'NODE_ENV=production',
    'APP_VERSION=1.0.0',
    'FRONTEND_ORIGIN=https://app.cybertronsecurity.com',
    'CORS_ALLOWED_ORIGINS=https://app.cybertronsecurity.com',
    'LOCAL_PRODUCTION_VALIDATION=false',
    'AUTH_MODE=jwt_hs256',
    'JWT_SECRET=prod-secure-jwt-secret-abcdefghijklmnopqrstuvwxyz-123456',
    'REDIS_URL=rediss://:prod-redis-password-abcdefghijklmnopqrstuvwxyz@redis.cybertronsecurity.com:6379',
    'REDIS_PASSWORD=prod-redis-password-abcdefghijklmnopqrstuvwxyz',
    'DATABASE_URL=postgresql://cybertron:prod-db-password-abcdefghijklmnopqrstuvwxyz@db.cybertronsecurity.com:5432/cybertron',
    'DB_SSL_MODE=require',
    'METRICS_REQUIRE_AUTH=true',
    'METRICS_AUTH_TOKEN=prod-metrics-token-abcdefghijklmnopqrstuvwxyz-123456',
    'REPORT_STORAGE_DRIVER=s3',
    'REPORT_STORAGE_S3_BUCKET=cybertron-prod-reports',
    'REPORT_STORAGE_S3_REGION=us-east-1',
    'LLM_PROVIDER=openai',
    'OPENAI_API_KEY=sk-prod-abcdefghijklmnopqrstuvwxyz-1234567890',
    'OPENAI_BASE_URL=https://api.openai.com/v1',
    'OPENAI_MODEL=gpt-4.1-mini',
    'STRICT_DEPENDENCIES=true',
    'TRUST_PROXY=true',
    'REQUIRE_AUTH_FOR_THREAT_ENDPOINTS=true',
    'REQUIRE_AUTH_FOR_PLATFORM_ENDPOINTS=true',
    'AUTH_COOKIE_SECURE=true',
    'CSRF_ENABLED=true',
  ];
}

async function main() {
  const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'cybertron-connector-readiness-'));

  try {
    const emptyEnvPath = path.join(tempRoot, 'empty-connectors.env');
    await writeFile(emptyEnvPath, buildBaseEnv().join('\n'));

    const emptyRun = runCheck(['--env-file', emptyEnvPath]);
    assertCondition(emptyRun.status === 0, 'connector readiness passes when no connectors are configured');
    assertCondition(
      emptyRun.output.includes('WARN: no external threat connectors are configured'),
      'connector readiness warns when connectors are absent'
    );

    const requireAnyRun = runCheck(['--env-file', emptyEnvPath, '--require-any']);
    assertCondition(requireAnyRun.status !== 0, 'connector readiness can require at least one configured connector');
    assertCondition(
      requireAnyRun.output.includes('FAIL: at least one threat connector is configured'),
      'connector readiness explains missing connector failure'
    );

    const privateHostEnvPath = path.join(tempRoot, 'private-host-connector.env');
    await writeFile(
      privateHostEnvPath,
      [...buildBaseEnv(), 'WAZUH_API_URL=https://localhost:9443'].join('\n')
    );
    const unhealthyRun = runCheck(['--env-file', privateHostEnvPath, '--require-healthy']);
    assertCondition(unhealthyRun.status !== 0, 'connector readiness fails when a configured connector is unhealthy');
    assertCondition(
      unhealthyRun.output.includes('SSRF blocked: request to private/internal address "localhost" is not allowed'),
      'connector readiness surfaces SSRF-safe connector failures'
    );

    process.stdout.write('Connector readiness self-checks passed.\n');
  } finally {
    await fs.rm(tempRoot, { recursive: true, force: true });
  }
}

main().catch(error => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
