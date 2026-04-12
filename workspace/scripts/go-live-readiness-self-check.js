#!/usr/bin/env node

const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const workspaceRoot = path.resolve(__dirname, '..');
const scriptPath = path.resolve(__dirname, 'go-live-readiness.js');

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

function runReadiness(args = []) {
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

async function main() {
  const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'cybertron-go-live-'));

  try {
    const insecureLocalEnvPath = path.join(tempRoot, '.env.production.local');
    await writeFile(
      insecureLocalEnvPath,
      [
        'NODE_ENV=production',
        'FRONTEND_ORIGIN=http://127.0.0.1:8088',
        'CORS_ALLOWED_ORIGINS=http://127.0.0.1:8088',
        'LOCAL_PRODUCTION_VALIDATION=true',
        'AUTH_MODE=jwt_hs256',
        'JWT_SECRET=cybertron-local-docker-jwt-secret-1234567890',
        'REDIS_URL=redis://:cybertron_redis_password@redis:6379',
        'REDIS_PASSWORD=cybertron_redis_password',
        'DATABASE_URL=postgresql://cybertron:cybertron_prod_password@postgres:5432/cybertron',
        'DB_SSL_MODE=disable',
        'METRICS_AUTH_TOKEN=cybertron-local-metrics-token-123456',
        'REPORT_STORAGE_DRIVER=local',
        'LLM_PROVIDER=none',
        'TRUST_PROXY=true',
      ].join('\n')
    );

    const insecureRun = runReadiness(['--env-file', insecureLocalEnvPath, '--skip-live']);
    assertCondition(insecureRun.status !== 0, 'go-live gate rejects local validation env files');
    assertCondition(
      insecureRun.output.includes('FAIL: internet deploy is not using a .local env template'),
      'go-live gate explains local env file rejection'
    );

    const secureEnvPath = path.join(tempRoot, 'internet-ready.env');
    await writeFile(
      secureEnvPath,
      [
        'NODE_ENV=production',
        'APP_VERSION=1.0.0',
        'FRONTEND_ORIGIN=https://app.cybertronsecurity.com',
        'CORS_ALLOWED_ORIGINS=https://app.cybertronsecurity.com',
        'LOCAL_PRODUCTION_VALIDATION=false',
        'AUTH_MODE=jwt_hs256',
        'JWT_SECRET=prod-secure-jwt-secret-abcdefghijklmnopqrstuvwxyz-123456',
        'POSTGRES_PASSWORD=prod-db-password-abcdefghijklmnopqrstuvwxyz',
        'REDIS_URL=rediss://:prod-redis-password-abcdefghijklmnopqrstuvwxyz@redis.cybertronsecurity.com:6379',
        'REDIS_PASSWORD=prod-redis-password-abcdefghijklmnopqrstuvwxyz',
        'DATABASE_URL=postgresql://cybertron:prod-db-password-abcdefghijklmnopqrstuvwxyz@db.cybertronsecurity.com:5432/cybertron',
        'DB_SSL_MODE=require',
        'METRICS_AUTH_TOKEN=prod-metrics-token-abcdefghijklmnopqrstuvwxyz-123456',
        'REPORT_STORAGE_DRIVER=s3',
        'REPORT_STORAGE_S3_BUCKET=cybertron-prod-reports',
        'REPORT_STORAGE_S3_REGION=us-east-1',
        'REPORT_STORAGE_S3_ENDPOINT=https://s3.us-east-1.amazonaws.com',
        'LLM_PROVIDER=openai',
        'OPENAI_API_KEY=sk-prod-abcdefghijklmnopqrstuvwxyz-1234567890',
        'OPENAI_BASE_URL=https://api.openai.com/v1',
        'OPENAI_MODEL=gpt-4.1-mini',
        'STRICT_DEPENDENCIES=true',
        'TRUST_PROXY=true',
        'REQUIRE_AUTH_FOR_THREAT_ENDPOINTS=true',
        'REQUIRE_AUTH_FOR_PLATFORM_ENDPOINTS=true',
        'METRICS_REQUIRE_AUTH=true',
        'AUTH_COOKIE_SECURE=true',
        'CSRF_ENABLED=true',
      ].join('\n')
    );

    const secureRun = runReadiness(['--env-file', secureEnvPath, '--skip-live']);
    assertCondition(secureRun.status === 0, 'go-live gate passes secure internet-ready env without live sweeps');
    assertCondition(
      secureRun.output.includes('PASS: backend runtime config validation passes for the go-live env'),
      'go-live gate runs backend runtime validation'
    );
    assertCondition(
      secureRun.output.includes('Go-live readiness checks passed without executing live sweeps.'),
      'go-live gate finishes with the expected success summary'
    );

    process.stdout.write('Go-live readiness self-checks passed.\n');
  } finally {
    await fs.rm(tempRoot, { recursive: true, force: true });
  }
}

main().catch(error => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
