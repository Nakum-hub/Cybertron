#!/usr/bin/env node

const { spawn } = require('node:child_process');
const path = require('node:path');

const backendRoot = path.resolve(__dirname, '..');
const portA = Number(process.env.BACKEND_DIST_RATE_PORT_A || 8211);
const portB = Number(process.env.BACKEND_DIST_RATE_PORT_B || 8212);

function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function assertCondition(condition, label) {
  if (!condition) {
    throw new Error(`Assertion failed: ${label}`);
  }

  process.stdout.write(`PASS: ${label}\n`);
}

function requireRedisUrl() {
  const redisUrl = String(process.env.REDIS_URL || '').trim();
  if (redisUrl) {
    return redisUrl;
  }

  if (String(process.env.ALLOW_QA_REDIS_SKIP || 'false').toLowerCase() === 'true') {
    process.stdout.write('SKIP: REDIS_URL is missing and ALLOW_QA_REDIS_SKIP=true.\n');
    process.exit(0);
  }

  throw new Error('REDIS_URL is required for qa:distributed-rate.');
}

async function waitForHealth(port, maxAttempts = 60) {
  const url = `http://127.0.0.1:${port}/v1/system/health`;

  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        return;
      }
    } catch {
      // service booting
    }
    await wait(150);
  }

  throw new Error(`Backend on port ${port} did not become healthy in time.`);
}

function startBackend(port, sharedEnv) {
  return spawn(process.execPath, ['server.js'], {
    cwd: backendRoot,
    env: {
      ...process.env,
      ...sharedEnv,
      PORT: String(port),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

async function stopBackend(child) {
  if (!child || child.killed || child.exitCode !== null) {
    return;
  }

  child.kill('SIGTERM');
  await wait(300);
  if (child.exitCode === null && !child.killed) {
    child.kill('SIGKILL');
  }
}

async function expectDistributed429(label, requestBuilder, attempts, ports) {
  let hit429 = false;
  const perPortHits = new Set();

  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const port = ports[attempt % ports.length];
    perPortHits.add(port);
    const response = await requestBuilder(port, attempt);
    if (response.status === 429) {
      hit429 = true;
      break;
    }
  }

  assertCondition(perPortHits.size === ports.length, `${label} sends traffic to all instances`);
  assertCondition(hit429, `${label} is rate-limited across instances`);
}

async function run() {
  const redisUrl = requireRedisUrl();
  const sharedEnv = {
    NODE_ENV: process.env.NODE_ENV || 'development',
    HOST: '127.0.0.1',
    AUTH_MODE: process.env.AUTH_MODE || 'jwt_hs256',
    JWT_SECRET: process.env.JWT_SECRET || 'distributed-rate-secret',
    REDIS_URL: redisUrl,
    DATABASE_URL: process.env.DATABASE_URL || '',
    DB_AUTO_MIGRATE: 'false',
    ALLOW_INSECURE_DEMO_AUTH: 'false',
    AUTH_COOKIE_SECURE: process.env.AUTH_COOKIE_SECURE || 'false',
    AUTH_COOKIE_SAMESITE: process.env.AUTH_COOKIE_SAMESITE || 'lax',
    CSRF_ENABLED: process.env.CSRF_ENABLED || 'true',
    METRICS_REQUIRE_AUTH: process.env.METRICS_REQUIRE_AUTH || 'false',
    RATE_LIMIT_WINDOW_MS: process.env.RATE_LIMIT_WINDOW_MS || '60000',
    RATE_LIMIT_MAX_REQUESTS: process.env.RATE_LIMIT_MAX_REQUESTS || '6',
    AUTH_RATE_LIMIT_WINDOW_MS: process.env.AUTH_RATE_LIMIT_WINDOW_MS || '60000',
    AUTH_RATE_LIMIT_MAX_REQUESTS: process.env.AUTH_RATE_LIMIT_MAX_REQUESTS || '3',
    AUTH_IDENTITY_RATE_LIMIT_MAX_REQUESTS:
      process.env.AUTH_IDENTITY_RATE_LIMIT_MAX_REQUESTS || '3',
    REPORT_RATE_LIMIT_WINDOW_MS: process.env.REPORT_RATE_LIMIT_WINDOW_MS || '60000',
    REPORT_RATE_LIMIT_MAX_REQUESTS: process.env.REPORT_RATE_LIMIT_MAX_REQUESTS || '3',
  };

  const instanceA = startBackend(portA, sharedEnv);
  const instanceB = startBackend(portB, sharedEnv);
  instanceA.stdout.on('data', chunk => process.stdout.write(`[A] ${chunk.toString()}`));
  instanceA.stderr.on('data', chunk => process.stderr.write(`[A] ${chunk.toString()}`));
  instanceB.stdout.on('data', chunk => process.stdout.write(`[B] ${chunk.toString()}`));
  instanceB.stderr.on('data', chunk => process.stderr.write(`[B] ${chunk.toString()}`));

  try {
    await waitForHealth(portA);
    await waitForHealth(portB);
    const ports = [portA, portB];

    await expectDistributed429(
      'general endpoint limiter',
      async port =>
        fetch(`http://127.0.0.1:${port}/v1/system/health`, {
          method: 'GET',
        }),
      12,
      ports
    );

    await expectDistributed429(
      'auth endpoint limiter',
      async port =>
        fetch(`http://127.0.0.1:${port}/v1/auth/password/forgot`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            tenant: 'global',
            email: 'distributed.rate@cybertron.local',
          }),
        }),
      12,
      ports
    );

    await expectDistributed429(
      'report endpoint limiter',
      async port =>
        fetch(`http://127.0.0.1:${port}/v1/reports?tenant=global`, {
          method: 'GET',
        }),
      12,
      ports
    );

    process.stdout.write('Distributed rate limiting checks passed.\n');
  } finally {
    await Promise.all([stopBackend(instanceA), stopBackend(instanceB)]);
  }
}

run().catch(error => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
