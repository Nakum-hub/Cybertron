#!/usr/bin/env node

const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const path = require('node:path');

const backendRoot = path.resolve(__dirname, '..');
const portA = Number(process.env.BACKEND_DIST_AUTH_PORT_A || 8201);
const portB = Number(process.env.BACKEND_DIST_AUTH_PORT_B || 8202);

function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
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

function requireRedisUrl() {
  const redisUrl = String(process.env.REDIS_URL || '').trim();
  if (redisUrl) {
    return redisUrl;
  }

  if (String(process.env.ALLOW_QA_REDIS_SKIP || 'false').toLowerCase() === 'true') {
    process.stdout.write('SKIP: REDIS_URL is missing and ALLOW_QA_REDIS_SKIP=true.\n');
    process.exit(0);
  }

  throw new Error('REDIS_URL is required for qa:distributed-auth.');
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
      // service still starting
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

async function run() {
  const redisUrl = requireRedisUrl();
  const jwtSecret = process.env.JWT_SECRET || 'distributed-auth-secret';
  const sharedEnv = {
    NODE_ENV: process.env.NODE_ENV || 'development',
    HOST: '127.0.0.1',
    AUTH_MODE: 'jwt_hs256',
    JWT_SECRET: jwtSecret,
    REDIS_URL: redisUrl,
    DATABASE_URL: process.env.DATABASE_URL || '',
    DB_AUTO_MIGRATE: 'false',
    ALLOW_INSECURE_DEMO_AUTH: 'false',
    AUTH_COOKIE_SECURE: process.env.AUTH_COOKIE_SECURE || 'false',
    AUTH_COOKIE_SAMESITE: process.env.AUTH_COOKIE_SAMESITE || 'lax',
    CSRF_ENABLED: process.env.CSRF_ENABLED || 'true',
    METRICS_REQUIRE_AUTH: process.env.METRICS_REQUIRE_AUTH || 'false',
    RATE_LIMIT_MAX_REQUESTS: process.env.RATE_LIMIT_MAX_REQUESTS || '1000',
    AUTH_RATE_LIMIT_MAX_REQUESTS: process.env.AUTH_RATE_LIMIT_MAX_REQUESTS || '200',
    REPORT_RATE_LIMIT_MAX_REQUESTS: process.env.REPORT_RATE_LIMIT_MAX_REQUESTS || '200',
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

    const nowSeconds = Math.floor(Date.now() / 1000);
    const accessToken = buildJwtHs256(jwtSecret, {
      sub: 'distributed-auth-user',
      email: 'distributed.auth@cybertron.local',
      role: 'security_analyst',
      tenant: 'global',
      iat: nowSeconds,
      exp: nowSeconds + 3600,
    });

    const meBefore = await fetch(`http://127.0.0.1:${portB}/v1/auth/me`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });
    assertCondition(meBefore.status === 200, 'token is accepted on instance B before logout');

    const logout = await fetch(`http://127.0.0.1:${portA}/v1/auth/logout`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        tenant: 'global',
      }),
    });
    assertCondition(logout.status === 204, 'logout on instance A succeeds');

    let revokedOnB = false;
    const startedAt = Date.now();
    while (Date.now() - startedAt <= 1_000) {
      const replay = await fetch(`http://127.0.0.1:${portB}/v1/auth/me`, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });

      if (replay.status === 401 || replay.status === 403) {
        revokedOnB = true;
        break;
      }

      await wait(100);
    }

    assertCondition(revokedOnB, 'revoked token is rejected on instance B within 1 second');
    process.stdout.write('Distributed auth revocation checks passed.\n');
  } finally {
    await Promise.all([stopBackend(instanceA), stopBackend(instanceB)]);
  }
}

run().catch(error => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
