/**
 * Integration tests - Auth flows.
 * Tests: register, login, me, logout, password-reset, rate-limit
 *
 * Run: npm run test:integration
 */
const { before, describe, it } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const BASE = process.env.TEST_BASE_URL || 'http://127.0.0.1:8001';
const TEST_TENANT = process.env.TEST_TENANT || 'test-tenant';

function request(method, path, body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE);
    const opts = {
      method,
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      headers: {
        'Content-Type': 'application/json',
        ...headers,
      },
    };

    const req = http.request(opts, res => {
      let data = '';
      res.on('data', chunk => {
        data += chunk;
      });
      res.on('end', () => {
        let parsed = null;
        try {
          parsed = JSON.parse(data);
        } catch {
          parsed = data;
        }
        resolve({ status: res.statusCode, headers: res.headers, body: parsed });
      });
    });

    req.on('error', reject);
    if (body) {
      req.write(JSON.stringify(body));
    }
    req.end();
  });
}

describe('Auth Integration Tests', () => {
  const uniqueEmail = `test-auth-${Date.now()}@cybertron-test.io`;
  const password = 'TestP@ssw0rd!2026';
  let accessToken = null;
  let dbReady = false;
  let readinessFailure = '';

  before(async () => {
    try {
      const readiness = await request('GET', '/api/v1/system/readiness');
      const database = readiness.body?.dependencies?.database;
      dbReady =
        readiness.status === 200 &&
        readiness.body?.ready === true &&
        database?.configured !== false &&
        database?.status !== 'down';

      if (!dbReady) {
        readinessFailure = `readiness=${readiness.status} database=${database?.status || 'unknown'}`;
      }
    } catch (error) {
      readinessFailure = error instanceof Error ? error.message : 'unknown readiness failure';
      dbReady = false;
    }
  });

  function requireDatabase(t) {
    if (!dbReady) {
      t.skip(`Database not ready for auth integration tests (${readinessFailure || 'unavailable'}).`);
      return false;
    }
    return true;
  }

  it('POST /v1/auth/register - should create user or return 409 for duplicate email', async t => {
    if (!requireDatabase(t)) {
      return;
    }

    const res = await request('POST', `/api/v1/auth/register?tenant=${TEST_TENANT}`, {
      email: uniqueEmail,
      password,
      displayName: 'Integration Test User',
    });

    assert.ok([201, 409].includes(res.status), `Expected 201 or 409, got ${res.status}`);
  });

  it('POST /v1/auth/login - correct credentials should return 200 and JWT', async t => {
    if (!requireDatabase(t)) {
      return;
    }

    const res = await request('POST', `/api/v1/auth/login?tenant=${TEST_TENANT}`, {
      email: uniqueEmail,
      password,
    });

    assert.equal(res.status, 200);
    assert.ok(res.body.user, 'Response should contain user');
    assert.ok(res.body.tokens || res.headers['set-cookie'], 'Should return tokens');
    if (res.body.tokens) {
      accessToken = res.body.tokens.accessToken;
    }
  });

  it('POST /v1/auth/login - wrong password should return 401', async t => {
    if (!requireDatabase(t)) {
      return;
    }

    const res = await request('POST', `/api/v1/auth/login?tenant=${TEST_TENANT}`, {
      email: uniqueEmail,
      password: 'wrong-password-12345',
    });

    assert.equal(res.status, 401);
  });

  it('GET /v1/auth/me - with valid token should return 200', async t => {
    if (!requireDatabase(t)) {
      return;
    }
    assert.ok(accessToken, 'Expected access token from login test');

    const res = await request('GET', '/api/v1/auth/me', null, {
      Authorization: `Bearer ${accessToken}`,
    });

    assert.equal(res.status, 200);
    assert.ok(res.body.email || res.body.user, 'Should return user profile');
  });

  it('GET /v1/auth/me - no token should return 401', async t => {
    if (!requireDatabase(t)) {
      return;
    }

    const res = await request('GET', '/api/v1/auth/me');
    assert.equal(res.status, 401);
  });

  it('POST /v1/auth/password/forgot - should return 200', async t => {
    if (!requireDatabase(t)) {
      return;
    }

    const res = await request('POST', `/api/v1/auth/password/forgot?tenant=${TEST_TENANT}`, {
      email: uniqueEmail,
    });

    assert.equal(res.status, 200);
    assert.ok(res.body.accepted !== undefined || res.body.message, 'Should confirm acceptance');
  });

  it('Rate limit: rapid login attempts should eventually return 429', async t => {
    if (!requireDatabase(t)) {
      return;
    }

    const attempts = [];
    for (let index = 0; index < 12; index += 1) {
      attempts.push(
        request('POST', `/api/v1/auth/login?tenant=${TEST_TENANT}`, {
          email: `ratelimit-${Date.now()}-${index}@test.io`,
          password: 'wrong',
        })
      );
    }

    const results = await Promise.all(attempts);
    const got429 = results.some(result => result.status === 429);

    assert.ok(got429, 'Expected at least one 429 response from auth rate limiting.');
  });
});
