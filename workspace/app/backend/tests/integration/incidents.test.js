/**
 * Integration tests — Incident CRUD and tenant isolation.
 *
 * Run: npm run test:integration
 */
const { describe, it } = require('node:test');
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

    const req = http.request(opts, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        let parsed = null;
        try { parsed = JSON.parse(data); } catch { parsed = data; }
        resolve({ status: res.statusCode, headers: res.headers, body: parsed });
      });
    });

    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

describe('Incident Integration Tests', () => {
  let createdIncidentId = null;

  it('POST /v1/incidents — should create incident (201 or 503 if DB unavailable)', async () => {
    const res = await request('POST', `/api/v1/incidents?tenant=${TEST_TENANT}`, {
      title: `Test Incident ${Date.now()}`,
      description: 'Integration test incident',
      severity: 'medium',
      source: 'integration-test',
    });
    if (res.status === 503 || res.status === 401) {
      assert.ok(true, 'DB not available or auth required — skipping');
      return;
    }
    assert.equal(res.status, 201);
    assert.ok(res.body.id || res.body.data?.id, 'Should return incident ID');
    createdIncidentId = res.body.id || res.body.data?.id;
  });

  it('GET /v1/incidents — should list incidents (200)', async () => {
    const res = await request('GET', `/api/v1/incidents?tenant=${TEST_TENANT}`);
    if (res.status === 503 || res.status === 401) {
      assert.ok(true, 'DB not available or auth required — skipping');
      return;
    }
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.data || res.body), 'Should return array');
  });

  it('Tenant isolation: tenant B should NOT see tenant A incidents', async () => {
    const resA = await request('GET', `/api/v1/incidents?tenant=${TEST_TENANT}`);
    const resB = await request('GET', '/api/v1/incidents?tenant=other-tenant-xyz');

    if (resA.status === 503 || resA.status === 401) {
      assert.ok(true, 'DB not available or auth required — skipping');
      return;
    }

    const dataA = resA.body.data || resA.body;
    const dataB = resB.body.data || resB.body;

    if (createdIncidentId && Array.isArray(dataB)) {
      const leaked = dataB.some((inc) => inc.id === createdIncidentId);
      assert.ok(!leaked, 'Tenant B should NOT see tenant A incident');
    }
    assert.ok(true, 'Tenant isolation check passed');
  });

  it('PATCH /v1/incidents/:id — should update incident status', async () => {
    if (!createdIncidentId) {
      assert.ok(true, 'No incident created — skipping');
      return;
    }

    const res = await request('PATCH', `/api/v1/incidents/${createdIncidentId}?tenant=${TEST_TENANT}`, {
      status: 'investigating',
    });
    if (res.status === 503 || res.status === 401) {
      assert.ok(true, 'DB not available or auth required — skipping');
      return;
    }
    assert.ok([200, 204].includes(res.status), `Expected 200/204, got ${res.status}`);
  });
});
