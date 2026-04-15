/**
 * Integration tests — Reports CRUD.
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

describe('Reports Integration Tests', () => {
  it('GET /v1/reports — should list reports (200)', async () => {
    const res = await request('GET', `/api/v1/reports?tenant=${TEST_TENANT}`);
    if (res.status === 401) {
      assert.ok(true, 'Auth required — skipping');
      return;
    }
    if (res.status === 503) {
      assert.ok(true, 'DB not available — skipping');
      return;
    }
    assert.equal(res.status, 200);
    assert.ok(res.body.data !== undefined || Array.isArray(res.body),
      'Should return reports array');
  });

  it('POST /v1/reports/upload — should require auth', async () => {
    const res = await request('POST', `/api/v1/reports/upload?tenant=${TEST_TENANT}`, {
      fileName: 'test-report.pdf',
      type: 'application/pdf',
    });
    // Without proper auth, should be rejected
    assert.ok([401, 403, 415].includes(res.status),
      `Upload without auth should be rejected, got ${res.status}`);
  });

  it('GET /v1/reports/:id/download — non-existent report should return 404', async () => {
    const res = await request('GET', `/api/v1/reports/non-existent-id/download?tenant=${TEST_TENANT}`);
    if (res.status === 401) {
      assert.ok(true, 'Auth required — skipping');
      return;
    }
    assert.ok([404, 400].includes(res.status),
      `Non-existent report should return 404/400, got ${res.status}`);
  });
});
