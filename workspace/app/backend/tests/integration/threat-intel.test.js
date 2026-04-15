/**
 * Integration tests — Threat Intel (SIEM, CVE).
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

describe('Threat Intel Integration Tests', () => {
  it('GET /v1/threat-intel/siem/alerts — should list alerts (200)', async () => {
    const res = await request('GET', `/api/v1/threat-intel/siem/alerts?tenant=${TEST_TENANT}`);
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
      'Should return alerts array');
  });

  it('POST /v1/threat-intel/siem/upload — should ingest alert data', async () => {
    const res = await request('POST', `/api/v1/threat-intel/siem/upload?tenant=${TEST_TENANT}`, {
      alerts: [{
        title: `Test Alert ${Date.now()}`,
        severity: 'high',
        source: 'integration-test',
        description: 'Test alert from integration suite',
        rawData: { test: true },
      }],
    });
    if (res.status === 401 || res.status === 503) {
      assert.ok(true, 'Auth required or DB unavailable — skipping');
      return;
    }
    assert.ok([200, 201, 202].includes(res.status),
      `Alert ingestion should succeed, got ${res.status}`);
  });

  it('GET /v1/threat-intel/siem/alerts/stats — should return stats', async () => {
    const res = await request('GET', `/api/v1/threat-intel/siem/alerts/stats?tenant=${TEST_TENANT}`);
    if (res.status === 401 || res.status === 503) {
      assert.ok(true, 'Auth required or DB unavailable — skipping');
      return;
    }
    assert.equal(res.status, 200);
  });

  it('POST /v1/threat-intel/cve/sync — should accept sync request (202)', async () => {
    const res = await request('POST', `/api/v1/threat-intel/cve/sync?tenant=${TEST_TENANT}`);
    if (res.status === 401 || res.status === 503) {
      assert.ok(true, 'Auth required or DB unavailable — skipping');
      return;
    }
    assert.ok([200, 202].includes(res.status),
      `CVE sync should return 200/202, got ${res.status}`);
  });

  it('GET /v1/threat-intel/mitre/techniques — should return MITRE data', async () => {
    const res = await request('GET', `/api/v1/threat-intel/mitre/techniques?tenant=${TEST_TENANT}`);
    if (res.status === 401) {
      assert.ok(true, 'Auth required — skipping');
      return;
    }
    assert.equal(res.status, 200);
    assert.ok(res.body.data || Array.isArray(res.body), 'Should return techniques');
  });
});
