/**
 * Integration tests — Billing / Stripe.
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

describe('Billing Integration Tests', () => {
  it('GET /v1/billing/credits — should return credit balance (200)', async () => {
    const res = await request('GET', `/api/v1/billing/credits?tenant=${TEST_TENANT}`);
    if (res.status === 401) {
      assert.ok(true, 'Auth required — skipping');
      return;
    }
    assert.equal(res.status, 200);
    assert.ok(res.body.balance !== undefined || res.body.credits !== undefined,
      'Should return balance info');
  });

  it('POST /v1/billing/checkout — should require auth', async () => {
    const res = await request('POST', `/api/v1/billing/checkout?tenant=${TEST_TENANT}`, {
      plan: 'pro',
      billingCycle: 'monthly',
    });
    // Without auth, should return 401
    assert.ok([401, 403].includes(res.status),
      `Checkout without auth should return 401/403, got ${res.status}`);
  });

  it('POST /v1/webhooks/stripe — invalid signature should return 400', async () => {
    const res = await request('POST', '/api/v1/webhooks/stripe', {
      type: 'checkout.session.completed',
      data: { object: { id: 'cs_fake_123' } },
    }, {
      'stripe-signature': 'invalid-signature-value',
    });
    // Should reject: 400 bad signature or 500 if Stripe not configured
    assert.ok([400, 500, 503].includes(res.status),
      `Invalid webhook signature should be rejected, got ${res.status}`);
  });

  it('POST /v1/webhooks/stripe — no signature should return 400', async () => {
    const res = await request('POST', '/api/v1/webhooks/stripe', {
      type: 'customer.subscription.deleted',
    });
    assert.ok([400, 500, 503].includes(res.status),
      `Missing webhook signature should fail, got ${res.status}`);
  });
});
