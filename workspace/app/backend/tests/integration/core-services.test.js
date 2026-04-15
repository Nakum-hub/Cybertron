/**
 * P3-1: Integration Test Suite
 *
 * Tests core backend services end-to-end against actual service logic.
 * Runs with: node --test tests/integration/*.test.js
 */
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

// ─── Email Service Tests ───────────────────────────────────────────────

describe('email-service', () => {
  const { sendPasswordResetEmail, sendWelcomeEmail, sendWorkspaceInviteEmail, sendAlertEscalationEmail } = require('../../src/email-service');

  const testConfig = {
    emailProvider: 'console',
    emailFromAddress: 'noreply@test.io',
    emailFromName: 'Test',
    frontendOrigin: 'http://localhost:3000',
  };

  it('sendPasswordResetEmail should not throw with console transport', async () => {
    await assert.doesNotReject(
      sendPasswordResetEmail(testConfig, {
        to: 'user@example.com',
        resetUrl: 'http://localhost:3000/reset?token=test',
        tenantName: 'test-tenant',
      })
    );
  });

  it('sendWelcomeEmail should not throw with console transport', async () => {
    await assert.doesNotReject(
      sendWelcomeEmail(testConfig, {
        to: 'user@example.com',
        displayName: 'Test User',
        loginUrl: 'http://localhost:3000',
      })
    );
  });

  it('sendWorkspaceInviteEmail should not throw with console transport', async () => {
    await assert.doesNotReject(
      sendWorkspaceInviteEmail(testConfig, {
        to: 'colleague@example.com',
        inviterName: 'Admin',
        workspaceName: 'test-workspace',
        inviteUrl: 'http://localhost:3000/invite/accept',
      })
    );
  });

  it('sendAlertEscalationEmail should not throw with console transport', async () => {
    await assert.doesNotReject(
      sendAlertEscalationEmail(testConfig, {
        to: 'admin@example.com',
        alertTitle: 'Critical SQL injection detected',
        severity: 'critical',
        alertUrl: 'http://localhost:3000/platform/alerts/123',
      })
    );
  });
});

// ─── Config Tests ──────────────────────────────────────────────────────

describe('config', () => {
  const { enforceProductionStartupGuard } = require('../../src/config');

  it('enforceProductionStartupGuard should not throw in development', () => {
    assert.doesNotThrow(() => {
      enforceProductionStartupGuard({
        environment: 'development',
        jwtSecret: 'dev-secret',
        databaseUrl: '',
      });
    });
  });

  it('enforceProductionStartupGuard should throw in production with missing JWT_SECRET', () => {
    assert.throws(
      () => {
        enforceProductionStartupGuard({
          environment: 'production',
          jwtSecret: '',
          databaseUrl: 'postgresql://prod:5432/db',
        });
      },
      (err) => err.message.includes('JWT_SECRET') || err.message.includes('critical')
    );
  });
});

// ─── API Key Service Tests ─────────────────────────────────────────────

describe('api-key-service (unit)', () => {
  it('should export createApiKey, verifyApiKey, listApiKeys, revokeApiKey', () => {
    const apiKeyService = require('../../src/api-key-service');
    assert.strictEqual(typeof apiKeyService.createApiKey, 'function');
    assert.strictEqual(typeof apiKeyService.verifyApiKey, 'function');
    assert.strictEqual(typeof apiKeyService.listApiKeys, 'function');
    assert.strictEqual(typeof apiKeyService.revokeApiKey, 'function');
  });
});

// ─── Connector Config Service Tests ────────────────────────────────────

describe('connector-config-service (unit)', () => {
  it('should export all connector functions', () => {
    const connService = require('../../src/connector-config-service');
    assert.strictEqual(typeof connService.listConnectorConfigs, 'function');
    assert.strictEqual(typeof connService.upsertConnectorConfig, 'function');
    assert.strictEqual(typeof connService.deleteConnectorConfig, 'function');
    assert.strictEqual(typeof connService.testConnectorConnection, 'function');
  });
});

// ─── Invite Service Tests ──────────────────────────────────────────────

describe('invite-service (unit)', () => {
  it('should export createInvite, acceptInvite, listInvites, revokeInvite', () => {
    const inviteService = require('../../src/invite-service');
    assert.strictEqual(typeof inviteService.createInvite, 'function');
    assert.strictEqual(typeof inviteService.acceptInvite, 'function');
    assert.strictEqual(typeof inviteService.listInvites, 'function');
    assert.strictEqual(typeof inviteService.revokeInvite, 'function');
  });
});

// ─── Stripe Service Tests ──────────────────────────────────────────────

describe('stripe-service (unit)', () => {
  it('should export createCheckoutSession, handleWebhookEvent, getSubscriptionStatus', () => {
    const stripeService = require('../../src/stripe-service');
    assert.strictEqual(typeof stripeService.createCheckoutSession, 'function');
    assert.strictEqual(typeof stripeService.handleWebhookEvent, 'function');
    assert.strictEqual(typeof stripeService.getSubscriptionStatus, 'function');
    assert.strictEqual(typeof stripeService.resolvePriceId, 'function');
  });

  it('resolvePriceId should return correct price IDs', () => {
    const { resolvePriceId } = require('../../src/stripe-service');
    const cfg = {
      stripePriceIdProMonthly: 'price_pro_m',
      stripePriceIdProAnnual: 'price_pro_a',
      stripePriceIdEnterpriseMonthly: 'price_ent_m',
    };
    assert.strictEqual(resolvePriceId(cfg, 'pro', 'monthly'), 'price_pro_m');
    assert.strictEqual(resolvePriceId(cfg, 'pro', 'annual'), 'price_pro_a');
    assert.strictEqual(resolvePriceId(cfg, 'enterprise', 'monthly'), 'price_ent_m');
    assert.strictEqual(resolvePriceId(cfg, 'unknown', 'monthly'), '');
  });
});

// ─── Notification Preferences Tests ────────────────────────────────────

describe('notification-preferences-service (unit)', () => {
  it('should export getNotificationPreferences and upsertNotificationPreferences', () => {
    const notifService = require('../../src/notification-preferences-service');
    assert.strictEqual(typeof notifService.getNotificationPreferences, 'function');
    assert.strictEqual(typeof notifService.upsertNotificationPreferences, 'function');
  });
});

// ─── LLM Provider Tests ───────────────────────────────────────────────

describe('llm-provider (vLLM)', () => {
  const { createLlmProvider } = require('../../src/ai/llm-provider');

  it('createLlmProvider with none should return provider object', () => {
    const provider = createLlmProvider({
      llmProvider: 'none',
      openaiApiKey: '',
      openaiBaseUrl: '',
      openaiModel: '',
      llmRequestTimeoutMs: 5000,
      llmRateLimitWindowMs: 60000,
      llmRateLimitMaxCalls: 10,
    });
    assert.ok(provider);
    assert.strictEqual(typeof provider.call, 'function');
  });
});

// ─── Module Service Validators ─────────────────────────────────────────

describe('module-service validators', () => {
  const { sanitizeTenant, toSafeInteger } = require('../../src/validators');

  it('sanitizeTenant should reject empty strings', () => {
    assert.throws(() => sanitizeTenant(''));
    assert.throws(() => sanitizeTenant(null));
  });

  it('sanitizeTenant should lowercase and trim', () => {
    assert.strictEqual(sanitizeTenant('  MyTenant  '), 'mytenant');
  });

  it('toSafeInteger should clamp values', () => {
    assert.strictEqual(toSafeInteger(150, 25, 1, 100), 100);
    assert.strictEqual(toSafeInteger(-5, 25, 1, 100), 1);
    assert.strictEqual(toSafeInteger(undefined, 25, 1, 100), 25);
  });
});

// ─── Admin Routes Smoke ────────────────────────────────────────────────

describe('admin routes (import)', () => {
  it('should export registerRoutes function', () => {
    const adminRoutes = require('../../src/routes/admin');
    assert.strictEqual(typeof adminRoutes.registerRoutes, 'function');
  });
});
