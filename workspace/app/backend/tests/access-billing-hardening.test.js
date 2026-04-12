const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  PLAN_FEATURES,
  VALID_TIERS,
  getTenantPlan,
  assertFeatureAllowed,
  __test__: billingTest,
} = require('../src/billing-service');
const {
  __test__: productTest,
} = require('../src/product-service');
const {
  ServiceError,
  __test__: authTest,
} = require('../src/auth-service');

describe('Billing plan enforcement', () => {
  it('exposes the expected commercial tiers', () => {
    assert.deepEqual(VALID_TIERS, ['free', 'pro', 'enterprise']);
    assert.equal(PLAN_FEATURES.free.label, 'Starter');
    assert.equal(PLAN_FEATURES.pro.label, 'Pro');
    assert.equal(PLAN_FEATURES.enterprise.label, 'Enterprise');
  });

  it('falls back to the free starter plan when no database is configured', async () => {
    const plan = await getTenantPlan(
      {
        databaseUrl: '',
        freePlanIncludedUnitsPerMonth: 250,
      },
      'starter-tenant'
    );

    assert.equal(plan.tenant, 'starter-tenant');
    assert.equal(plan.tier, 'free');
    assert.equal(plan.features.label, 'Starter');
    assert.deepEqual(plan.features.modules, ['threat-command']);
    assert.equal(plan.features.includedUnitsPerMonth, 250);
  });

  it('normalizes unknown or mixed-case tiers back to supported values', () => {
    assert.equal(billingTest.normalizeTier('PRO'), 'pro');
    assert.equal(billingTest.normalizeTier(' Enterprise '), 'enterprise');
    assert.equal(billingTest.normalizeTier('starter-plus'), 'free');
  });

  it('builds enterprise plan features with the full module surface', () => {
    const features = billingTest.buildPlanFeatures(
      {
        enterprisePlanIncludedUnitsPerMonth: 5000,
      },
      'enterprise'
    );

    assert.equal(features.label, 'Enterprise');
    assert.equal(features.includedUnitsPerMonth, 5000);
    assert.ok(features.modules.includes('risk-copilot'));
    assert.ok(features.modules.includes('compliance-engine'));
    assert.ok(features.modules.includes('threat-intel'));
    assert.equal(features.whiteLabel, true);
    assert.equal(features.slaGuarantee, true);
  });

  it('builds UTC billing windows on month boundaries', () => {
    const { start, end } = billingTest.buildUsageWindow(new Date('2026-03-12T10:30:00.000Z'));

    assert.equal(start.toISOString(), '2026-03-01T00:00:00.000Z');
    assert.equal(end.toISOString(), '2026-04-01T00:00:00.000Z');
  });

  it('blocks premium boolean features on starter tier with upgrade guidance', () => {
    assert.throws(
      () =>
        assertFeatureAllowed(
          {
            tier: 'free',
            features: {
              ...PLAN_FEATURES.free,
            },
          },
          'reportUpload'
        ),
      error => {
        assert.ok(error instanceof ServiceError);
        assert.equal(error.code, 'feature_not_available');
        assert.equal(error.details.currentTier, 'free');
        assert.equal(error.details.requiredTier, 'pro');
        assert.equal(error.details.upgradeUrl, '/pricing');
        return true;
      }
    );
  });

  it('blocks modules that are not in the current plan', () => {
    assert.throws(
      () =>
        assertFeatureAllowed(
          {
            tier: 'free',
            features: {
              ...PLAN_FEATURES.free,
            },
          },
          'module',
          { moduleId: 'risk-copilot' }
        ),
      error => {
        assert.ok(error instanceof ServiceError);
        assert.equal(error.code, 'module_not_available');
        assert.equal(error.details.currentTier, 'free');
        assert.equal(error.details.module, 'risk-copilot');
        assert.equal(error.details.upgradeUrl, '/pricing');
        return true;
      }
    );
  });

  it('enforces team member caps with an upgrade prompt', () => {
    assert.throws(
      () =>
        assertFeatureAllowed(
          {
            tier: 'pro',
            features: {
              ...PLAN_FEATURES.pro,
            },
          },
          'teamMember',
          { currentCount: 10 }
        ),
      error => {
        assert.ok(error instanceof ServiceError);
        assert.equal(error.code, 'team_limit_reached');
        assert.equal(error.details.currentTier, 'pro');
        assert.equal(error.details.maxAllowed, 10);
        assert.equal(error.details.upgradeUrl, '/pricing');
        return true;
      }
    );
  });
});

describe('Product gating helpers', () => {
  it('rejects malformed product ids', () => {
    assert.throws(
      () => productTest.normalizeProductId('not valid'),
      error => {
        assert.ok(error instanceof ServiceError);
        assert.equal(error.code, 'invalid_product_id');
        return true;
      }
    );
  });

  it('collects plan aliases from product id, key, path, and path tail', () => {
    const aliases = productTest.collectPlanAliases({
      productId: 'risk-copilot',
      productKey: 'risk-copilot',
      modulePath: '/modules/risk-copilot',
    });

    assert.ok(aliases.includes('risk-copilot'));
    assert.ok(aliases.includes('/modules/risk-copilot'));
  });

  it('recognizes plan access through either product ids or module aliases', () => {
    const row = {
      productId: 'resilience-hq',
      productKey: 'resilience-hq',
      modulePath: '/modules/compliance-engine',
    };

    assert.equal(
      productTest.isPlanAllowed(row, {
        features: {
          modules: ['resilience-hq'],
        },
      }),
      true
    );

    assert.equal(
      productTest.isPlanAllowed(row, {
        features: {
          modules: ['compliance-engine'],
        },
      }),
      true
    );

    assert.equal(
      productTest.isPlanAllowed(row, {
        features: {
          modules: ['threat-command'],
        },
      }),
      false
    );
  });

  it('derives effective enabled state from product, tenant, flag, and plan gates', () => {
    const baseRow = {
      enabled: true,
      tenantEnabled: true,
      featureGate: { allowed: true },
    };

    assert.equal(productTest.deriveEnabledState(baseRow, true), true);
    assert.equal(productTest.deriveEnabledState({ ...baseRow, tenantEnabled: false }, true), false);
    assert.equal(productTest.deriveEnabledState({ ...baseRow, featureGate: { allowed: false } }, true), false);
    assert.equal(productTest.deriveEnabledState(baseRow, false), false);
  });

  it('marks a product visible only when plan, quota, and role all permit it', () => {
    const starterProduct = productTest.asTenantProduct(
      {
        productId: 'threat-command',
        productKey: 'threat-command',
        modulePath: '/modules/threat-intel',
        enabled: true,
        roleMin: 'executive_viewer',
        tenantEnabled: true,
        featureGate: { allowed: true, flags: [] },
      },
      'executive_viewer',
      {
        tier: 'free',
        features: {
          label: 'Starter',
          modules: ['threat-command'],
        },
      },
      {
        quotaEnforced: true,
        exhausted: false,
        quotaRemainingUnits: 25,
        quotaLimitUnits: 250,
        periodEndsAt: '2026-04-01T00:00:00.000Z',
      }
    );

    assert.equal(starterProduct.planAllowed, true);
    assert.equal(starterProduct.allowedForRole, true);
    assert.equal(starterProduct.visible, true);
    assert.equal(starterProduct.planTier, 'free');
    assert.equal(starterProduct.planLabel, 'Starter');
    assert.equal(starterProduct.quotaRemainingUnits, 25);
  });

  it('blocks visibility when the role or plan does not allow the product', () => {
    const blockedByRole = productTest.asTenantProduct(
      {
        productId: 'identity-guardian',
        productKey: 'identity-guardian',
        modulePath: '/modules/core',
        enabled: true,
        roleMin: 'security_analyst',
        tenantEnabled: true,
        featureGate: { allowed: true, flags: [] },
      },
      'executive_viewer',
      {
        tier: 'pro',
        features: {
          label: 'Pro',
          modules: ['identity-guardian'],
        },
      }
    );

    const blockedByPlan = productTest.asTenantProduct(
      {
        productId: 'risk-copilot',
        productKey: 'risk-copilot',
        modulePath: '/modules/risk-copilot',
        enabled: true,
        roleMin: 'executive_viewer',
        tenantEnabled: true,
        featureGate: { allowed: true, flags: [] },
      },
      'tenant_admin',
      {
        tier: 'free',
        features: {
          label: 'Starter',
          modules: ['threat-command'],
        },
      }
    );

    assert.equal(blockedByRole.allowedForRole, false);
    assert.equal(blockedByRole.visible, false);
    assert.equal(blockedByPlan.planAllowed, false);
    assert.equal(blockedByPlan.visible, false);
  });
});

describe('Workspace bootstrap abuse guards', () => {
  it('requires an explicit public workspace slug when the flow demands it', () => {
    assert.throws(
      () => authTest.normalizePublicWorkspaceSlug('', { requireExplicit: true }),
      error => {
        assert.ok(error instanceof ServiceError);
        assert.equal(error.code, 'workspace_slug_required');
        return true;
      }
    );
  });

  it('blocks reserved public workspace slugs unless explicitly allowed', () => {
    assert.throws(
      () => authTest.normalizePublicWorkspaceSlug('global'),
      error => {
        assert.ok(error instanceof ServiceError);
        assert.equal(error.code, 'reserved_workspace_slug');
        assert.equal(error.details.tenant, 'global');
        return true;
      }
    );

    assert.equal(
      authTest.normalizePublicWorkspaceSlug('global', { allowReserved: true }),
      'global'
    );
  });

  it('accepts only safe browser fingerprints', () => {
    assert.equal(authTest.normalizePublicFingerprint('browser.fingerprint-1234'), 'browser.fingerprint-1234');
    assert.equal(authTest.normalizePublicFingerprint('too-short'), null);
    assert.equal(authTest.normalizePublicFingerprint('fingerprint with spaces'), null);
  });

  it('detects loopback addresses so local dev does not burn network bootstrap limits', () => {
    assert.equal(authTest.isLoopbackAddress('127.0.0.1'), true);
    assert.equal(authTest.isLoopbackAddress('::1'), true);
    assert.equal(authTest.isLoopbackAddress('localhost'), true);
    assert.equal(authTest.isLoopbackAddress('203.0.113.5'), false);
  });

  it('builds stable but namespace-specific bootstrap hashes', () => {
    const config = {
      jwtSecret: 'cybertron-test-secret',
    };
    const fingerprintHash = authTest.hashWorkspaceBootstrapMarker(config, 'fingerprint', 'browser-123');
    const fingerprintHashAgain = authTest.hashWorkspaceBootstrapMarker(config, 'fingerprint', 'browser-123');
    const networkHash = authTest.hashWorkspaceBootstrapMarker(config, 'network', 'browser-123');

    assert.equal(fingerprintHash, fingerprintHashAgain);
    assert.notEqual(fingerprintHash, networkHash);
  });

  it('computes retry-after seconds from the oldest matching bootstrap event', () => {
    const originalNow = Date.now;
    Date.now = () => Date.parse('2026-03-12T12:00:00.000Z');

    try {
      const retryAfter = authTest.buildWorkspaceBootstrapRetryAfterSeconds(
        [{ created_at: '2026-03-12T11:30:00.000Z' }],
        60 * 60 * 1000
      );

      assert.equal(retryAfter, 1800);
    } finally {
      Date.now = originalNow;
    }
  });

  it('returns upgrade-aware workspace limit errors for repeated self-service signup abuse', () => {
    const error = authTest.buildWorkspaceLimitError(
      'founder@cybertron.ai',
      'alpha-tenant',
      ['existing-tenant']
    );

    assert.ok(error instanceof ServiceError);
    assert.equal(error.code, 'self_service_workspace_limit_reached');
    assert.equal(error.details.email, 'founder@cybertron.ai');
    assert.equal(error.details.upgradeUrl, '/pricing');
    assert.deepEqual(error.details.existingTenants, ['existing-tenant']);
  });

  it('returns an external identity workspace limit error when OAuth is reused across tenants', () => {
    const error = authTest.buildExternalIdentityWorkspaceLimitError('google', 'locked-tenant');

    assert.ok(error instanceof ServiceError);
    assert.equal(error.code, 'external_identity_workspace_limit_reached');
    assert.equal(error.details.provider, 'google');
    assert.equal(error.details.tenant, 'locked-tenant');
  });

  it('normalizes default tenant plan tiers to supported values only', () => {
    assert.equal(authTest.normalizeDefaultTenantPlanTier('enterprise'), 'enterprise');
    assert.equal(authTest.normalizeDefaultTenantPlanTier('Pro'), 'pro');
    assert.equal(authTest.normalizeDefaultTenantPlanTier('starter-plus'), 'free');
  });

  it('blocks tenant admins from provisioning users into other tenants', () => {
    assert.throws(
      () =>
        authTest.resolveRegistrationTenant('victim-tenant', {
          isAdmin: true,
          actorRole: 'tenant_admin',
          actorTenant: 'alpha-tenant',
        }),
      error => {
        assert.ok(error instanceof ServiceError);
        assert.equal(error.code, 'tenant_scope_denied');
        assert.equal(error.details.actorTenant, 'alpha-tenant');
        assert.equal(error.details.requestedTenant, 'victim-tenant');
        return true;
      }
    );
  });

  it('allows super admins to provision across tenants when needed', () => {
    assert.equal(
      authTest.resolveRegistrationTenant('victim-tenant', {
        isAdmin: true,
        actorRole: 'super_admin',
        actorTenant: 'alpha-tenant',
      }),
      'victim-tenant'
    );
  });

  it('blocks tenant admins from assigning super_admin', () => {
    assert.throws(
      () =>
        authTest.assertAdminCanAssignRole(
          {
            isAdmin: true,
            actorRole: 'tenant_admin',
          },
          'super_admin'
        ),
      error => {
        assert.ok(error instanceof ServiceError);
        assert.equal(error.code, 'role_not_allowed');
        assert.equal(error.details.actorRole, 'tenant_admin');
        assert.equal(error.details.requestedRole, 'super_admin');
        return true;
      }
    );
  });

  it('allows super admins to assign super_admin explicitly', () => {
    assert.doesNotThrow(() =>
      authTest.assertAdminCanAssignRole(
        {
          isAdmin: true,
          actorRole: 'super_admin',
        },
        'super_admin'
      )
    );
  });
});
