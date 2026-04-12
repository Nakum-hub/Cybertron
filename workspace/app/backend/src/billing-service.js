const { query } = require('./database');
const { sanitizeTenant, toSafeInteger } = require('./validators');
const { ServiceError } = require('./auth-service');

function normalizeProductKey(value) {
  const normalized = String(value || '').trim().toLowerCase();
  if (!/^[a-z0-9-]{2,64}$/.test(normalized)) {
    throw new ServiceError(400, 'invalid_product_key', 'Product key is invalid.');
  }
  return normalized;
}

function normalizeActionKey(value) {
  const normalized = String(value || '').trim().toLowerCase();
  if (!/^[a-z0-9_.:-]{2,128}$/.test(normalized)) {
    throw new ServiceError(400, 'invalid_action_key', 'Action key is invalid.');
  }
  return normalized;
}

function normalizeOptionalUserId(value) {
  if (value === undefined || value === null || value === '') {
    return null;
  }

  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    return null;
  }

  return parsed;
}

async function ensureCreditsRow(config, tenant) {
  const tenantSlug = sanitizeTenant(tenant || 'global');
  await query(
    config,
    `
      INSERT INTO credits (tenant_slug, balance_units)
      VALUES ($1, 0)
      ON CONFLICT (tenant_slug) DO NOTHING
    `,
    [tenantSlug]
  );
}

async function recordUsageEvent(config, payload = {}) {
  const tenantSlug = sanitizeTenant(payload.tenant || 'global');
  const productKey = normalizeProductKey(payload.productKey || 'threat-command');
  const actionKey = normalizeActionKey(payload.actionKey || 'api.request');
  const units = toSafeInteger(payload.units, 1, 1, 10_000);
  const actorUserId = normalizeOptionalUserId(payload.userId);
  const metaJson = payload.meta && typeof payload.meta === 'object' ? payload.meta : {};

  await ensureCreditsRow(config, tenantSlug);

  await query(
    config,
    `
      INSERT INTO usage_events (
        tenant_slug,
        user_id,
        product_key,
        action_key,
        units,
        meta_json
      )
      VALUES ($1,$2,$3,$4,$5,$6::jsonb)
    `,
    [tenantSlug, actorUserId, productKey, actionKey, units, JSON.stringify(metaJson)]
  );
}

async function listUsageEvents(config, tenant, options = {}) {
  const tenantSlug = sanitizeTenant(tenant || 'global');
  const limit = toSafeInteger(options.limit, 50, 1, 500);
  const offset = toSafeInteger(options.offset, 0, 0, 50_000);
  const productKey = options.productKey ? normalizeProductKey(options.productKey) : null;

  const values = [tenantSlug];
  const where = ['tenant_slug = $1'];
  if (productKey) {
    values.push(productKey);
    where.push(`product_key = $${values.length}`);
  }
  const whereSql = where.join(' AND ');

  const count = await query(
    config,
    `SELECT COUNT(*)::INT AS total FROM usage_events WHERE ${whereSql}`,
    values
  );
  const total = Number(count?.rows?.[0]?.total || 0);

  values.push(limit, offset);
  const result = await query(
    config,
    `
      SELECT
        id,
        tenant_slug,
        user_id,
        product_key,
        action_key,
        units,
        meta_json,
        created_at
      FROM usage_events
      WHERE ${whereSql}
      ORDER BY created_at DESC, id DESC
      LIMIT $${values.length - 1}
      OFFSET $${values.length}
    `,
    values
  );

  const data = (result?.rows || []).map(row => ({
    id: String(row.id),
    tenant: row.tenant_slug,
    userId: row.user_id ? String(row.user_id) : null,
    productKey: row.product_key,
    actionKey: row.action_key,
    units: Number(row.units || 0),
    meta: row.meta_json || {},
    createdAt: new Date(row.created_at).toISOString(),
  }));

  return {
    data,
    pagination: {
      limit,
      offset,
      total,
      hasMore: offset + data.length < total,
    },
    message: data.length ? undefined : 'No usage events recorded for this tenant yet.',
  };
}

async function getCredits(config, tenant) {
  const tenantSlug = sanitizeTenant(tenant || 'global');
  await ensureCreditsRow(config, tenantSlug);

  const result = await query(
    config,
    `
      SELECT tenant_slug, balance_units, updated_at
      FROM credits
      WHERE tenant_slug = $1
      LIMIT 1
    `,
    [tenantSlug]
  );

  const row = result?.rows?.[0];
  const storedBalanceUnits = Number(row?.balance_units || 0);
  const updatedAt = row?.updated_at ? new Date(row.updated_at).toISOString() : null;
  const planData = await getTenantPlan(config, tenantSlug);
  const allowance = await getUsageAllowance(config, tenantSlug, planData, {
    storedBalanceUnits,
    updatedAt,
  });

  return {
    tenant: tenantSlug,
    balanceUnits: allowance.quotaEnforced
      ? allowance.quotaRemainingUnits
      : allowance.topUpUnits,
    updatedAt,
    topUpUnits: allowance.topUpUnits,
    includedUnits: allowance.includedUnits,
    usedUnits: allowance.usedUnits,
    quotaLimitUnits: allowance.quotaLimitUnits,
    quotaRemainingUnits: allowance.quotaRemainingUnits,
    quotaEnforced: allowance.quotaEnforced,
    exhausted: allowance.exhausted,
    periodStart: allowance.periodStart,
    periodEndsAt: allowance.periodEndsAt,
    planTier: allowance.planTier,
    planLabel: allowance.planLabel,
  };
}

// ── License Tier Definitions ──

const VALID_TIERS = ['free', 'pro', 'enterprise'];

const PLAN_FEATURES = {
  free: {
    label: 'Starter',
    maxTeamMembers: 3,
    maxTenants: 1,
    modules: ['threat-command'],
    auditLogAccess: false,
    connectorAccess: false,
    reportUpload: false,
    whiteLabel: false,
    prioritySupport: false,
    slaGuarantee: false,
  },
  pro: {
    label: 'Pro',
    maxTeamMembers: 10,
    maxTenants: 5,
    modules: ['threat-command', 'identity-guardian', 'resilience-hq'],
    auditLogAccess: true,
    connectorAccess: true,
    reportUpload: true,
    whiteLabel: false,
    prioritySupport: true,
    slaGuarantee: false,
  },
  enterprise: {
    label: 'Enterprise',
    maxTeamMembers: 999999,
    maxTenants: 999999,
    modules: ['threat-command', 'identity-guardian', 'resilience-hq', 'risk-copilot', 'compliance-engine', 'threat-intel'],
    auditLogAccess: true,
    connectorAccess: true,
    reportUpload: true,
    whiteLabel: true,
    prioritySupport: true,
    slaGuarantee: true,
  },
};

function resolveTierQuotaLimit(config, tier) {
  const normalizedTier = normalizeTier(tier);
  if (normalizedTier === 'free') {
    return Math.max(1, Number(config.freePlanIncludedUnitsPerMonth || 250));
  }
  if (normalizedTier === 'pro') {
    return Number(config.proPlanIncludedUnitsPerMonth || 0) > 0
      ? Number(config.proPlanIncludedUnitsPerMonth)
      : null;
  }
  if (normalizedTier === 'enterprise') {
    return Number(config.enterprisePlanIncludedUnitsPerMonth || 0) > 0
      ? Number(config.enterprisePlanIncludedUnitsPerMonth)
      : null;
  }
  return null;
}

function buildPlanFeatures(config, tier) {
  const normalizedTier = normalizeTier(tier);
  const baseFeatures = PLAN_FEATURES[normalizedTier] || PLAN_FEATURES.free;
  const includedUnitsPerMonth = resolveTierQuotaLimit(config, normalizedTier);
  return {
    ...baseFeatures,
    includedUnitsPerMonth,
  };
}

function buildUsageWindow(referenceDate = new Date()) {
  const year = referenceDate.getUTCFullYear();
  const month = referenceDate.getUTCMonth();
  const start = new Date(Date.UTC(year, month, 1, 0, 0, 0, 0));
  const end = new Date(Date.UTC(year, month + 1, 1, 0, 0, 0, 0));
  return {
    start,
    end,
  };
}

async function getUsageAllowance(
  config,
  tenant,
  planData = null,
  options = {}
) {
  const tenantSlug = sanitizeTenant(tenant || 'global');
  const resolvedPlan = planData || (await getTenantPlan(config, tenantSlug));
  const topUpUnits = Math.max(0, Number(options.storedBalanceUnits || 0));
  const updatedAt = options.updatedAt || null;
  const quotaLimit = Number(resolvedPlan?.features?.includedUnitsPerMonth || 0);
  const quotaEnforced = quotaLimit > 0;
  const usageWindow = buildUsageWindow(new Date());

  let usedUnits = 0;
  if (config.databaseUrl && quotaEnforced) {
    const usageResult = await query(
      config,
      `
        SELECT COALESCE(SUM(units), 0)::INT AS used_units
        FROM usage_events
        WHERE tenant_slug = $1
          AND created_at >= $2
          AND created_at < $3
      `,
      [tenantSlug, usageWindow.start.toISOString(), usageWindow.end.toISOString()]
    );
    usedUnits = Math.max(0, Number(usageResult?.rows?.[0]?.used_units || 0));
  }

  const quotaLimitUnits = quotaEnforced ? quotaLimit + topUpUnits : null;
  const quotaRemainingUnits = quotaEnforced
    ? Math.max(0, quotaLimit + topUpUnits - usedUnits)
    : null;

  return {
    tenant: tenantSlug,
    updatedAt,
    topUpUnits,
    includedUnits: quotaEnforced ? quotaLimit : 0,
    usedUnits,
    quotaLimitUnits,
    quotaRemainingUnits,
    quotaEnforced,
    exhausted: quotaEnforced ? quotaRemainingUnits <= 0 : false,
    periodStart: quotaEnforced ? usageWindow.start.toISOString() : null,
    periodEndsAt: quotaEnforced ? usageWindow.end.toISOString() : null,
    planTier: resolvedPlan?.tier || 'free',
    planLabel: resolvedPlan?.features?.label || PLAN_FEATURES.free.label,
  };
}

async function assertUsageAllowed(config, tenant, units = 1, planData = null) {
  const allowance = await getUsageAllowance(config, tenant, planData);
  if (!allowance.quotaEnforced) {
    return allowance;
  }

  const requestedUnits = Math.max(1, toSafeInteger(units, 1, 1, 10_000));
  if ((allowance.quotaRemainingUnits || 0) >= requestedUnits) {
    return allowance;
  }

  throw new ServiceError(
    403,
    'billing_quota_exhausted',
    `${allowance.planLabel || 'Current'} plan quota is exhausted for this billing window. Upgrade to continue using Cybertron.`,
    {
      currentTier: allowance.planTier,
      planLabel: allowance.planLabel,
      quotaLimitUnits: allowance.quotaLimitUnits,
      quotaRemainingUnits: allowance.quotaRemainingUnits,
      usedUnits: allowance.usedUnits,
      periodStart: allowance.periodStart,
      periodEndsAt: allowance.periodEndsAt,
      upgradeUrl: '/pricing',
    }
  );
}

function normalizeTier(value) {
  const normalized = String(value || 'free').trim().toLowerCase();
  return VALID_TIERS.includes(normalized) ? normalized : 'free';
}

async function getTenantPlan(config, tenant) {
  const tenantSlug = sanitizeTenant(tenant || 'global');

  if (!config.databaseUrl) {
    return {
      tenant: tenantSlug,
      tier: 'free',
      features: buildPlanFeatures(config, 'free'),
      activeSince: null,
      expiresAt: null,
    };
  }

  const result = await query(
    config,
    `
      SELECT tier, active_since, expires_at
      FROM tenant_plans
      WHERE tenant_slug = $1
      LIMIT 1
    `,
    [tenantSlug]
  );

  const row = result?.rows?.[0];
  const tier = row ? normalizeTier(row.tier) : 'free';

  // If plan has expired, treat as free
  if (row?.expires_at && new Date(row.expires_at).getTime() <= Date.now()) {
    return {
      tenant: tenantSlug,
      tier: 'free',
      features: buildPlanFeatures(config, 'free'),
      activeSince: row.active_since ? new Date(row.active_since).toISOString() : null,
      expiresAt: new Date(row.expires_at).toISOString(),
      expired: true,
    };
  }

  return {
    tenant: tenantSlug,
    tier,
    features: buildPlanFeatures(config, tier),
    activeSince: row?.active_since ? new Date(row.active_since).toISOString() : null,
    expiresAt: row?.expires_at ? new Date(row.expires_at).toISOString() : null,
  };
}

async function setPlanForTenant(config, tenant, tier, expiresAt = null) {
  const tenantSlug = sanitizeTenant(tenant || 'global');
  const normalizedTier = normalizeTier(tier);

  await query(
    config,
    `
      INSERT INTO tenant_plans (tenant_slug, tier, active_since, expires_at)
      VALUES ($1, $2, NOW(), $3)
      ON CONFLICT (tenant_slug) DO UPDATE
      SET tier = $2, active_since = NOW(), expires_at = $3
    `,
    [tenantSlug, normalizedTier, expiresAt]
  );

  return {
    tenant: tenantSlug,
    tier: normalizedTier,
    features: buildPlanFeatures(config, normalizedTier),
    expiresAt,
  };
}

function assertFeatureAllowed(planData, featureKey, context = {}) {
  const features = planData?.features || PLAN_FEATURES.free;
  const tier = planData?.tier || 'free';

  // Boolean feature check
  if (typeof features[featureKey] === 'boolean' && !features[featureKey]) {
    throw new ServiceError(
      403,
      'feature_not_available',
      `This feature requires a higher plan. Your current plan: ${features.label || tier}.`,
      {
        currentTier: tier,
        feature: featureKey,
        requiredTier: featureKey === 'whiteLabel' || featureKey === 'slaGuarantee' ? 'enterprise' : 'pro',
        upgradeUrl: '/pricing',
      }
    );
  }

  // Module access check
  if (featureKey === 'module' && context.moduleId) {
    const allowedModules = features.modules || [];
    if (!allowedModules.includes(context.moduleId)) {
      throw new ServiceError(
        403,
        'module_not_available',
        `Module "${context.moduleId}" is not included in your ${features.label || tier} plan.`,
        {
          currentTier: tier,
          module: context.moduleId,
          allowedModules,
          upgradeUrl: '/pricing',
        }
      );
    }
  }

  // Team member limit check
  if (featureKey === 'teamMember' && context.currentCount !== undefined) {
    const maxMembers = features.maxTeamMembers || 3;
    if (context.currentCount >= maxMembers) {
      throw new ServiceError(
        403,
        'team_limit_reached',
        `Your ${features.label || tier} plan allows up to ${maxMembers === Infinity ? 'unlimited' : maxMembers} team members.`,
        {
          currentTier: tier,
          currentCount: context.currentCount,
          maxAllowed: maxMembers,
          upgradeUrl: '/pricing',
        }
      );
    }
  }
}

module.exports = {
  recordUsageEvent,
  listUsageEvents,
  getCredits,
  getUsageAllowance,
  PLAN_FEATURES,
  VALID_TIERS,
  getTenantPlan,
  setPlanForTenant,
  assertFeatureAllowed,
  assertUsageAllowed,
  __test__: {
    normalizeProductKey,
    normalizeActionKey,
    normalizeOptionalUserId,
    normalizeTier,
    resolveTierQuotaLimit,
    buildPlanFeatures,
    buildUsageWindow,
  },
};
