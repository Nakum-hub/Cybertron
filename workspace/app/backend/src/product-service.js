const { query } = require('./database');
const { sanitizeTenant } = require('./validators');
const { appendAuditLog } = require('./audit-log');
const { ServiceError } = require('./auth-service');
const { normalizeRole, hasRoleAccess } = require('./security-policy');
const { evaluateProductFlags } = require('./feature-flag-service');
const { getTenantPlan, getUsageAllowance } = require('./billing-service');

const DEFAULT_PRODUCT_CATALOG = [
  {
    productId: 'threat-command',
    productKey: 'threat-command',
    name: 'Threat Command',
    description: 'Real-time threat intelligence and SOC orchestration.',
    modulePath: '/modules/threat-intel',
    roleMin: 'executive_viewer',
    enabled: true,
  },
  {
    productId: 'identity-guardian',
    productKey: 'identity-guardian',
    name: 'Identity Guardian',
    description: 'Adaptive identity trust and access governance.',
    modulePath: '/modules/core',
    roleMin: 'security_analyst',
    enabled: true,
  },
  {
    productId: 'resilience-hq',
    productKey: 'resilience-hq',
    name: 'Resilience HQ',
    description: 'Executive reliability and security KPI cockpit.',
    modulePath: '/modules/compliance-engine',
    roleMin: 'executive_viewer',
    enabled: true,
  },
  {
    productId: 'risk-copilot',
    productKey: 'risk-copilot',
    name: 'Risk Copilot',
    description: 'AI-assisted risk analysis and prioritization.',
    modulePath: '/modules/risk-copilot',
    roleMin: 'executive_viewer',
    enabled: true,
  },
];

function normalizeProductId(value) {
  const normalized = String(value || '').toLowerCase().trim();
  if (!/^[a-z0-9-]{2,64}$/.test(normalized)) {
    throw new ServiceError(400, 'invalid_product_id', 'Product id must match [a-z0-9-] and be 2-64 chars.');
  }

  return normalized;
}

function normalizeRoleMin(value, fallback = 'executive_viewer') {
  const normalized = normalizeRole(value || fallback);
  return normalized || 'executive_viewer';
}

async function seedDefaultCatalogIfEmpty(config) {
  if (!config.databaseUrl) {
    return false;
  }

  const countResult = await query(
    config,
    `
      SELECT COUNT(*)::INT AS total
      FROM products
    `
  );
  const total = Number(countResult?.rows?.[0]?.total || 0);
  if (total > 0) {
    return false;
  }

  for (const product of DEFAULT_PRODUCT_CATALOG) {
    await query(
      config,
      `
        INSERT INTO products (
          product_id,
          product_key,
          name,
          description,
          module_path,
          is_active,
          enabled,
          role_min
        )
        VALUES ($1,$2,$3,$4,$5,TRUE,$6,$7)
        ON CONFLICT (product_id) DO NOTHING
      `,
      [
        product.productId,
        product.productKey,
        product.name,
        product.description,
        product.modulePath,
        product.enabled,
        product.roleMin,
      ]
    );
  }

  return true;
}

function toProductRow(row, options = {}) {
  const includeInternal = Boolean(options.includeInternal);
  const shape = {
    productId: row.product_id,
    productKey: row.product_key || row.product_id,
    name: row.name,
    description: row.description || null,
    modulePath: row.module_path,
    active: Boolean(row.is_active),
    enabled: Boolean(row.enabled),
    roleMin: normalizeRoleMin(row.role_min),
    tenantEnabled: row.tenant_enabled === null ? null : Boolean(row.tenant_enabled),
    tenantRoleMin: row.tenant_role_min ? normalizeRoleMin(row.tenant_role_min) : null,
    updatedAt: row.tenant_updated_at ? new Date(row.tenant_updated_at).toISOString() : null,
    createdAt: row.created_at ? new Date(row.created_at).toISOString() : null,
  };

  if (!includeInternal) {
    return shape;
  }

  return {
    ...shape,
    _tenantSlug: row.tenant_slug || null,
  };
}

async function listProducts(config, tenant, options = {}) {
  const tenantSlug = sanitizeTenant(tenant || 'global');
  let result = await query(
    config,
    `
      SELECT
        p.product_id,
        p.product_key,
        p.name,
        p.description,
        p.module_path,
        p.is_active,
        p.enabled,
        p.role_min,
        p.created_at,
        tp.tenant_slug,
        tp.enabled AS tenant_enabled,
        tp.role_min AS tenant_role_min,
        tp.updated_at AS tenant_updated_at
      FROM products p
      LEFT JOIN tenant_products tp
        ON tp.product_id = p.product_id
       AND tp.tenant_slug = $1
      ORDER BY p.name ASC, p.product_id ASC
    `,
    [tenantSlug]
  );

  let rows = (result?.rows || []).map(row => toProductRow(row, options));
  if (rows.length === 0 && (await seedDefaultCatalogIfEmpty(config))) {
    result = await query(
      config,
      `
        SELECT
          p.product_id,
          p.product_key,
          p.name,
          p.description,
          p.module_path,
          p.is_active,
          p.enabled,
          p.role_min,
          p.created_at,
          tp.tenant_slug,
          tp.enabled AS tenant_enabled,
          tp.role_min AS tenant_role_min,
          tp.updated_at AS tenant_updated_at
        FROM products p
        LEFT JOIN tenant_products tp
          ON tp.product_id = p.product_id
         AND tp.tenant_slug = $1
        ORDER BY p.name ASC, p.product_id ASC
      `,
      [tenantSlug]
    );
    rows = (result?.rows || []).map(row => toProductRow(row, options));
  }

  const includeFlags = options.includeFlags !== false;
  if (!includeFlags) {
    return rows;
  }

  const featureGates = await evaluateProductFlags(
    config,
    tenantSlug,
    rows.map(row => row.productKey)
  );

  return rows.map(row => ({
    ...row,
    featureGate: featureGates[row.productKey] || {
      allowed: true,
      flags: [],
    },
  }));
}

function deriveEffectiveRoleMin(row) {
  return normalizeRoleMin(row.tenantRoleMin || row.roleMin || 'executive_viewer');
}

function normalizePlanModule(value) {
  return String(value || '').trim().toLowerCase();
}

function collectPlanAliases(row) {
  const aliases = new Set();
  const add = value => {
    const normalized = normalizePlanModule(value);
    if (normalized) {
      aliases.add(normalized);
    }
  };

  add(row.productId);
  add(row.productKey);

  if (row.modulePath) {
    const modulePath = String(row.modulePath).trim().toLowerCase();
    add(modulePath);
    const segments = modulePath.split('/').filter(Boolean);
    add(segments[segments.length - 1]);
  }

  return [...aliases];
}

function isPlanAllowed(row, planData) {
  const modules = Array.isArray(planData?.features?.modules)
    ? new Set(planData.features.modules.map(normalizePlanModule).filter(Boolean))
    : new Set();

  if (modules.size === 0) {
    return false;
  }

  return collectPlanAliases(row).some(alias => modules.has(alias));
}

function deriveEnabledState(row, planAllowed = true) {
  const productEnabled = Boolean(row.enabled);
  const tenantEnabled = row.tenantEnabled === null ? true : Boolean(row.tenantEnabled);
  const flagEnabled = row.featureGate ? Boolean(row.featureGate.allowed) : true;
  return productEnabled && tenantEnabled && flagEnabled && planAllowed;
}

function asTenantProduct(row, role, planData, usageAllowance = null) {
  const roleMin = deriveEffectiveRoleMin(row);
  const planAllowed = isPlanAllowed(row, planData);
  const effectiveEnabled = deriveEnabledState(row, planAllowed);
  const allowedForRole = hasRoleAccess(normalizeRole(role), roleMin);
  const quotaEnforced = Boolean(usageAllowance?.quotaEnforced);
  const quotaExhausted = Boolean(usageAllowance?.exhausted);
  return {
    ...row,
    roleMin,
    planAllowed,
    planTier: planData?.tier || 'free',
    planLabel: planData?.features?.label || null,
    quotaEnforced,
    quotaAllowed: !quotaExhausted,
    quotaRemainingUnits: usageAllowance?.quotaRemainingUnits ?? null,
    quotaLimitUnits: usageAllowance?.quotaLimitUnits ?? null,
    quotaPeriodEndsAt: usageAllowance?.periodEndsAt ?? null,
    quotaExhausted,
    effectiveEnabled,
    allowedForRole,
    visible: effectiveEnabled && allowedForRole,
  };
}

async function listTenantProducts(config, tenant, role = 'executive_viewer') {
  const tenantSlug = sanitizeTenant(tenant || 'global');
  const catalog = await listProducts(config, tenantSlug, {
    includeFlags: true,
  });
  const planData = await getTenantPlan(config, tenantSlug);
  const usageAllowance = await getUsageAllowance(config, tenantSlug, planData);
  return catalog.map(row => asTenantProduct(row, role, planData, usageAllowance));
}

async function getTenantProduct(config, tenant, productKey, role = 'executive_viewer') {
  const normalizedProductKey = normalizeProductId(productKey);
  const catalog = await listTenantProducts(config, tenant, role);
  return catalog.find(item => item.productKey === normalizedProductKey || item.productId === normalizedProductKey) || null;
}

async function setTenantProductState(config, payload, contextMeta = {}) {
  const tenantSlug = sanitizeTenant(payload.tenant || 'global');
  const productId = normalizeProductId(payload.productId || payload.productKey);
  const enabled = Boolean(payload.enabled);
  const roleMin = payload.roleMin ? normalizeRoleMin(payload.roleMin) : null;

  const product = await query(
    config,
    `
      SELECT product_id, product_key, is_active, enabled, role_min
      FROM products
      WHERE product_id = $1 OR product_key = $1
      LIMIT 1
    `,
    [productId]
  );

  if (!product?.rows?.length) {
    throw new ServiceError(404, 'product_not_found', 'Product was not found.');
  }

  await query(
    config,
    `
      INSERT INTO tenant_products (
        tenant_slug,
        product_id,
        enabled,
        role_min
      )
      VALUES ($1,$2,$3,$4)
      ON CONFLICT (tenant_slug, product_id)
      DO UPDATE SET
        enabled = EXCLUDED.enabled,
        role_min = EXCLUDED.role_min,
        updated_at = NOW()
    `,
    [tenantSlug, product.rows[0].product_id, enabled, roleMin]
  );

  await appendAuditLog(config, {
    tenantSlug,
    actorId: contextMeta.actorUserId || null,
    actorEmail: contextMeta.actorEmail || null,
    action: 'products.tenant_toggle',
    targetType: 'product',
    targetId: productId,
    ipAddress: contextMeta.ipAddress || null,
    userAgent: contextMeta.userAgent || null,
    traceId: contextMeta.traceId || null,
    payload: {
      enabled,
      roleMin,
    },
  });

  const effectiveProductKey = product.rows[0].product_key || product.rows[0].product_id;
  return {
    tenant: tenantSlug,
    productId: product.rows[0].product_id,
    productKey: effectiveProductKey,
    enabled,
    roleMin: roleMin || normalizeRoleMin(product.rows[0].role_min),
    updatedAt: new Date().toISOString(),
  };
}

module.exports = {
  listProducts,
  listTenantProducts,
  getTenantProduct,
  setTenantProductState,
  __test__: {
    normalizeProductId,
    normalizeRoleMin,
    toProductRow,
    deriveEffectiveRoleMin,
    normalizePlanModule,
    collectPlanAliases,
    isPlanAllowed,
    deriveEnabledState,
    asTenantProduct,
  },
};
