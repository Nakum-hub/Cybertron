const { query } = require('./database');
const { sanitizeTenant } = require('./validators');
const { ServiceError } = require('./auth-service');
const { appendAuditLog } = require('./audit-log');

function normalizeFlagKey(value) {
  const normalized = String(value || '').trim().toLowerCase();
  if (!/^[a-z0-9_:-]{2,96}$/.test(normalized)) {
    throw new ServiceError(400, 'invalid_flag_key', 'Feature flag key is invalid.');
  }

  return normalized;
}

async function listFeatureFlags(config) {
  const result = await query(
    config,
    `
      SELECT flag_key, description, created_at
      FROM feature_flags
      ORDER BY flag_key ASC
    `
  );

  return (result?.rows || []).map(row => ({
    flagKey: row.flag_key,
    description: row.description || null,
    createdAt: row.created_at ? new Date(row.created_at).toISOString() : null,
  }));
}

async function listTenantFeatureFlags(config, tenant) {
  const tenantSlug = sanitizeTenant(tenant || 'global');
  const result = await query(
    config,
    `
      SELECT
        ff.flag_key,
        ff.description,
        COALESCE(tff.enabled, FALSE) AS enabled,
        tff.updated_at
      FROM feature_flags ff
      LEFT JOIN tenant_feature_flags tff
        ON tff.flag_key = ff.flag_key
       AND tff.tenant_slug = $1
      ORDER BY ff.flag_key ASC
    `,
    [tenantSlug]
  );

  return (result?.rows || []).map(row => ({
    flagKey: row.flag_key,
    description: row.description || null,
    enabled: Boolean(row.enabled),
    updatedAt: row.updated_at ? new Date(row.updated_at).toISOString() : null,
  }));
}

async function setTenantFeatureFlag(config, payload, contextMeta = {}) {
  const tenantSlug = sanitizeTenant(payload?.tenant || 'global');
  const flagKey = normalizeFlagKey(payload?.flagKey);
  const enabled = Boolean(payload?.enabled);

  const flag = await query(
    config,
    `
      SELECT flag_key
      FROM feature_flags
      WHERE flag_key = $1
      LIMIT 1
    `,
    [flagKey]
  );
  if (!flag?.rows?.length) {
    throw new ServiceError(404, 'feature_flag_not_found', 'Feature flag does not exist.');
  }

  const result = await query(
    config,
    `
      INSERT INTO tenant_feature_flags (tenant_slug, flag_key, enabled)
      VALUES ($1,$2,$3)
      ON CONFLICT (tenant_slug, flag_key)
      DO UPDATE SET
        enabled = EXCLUDED.enabled,
        updated_at = NOW()
      RETURNING tenant_slug, flag_key, enabled, updated_at
    `,
    [tenantSlug, flagKey, enabled]
  );

  await appendAuditLog(config, {
    tenantSlug,
    actorId: contextMeta.actorUserId || null,
    actorEmail: contextMeta.actorEmail || null,
    action: 'feature_flag.tenant_updated',
    targetType: 'feature_flag',
    targetId: flagKey,
    ipAddress: contextMeta.ipAddress || null,
    userAgent: contextMeta.userAgent || null,
    traceId: contextMeta.traceId || null,
    payload: {
      enabled,
    },
  });

  const row = result.rows[0];
  return {
    tenant: row.tenant_slug,
    flagKey: row.flag_key,
    enabled: Boolean(row.enabled),
    updatedAt: new Date(row.updated_at).toISOString(),
  };
}

async function evaluateProductFlags(config, tenant, productKeys) {
  const tenantSlug = sanitizeTenant(tenant || 'global');
  const keys = Array.isArray(productKeys)
    ? [...new Set(productKeys.map(value => String(value || '').trim().toLowerCase()).filter(Boolean))]
    : [];
  if (!keys.length) {
    return {};
  }

  const result = await query(
    config,
    `
      SELECT
        pff.product_key,
        pff.flag_key,
        pff.enabled_by_default,
        tff.enabled AS tenant_enabled
      FROM product_feature_flags pff
      LEFT JOIN tenant_feature_flags tff
        ON tff.flag_key = pff.flag_key
       AND tff.tenant_slug = $1
      WHERE pff.product_key = ANY($2::text[])
      ORDER BY pff.product_key ASC, pff.flag_key ASC
    `,
    [tenantSlug, keys]
  );

  const gateMap = {};
  for (const key of keys) {
    gateMap[key] = {
      allowed: true,
      flags: [],
    };
  }

  for (const row of result?.rows || []) {
    const productKey = String(row.product_key || '').trim();
    if (!productKey) {
      continue;
    }

    const enabled = row.tenant_enabled === null
      ? Boolean(row.enabled_by_default)
      : Boolean(row.tenant_enabled);
    const state = gateMap[productKey] || {
      allowed: true,
      flags: [],
    };
    state.flags.push({
      flagKey: row.flag_key,
      enabled,
      source: row.tenant_enabled === null ? 'default' : 'tenant_override',
    });
    if (!enabled) {
      state.allowed = false;
    }
    gateMap[productKey] = state;
  }

  return gateMap;
}

module.exports = {
  listFeatureFlags,
  listTenantFeatureFlags,
  setTenantFeatureFlag,
  evaluateProductFlags,
};
