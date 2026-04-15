/**
 * P2-4: API Key Service
 *
 * Manages API key lifecycle: create, verify, list, revoke.
 * Keys are formatted as: cyk_live_{random48chars}
 * Only the hash is stored; raw key is returned once on creation.
 */

const crypto = require('node:crypto');
const { ServiceError } = require('./auth-service');
const { query } = require('./database');

function generateApiKey() {
  const random = crypto.randomBytes(36).toString('base64url').slice(0, 48);
  return `cyk_live_${random}`;
}

function hashApiKey(rawKey) {
  return crypto.createHash('sha256').update(String(rawKey)).digest('hex');
}

function getKeyPrefix(rawKey) {
  return String(rawKey).slice(0, 12);
}

async function createApiKey(config, { tenant, userId, name, scopes, expiresIn }) {
  if (!name || typeof name !== 'string' || name.trim().length === 0) {
    throw new ServiceError(400, 'invalid_key_name', 'API key name is required.');
  }

  const rawKey = generateApiKey();
  const keyHash = hashApiKey(rawKey);
  const keyPrefix = getKeyPrefix(rawKey);
  const normalizedScopes = Array.isArray(scopes) ? scopes.filter(s => typeof s === 'string') : [];
  const expiresAt = expiresIn
    ? new Date(Date.now() + Math.max(3600000, Number(expiresIn))).toISOString()
    : null;

  const result = await query(
    config,
    `INSERT INTO api_keys (tenant_slug, user_id, name, key_hash, key_prefix, expires_at, scopes)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     RETURNING id, name, key_prefix, expires_at, scopes, created_at`,
    [tenant, Number(userId), name.trim(), keyHash, keyPrefix, expiresAt, normalizedScopes]
  );

  const row = result?.rows?.[0];
  return {
    id: String(row.id),
    name: row.name,
    keyPrefix: row.key_prefix,
    rawKey, // Returned ONCE only — never stored
    expiresAt: row.expires_at,
    scopes: row.scopes,
    createdAt: row.created_at,
  };
}

async function verifyApiKey(config, rawKey) {
  if (!rawKey || !rawKey.startsWith('cyk_live_')) {
    return null;
  }

  const keyHash = hashApiKey(rawKey);
  const result = await query(
    config,
    `SELECT ak.id, ak.tenant_slug, ak.user_id, ak.scopes, ak.revoked, ak.expires_at,
            u.email, u.role, u.display_name, u.is_active
     FROM api_keys ak
     JOIN users u ON u.id = ak.user_id
     WHERE ak.key_hash = $1`,
    [keyHash]
  );

  const row = result?.rows?.[0];
  if (!row) return null;
  if (row.revoked) return null;
  if (row.expires_at && new Date(row.expires_at) < new Date()) return null;
  if (!row.is_active) return null;

  // Update last_used_at
  await query(config, 'UPDATE api_keys SET last_used_at = NOW() WHERE id = $1', [row.id]).catch(() => {});

  return {
    tenant: row.tenant_slug,
    userId: row.user_id,
    scopes: row.scopes || [],
    email: row.email,
    role: row.role,
    displayName: row.display_name,
  };
}

async function listApiKeys(config, tenant, userId) {
  const result = await query(
    config,
    `SELECT id, name, key_prefix, last_used_at, expires_at, scopes, revoked, created_at
     FROM api_keys
     WHERE tenant_slug = $1 AND user_id = $2
     ORDER BY created_at DESC
     LIMIT 50`,
    [tenant, Number(userId)]
  );

  return result?.rows || [];
}

async function revokeApiKey(config, keyId, requestingUserId) {
  const result = await query(
    config,
    `UPDATE api_keys SET revoked = true WHERE id = $1 AND user_id = $2 AND revoked = false RETURNING id`,
    [Number(keyId), Number(requestingUserId)]
  );

  if (!result?.rows?.length) {
    throw new ServiceError(404, 'key_not_found', 'API key not found or already revoked.');
  }

  return { revoked: true };
}

module.exports = {
  createApiKey,
  verifyApiKey,
  listApiKeys,
  revokeApiKey,
};
