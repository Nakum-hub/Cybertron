const { query } = require('./database');
const { getRedisClient } = require('./redis-client');

const REVOCATION_PREFIX = 'auth:revoked:access:';

function makeRevocationKey(tokenHash) {
  return `${REVOCATION_PREFIX}${tokenHash}`;
}

function computeRevocationTtlMs(expiresAtMs, fallbackMs) {
  const fallback = Number.isFinite(Number(fallbackMs)) ? Number(fallbackMs) : 60 * 60_000;
  const ttl = Number(expiresAtMs) - Date.now();
  if (!Number.isFinite(ttl)) {
    return Math.max(1_000, fallback);
  }

  return Math.max(1_000, ttl);
}

async function markTokenHashRevoked(config, tokenHash, expiresAtMs, log = () => {}) {
  if (!tokenHash) {
    return;
  }

  const redis = await getRedisClient(config, log);
  if (!redis) {
    return;
  }

  const ttlMs = computeRevocationTtlMs(expiresAtMs, config.authTokenTtlMs);
  await redis.set(makeRevocationKey(tokenHash), '1', {
    PX: ttlMs,
  });
}

async function isTokenHashRevokedInRedis(config, tokenHash, log = () => {}) {
  if (!tokenHash) {
    return false;
  }

  const redis = await getRedisClient(config, log);
  if (!redis) {
    return false;
  }

  try {
    const state = await redis.get(makeRevocationKey(tokenHash));
    return state === '1';
  } catch (error) {
    log('warn', 'auth.revocation_redis_lookup_failed', {
      error: error instanceof Error ? error.message : 'unknown redis revocation lookup failure',
    });
    return false;
  }
}

async function isTokenHashRevokedInDatabase(config, tokenHash) {
  if (!config.databaseUrl || !tokenHash) {
    return false;
  }

  const result = await query(
    config,
    `
      SELECT 1
      FROM auth_access_token_revocations
      WHERE token_hash = $1
        AND (expires_at IS NULL OR expires_at > NOW())
      LIMIT 1
    `,
    [tokenHash]
  );

  return Boolean(result?.rows?.length);
}

async function isTokenHashRevoked(config, tokenHash, log = () => {}) {
  if (!tokenHash) {
    return false;
  }

  const redisRevoked = await isTokenHashRevokedInRedis(config, tokenHash, log);
  if (redisRevoked) {
    return true;
  }

  return isTokenHashRevokedInDatabase(config, tokenHash);
}

module.exports = {
  markTokenHashRevoked,
  isTokenHashRevoked,
};
