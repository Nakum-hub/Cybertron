const { getRedisClient } = require('./redis-client');

class InMemoryRateLimiter {
  constructor(windowMs, maxRequests, maxStoreSize = 50_000) {
    this.windowMs = windowMs;
    this.maxRequests = maxRequests;
    this.store = new Map();
    this.maxStoreSize = maxStoreSize;
  }

  _evictExpired() {
    const now = Date.now();
    for (const [key, value] of this.store.entries()) {
      if (now >= value.resetAt) {
        this.store.delete(key);
      }
    }
  }

  async take(key) {
    const now = Date.now();
    const active = this.store.get(key);

    if (!active || now >= active.resetAt) {
      // Enforce size cap before inserting new entry
      if (!this.store.has(key) && this.store.size >= this.maxStoreSize) {
        this._evictExpired();
        // If still at capacity after eviction, drop oldest entry
        if (this.store.size >= this.maxStoreSize) {
          const oldestKey = this.store.keys().next().value;
          this.store.delete(oldestKey);
        }
      }

      const next = {
        count: 1,
        resetAt: now + this.windowMs,
      };

      this.store.set(key, next);
      return {
        allowed: true,
        limit: this.maxRequests,
        remaining: this.maxRequests - 1,
        resetAt: next.resetAt,
      };
    }

    active.count += 1;

    return {
      allowed: active.count <= this.maxRequests,
      limit: this.maxRequests,
      remaining: Math.max(0, this.maxRequests - active.count),
      resetAt: active.resetAt,
    };
  }

  cleanup() {
    const now = Date.now();

    for (const [key, value] of this.store.entries()) {
      if (now >= value.resetAt) {
        this.store.delete(key);
      }
    }
  }
}

class RedisRateLimiter {
  constructor(name, windowMs, maxRequests, config, log = () => {}, allowFallback = true) {
    this.name = String(name || 'global');
    this.windowMs = windowMs;
    this.maxRequests = maxRequests;
    this.config = config;
    this.log = log;
    this.fallback = new InMemoryRateLimiter(windowMs, maxRequests);
    this.allowFallback = Boolean(allowFallback);
  }

  buildRedisKey(key) {
    return `rate:${this.name}:${key}`;
  }

  denyDueToUnavailableStore() {
    const now = Date.now();
    return {
      allowed: false,
      limit: this.maxRequests,
      remaining: 0,
      resetAt: now + this.windowMs,
    };
  }

  async take(key) {
    const redis = await getRedisClient(this.config, this.log);
    if (!redis) {
      if (!this.allowFallback) {
        this.log('error', 'rate_limit.redis_unavailable_strict', {
          limiter: this.name,
          key,
        });
        return this.denyDueToUnavailableStore();
      }
      return this.fallback.take(key);
    }

    const redisKey = this.buildRedisKey(key);
    try {
      const count = Number(await redis.incr(redisKey));
      if (count === 1) {
        await redis.pExpire(redisKey, this.windowMs);
      }

      let ttlMs = Number(await redis.pTTL(redisKey));
      if (!Number.isFinite(ttlMs) || ttlMs < 1) {
        ttlMs = this.windowMs;
        await redis.pExpire(redisKey, this.windowMs);
      }

      const resetAt = Date.now() + ttlMs;
      return {
        allowed: count <= this.maxRequests,
        limit: this.maxRequests,
        remaining: Math.max(0, this.maxRequests - count),
        resetAt,
      };
    } catch (error) {
      this.log('warn', 'rate_limit.redis_failed', {
        limiter: this.name,
        key,
        error: error instanceof Error ? error.message : 'unknown redis rate limiter failure',
      });
      if (!this.allowFallback) {
        return this.denyDueToUnavailableStore();
      }
      return this.fallback.take(key);
    }
  }

  cleanup() {
    this.fallback.cleanup();
  }
}

function createRateLimiter(options) {
  const windowMs = Number(options.windowMs);
  const maxRequests = Number(options.maxRequests);
  const useRedis = Boolean(options.useRedis);
  const name = String(options.name || 'global');
  const allowFallback =
    options.allowFallback !== undefined
      ? Boolean(options.allowFallback)
      : String(options?.config?.environment || '').toLowerCase() !== 'production';

  if (useRedis) {
    return new RedisRateLimiter(name, windowMs, maxRequests, options.config, options.log, allowFallback);
  }

  return new InMemoryRateLimiter(windowMs, maxRequests);
}

module.exports = {
  InMemoryRateLimiter,
  RedisRateLimiter,
  createRateLimiter,
};
