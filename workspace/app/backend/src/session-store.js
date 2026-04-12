const crypto = require('node:crypto');
const { getRedisClient } = require('./redis-client');

class SessionStore {
  constructor(ttlMs, options = {}) {
    this.ttlMs = ttlMs;
    this.allowDemoToken = Boolean(options.allowDemoToken);
    this.maxSessions = Number(options.maxSessions) > 0 ? Number(options.maxSessions) : 50_000;
    this.sessions = new Map();
  }

  async createSession({ role, tenant }) {
    if (this.sessions.size >= this.maxSessions) {
      const oldestToken = this.sessions.keys().next().value;
      if (oldestToken) {
        this.sessions.delete(oldestToken);
      }
    }

    const token = `ctrt_${crypto.randomBytes(18).toString('base64url')}`;
    const createdAt = Date.now();
    const expiresAt = createdAt + this.ttlMs;
    const normalizedRole = role || 'security_analyst';
    const normalizedTenant = tenant || 'global';

    const user = {
      id: `user-${normalizedTenant}-${normalizedRole}`,
      name: 'Cybertron Operator',
      email: `${normalizedRole}.${normalizedTenant}@cybertron.local`,
      role: normalizedRole,
      tenant: normalizedTenant,
      createdAt: new Date(createdAt).toISOString(),
    };

    this.sessions.set(token, {
      token,
      user,
      createdAt,
      expiresAt,
    });

    return {
      token,
      user,
      expiresAt,
    };
  }

  async getSession(token) {
    if (!token) {
      return null;
    }

    const session = this.sessions.get(token);

    if (!session) {
      return null;
    }

    if (Date.now() >= session.expiresAt) {
      this.sessions.delete(token);
      return null;
    }

    return session;
  }

  cleanup() {
    const now = Date.now();

    for (const [token, session] of this.sessions.entries()) {
      if (now >= session.expiresAt) {
        this.sessions.delete(token);
      }
    }
  }

  async invalidateSession(token) {
    if (!token) {
      return false;
    }

    return this.sessions.delete(token);
  }

  getStats() {
    return {
      activeSessions: this.sessions.size,
      maxSessions: this.maxSessions,
      ttlSeconds: Math.floor(this.ttlMs / 1000),
    };
  }
}

class RedisSessionStore {
  constructor(ttlMs, options = {}, config = {}, log = () => {}) {
    this.ttlMs = ttlMs;
    this.allowDemoToken = Boolean(options.allowDemoToken);
    this.maxSessions = Number(options.maxSessions) > 0 ? Number(options.maxSessions) : 50_000;
    this.config = config;
    this.log = log;
    this.allowFallback = options.allowFallback !== undefined
      ? Boolean(options.allowFallback)
      : String(config.environment || '').toLowerCase() !== 'production';
    this.fallback = new SessionStore(ttlMs, options);
  }

  buildRedisKey(token) {
    return `session:${token}`;
  }

  buildSessionPayload({ role, tenant }) {
    const token = `ctrt_${crypto.randomBytes(18).toString('base64url')}`;
    const createdAt = Date.now();
    const expiresAt = createdAt + this.ttlMs;
    const normalizedRole = role || 'security_analyst';
    const normalizedTenant = tenant || 'global';

    const user = {
      id: `user-${normalizedTenant}-${normalizedRole}`,
      name: 'Cybertron Operator',
      email: `${normalizedRole}.${normalizedTenant}@cybertron.local`,
      role: normalizedRole,
      tenant: normalizedTenant,
      createdAt: new Date(createdAt).toISOString(),
    };

    return { token, user, createdAt, expiresAt };
  }

  async createSession({ role, tenant }) {
    const { token, user, createdAt, expiresAt } = this.buildSessionPayload({ role, tenant });
    const redis = await getRedisClient(this.config, this.log);

    if (!redis) {
      if (!this.allowFallback) {
        this.log('error', 'session.redis_unavailable_strict', { action: 'createSession' });
        throw new Error('Redis unavailable and fallback disabled');
      }
      return this.fallback.createSession({ role, tenant });
    }

    try {
      const sessionData = JSON.stringify({ token, user, createdAt, expiresAt });
      await redis.set(this.buildRedisKey(token), sessionData, { PX: this.ttlMs });
      return { token, user, expiresAt };
    } catch (error) {
      this.log('warn', 'session.redis_create_failed', {
        error: error instanceof Error ? error.message : 'unknown',
      });
      if (!this.allowFallback) {
        throw error;
      }
      return this.fallback.createSession({ role, tenant });
    }
  }

  async getSession(token) {
    if (!token) {
      return null;
    }

    const redis = await getRedisClient(this.config, this.log);

    if (!redis) {
      if (!this.allowFallback) {
        return null;
      }
      return this.fallback.getSession(token);
    }

    try {
      const raw = await redis.get(this.buildRedisKey(token));
      if (!raw) {
        return null;
      }

      const session = JSON.parse(raw);

      if (Date.now() >= session.expiresAt) {
        await redis.del(this.buildRedisKey(token));
        return null;
      }

      return session;
    } catch (error) {
      this.log('warn', 'session.redis_get_failed', {
        error: error instanceof Error ? error.message : 'unknown',
      });
      if (!this.allowFallback) {
        return null;
      }
      return this.fallback.getSession(token);
    }
  }

  async invalidateSession(token) {
    if (!token) {
      return false;
    }

    const redis = await getRedisClient(this.config, this.log);

    if (!redis) {
      if (!this.allowFallback) {
        return false;
      }
      return this.fallback.invalidateSession(token);
    }

    try {
      const removed = await redis.del(this.buildRedisKey(token));
      return removed > 0;
    } catch (error) {
      this.log('warn', 'session.redis_invalidate_failed', {
        error: error instanceof Error ? error.message : 'unknown',
      });
      if (!this.allowFallback) {
        return false;
      }
      return this.fallback.invalidateSession(token);
    }
  }

  cleanup() {
    // Redis handles expiry via PX TTL — only clean up in-memory fallback
    this.fallback.cleanup();
  }

  getStats() {
    return {
      activeSessions: this.fallback.getStats().activeSessions,
      maxSessions: this.maxSessions,
      ttlSeconds: Math.floor(this.ttlMs / 1000),
      backend: 'redis',
    };
  }
}

function createSessionStore(options) {
  const ttlMs = Number(options.ttlMs);
  const useRedis = Boolean(options.useRedis);
  const storeOptions = {
    allowDemoToken: options.allowDemoToken,
    maxSessions: options.maxSessions,
    allowFallback: options.allowFallback,
  };

  if (useRedis) {
    return new RedisSessionStore(ttlMs, storeOptions, options.config, options.log);
  }

  return new SessionStore(ttlMs, storeOptions);
}

function parseBearerToken(authorizationHeader) {
  const value = String(authorizationHeader || '').trim();

  if (!value.toLowerCase().startsWith('bearer ')) {
    return null;
  }

  const token = value.slice(7).trim();
  return token || null;
}

module.exports = {
  SessionStore,
  RedisSessionStore,
  createSessionStore,
  parseBearerToken,
};
