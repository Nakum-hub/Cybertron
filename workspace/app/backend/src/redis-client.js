const { createClient } = require('redis');

let sharedClient = null;
let sharedClientPromise = null;
let disabledUntilMs = 0;

function canAttemptConnection() {
  return Date.now() >= disabledUntilMs;
}

function markTemporarilyUnavailable() {
  disabledUntilMs = Date.now() + 5_000;
}

function toPositiveInt(value, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 1) {
    return fallback;
  }

  return Math.floor(parsed);
}

async function connectRedis(config, log = () => {}) {
  const url = String(config.redisUrl || '').trim();
  if (!url) {
    return null;
  }

  if (!canAttemptConnection()) {
    return null;
  }

  const connectTimeoutMs = toPositiveInt(config.redisConnectTimeoutMs, 2_000);
  const maxRetries = toPositiveInt(config.redisConnectMaxRetries, 4);

  const clientOpts = {
    url,
    socket: {
      connectTimeout: connectTimeoutMs,
      reconnectStrategy(retries) {
        if (retries >= maxRetries) {
          return new Error('redis reconnect retries exhausted');
        }

        return Math.min(200 + retries * 120, 1_000);
      },
    },
  };

  // Support explicit Redis credentials (when not embedded in the URL)
  if (config.redisPassword) {
    clientOpts.password = String(config.redisPassword);
  }
  if (config.redisUsername) {
    clientOpts.username = String(config.redisUsername);
  }

  const client = createClient(clientOpts);

  client.on('error', error => {
    log('warn', 'redis.client_error', {
      error: error instanceof Error ? error.message : 'unknown redis error',
    });
  });

  const overallTimeoutMs = connectTimeoutMs * (maxRetries + 1);
  let timeoutHandle = null;

  try {
    const connectPromise = client.connect();
    const timeoutPromise = new Promise((_, reject) => {
      timeoutHandle = setTimeout(() => {
        reject(new Error(`redis connect timed out after ${overallTimeoutMs}ms`));
      }, overallTimeoutMs);
    });

    await Promise.race([connectPromise, timeoutPromise]);
  } catch (error) {
    try {
      client.disconnect();
    } catch {
      // Ignore disconnect errors during failed startup.
    }
    throw error;
  } finally {
    if (timeoutHandle) {
      clearTimeout(timeoutHandle);
    }
  }
  return client;
}

async function getRedisClient(config, log = () => {}) {
  if (sharedClient) {
    return sharedClient;
  }

  if (sharedClientPromise) {
    return sharedClientPromise;
  }

  sharedClientPromise = connectRedis(config, log)
    .then(client => {
      sharedClient = client;
      return client;
    })
    .catch(error => {
      markTemporarilyUnavailable();
      log('warn', 'redis.connect_failed', {
        error: error instanceof Error ? error.message : 'unknown redis connect failure',
      });
      return null;
    })
    .finally(() => {
      sharedClientPromise = null;
    });

  return sharedClientPromise;
}

async function checkRedisHealth(config, log = () => {}) {
  const startedAt = Date.now();
  const client = await getRedisClient(config, log);
  if (!client) {
    return {
      configured: Boolean(config.redisUrl),
      status: config.redisUrl ? 'unavailable' : 'not_configured',
      latencyMs: Date.now() - startedAt,
    };
  }

  try {
    const pong = await client.ping();
    return {
      configured: true,
      status: pong === 'PONG' ? 'healthy' : 'degraded',
      latencyMs: Date.now() - startedAt,
    };
  } catch (error) {
    markTemporarilyUnavailable();
    log('warn', 'redis.ping_failed', {
      error: error instanceof Error ? error.message : 'unknown redis ping failure',
    });
    return {
      configured: true,
      status: 'unavailable',
      latencyMs: Date.now() - startedAt,
    };
  }
}

async function closeRedisClient() {
  const client = sharedClient;
  sharedClient = null;
  sharedClientPromise = null;

  if (!client) {
    return;
  }

  try {
    await client.quit();
  } catch {
    try {
      client.disconnect();
    } catch {
      // Ignore hard disconnect failures during shutdown.
    }
  }
}

module.exports = {
  getRedisClient,
  checkRedisHealth,
  closeRedisClient,
};
