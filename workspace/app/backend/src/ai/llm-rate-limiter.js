/**
 * Per-tenant LLM rate limiter.
 * Enforces a maximum number of LLM API calls per tenant within a time window.
 * Uses InMemoryRateLimiter from the shared rate-limiter module.
 */
const { InMemoryRateLimiter } = require('../rate-limiter');

const DEFAULT_WINDOW_MS = 3600_000; // 1 hour
const DEFAULT_MAX_LLM_CALLS = 100;  // 100 LLM calls per tenant per hour

let _instance = null;

function getLlmRateLimiter(config = {}) {
  if (!_instance) {
    const windowMs = Number(config.llmRateLimitWindowMs) || DEFAULT_WINDOW_MS;
    const maxCalls = Number(config.llmRateLimitMaxCalls) || DEFAULT_MAX_LLM_CALLS;
    _instance = new InMemoryRateLimiter(windowMs, maxCalls);
  }
  return _instance;
}

/**
 * Check if a tenant is allowed to make an LLM call.
 * @param {string} tenantSlug - The tenant identifier
 * @param {object} config - Application config
 * @returns {Promise<{ allowed: boolean, limit: number, remaining: number, resetAt: number }>}
 */
async function checkLlmRateLimit(tenantSlug, config = {}) {
  const limiter = getLlmRateLimiter(config);
  const key = `llm:${String(tenantSlug || 'unknown')}`;
  return limiter.take(key);
}

/**
 * Reset the singleton (for testing).
 */
function resetLlmRateLimiter() {
  if (_instance) {
    _instance.cleanup();
  }
  _instance = null;
}

module.exports = {
  checkLlmRateLimit,
  resetLlmRateLimiter,
  getLlmRateLimiter,
};
