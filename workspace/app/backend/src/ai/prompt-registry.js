/**
 * Prompt A/B testing registry.
 * Allows registering prompt variants and selecting them for evaluation.
 * Results are logged via the standard log function for offline analysis.
 */

const _registry = new Map();

/**
 * Register a prompt variant for a given prompt key.
 * @param {string} promptKey - The prompt identifier (e.g., 'risk-v2', 'threat-v2')
 * @param {string} variantId - The variant identifier (e.g., 'A', 'B', 'control')
 * @param {object} variantConfig - The variant configuration
 * @param {string} variantConfig.systemPrompt - The system prompt text
 * @param {number} [variantConfig.temperature] - Temperature override
 * @param {number} [variantConfig.weight] - Selection weight (default 1). Higher = more likely to be selected.
 */
function registerPromptVariant(promptKey, variantId, variantConfig) {
  const key = String(promptKey);
  if (!_registry.has(key)) {
    _registry.set(key, new Map());
  }
  _registry.get(key).set(String(variantId), {
    ...variantConfig,
    weight: Number(variantConfig.weight) || 1,
  });
}

/**
 * Select a prompt variant for a given prompt key using weighted random selection.
 * Returns null if no variants are registered for the key.
 * @param {string} promptKey - The prompt identifier
 * @returns {{ variantId: string, systemPrompt: string, temperature?: number } | null}
 */
function selectPromptVariant(promptKey) {
  const variants = _registry.get(String(promptKey));
  if (!variants || variants.size === 0) {
    return null;
  }

  const entries = [...variants.entries()];
  const totalWeight = entries.reduce((sum, [, config]) => sum + config.weight, 0);
  let random = Math.random() * totalWeight;

  for (const [variantId, config] of entries) {
    random -= config.weight;
    if (random <= 0) {
      return {
        variantId,
        systemPrompt: config.systemPrompt,
        temperature: config.temperature,
      };
    }
  }

  // Fallback to last entry (should not happen due to floating point)
  const last = entries[entries.length - 1];
  return {
    variantId: last[0],
    systemPrompt: last[1].systemPrompt,
    temperature: last[1].temperature,
  };
}

/**
 * Build a log entry for prompt experiment tracking.
 * Call this after receiving the LLM response to record the experiment result.
 * @param {object} params
 * @param {string} params.promptKey - The prompt key
 * @param {string} params.variantId - The selected variant
 * @param {string} params.requestId - The request ID
 * @param {string} params.tenantSlug - The tenant
 * @param {number} params.latencyMs - LLM response time
 * @param {number} params.groundingScore - Output grounding score (0-100)
 * @param {boolean} params.parsedSuccessfully - Whether structured output was parsed
 * @returns {object} Log entry for the experiment
 */
function buildExperimentLogEntry(params) {
  return {
    event: 'prompt_experiment',
    promptKey: params.promptKey,
    variantId: params.variantId,
    requestId: params.requestId,
    tenantSlug: params.tenantSlug,
    latencyMs: params.latencyMs,
    groundingScore: params.groundingScore,
    parsedSuccessfully: params.parsedSuccessfully,
    timestamp: new Date().toISOString(),
  };
}

/**
 * Get all registered prompt keys and their variants (for admin/debugging).
 * @returns {object} Map of promptKey -> [variantId, ...]
 */
function getRegisteredVariants() {
  const result = {};
  for (const [key, variants] of _registry.entries()) {
    result[key] = [...variants.keys()];
  }
  return result;
}

/**
 * Clear all registered variants (for testing).
 */
function clearRegistry() {
  _registry.clear();
}

module.exports = {
  registerPromptVariant,
  selectPromptVariant,
  buildExperimentLogEntry,
  getRegisteredVariants,
  clearRegistry,
};
