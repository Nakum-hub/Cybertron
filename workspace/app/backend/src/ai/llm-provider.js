const { ServiceError } = require('../auth-service');
const { validateUrl } = require('../url-guard');

const { checkLlmRateLimit } = require('./llm-rate-limiter');
function normalizeProvider(value) {
  const normalized = String(value || 'none').trim().toLowerCase();
  if (normalized === 'openai') return 'openai';
  if (normalized === 'ollama') return 'ollama';
  if (normalized === 'vllm') return 'vllm';
  return 'none';
}

function createTimeoutController(timeoutMs) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), Math.max(1, Number(timeoutMs) || 15_000));
  return { controller, timeout };
}

function toSafeText(value) {
  if (typeof value !== 'string') {
    return '';
  }
  return value.trim();
}

function resolveMaxTokens(config, promptPayload) {
  const explicit = Number(promptPayload?.maxTokens);
  if (Number.isFinite(explicit) && explicit > 0) {
    return Math.floor(explicit);
  }

  const configured = Number(config?.llmDefaultMaxTokens || 1024);
  if (Number.isFinite(configured) && configured > 0) {
    return Math.floor(configured);
  }

  return 1024;
}

function buildUpstreamErrorDetails(status, rawBody) {
  const text = toSafeText(String(rawBody || ''));
  if (!text) {
    return status ? { upstreamStatus: status } : null;
  }

  try {
    const parsed = JSON.parse(text);
    const message = toSafeText(
      parsed?.error?.message ||
      parsed?.message ||
      parsed?.detail ||
      parsed?.details
    );
    if (message) {
      return {
        upstreamStatus: status,
        upstreamMessage: message.slice(0, 500),
      };
    }
  } catch {
    // Fall through to a plain-text snippet.
  }

  return {
    upstreamStatus: status,
    upstreamMessage: text.slice(0, 500),
  };
}

function isLocalLikeHostname(hostname) {
  const normalized = String(hostname || '').toLowerCase().trim();
  return (
    normalized === 'localhost' ||
    normalized === '127.0.0.1' ||
    normalized === '::1' ||
    normalized === '[::1]' ||
    normalized === 'host.docker.internal'
  );
}

function sanitizeEndpointLabel(value) {
  try {
    const parsed = new URL(String(value || ''));
    const path = parsed.pathname.replace(/\/+$/, '');
    return `${parsed.protocol}//${parsed.host}${path || ''}`;
  } catch {
    return '';
  }
}

function classifyOpenAiDeployment(baseUrl) {
  try {
    const parsed = new URL(String(baseUrl || ''));
    if (String(parsed.hostname || '').toLowerCase().trim() === 'api.openai.com') {
      return 'hosted_openai';
    }
    if (isLocalLikeHostname(parsed.hostname)) {
      return 'self_hosted_tunnel';
    }
  } catch {
    return 'openai_compatible';
  }
  return 'self_hosted_openai_compatible';
}

function buildUnconfiguredRuntime(provider, config, reason) {
  const model = provider === 'openai'
    ? toSafeText(config.openaiModel) || 'gpt-4.1-mini'
    : provider === 'ollama'
      ? toSafeText(config.ollamaModel) || 'llama3.1'
      : provider === 'vllm'
        ? toSafeText(config.vllmModel) || 'cybertron'
        : null;
  const endpoint = provider === 'openai'
    ? sanitizeEndpointLabel(config.openaiBaseUrl || 'https://api.openai.com/v1')
    : provider === 'ollama'
      ? sanitizeEndpointLabel(config.ollamaUrl || '')
      : provider === 'vllm'
        ? sanitizeEndpointLabel(config.vllmBaseUrl || 'http://localhost:8000/v1')
        : '';

  return {
    provider,
    deployment: provider === 'vllm' ? 'self_hosted_openai_compatible' : 'fallback_only',
    configured: false,
    reachable: false,
    model,
    endpoint,
    checkedAt: new Date().toISOString(),
    latencyMs: null,
    availableModels: [],
    sshTunnelSuggested: false,
    reason,
  };
}

function ensureConfigured(provider, config) {
  if (provider === 'none') {
    throw new ServiceError(
      503,
      'LLM_NOT_CONFIGURED',
      'LLM provider is not configured. Set LLM_PROVIDER and provider credentials.'
    );
  }

  if (provider === 'openai' && !toSafeText(config.openaiApiKey)) {
    throw new ServiceError(
      503,
      'LLM_NOT_CONFIGURED',
      'OPENAI_API_KEY is required when LLM_PROVIDER=openai.'
    );
  }

  if (provider === 'ollama' && !toSafeText(config.ollamaUrl)) {
    throw new ServiceError(
      503,
      'LLM_NOT_CONFIGURED',
      'OLLAMA_URL is required when LLM_PROVIDER=ollama.'
    );
  }

  if (provider === 'vllm' && !toSafeText(config.vllmBaseUrl)) {
    throw new ServiceError(
      503,
      'LLM_NOT_CONFIGURED',
      'LLM_VLLM_BASE_URL is required when LLM_PROVIDER=vllm.'
    );
  }
}

async function callOpenAi(config, promptPayload) {
  const baseUrl = String(config.openaiBaseUrl || 'https://api.openai.com/v1').replace(/\/+$/, '');
  const url = `${baseUrl}/chat/completions`;
  const maxTokens = resolveMaxTokens(config, promptPayload);
  const body = {
    model: toSafeText(config.openaiModel) || 'gpt-4.1-mini',
    temperature: Number.isFinite(promptPayload.temperature) ? promptPayload.temperature : 0.2,
    max_tokens: maxTokens,
    messages: [
      {
        role: 'system',
        content: promptPayload.systemPrompt || 'You are a cybersecurity assistant.',
      },
      {
        role: 'user',
        content: promptPayload.userPrompt,
      },
    ],
  };

  const { controller, timeout } = createTimeoutController(config.llmRequestTimeoutMs);
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${config.openaiApiKey}`,
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    const rawBody = await response.text();
    if (!response.ok) {
      throw new ServiceError(
        502,
        'LLM_UPSTREAM_ERROR',
        `OpenAI upstream returned ${response.status}.`,
        buildUpstreamErrorDetails(response.status, rawBody)
      );
    }

    if (rawBody.length > 2_000_000) {
      throw new ServiceError(502, 'LLM_UPSTREAM_ERROR', 'OpenAI response exceeds maximum allowed size.');
    }
    const payload = JSON.parse(rawBody);
    const text = payload?.choices?.[0]?.message?.content;
    if (!toSafeText(text)) {
      throw new ServiceError(502, 'LLM_UPSTREAM_ERROR', 'OpenAI returned an empty response.');
    }

    return {
      text: String(text),
      model: String(payload?.model || body.model),
      provider: 'openai',
    };
  } catch (error) {
    if (error instanceof ServiceError) {
      throw error;
    }

    throw new ServiceError(502, 'LLM_UPSTREAM_ERROR', 'OpenAI request failed.');
  } finally {
    clearTimeout(timeout);
  }
}

async function callOllama(config, promptPayload) {
  const baseUrl = String(config.ollamaUrl || '').replace(/\/+$/, '');
  const url = `${baseUrl}/api/generate`;
  const maxTokens = resolveMaxTokens(config, promptPayload);

  // SSRF protection: validate the Ollama URL does not resolve to private/internal IPs
  const urlCheck = await validateUrl(url);
  if (!urlCheck.safe) {
    throw new ServiceError(
      503,
      'LLM_SSRF_BLOCKED',
      `Ollama URL blocked by SSRF protection: ${urlCheck.reason}`
    );
  }
  const body = {
    model: toSafeText(config.ollamaModel) || 'llama3.1',
    prompt: `${promptPayload.systemPrompt || ''}\n\n${promptPayload.userPrompt}`.trim(),
    stream: false,
    options: {
      temperature: Number.isFinite(promptPayload.temperature) ? promptPayload.temperature : 0.2,
      num_predict: maxTokens,
    },
  };

  const { controller, timeout } = createTimeoutController(config.llmRequestTimeoutMs);
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    const rawBody = await response.text();
    if (!response.ok) {
      throw new ServiceError(
        502,
        'LLM_UPSTREAM_ERROR',
        `Ollama upstream returned ${response.status}.`,
        buildUpstreamErrorDetails(response.status, rawBody)
      );
    }

    if (rawBody.length > 2_000_000) {
      throw new ServiceError(502, 'LLM_UPSTREAM_ERROR', 'Ollama response exceeds maximum allowed size.');
    }
    const payload = JSON.parse(rawBody);
    const text = payload?.response;
    if (!toSafeText(text)) {
      throw new ServiceError(502, 'LLM_UPSTREAM_ERROR', 'Ollama returned an empty response.');
    }

    return {
      text: String(text),
      model: String(body.model),
      provider: 'ollama',
    };
  } catch (error) {
    if (error instanceof ServiceError) {
      throw error;
    }

    throw new ServiceError(502, 'LLM_UPSTREAM_ERROR', 'Ollama request failed.');
  } finally {
    clearTimeout(timeout);
  }
}

async function probeOpenAiRuntime(config) {
  const baseUrl = String(config.openaiBaseUrl || 'https://api.openai.com/v1').replace(/\/+$/, '');
  const endpoint = sanitizeEndpointLabel(baseUrl);
  const model = toSafeText(config.openaiModel) || 'gpt-4.1-mini';
  const checkedAt = new Date().toISOString();
  let sshTunnelSuggested = false;

  try {
    const parsed = new URL(baseUrl);
    sshTunnelSuggested = isLocalLikeHostname(parsed.hostname);
  } catch {
    return {
      provider: 'openai',
      deployment: 'openai_compatible',
      configured: true,
      reachable: false,
      model,
      endpoint,
      checkedAt,
      latencyMs: null,
      availableModels: [],
      sshTunnelSuggested,
      reason: 'OPENAI_BASE_URL is invalid.',
    };
  }

  const url = `${baseUrl}/models`;
  const { controller, timeout } = createTimeoutController(config.llmRequestTimeoutMs);
  const startedAt = Date.now();
  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${config.openaiApiKey}`,
      },
      signal: controller.signal,
    });

    const rawBody = await response.text();
    if (rawBody.length > 2_000_000) {
      return {
        provider: 'openai',
        deployment: classifyOpenAiDeployment(baseUrl),
        configured: true,
        reachable: false,
        model,
        endpoint,
        checkedAt,
        latencyMs: Date.now() - startedAt,
        availableModels: [],
        sshTunnelSuggested,
        reason: 'OpenAI-compatible runtime probe returned an oversized response.',
      };
    }

    let payload = null;
    try {
      payload = rawBody ? JSON.parse(rawBody) : null;
    } catch {
      payload = null;
    }

    if (!response.ok) {
      return {
        provider: 'openai',
        deployment: classifyOpenAiDeployment(baseUrl),
        configured: true,
        reachable: false,
        model,
        endpoint,
        checkedAt,
        latencyMs: Date.now() - startedAt,
        availableModels: [],
        sshTunnelSuggested,
        reason: `OpenAI-compatible runtime probe returned ${response.status}.`,
      };
    }

    const availableModels = Array.isArray(payload?.data)
      ? payload.data
        .map(item => toSafeText(item?.id))
        .filter(Boolean)
        .slice(0, 12)
      : [];

    return {
      provider: 'openai',
      deployment: classifyOpenAiDeployment(baseUrl),
      configured: true,
      reachable: true,
      model,
      endpoint,
      checkedAt,
      latencyMs: Date.now() - startedAt,
      availableModels,
      sshTunnelSuggested,
      reason: null,
    };
  } catch (error) {
    const reason = error?.name === 'AbortError'
      ? 'OpenAI-compatible runtime probe timed out.'
      : 'OpenAI-compatible runtime probe failed.';
    return {
      provider: 'openai',
      deployment: classifyOpenAiDeployment(baseUrl),
      configured: true,
      reachable: false,
      model,
      endpoint,
      checkedAt,
      latencyMs: Date.now() - startedAt,
      availableModels: [],
      sshTunnelSuggested,
      reason,
    };
  } finally {
    clearTimeout(timeout);
  }
}

async function probeOllamaRuntime(config) {
  const baseUrl = String(config.ollamaUrl || '').replace(/\/+$/, '');
  const endpoint = sanitizeEndpointLabel(baseUrl);
  const model = toSafeText(config.ollamaModel) || 'llama3.1';
  const checkedAt = new Date().toISOString();
  const url = `${baseUrl}/api/tags`;

  const urlCheck = await validateUrl(url);
  if (!urlCheck.safe) {
    return {
      provider: 'ollama',
      deployment: 'ollama',
      configured: true,
      reachable: false,
      model,
      endpoint,
      checkedAt,
      latencyMs: null,
      availableModels: [],
      sshTunnelSuggested: false,
      reason: `Ollama URL blocked by SSRF protection: ${urlCheck.reason}`,
    };
  }

  const { controller, timeout } = createTimeoutController(config.llmRequestTimeoutMs);
  const startedAt = Date.now();
  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
      },
      signal: controller.signal,
    });
    const rawBody = await response.text();
    if (rawBody.length > 2_000_000) {
      return {
        provider: 'ollama',
        deployment: 'ollama',
        configured: true,
        reachable: false,
        model,
        endpoint,
        checkedAt,
        latencyMs: Date.now() - startedAt,
        availableModels: [],
        sshTunnelSuggested: false,
        reason: 'Ollama runtime probe returned an oversized response.',
      };
    }

    let payload = null;
    try {
      payload = rawBody ? JSON.parse(rawBody) : null;
    } catch {
      payload = null;
    }

    if (!response.ok) {
      return {
        provider: 'ollama',
        deployment: 'ollama',
        configured: true,
        reachable: false,
        model,
        endpoint,
        checkedAt,
        latencyMs: Date.now() - startedAt,
        availableModels: [],
        sshTunnelSuggested: false,
        reason: `Ollama runtime probe returned ${response.status}.`,
      };
    }

    const availableModels = Array.isArray(payload?.models)
      ? payload.models
        .map(item => toSafeText(item?.name || item?.model))
        .filter(Boolean)
        .slice(0, 12)
      : [];

    return {
      provider: 'ollama',
      deployment: 'ollama',
      configured: true,
      reachable: true,
      model,
      endpoint,
      checkedAt,
      latencyMs: Date.now() - startedAt,
      availableModels,
      sshTunnelSuggested: false,
      reason: null,
    };
  } catch (error) {
    const reason = error?.name === 'AbortError'
      ? 'Ollama runtime probe timed out.'
      : 'Ollama runtime probe failed.';
    return {
      provider: 'ollama',
      deployment: 'ollama',
      configured: true,
      reachable: false,
      model,
      endpoint,
      checkedAt,
      latencyMs: Date.now() - startedAt,
      availableModels: [],
      sshTunnelSuggested: false,
      reason,
    };
  } finally {
    clearTimeout(timeout);
  }
}

async function probeVllmRuntime(config) {
  const baseUrl = String(config.vllmBaseUrl || 'http://localhost:8000/v1').replace(/\/+$/, '');
  const endpoint = sanitizeEndpointLabel(baseUrl);
  const model = toSafeText(config.vllmModel) || 'cybertron';
  const checkedAt = new Date().toISOString();
  let sshTunnelSuggested = false;

  try {
    const parsed = new URL(baseUrl);
    sshTunnelSuggested = isLocalLikeHostname(parsed.hostname);
  } catch {
    return {
      provider: 'vllm',
      deployment: 'self_hosted_openai_compatible',
      configured: true,
      reachable: false,
      model,
      endpoint,
      checkedAt,
      latencyMs: null,
      availableModels: [],
      sshTunnelSuggested,
      reason: 'LLM_VLLM_BASE_URL is invalid.',
    };
  }

  const url = `${baseUrl}/models`;
  const apiKey = config.vllmApiKey || 'cybertron-local-key';
  const { controller, timeout } = createTimeoutController(config.llmRequestTimeoutMs);
  const startedAt = Date.now();
  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${apiKey}`,
      },
      signal: controller.signal,
    });

    const rawBody = await response.text();
    if (rawBody.length > 2_000_000) {
      return {
        provider: 'vllm',
        deployment: 'self_hosted_openai_compatible',
        configured: true,
        reachable: false,
        model,
        endpoint,
        checkedAt,
        latencyMs: Date.now() - startedAt,
        availableModels: [],
        sshTunnelSuggested,
        reason: 'vLLM runtime probe returned an oversized response.',
      };
    }

    let payload = null;
    try {
      payload = rawBody ? JSON.parse(rawBody) : null;
    } catch {
      payload = null;
    }

    if (!response.ok) {
      return {
        provider: 'vllm',
        deployment: 'self_hosted_openai_compatible',
        configured: true,
        reachable: false,
        model,
        endpoint,
        checkedAt,
        latencyMs: Date.now() - startedAt,
        availableModels: [],
        sshTunnelSuggested,
        reason: `vLLM runtime probe returned ${response.status}.`,
      };
    }

    const availableModels = Array.isArray(payload?.data)
      ? payload.data
        .map(item => toSafeText(item?.id))
        .filter(Boolean)
        .slice(0, 12)
      : [];

    return {
      provider: 'vllm',
      deployment: 'self_hosted_openai_compatible',
      configured: true,
      reachable: true,
      model,
      endpoint,
      checkedAt,
      latencyMs: Date.now() - startedAt,
      availableModels,
      sshTunnelSuggested,
      reason: null,
      loraAdapter: 'cybertron-qwen25-1_5b-t4-lora',
    };
  } catch (error) {
    const reason = error?.name === 'AbortError'
      ? 'vLLM runtime probe timed out.'
      : 'vLLM runtime probe failed.';
    return {
      provider: 'vllm',
      deployment: 'self_hosted_openai_compatible',
      configured: true,
      reachable: false,
      model,
      endpoint,
      checkedAt,
      latencyMs: Date.now() - startedAt,
      availableModels: [],
      sshTunnelSuggested,
      reason,
    };
  } finally {
    clearTimeout(timeout);
  }
}

async function probeLlmRuntime(config) {
  const provider = normalizeProvider(config.llmProvider);
  try {
    ensureConfigured(provider, config);
  } catch (error) {
    return buildUnconfiguredRuntime(
      provider,
      config,
      error instanceof ServiceError ? error.message : 'LLM provider is not configured.'
    );
  }

  if (provider === 'openai') {
    return probeOpenAiRuntime(config);
  }

  if (provider === 'vllm') {
    return probeVllmRuntime(config);
  }

  return probeOllamaRuntime(config);
}

function createLlmProvider(config, log = () => {}) {
  const provider = normalizeProvider(config.llmProvider);

  return {
    provider,
    isConfigured() {
      try {
        ensureConfigured(provider, config);
        return true;
      } catch {
        return false;
      }
    },
    async generateText(promptPayload, context = {}) {
      ensureConfigured(provider, config);

      // Per-tenant LLM rate limit check
      const tenantSlug = context.tenantSlug || context.tenant || 'unknown';
      const rateCheck = await checkLlmRateLimit(tenantSlug, config);
      if (!rateCheck.allowed) {
        throw new ServiceError(
          429,
          'LLM_RATE_LIMIT_EXCEEDED',
          `LLM rate limit exceeded for tenant. Limit: ${rateCheck.limit}, resets at: ${new Date(rateCheck.resetAt).toISOString()}`
        );
      }
      const requestId = context.requestId || 'unknown';
      log('info', 'llm.request.start', {
        provider,
        requestId,
      });

      const startedAt = Date.now();
      let result;
      if (provider === 'openai') {
        result = await callOpenAi(config, promptPayload);
      } else if (provider === 'vllm') {
        // vLLM exposes an OpenAI-compatible /v1/chat/completions endpoint
        const vllmConfig = {
          ...config,
          openaiBaseUrl: config.vllmBaseUrl || config.openaiBaseUrl,
          openaiApiKey: config.vllmApiKey || config.openaiApiKey || 'vllm',
          openaiModel: config.vllmModel || config.openaiModel || 'default',
        };
        result = await callOpenAi(vllmConfig, promptPayload);
        result.provider = 'vllm';
      } else {
        result = await callOllama(config, promptPayload);
      }

      const promptChars = (promptPayload.userPrompt || '').length + (promptPayload.systemPrompt || '').length;
      const responseChars = (result.text || '').length;

      log('info', 'llm.request.finish', {
        provider,
        requestId,
        latencyMs: Date.now() - startedAt,
        model: result.model,
        promptChars,
        responseChars,
        estimatedPromptTokens: Math.ceil(promptChars / 4),
        estimatedResponseTokens: Math.ceil(responseChars / 4),
      });

      return result;
    },
  };
}

module.exports = {
  createLlmProvider,
  probeLlmRuntime,
};
