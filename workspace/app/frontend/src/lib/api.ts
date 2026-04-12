import {
  clearAccessToken,
  getAccessToken,
  getCsrfToken,
  getPublicSignupFingerprint,
  setAuthTokens,
} from './auth';
import { getConfig } from './config';
import { recordApiObservation } from './observability';

type PrimitiveQuery = string | number | boolean | null | undefined;

export interface ApiRequestOptions {
  auth?: boolean;
  headers?: Record<string, string>;
  query?: Record<string, PrimitiveQuery>;
  retryCount?: number;
  timeoutMs?: number;
  signal?: AbortSignal;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code?: string;
  readonly requestId?: string;
  readonly details?: unknown;
  readonly path: string;

  constructor(message: string, options: {
    status: number;
    path: string;
    code?: string;
    requestId?: string;
    details?: unknown;
  }) {
    super(message);
    this.name = 'ApiError';
    this.status = options.status;
    this.path = options.path;
    this.code = options.code;
    this.requestId = options.requestId;
    this.details = options.details;
  }
}

const RETRYABLE_STATUS = new Set([408, 425, 429, 500, 502, 503, 504]);
let refreshInFlight: Promise<boolean> | null = null;

function canRetry(status: number): boolean {
  return RETRYABLE_STATUS.has(status);
}

function isAbsoluteUrl(value: string): boolean {
  return /^https?:\/\//i.test(value);
}

function normalizePath(path: string): string {
  const cleaned = String(path || '').trim();
  if (!cleaned) {
    return '/';
  }

  return cleaned.startsWith('/') ? cleaned : `/${cleaned}`;
}

function buildUrl(path: string, query?: Record<string, PrimitiveQuery>): string {
  const { apiBaseUrl } = getConfig();
  const normalizedPath = normalizePath(path);

  let base = apiBaseUrl === '/' ? '' : apiBaseUrl;
  if (base.endsWith('/')) {
    base = base.slice(0, -1);
  }

  const combined = isAbsoluteUrl(normalizedPath)
    ? normalizedPath
    : `${base}${normalizedPath}`;

  const url = new URL(combined, window.location.origin);

  Object.entries(query || {}).forEach(([key, value]) => {
    if (value === undefined || value === null || value === '') {
      return;
    }

    url.searchParams.set(key, String(value));
  });

  if (isAbsoluteUrl(combined)) {
    return url.toString();
  }

  return `${url.pathname}${url.search}`;
}

function delay(ms: number): Promise<void> {
  return new Promise(resolve => {
    setTimeout(resolve, ms);
  });
}

function isUpgradeRedirectCode(code?: string): boolean {
  return code === 'billing_quota_exhausted' || code === 'plan_upgrade_required';
}

function toDetailsRecord(details: unknown): Record<string, unknown> | null {
  if (!details || typeof details !== 'object' || Array.isArray(details)) {
    return null;
  }

  return details as Record<string, unknown>;
}

function setPricingParam(url: URL, key: string, value: unknown) {
  if (value === null || value === undefined) {
    return;
  }

  if (typeof value === 'string' && !value.trim()) {
    return;
  }

  url.searchParams.set(key, String(value));
}

function redirectToPricingIfNeeded(error: ApiError) {
  if (typeof window === 'undefined' || !isUpgradeRedirectCode(error.code)) {
    return;
  }

  const currentPath = window.location.pathname;
  const isProtectedWorkspace =
    currentPath.startsWith('/platform') || currentPath.startsWith('/products');

  if (!isProtectedWorkspace || currentPath.startsWith('/pricing')) {
    return;
  }

  const details = toDetailsRecord(error.details);
  const redirectPath =
    typeof details?.upgradeUrl === 'string' && details.upgradeUrl.startsWith('/')
      ? details.upgradeUrl
      : '/pricing';
  const target = new URL(redirectPath, window.location.origin);
  setPricingParam(target, 'reason', error.code);
  setPricingParam(target, 'tier', details?.currentTier);
  setPricingParam(target, 'planLabel', details?.planLabel);
  setPricingParam(target, 'limit', details?.quotaLimitUnits);
  setPricingParam(target, 'remaining', details?.quotaRemainingUnits);
  setPricingParam(target, 'used', details?.usedUnits);
  setPricingParam(target, 'periodStart', details?.periodStart);
  setPricingParam(target, 'periodEndsAt', details?.periodEndsAt);
  setPricingParam(target, 'returnTo', `${window.location.pathname}${window.location.search}`);

  const nextTarget = `${target.pathname}${target.search}`;
  const currentTarget = `${window.location.pathname}${window.location.search}`;
  if (nextTarget === currentTarget) {
    return;
  }

  window.location.assign(nextTarget);
}

async function tryRefreshAccessToken(): Promise<boolean> {
  if (refreshInFlight) {
    return refreshInFlight;
  }

  refreshInFlight = (async () => {
    const cfg = getConfig();
    const tokenPath = cfg.authTokenPath || '/v1/auth/token';
    const url = buildUrl(tokenPath);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), Math.max(1, cfg.requestTimeoutMs));

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          ...(cfg.csrfEnabled
            ? {
                [cfg.csrfHeaderName || 'x-csrf-token']: getCsrfToken(
                  cfg.csrfCookieName || 'ct_csrf'
                ),
              }
            : {}),
        },
        body: JSON.stringify({
          grantType: 'refresh_token',
        }),
        credentials: 'include',
        signal: controller.signal,
      });

      if (!response.ok) {
        if (response.status === 400 || response.status === 401) {
          clearAccessToken();
        }
        return false;
      }

      const contentType = response.headers.get('content-type') || '';
      if (!contentType.includes('application/json')) {
        return false;
      }

      const payload = (await response.json()) as {
        tokens?: {
          accessToken?: string;
          refreshToken?: string;
        };
      };

      const accessToken = payload?.tokens?.accessToken;
      if (!accessToken) {
        clearAccessToken();
        return false;
      }
      setAuthTokens(accessToken, payload?.tokens?.refreshToken || '');
      return true;
    } catch {
      return false;
    } finally {
      clearTimeout(timeout);
    }
  })().finally(() => {
    refreshInFlight = null;
  });

  return refreshInFlight;
}

function composeSignals(primary: AbortSignal, secondary?: AbortSignal): AbortSignal {
  if (!secondary) {
    return primary;
  }

  if (typeof AbortSignal.any === 'function') {
    return AbortSignal.any([primary, secondary]);
  }

  const fallbackController = new AbortController();
  const abort = () => fallbackController.abort();

  primary.addEventListener('abort', abort, { once: true });
  secondary.addEventListener('abort', abort, { once: true });

  return fallbackController.signal;
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  options: ApiRequestOptions = {}
): Promise<T> {
  const cfg = getConfig();
  const normalizedPath = normalizePath(path);
  const url = buildUrl(normalizedPath, options.query);
  const retries = Math.max(0, options.retryCount ?? cfg.apiRetryCount);
  let refreshAttempted = false;

  let attempt = 0;
  let lastError: unknown = null;

  while (attempt <= retries) {
    const startedAt = performance.now();
    const controller = new AbortController();
    const timeoutMs = Math.max(1, options.timeoutMs ?? cfg.requestTimeoutMs);

    const timeout = setTimeout(() => {
      controller.abort();
    }, timeoutMs);

    const signal = composeSignals(controller.signal, options.signal);

    try {
      const headers: Record<string, string> = {
        Accept: 'application/json',
        ...options.headers,
      };

      if (body !== undefined) {
        headers['Content-Type'] = 'application/json';
      }

      if (options.auth !== false) {
        const token = getAccessToken();
        if (token) {
          headers.Authorization = `Bearer ${token}`;
        }
      }

      if (
        normalizedPath.startsWith('/v1/auth/') &&
        method !== 'GET' &&
        method !== 'HEAD' &&
        method !== 'OPTIONS'
      ) {
        headers['x-cybertron-public-fingerprint'] = getPublicSignupFingerprint();
      }

      const requiresCsrf =
        cfg.csrfEnabled &&
        method !== 'GET' &&
        method !== 'HEAD' &&
        method !== 'OPTIONS';
      if (requiresCsrf) {
        const csrfToken = getCsrfToken(cfg.csrfCookieName || 'ct_csrf');
        if (csrfToken) {
          headers[cfg.csrfHeaderName || 'x-csrf-token'] = csrfToken;
        }
      }

      const response = await fetch(url, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        credentials: 'include',
        signal,
      });

      const contentType = response.headers.get('content-type') || '';
      const requestId = response.headers.get('x-request-id') || response.headers.get('x-correlation-id') || undefined;
      const durationMs = Math.round(performance.now() - startedAt);

      if (cfg.enableApiObservability) {
        recordApiObservation({
          path,
          method,
          status: response.status,
          durationMs,
          ok: response.ok,
          requestId,
          attempt: attempt + 1,
          timestamp: new Date().toISOString(),
        });
      }

      if (response.ok) {
        if (response.status === 204) {
          return undefined as T;
        }

        if (!contentType.includes('application/json')) {
          return undefined as T;
        }

        return (await response.json()) as T;
      }

      if (
        response.status === 401 &&
        options.auth !== false &&
        !refreshAttempted
      ) {
        const refreshed = await tryRefreshAccessToken();
        if (refreshed) {
          refreshAttempted = true;
          continue;
        }
      }

      let errorBody: {
        error?: {
          code?: string;
          message?: string;
          requestId?: string;
          details?: unknown;
        };
      } | null = null;

      if (contentType.includes('application/json')) {
        try {
          errorBody = (await response.json()) as typeof errorBody;
        } catch {
          errorBody = null;
        }
      }

      const message =
        errorBody?.error?.message || `Request failed with status ${response.status}`;
      const apiError = new ApiError(message, {
        status: response.status,
        path,
        code: errorBody?.error?.code,
        requestId: errorBody?.error?.requestId || requestId,
        details: errorBody?.error?.details,
      });

      if (!canRetry(response.status) || attempt >= retries) {
        redirectToPricingIfNeeded(apiError);
        throw apiError;
      }

      lastError = apiError;
    } catch (error) {
      const aborted = error instanceof DOMException && error.name === 'AbortError';
      const apiError =
        error instanceof ApiError
          ? error
          : new ApiError(aborted ? 'Request timed out' : 'Network request failed', {
              status: aborted ? 408 : 0,
              path,
            });

      if (attempt >= retries || (!aborted && apiError.status > 0 && !canRetry(apiError.status))) {
        redirectToPricingIfNeeded(apiError);
        throw apiError;
      }

      lastError = apiError;
    } finally {
      clearTimeout(timeout);
    }

    attempt += 1;
    const backoff = cfg.apiRetryBaseDelayMs * Math.pow(2, Math.max(0, attempt - 1));
    await delay(Math.min(backoff, 2_000));
  }

  throw lastError instanceof Error
    ? lastError
    : new ApiError('Unexpected API client failure', {
        status: 500,
        path,
      });
}

export const api = {
  request,
  get<T>(path: string, options?: ApiRequestOptions) {
    return request<T>('GET', path, undefined, options);
  },
  post<T>(path: string, body?: unknown, options?: ApiRequestOptions) {
    return request<T>('POST', path, body, options);
  },
  put<T>(path: string, body?: unknown, options?: ApiRequestOptions) {
    return request<T>('PUT', path, body, options);
  },
  patch<T>(path: string, body?: unknown, options?: ApiRequestOptions) {
    return request<T>('PATCH', path, body, options);
  },
  delete<T>(path: string, options?: ApiRequestOptions) {
    return request<T>('DELETE', path, undefined, options);
  },
};
