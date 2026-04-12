export interface AppConfig {
  apiBaseUrl: string;
  API_BASE_URL: string;
  requestTimeoutMs: number;
  apiRetryCount: number;
  apiRetryBaseDelayMs: number;
  enableApiObservability: boolean;
  authLoginUrl: string;
  authMode: string;
  demoAuthEnabled: boolean;
  authTransport: string;
  csrfEnabled: boolean;
  csrfHeaderName: string;
  csrfCookieName: string;
  authLoginPath: string;
  authTokenPath: string;
  authMePath: string;
  authLogoutPath: string;
  tenantsPath: string;
  productsPath: string;
  tenantProductsPathTemplate: string;
  tenantFeatureFlagsPathTemplate: string;
  modulesPath: string;
  billingUsagePath: string;
  billingCreditsPath: string;
  threatSummaryPath: string;
  threatIncidentsPath: string;
  systemHealthPath: string;
  platformAppsPath: string;
  reportsPath: string;
  reportUploadPath: string;
  reportDownloadPathTemplate: string;
  requireAuthForThreatEndpoints: boolean;
  requireAuthForPlatformEndpoints: boolean;
  strictDependencies: boolean;
  analyticsEnabled: boolean;
  enterpriseMode: boolean;
  publicBackendProbesEnabled: boolean;
  environment: string;
}

type RuntimeConfigPayload = Partial<
  AppConfig & {
    API_BASE_URL: string;
    apiBaseURL: string;
    VITE_API_BASE_URL: string;
    authLoginURL: string;
  }
>;

const RUNTIME_CONFIG_ENDPOINT = '/api/config';

let runtimeConfig: RuntimeConfigPayload | null = null;
let configLoading = true;
let loadingPromise: Promise<void> | null = null;

function toPositiveNumber(value: unknown, fallback: number): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }

  return Math.round(parsed);
}

function toBoolean(value: unknown, fallback: boolean): boolean {
  if (value === undefined || value === null || value === '') {
    return fallback;
  }

  const normalized = String(value).trim().toLowerCase();
  if (normalized === 'true') return true;
  if (normalized === 'false') return false;
  return fallback;
}

function normalizeBaseUrl(value: unknown, fallback: string): string {
  const raw = String(value || fallback).trim();
  if (!raw) {
    return fallback;
  }

  if (raw === '/') {
    return '/';
  }

  return raw.replace(/\/+$/, '');
}

const defaultConfig: AppConfig = {
  apiBaseUrl: normalizeBaseUrl(import.meta.env.VITE_API_BASE_URL, '/api'),
  API_BASE_URL: normalizeBaseUrl(import.meta.env.VITE_API_BASE_URL, '/api'),
  requestTimeoutMs: toPositiveNumber(import.meta.env.VITE_REQUEST_TIMEOUT_MS, 15_000),
  apiRetryCount: toPositiveNumber(import.meta.env.VITE_API_RETRY_COUNT, 2),
  apiRetryBaseDelayMs: toPositiveNumber(import.meta.env.VITE_API_RETRY_BASE_DELAY_MS, 250),
  enableApiObservability: toBoolean(import.meta.env.VITE_ENABLE_API_OBSERVABILITY, true),
  authLoginUrl: String(import.meta.env.VITE_AUTH_LOGIN_URL || '').trim(),
  authMode: String(import.meta.env.VITE_AUTH_MODE || 'jwt_hs256').trim().toLowerCase(),
  demoAuthEnabled: toBoolean(import.meta.env.VITE_DEMO_AUTH_ENABLED, false),
  authTransport: String(import.meta.env.VITE_AUTH_TRANSPORT || 'cookie').trim().toLowerCase(),
  csrfEnabled: toBoolean(import.meta.env.VITE_CSRF_ENABLED, true),
  csrfHeaderName: String(import.meta.env.VITE_CSRF_HEADER_NAME || 'x-csrf-token').trim().toLowerCase(),
  csrfCookieName: String(import.meta.env.VITE_CSRF_COOKIE_NAME || 'ct_csrf').trim(),
  authLoginPath: String(import.meta.env.VITE_AUTH_LOGIN_PATH || '/v1/auth/login').trim(),
  authTokenPath: String(import.meta.env.VITE_AUTH_TOKEN_PATH || '/v1/auth/token').trim(),
  authMePath: String(import.meta.env.VITE_AUTH_ME_PATH || '/v1/auth/me').trim(),
  authLogoutPath: String(import.meta.env.VITE_AUTH_LOGOUT_PATH || '/v1/auth/logout').trim(),
  tenantsPath: String(import.meta.env.VITE_TENANTS_PATH || '/v1/tenants').trim(),
  productsPath: String(import.meta.env.VITE_PRODUCTS_PATH || '/v1/products').trim(),
  tenantProductsPathTemplate: String(
    import.meta.env.VITE_TENANT_PRODUCTS_PATH_TEMPLATE || '/v1/tenants/{tenant}/products'
  ).trim(),
  tenantFeatureFlagsPathTemplate: String(
    import.meta.env.VITE_TENANT_FEATURE_FLAGS_PATH_TEMPLATE || '/v1/tenants/{tenant}/feature-flags'
  ).trim(),
  modulesPath: String(import.meta.env.VITE_MODULES_PATH || '/v1/modules').trim(),
  billingUsagePath: String(import.meta.env.VITE_BILLING_USAGE_PATH || '/v1/billing/usage').trim(),
  billingCreditsPath: String(import.meta.env.VITE_BILLING_CREDITS_PATH || '/v1/billing/credits').trim(),
  threatSummaryPath: String(import.meta.env.VITE_THREAT_SUMMARY_PATH || '/v1/threats/summary').trim(),
  threatIncidentsPath: String(
    import.meta.env.VITE_THREAT_INCIDENTS_PATH || '/v1/threats/incidents'
  ).trim(),
  systemHealthPath: String(import.meta.env.VITE_SYSTEM_HEALTH_PATH || '/v1/system/health').trim(),
  platformAppsPath: String(import.meta.env.VITE_PLATFORM_APPS_PATH || '/v1/platform/apps').trim(),
  reportsPath: String(import.meta.env.VITE_REPORTS_PATH || '/v1/reports').trim(),
  reportUploadPath: String(import.meta.env.VITE_REPORT_UPLOAD_PATH || '/v1/reports/upload').trim(),
  reportDownloadPathTemplate: String(
    import.meta.env.VITE_REPORT_DOWNLOAD_PATH_TEMPLATE || '/v1/reports/{reportId}/download'
  ).trim(),
  requireAuthForThreatEndpoints: toBoolean(import.meta.env.VITE_REQUIRE_AUTH_FOR_THREAT_ENDPOINTS, false),
  requireAuthForPlatformEndpoints: toBoolean(import.meta.env.VITE_REQUIRE_AUTH_FOR_PLATFORM_ENDPOINTS, true),
  strictDependencies: toBoolean(import.meta.env.VITE_STRICT_DEPENDENCIES, true),
  analyticsEnabled: toBoolean(import.meta.env.VITE_ANALYTICS_ENABLED, true),
  enterpriseMode: toBoolean(import.meta.env.VITE_ENTERPRISE_MODE, true),
  publicBackendProbesEnabled: toBoolean(import.meta.env.VITE_PUBLIC_BACKEND_PROBES_ENABLED, false),
  environment: String(import.meta.env.MODE || 'development'),
};

function mergeConfig(base: AppConfig, override?: RuntimeConfigPayload | null): AppConfig {
  if (!override) {
    return base;
  }

  const apiBaseUrl = normalizeBaseUrl(
    override.apiBaseUrl ?? override.apiBaseURL ?? override.API_BASE_URL ?? override.VITE_API_BASE_URL,
    base.apiBaseUrl
  );

  return {
    ...base,
    apiBaseUrl,
    API_BASE_URL: apiBaseUrl,
    requestTimeoutMs: toPositiveNumber(override.requestTimeoutMs, base.requestTimeoutMs),
    apiRetryCount: toPositiveNumber(override.apiRetryCount, base.apiRetryCount),
    apiRetryBaseDelayMs: toPositiveNumber(override.apiRetryBaseDelayMs, base.apiRetryBaseDelayMs),
    enableApiObservability: toBoolean(override.enableApiObservability, base.enableApiObservability),
    authLoginUrl: String(override.authLoginUrl ?? override.authLoginURL ?? base.authLoginUrl).trim(),
    authMode: String(override.authMode ?? base.authMode).trim().toLowerCase(),
    demoAuthEnabled: toBoolean(override.demoAuthEnabled, base.demoAuthEnabled),
    authTransport: String(override.authTransport ?? base.authTransport).trim().toLowerCase(),
    csrfEnabled: toBoolean(override.csrfEnabled, base.csrfEnabled),
    csrfHeaderName: String(override.csrfHeaderName ?? base.csrfHeaderName).trim().toLowerCase(),
    csrfCookieName: String(override.csrfCookieName ?? base.csrfCookieName).trim(),
    authLoginPath: String(override.authLoginPath ?? base.authLoginPath).trim(),
    authTokenPath: String(override.authTokenPath ?? base.authTokenPath).trim(),
    authMePath: String(override.authMePath ?? base.authMePath).trim(),
    authLogoutPath: String(override.authLogoutPath ?? base.authLogoutPath).trim(),
    tenantsPath: String(override.tenantsPath ?? base.tenantsPath).trim(),
    productsPath: String(override.productsPath ?? base.productsPath).trim(),
    tenantProductsPathTemplate: String(
      override.tenantProductsPathTemplate ?? base.tenantProductsPathTemplate
    ).trim(),
    tenantFeatureFlagsPathTemplate: String(
      override.tenantFeatureFlagsPathTemplate ?? base.tenantFeatureFlagsPathTemplate
    ).trim(),
    modulesPath: String(override.modulesPath ?? base.modulesPath).trim(),
    billingUsagePath: String(override.billingUsagePath ?? base.billingUsagePath).trim(),
    billingCreditsPath: String(override.billingCreditsPath ?? base.billingCreditsPath).trim(),
    threatSummaryPath: String(override.threatSummaryPath ?? base.threatSummaryPath).trim(),
    threatIncidentsPath: String(override.threatIncidentsPath ?? base.threatIncidentsPath).trim(),
    systemHealthPath: String(override.systemHealthPath ?? base.systemHealthPath).trim(),
    platformAppsPath: String(override.platformAppsPath ?? base.platformAppsPath).trim(),
    reportsPath: String(override.reportsPath ?? base.reportsPath).trim(),
    reportUploadPath: String(override.reportUploadPath ?? base.reportUploadPath).trim(),
    reportDownloadPathTemplate: String(
      override.reportDownloadPathTemplate ?? base.reportDownloadPathTemplate
    ).trim(),
    requireAuthForThreatEndpoints: toBoolean(
      override.requireAuthForThreatEndpoints,
      base.requireAuthForThreatEndpoints
    ),
    requireAuthForPlatformEndpoints: toBoolean(
      override.requireAuthForPlatformEndpoints,
      base.requireAuthForPlatformEndpoints
    ),
    strictDependencies: toBoolean(override.strictDependencies, base.strictDependencies),
    analyticsEnabled: toBoolean(override.analyticsEnabled, base.analyticsEnabled),
    enterpriseMode: toBoolean(override.enterpriseMode, base.enterpriseMode),
    publicBackendProbesEnabled: toBoolean(
      override.publicBackendProbesEnabled,
      base.publicBackendProbesEnabled
    ),
    environment: String(override.environment ?? base.environment),
  };
}

function shouldLoadRuntimeConfig(): boolean {
  const explicitMode = import.meta.env.VITE_LOAD_RUNTIME_CONFIG;
  if (explicitMode !== undefined && explicitMode !== null && explicitMode !== '') {
    return toBoolean(explicitMode, false);
  }

  if (typeof window !== 'undefined') {
    const hostname = String(window.location.hostname || '').trim().toLowerCase();
    if (hostname === 'localhost' || hostname === '127.0.0.1') {
      return false;
    }
  }

  return true;
}

export async function loadRuntimeConfig(): Promise<void> {
  if (loadingPromise) {
    return loadingPromise;
  }

  if (!shouldLoadRuntimeConfig()) {
    runtimeConfig = null;
    configLoading = false;
    return;
  }

  loadingPromise = (async () => {
    try {
      const response = await fetch(RUNTIME_CONFIG_ENDPOINT, {
        method: 'GET',
        headers: {
          Accept: 'application/json',
        },
      });

      if (!response.ok) {
        return;
      }

      const contentType = response.headers.get('content-type') || '';
      if (!contentType.includes('application/json')) {
        return;
      }

      const payload = (await response.json()) as RuntimeConfigPayload;
      runtimeConfig = payload;
    } catch {
      runtimeConfig = null;
    } finally {
      configLoading = false;
    }
  })();

  return loadingPromise;
}

export function getConfig(): AppConfig {
  if (configLoading) {
    return defaultConfig;
  }

  return mergeConfig(defaultConfig, runtimeConfig);
}

export function getAPIBaseURL(): string {
  const baseURL = getConfig().apiBaseUrl;
  if (baseURL === '/') {
    return '';
  }

  return baseURL;
}

export const config = {
  get API_BASE_URL() {
    return getAPIBaseURL();
  },
};
