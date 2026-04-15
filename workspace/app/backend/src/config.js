const path = require('node:path');

function toNumber(value, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }

  return parsed;
}

function parseOriginList(value, fallback) {
  if (!value) {
    return fallback;
  }

  return value
    .split(',')
    .map(item => item.trim())
    .filter(Boolean);
}

function parseCsvList(value, fallback) {
  if (!value) {
    return fallback;
  }

  return String(value)
    .split(',')
    .map(item => item.trim())
    .filter(Boolean);
}

function toBoolean(value, fallback) {
  if (value === undefined || value === null || value === '') {
    return fallback;
  }

  const normalized = String(value).toLowerCase().trim();
  if (normalized === 'true') return true;
  if (normalized === 'false') return false;
  return fallback;
}

function isStrictDependencyDefault(nodeEnv) {
  const normalized = String(nodeEnv || 'development').toLowerCase().trim();
  if (normalized === 'production') {
    return true;
  }
  if (normalized === 'staging') {
    return true;
  }
  return false;
}

function normalizeAuthMode(value) {
  const normalized = String(value || 'jwt_hs256').toLowerCase().trim();
  if (normalized === 'jwt_hs256') return 'jwt_hs256';
  return 'demo';
}

function normalizeLlmProvider(value) {
  const normalized = String(value || 'none').toLowerCase().trim();
  if (normalized === 'openai') return 'openai';
  if (normalized === 'ollama') return 'ollama';
  if (normalized === 'vllm') return 'vllm';
  return 'none';
}

function normalizeJwtAlgorithm(value) {
  const normalized = String(value || 'HS256').toUpperCase().trim();
  if (normalized === 'RS256') return 'RS256';
  return 'HS256';
}

function normalizeSameSite(value, fallback = 'lax') {
  const normalized = String(value || fallback).toLowerCase().trim();
  if (normalized === 'strict') return 'strict';
  if (normalized === 'none') return 'none';
  return 'lax';
}

function isHttpsUrl(value) {
  try {
    const parsed = new URL(String(value || ''));
    return parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

function isHttpOrHttpsUrl(value) {
  try {
    const parsed = new URL(String(value || ''));
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

function isLocalOrigin(value) {
  return /:\/\/(localhost|127\.0\.0\.1)(:|\/|$)/i.test(String(value || ''));
}

function isLocalValidationServiceUrl(value) {
  try {
    const parsed = new URL(String(value || ''));
    const hostname = String(parsed.hostname || '').toLowerCase().trim();
    return (
      hostname === 'localhost' ||
      hostname === '127.0.0.1' ||
      hostname === 'host.docker.internal' ||
      hostname === 'minio'
    );
  } catch {
    return false;
  }
}

function isValidPublicApiBase(value) {
  const raw = String(value || '').trim();
  if (!raw) {
    return false;
  }

  if (raw.startsWith('/')) {
    return true;
  }

  return /^https?:\/\//i.test(raw);
}

function hasInsecureConnectorInProduction(config) {
  if (config.environment !== 'production') {
    return false;
  }

  const urls = [config.wazuhApiUrl, config.mispApiUrl, config.openCtiApiUrl, config.theHiveApiUrl];
  return urls.filter(Boolean).some(url => !isHttpsUrl(url));
}

const config = {
  environment: process.env.NODE_ENV || 'development',
  host: process.env.HOST || '0.0.0.0',
  port: toNumber(process.env.PORT, 8001),
  appVersion: process.env.APP_VERSION || '0.3.0-dev',
  region: process.env.REGION || 'local-dev',
  frontendOrigin: process.env.FRONTEND_ORIGIN || 'http://localhost:3000',
  localProductionValidation: toBoolean(process.env.LOCAL_PRODUCTION_VALIDATION, false),
  authMode: normalizeAuthMode(process.env.AUTH_MODE),
  strictDependencies: toBoolean(
    process.env.STRICT_DEPENDENCIES,
    isStrictDependencyDefault(process.env.NODE_ENV)
  ),
  redisUrl: process.env.REDIS_URL || '',
  redisPassword: process.env.REDIS_PASSWORD || '',
  redisUsername: process.env.REDIS_USERNAME || '',
  redisConnectTimeoutMs: toNumber(process.env.REDIS_CONNECT_TIMEOUT_MS, 2_000),
  redisConnectMaxRetries: toNumber(process.env.REDIS_CONNECT_MAX_RETRIES, 4),
  allowedOrigins: parseOriginList(
    process.env.CORS_ALLOWED_ORIGINS,
    ['http://localhost:3000', 'http://127.0.0.1:3000']
  ),
  jwtSecret:
    process.env.JWT_SECRET ||
    (String(process.env.NODE_ENV || 'development').toLowerCase() === 'production'
      ? ''
      : 'dev-jwt-secret-change-me'),
  jwtIssuer: process.env.JWT_ISSUER || '',
  jwtAudience: process.env.JWT_AUDIENCE || '',
  jwtAlgorithm: normalizeJwtAlgorithm(process.env.JWT_ALGORITHM),
  jwtPublicKey: process.env.JWT_PUBLIC_KEY || '',
  jwtPrivateKey: process.env.JWT_PRIVATE_KEY || '',
  jwtClockSkewSeconds: toNumber(process.env.JWT_CLOCK_SKEW_SECONDS, 30),
  enforceOriginValidation: toBoolean(process.env.ENFORCE_ORIGIN_VALIDATION, true),
  authTokenTtlMs: toNumber(process.env.AUTH_TOKEN_TTL_MS, 1000 * 60 * 30),
  authMaxSessions: toNumber(process.env.AUTH_MAX_SESSIONS, 50_000),
  refreshTokenTtlMs: toNumber(process.env.REFRESH_TOKEN_TTL_MS, 1000 * 60 * 60 * 24 * 30),
  passwordResetTokenTtlMs: toNumber(process.env.PASSWORD_RESET_TOKEN_TTL_MS, 1000 * 60 * 30),
  passwordHashRounds: toNumber(process.env.PASSWORD_HASH_ROUNDS, 12),
  authMaxFailedAttempts: toNumber(process.env.AUTH_MAX_FAILED_ATTEMPTS, 5),
  authLockoutMs: toNumber(process.env.AUTH_LOCKOUT_MS, 1000 * 60 * 15),
  authCookieSecure: toBoolean(process.env.AUTH_COOKIE_SECURE, process.env.NODE_ENV === 'production'),
  authCookieSameSite: normalizeSameSite(process.env.AUTH_COOKIE_SAMESITE, 'lax'),
  authCookieDomain: String(process.env.AUTH_COOKIE_DOMAIN || '').trim(),
  authCookiePath: String(process.env.AUTH_COOKIE_PATH || '/').trim() || '/',
  authAccessCookieName: String(process.env.AUTH_ACCESS_COOKIE_NAME || 'ct_access').trim() || 'ct_access',
  authRefreshCookieName: String(process.env.AUTH_REFRESH_COOKIE_NAME || 'ct_refresh').trim() || 'ct_refresh',
  csrfCookieName: String(process.env.AUTH_CSRF_COOKIE_NAME || 'ct_csrf').trim() || 'ct_csrf',
  csrfEnabled: toBoolean(process.env.CSRF_ENABLED, true),
  requireDatabaseForCi: toBoolean(process.env.REQUIRE_DATABASE_FOR_CI, process.env.CI === 'true'),
  allowPublicRegistration: toBoolean(process.env.ALLOW_PUBLIC_REGISTRATION, false),
  rateLimitWindowMs: toNumber(process.env.RATE_LIMIT_WINDOW_MS, 60_000),
  rateLimitMaxRequests: toNumber(process.env.RATE_LIMIT_MAX_REQUESTS, 200),
  authRateLimitWindowMs: toNumber(process.env.AUTH_RATE_LIMIT_WINDOW_MS, 60_000),
  authRateLimitMaxRequests: toNumber(process.env.AUTH_RATE_LIMIT_MAX_REQUESTS, 25),
  authIdentityRateLimitMaxRequests: toNumber(process.env.AUTH_IDENTITY_RATE_LIMIT_MAX_REQUESTS, 8),
  reportRateLimitWindowMs: toNumber(process.env.REPORT_RATE_LIMIT_WINDOW_MS, 60_000),
  reportRateLimitMaxRequests: toNumber(process.env.REPORT_RATE_LIMIT_MAX_REQUESTS, 80),
  trustProxy: toBoolean(process.env.TRUST_PROXY, false),
  allowInsecureDemoAuth: toBoolean(process.env.ALLOW_INSECURE_DEMO_AUTH, false),
  requireAuthForThreatEndpoints: toBoolean(
    process.env.REQUIRE_AUTH_FOR_THREAT_ENDPOINTS,
    process.env.NODE_ENV === 'production'
  ),
  requireAuthForPlatformEndpoints: toBoolean(
    process.env.REQUIRE_AUTH_FOR_PLATFORM_ENDPOINTS,
    process.env.NODE_ENV === 'production'
  ),
  metricsRequireAuth: toBoolean(process.env.METRICS_REQUIRE_AUTH, process.env.NODE_ENV === 'production'),
  metricsAuthToken: process.env.METRICS_AUTH_TOKEN || '',
  requestTimeoutMs: toNumber(process.env.REQUEST_TIMEOUT_MS, 15_000),
  headersTimeoutMs: toNumber(process.env.HEADERS_TIMEOUT_MS, 16_000),
  keepAliveTimeoutMs: toNumber(process.env.KEEP_ALIVE_TIMEOUT_MS, 5_000),
  maxConcurrentRequests: toNumber(process.env.MAX_CONCURRENT_REQUESTS, 2_000),

  // Public runtime config served to frontend at /api/config
  publicApiBaseUrl: process.env.PUBLIC_API_BASE_URL || '/api',
  publicAuthLoginPath: process.env.PUBLIC_AUTH_LOGIN_PATH || '/v1/auth/login',
  publicAuthTokenPath: process.env.PUBLIC_AUTH_TOKEN_PATH || '/v1/auth/token',
  publicAuthMePath: process.env.PUBLIC_AUTH_ME_PATH || '/v1/auth/me',
  publicAuthLogoutPath: process.env.PUBLIC_AUTH_LOGOUT_PATH || '/v1/auth/logout',
  publicThreatSummaryPath: process.env.PUBLIC_THREAT_SUMMARY_PATH || '/v1/threats/summary',
  publicThreatIncidentsPath: process.env.PUBLIC_THREAT_INCIDENTS_PATH || '/v1/threats/incidents',
  publicSystemHealthPath: process.env.PUBLIC_SYSTEM_HEALTH_PATH || '/v1/system/health',
  publicPlatformAppsPath: process.env.PUBLIC_PLATFORM_APPS_PATH || '/v1/platform/apps',
  publicReportsPath: process.env.PUBLIC_REPORTS_PATH || '/v1/reports',
  publicReportUploadPath: process.env.PUBLIC_REPORT_UPLOAD_PATH || '/v1/reports/upload',
  publicReportDownloadPathTemplate:
    process.env.PUBLIC_REPORT_DOWNLOAD_PATH_TEMPLATE || '/v1/reports/{reportId}/download',
  publicAnalyticsEnabled: toBoolean(process.env.PUBLIC_ANALYTICS_ENABLED, true),
  publicEnterpriseMode: toBoolean(process.env.PUBLIC_ENTERPRISE_MODE, true),
  publicBackendProbesEnabled: toBoolean(
    process.env.PUBLIC_BACKEND_PROBES_ENABLED,
    process.env.NODE_ENV === 'production'
  ),

  // Database / persistence
  databaseUrl: process.env.DATABASE_URL || '',
  dbSslMode: process.env.DB_SSL_MODE || (process.env.NODE_ENV === 'production' ? 'require' : 'disable'),
  dbPoolMax: toNumber(process.env.DB_POOL_MAX, 20),
  dbIdleTimeoutMs: toNumber(process.env.DB_IDLE_TIMEOUT_MS, 30_000),
  dbConnectTimeoutMs: toNumber(process.env.DB_CONNECT_TIMEOUT_MS, 5_000),
  dbStatementTimeoutMs: toNumber(process.env.DB_STATEMENT_TIMEOUT_MS, 10_000),
  dbAutoMigrate: toBoolean(process.env.DB_AUTO_MIGRATE, true),

  // Report file storage/upload pipeline.
  reportStorageDriver: String(process.env.REPORT_STORAGE_DRIVER || 'local').toLowerCase().trim(),
  reportStorageLocalPath:
    process.env.REPORT_STORAGE_LOCAL_PATH ||
    path.resolve(__dirname, '..', '..', '..', '.runtime', 'uploads', 'reports'),
  reportUploadMaxBytes: toNumber(process.env.REPORT_UPLOAD_MAX_BYTES, 15 * 1024 * 1024),
  reportUploadAllowedMimeTypes: parseCsvList(
    process.env.REPORT_UPLOAD_ALLOWED_MIME_TYPES,
    ['application/pdf', 'text/csv', 'application/json']
  ),
  reportStorageS3Bucket: process.env.REPORT_STORAGE_S3_BUCKET || '',
  reportStorageS3Region: process.env.REPORT_STORAGE_S3_REGION || 'us-east-1',
  reportStorageS3Endpoint: process.env.REPORT_STORAGE_S3_ENDPOINT || '',
  reportStorageS3AccessKeyId: process.env.REPORT_STORAGE_S3_ACCESS_KEY_ID || '',
  reportStorageS3SecretAccessKey: process.env.REPORT_STORAGE_S3_SECRET_ACCESS_KEY || '',
  reportStorageS3ForcePathStyle: toBoolean(process.env.REPORT_STORAGE_S3_FORCE_PATH_STYLE, true),
  reportRetentionDays: toNumber(process.env.REPORT_RETENTION_DAYS, 365),
  reportRetentionCleanupIntervalMs: toNumber(
    process.env.REPORT_RETENTION_CLEANUP_INTERVAL_MS,
    6 * 60 * 60 * 1000
  ),
  reportRetentionBatchSize: toNumber(process.env.REPORT_RETENTION_BATCH_SIZE, 200),
  freePlanIncludedUnitsPerMonth: toNumber(process.env.FREE_PLAN_INCLUDED_UNITS_PER_MONTH, 250),
  proPlanIncludedUnitsPerMonth: toNumber(process.env.PRO_PLAN_INCLUDED_UNITS_PER_MONTH, 0),
  enterprisePlanIncludedUnitsPerMonth: toNumber(
    process.env.ENTERPRISE_PLAN_INCLUDED_UNITS_PER_MONTH,
    0
  ),
  aiUploadMaxBytes: toNumber(
    process.env.AI_UPLOAD_MAX_BYTES,
    toNumber(process.env.MAX_UPLOAD_MB, 10) * 1024 * 1024
  ),
  complianceEvidenceAllowedMimeTypes: parseCsvList(
    process.env.COMPLIANCE_EVIDENCE_ALLOWED_MIME_TYPES,
    ['application/pdf', 'text/csv', 'application/json']
  ),

  // LLM provider settings (fail-closed at endpoint invocation).
  llmProvider: normalizeLlmProvider(process.env.LLM_PROVIDER),
  defaultTenantPlanTier: String(process.env.DEFAULT_TENANT_PLAN_TIER || 'free').trim().toLowerCase(),
  openaiApiKey: process.env.OPENAI_API_KEY || '',
  openaiBaseUrl: process.env.OPENAI_BASE_URL || 'https://api.openai.com/v1',
  openaiModel: process.env.OPENAI_MODEL || 'gpt-4.1-mini',
  ollamaUrl: process.env.OLLAMA_URL || '',
  ollamaModel: process.env.OLLAMA_MODEL || 'llama3.1',

  // vLLM (OpenAI-compatible self-hosted endpoint for fine-tuned Cybertron LoRA model)
  vllmBaseUrl: process.env.LLM_VLLM_BASE_URL || 'http://localhost:8000/v1',
  vllmModel: process.env.LLM_VLLM_MODEL || 'cybertron',
  vllmApiKey: process.env.LLM_VLLM_API_KEY || 'cybertron-local-key',

  llmRequestTimeoutMs: toNumber(process.env.LLM_REQUEST_TIMEOUT_MS, 120_000),
  llmDefaultMaxTokens: toNumber(process.env.LLM_DEFAULT_MAX_TOKENS, 1024),
  llmRateLimitWindowMs: toNumber(process.env.LLM_RATE_LIMIT_WINDOW_MS, 3_600_000),
  llmRateLimitMaxCalls: toNumber(process.env.LLM_RATE_LIMIT_MAX_CALLS, 100),

  // CVE/NVD ingestion settings.
  nvdFeedUrl: process.env.NVD_FEED_URL || 'https://services.nvd.nist.gov/rest/json/cves/2.0',
  nvdApiKey: process.env.NVD_API_KEY || '',
  nvdRequestTimeoutMs: toNumber(process.env.NVD_REQUEST_TIMEOUT_MS, 20_000),
  nvdResultsPerPage: toNumber(process.env.NVD_RESULTS_PER_PAGE, 200),
  nvdSyncMaxEntries: toNumber(process.env.NVD_SYNC_MAX_ENTRIES, 400),
  nvdSyncBackoffBaseMs: toNumber(process.env.NVD_SYNC_BACKOFF_BASE_MS, 30_000),
  nvdSyncBackoffMaxMs: toNumber(process.env.NVD_SYNC_BACKOFF_MAX_MS, 15 * 60 * 1000),

  // URLhaus threat feed (free, no auth required)
  urlhausEnabled: toBoolean(process.env.URLHAUS_ENABLED, false),
  urlhausRequestTimeoutMs: toNumber(process.env.URLHAUS_REQUEST_TIMEOUT_MS, 15_000),

  // Optional external threat connectors
  wazuhApiUrl: process.env.WAZUH_API_URL || '',
  wazuhApiToken: process.env.WAZUH_API_TOKEN || '',
  mispApiUrl: process.env.MISP_API_URL || '',
  mispApiKey: process.env.MISP_API_KEY || '',
  openCtiApiUrl: process.env.OPENCTI_API_URL || '',
  openCtiApiToken: process.env.OPENCTI_API_TOKEN || '',
  theHiveApiUrl: process.env.THEHIVE_API_URL || '',
  theHiveApiToken: process.env.THEHIVE_API_TOKEN || '',
  connectorTimeoutMs: toNumber(process.env.CONNECTOR_TIMEOUT_MS, 6_000),

  // OAuth2 social login providers (fail-closed if not configured)
  googleClientId: process.env.GOOGLE_CLIENT_ID || '',
  googleClientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
  microsoftClientId: process.env.MICROSOFT_CLIENT_ID || '',
  microsoftClientSecret: process.env.MICROSOFT_CLIENT_SECRET || '',
  githubClientId: process.env.GITHUB_CLIENT_ID || '',
  githubClientSecret: process.env.GITHUB_CLIENT_SECRET || '',
  oauthCallbackBaseUrl: process.env.OAUTH_CALLBACK_BASE_URL || process.env.FRONTEND_ORIGIN || 'http://localhost:3000',

  // OIDC (OpenID Connect) generic provider for enterprise IdPs
  oidcIssuerUrl: process.env.OIDC_ISSUER_URL || '',
  oidcClientId: process.env.OIDC_CLIENT_ID || '',
  oidcClientSecret: process.env.OIDC_CLIENT_SECRET || '',
  oidcScopes: process.env.OIDC_SCOPES || 'openid email profile',
  oidcAudience: process.env.OIDC_AUDIENCE || '',

  // Multi-account abuse prevention via device fingerprinting
  maxRegistrationsPerFingerprint: toNumber(process.env.MAX_REGISTRATIONS_PER_FINGERPRINT, 1),
  maxWorkspaceBootstrapsPerNetwork: toNumber(process.env.MAX_WORKSPACE_BOOTSTRAPS_PER_NETWORK, 3),
  fingerprintWindowMs: toNumber(process.env.FINGERPRINT_WINDOW_MS, 1000 * 60 * 60 * 24),

  // OpenTelemetry tracing
  otelEnabled: toBoolean(process.env.OTEL_ENABLED, false),
  otelServiceName: process.env.OTEL_SERVICE_NAME || 'cybertron-backend',
  otelExporterEndpoint: process.env.OTEL_EXPORTER_OTLP_ENDPOINT || '',

  // Email provider settings (P1-1)
  emailProvider: String(process.env.EMAIL_PROVIDER || 'console').toLowerCase().trim(),
  emailFromAddress: process.env.EMAIL_FROM_ADDRESS || 'noreply@cybertron.io',
  emailFromName: process.env.EMAIL_FROM_NAME || 'Cybertron',
  resendApiKey: process.env.RESEND_API_KEY || '',
  smtpHost: process.env.SMTP_HOST || '',
  smtpPort: toNumber(process.env.SMTP_PORT, 587),
  smtpUser: process.env.SMTP_USER || '',
  smtpPass: process.env.SMTP_PASS || '',
  smtpSecure: toBoolean(process.env.SMTP_SECURE, false),

  // Stripe billing integration (P1-4)
  stripeSecretKey: process.env.STRIPE_SECRET_KEY || '',
  stripeWebhookSecret: process.env.STRIPE_WEBHOOK_SECRET || '',
  stripePriceIdProMonthly: process.env.STRIPE_PRICE_ID_PRO_MONTHLY || '',
  stripePriceIdProAnnual: process.env.STRIPE_PRICE_ID_PRO_ANNUAL || '',
  stripePriceIdEnterpriseMonthly: process.env.STRIPE_PRICE_ID_ENTERPRISE_MONTHLY || '',

  // Connector secrets encryption key (P1-10)
  connectorSecretsKey: process.env.CONNECTOR_SECRETS_KEY || '',

  // Fine-tuned model via vLLM (P2-5)
  llmVllmBaseUrl: process.env.LLM_VLLM_BASE_URL || 'http://vllm:8000/v1',
  llmVllmModel: process.env.LLM_VLLM_MODEL || 'cybertron-lora',
};

function validateRuntimeConfig(activeConfig) {
  const errors = [];
  const warnings = [];
  const isProduction = activeConfig.environment === 'production';
  const isLocalProductionValidation = isProduction && activeConfig.localProductionValidation;

  if (!Array.isArray(activeConfig.allowedOrigins) || activeConfig.allowedOrigins.length === 0) {
    errors.push('CORS_ALLOWED_ORIGINS must include at least one origin.');
  }

  if (activeConfig.requestTimeoutMs >= activeConfig.headersTimeoutMs) {
    errors.push('REQUEST_TIMEOUT_MS must be lower than HEADERS_TIMEOUT_MS.');
  }

  if (activeConfig.authMode === 'jwt_hs256' && !activeConfig.jwtSecret) {
    errors.push('JWT_SECRET is required when AUTH_MODE=jwt_hs256.');
  }

  if (
    isProduction &&
    activeConfig.authMode === 'jwt_hs256' &&
    activeConfig.jwtSecret &&
    activeConfig.jwtSecret.length < 32
  ) {
    errors.push('JWT_SECRET must be at least 32 characters in production for adequate signing entropy.');
  }

  if (activeConfig.jwtAlgorithm === 'RS256') {
    if (!activeConfig.jwtPublicKey) {
      errors.push('JWT_PUBLIC_KEY is required when JWT_ALGORITHM=RS256.');
    }
    if (!activeConfig.jwtPrivateKey) {
      errors.push('JWT_PRIVATE_KEY is required when JWT_ALGORITHM=RS256 for token signing.');
    }
  }

  if (
    isProduction &&
    activeConfig.jwtSecret === 'dev-jwt-secret-change-me'
  ) {
    errors.push('JWT_SECRET is still set to the default development value. Generate a secure random secret for production.');
  }

  if (
    isProduction &&
    /^change.?me/i.test(activeConfig.jwtSecret)
  ) {
    errors.push('JWT_SECRET appears to be a placeholder value. Generate a secure random secret with: node -e "console.log(require(\'crypto\').randomBytes(48).toString(\'base64\'))"');
  }

  if (!['lax', 'strict', 'none'].includes(activeConfig.authCookieSameSite)) {
    errors.push('AUTH_COOKIE_SAMESITE must be one of lax, strict, none.');
  }

  if (activeConfig.authCookieSameSite === 'none' && !activeConfig.authCookieSecure) {
    errors.push('AUTH_COOKIE_SECURE must be true when AUTH_COOKIE_SAMESITE=none.');
  }

  if (!activeConfig.redisUrl) {
    if (activeConfig.environment === 'production') {
      errors.push('REDIS_URL is required in production for distributed auth revocation and rate limiting.');
    } else if (activeConfig.strictDependencies) {
      warnings.push(
        'REDIS_URL is not set while STRICT_DEPENDENCIES=true; Redis will not be required for readiness until a URL is provided. Distributed revocation/rate limiting falls back to local mode.'
      );
    } else {
      warnings.push('REDIS_URL is not set; distributed revocation/rate limiting falls back to local mode.');
    }
  }

  if (activeConfig.redisConnectTimeoutMs < 250) {
    errors.push('REDIS_CONNECT_TIMEOUT_MS must be at least 250.');
  }

  if (activeConfig.redisConnectMaxRetries < 1) {
    errors.push('REDIS_CONNECT_MAX_RETRIES must be at least 1.');
  }

  if (activeConfig.databaseUrl && !activeConfig.jwtSecret) {
    warnings.push('JWT_SECRET is not set. Password auth endpoints cannot issue access tokens.');
  }

  if (!isValidPublicApiBase(activeConfig.publicApiBaseUrl)) {
    errors.push('PUBLIC_API_BASE_URL must be a relative path (e.g. /api) or absolute http(s) URL.');
  }

  if (isProduction) {
    if (isLocalProductionValidation) {
      if (!isLocalOrigin(activeConfig.frontendOrigin)) {
        errors.push('FRONTEND_ORIGIN must use localhost/127.0.0.1 when LOCAL_PRODUCTION_VALIDATION=true.');
      }

      if (activeConfig.allowedOrigins.some(origin => !isLocalOrigin(origin))) {
        errors.push('CORS_ALLOWED_ORIGINS must contain only localhost/127.0.0.1 origins when LOCAL_PRODUCTION_VALIDATION=true.');
      }

      if (activeConfig.authCookieSecure) {
        errors.push('AUTH_COOKIE_SECURE must be false when LOCAL_PRODUCTION_VALIDATION=true over http localhost.');
      }

      warnings.push(
        'LOCAL_PRODUCTION_VALIDATION is enabled. Localhost origins and non-secure auth cookies are allowed only for browser-based Docker validation on this machine.'
      );
    } else if (!isHttpsUrl(activeConfig.frontendOrigin)) {
      errors.push('FRONTEND_ORIGIN must use https in production.');
    }

    if (activeConfig.allowedOrigins.some(origin => origin === '*')) {
      errors.push('CORS_ALLOWED_ORIGINS cannot include * in production.');
    }

    if (!isLocalProductionValidation && activeConfig.allowedOrigins.some(isLocalOrigin)) {
      errors.push('CORS_ALLOWED_ORIGINS cannot include localhost/127.0.0.1 in production.');
    }

    if (!activeConfig.enforceOriginValidation) {
      errors.push('ENFORCE_ORIGIN_VALIDATION must be true in production.');
    }

    if (activeConfig.allowInsecureDemoAuth) {
      errors.push('ALLOW_INSECURE_DEMO_AUTH must be false in production.');
    }

    if (activeConfig.authMode === 'demo') {
      errors.push('AUTH_MODE cannot be demo in production.');
    }

    if (!isLocalProductionValidation && !activeConfig.authCookieSecure) {
      errors.push('AUTH_COOKIE_SECURE must be true in production.');
    }

    if (!activeConfig.csrfEnabled) {
      errors.push('CSRF_ENABLED must be true in production.');
    }

    if (activeConfig.allowPublicRegistration) {
      warnings.push('ALLOW_PUBLIC_REGISTRATION is enabled in production.');
    }

    if (!activeConfig.databaseUrl) {
      errors.push('DATABASE_URL is required in production for real persistence.');
    }

    if (hasInsecureConnectorInProduction(activeConfig)) {
      errors.push('All connector URLs must use https in production.');
    }

    if (!activeConfig.requireAuthForThreatEndpoints) {
      errors.push('REQUIRE_AUTH_FOR_THREAT_ENDPOINTS must be true in production.');
    }

    if (!activeConfig.requireAuthForPlatformEndpoints) {
      errors.push('REQUIRE_AUTH_FOR_PLATFORM_ENDPOINTS must be true in production.');
    }

    if (!activeConfig.metricsRequireAuth) {
      errors.push('METRICS_REQUIRE_AUTH must be true in production.');
    }
  } else if (!activeConfig.databaseUrl) {
    warnings.push('DATABASE_URL is not set; threat endpoints will return truthful empty payloads.');
  }

  if (activeConfig.strictDependencies && !activeConfig.databaseUrl) {
    warnings.push(
      'DATABASE_URL is not set while STRICT_DEPENDENCIES=true; database will not be required for readiness until a URL is provided. Threat endpoints return truthful empty payloads.'
    );
  }

  if (!['local', 's3'].includes(activeConfig.reportStorageDriver)) {
    errors.push('REPORT_STORAGE_DRIVER must be either local or s3.');
  }

  if (!Array.isArray(activeConfig.reportUploadAllowedMimeTypes) || activeConfig.reportUploadAllowedMimeTypes.length === 0) {
    errors.push('REPORT_UPLOAD_ALLOWED_MIME_TYPES must include at least one mime type.');
  }

  if (activeConfig.reportUploadMaxBytes < 1024) {
    errors.push('REPORT_UPLOAD_MAX_BYTES must be at least 1024 bytes.');
  }

  if (activeConfig.reportRetentionDays < 1) {
    errors.push('REPORT_RETENTION_DAYS must be at least 1.');
  }

  if (activeConfig.reportRetentionCleanupIntervalMs < 60_000) {
    errors.push('REPORT_RETENTION_CLEANUP_INTERVAL_MS must be at least 60000.');
  }

  if (activeConfig.reportRetentionBatchSize < 1 || activeConfig.reportRetentionBatchSize > 10_000) {
    errors.push('REPORT_RETENTION_BATCH_SIZE must be between 1 and 10000.');
  }

  if (activeConfig.maxRegistrationsPerFingerprint < 1) {
    errors.push('MAX_REGISTRATIONS_PER_FINGERPRINT must be at least 1.');
  }

  if (activeConfig.maxWorkspaceBootstrapsPerNetwork < 1) {
    errors.push('MAX_WORKSPACE_BOOTSTRAPS_PER_NETWORK must be at least 1.');
  }

  if (activeConfig.fingerprintWindowMs < 60_000) {
    errors.push('FINGERPRINT_WINDOW_MS must be at least 60000.');
  }

  if (activeConfig.reportStorageDriver === 's3') {
    if (!activeConfig.reportStorageS3Bucket) {
      errors.push('REPORT_STORAGE_S3_BUCKET is required when REPORT_STORAGE_DRIVER=s3.');
    }

    if (!activeConfig.reportStorageS3Region) {
      errors.push('REPORT_STORAGE_S3_REGION is required when REPORT_STORAGE_DRIVER=s3.');
    }

    if (
      activeConfig.environment === 'production' &&
      activeConfig.reportStorageS3Endpoint &&
      !isHttpsUrl(activeConfig.reportStorageS3Endpoint) &&
      !(isLocalProductionValidation && isLocalValidationServiceUrl(activeConfig.reportStorageS3Endpoint))
    ) {
      errors.push('REPORT_STORAGE_S3_ENDPOINT must use https in production.');
    }
  }

  if (activeConfig.metricsRequireAuth && !activeConfig.metricsAuthToken) {
    errors.push('METRICS_AUTH_TOKEN is required when METRICS_REQUIRE_AUTH=true.');
  }

  if (
    activeConfig.metricsRequireAuth &&
    activeConfig.metricsAuthToken &&
    /^change.?me/i.test(activeConfig.metricsAuthToken)
  ) {
    errors.push('METRICS_AUTH_TOKEN appears to be a placeholder value. Generate a secure random token with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
  }

  if (activeConfig.authRateLimitMaxRequests > activeConfig.rateLimitMaxRequests) {
    warnings.push('AUTH_RATE_LIMIT_MAX_REQUESTS exceeds RATE_LIMIT_MAX_REQUESTS.');
  }

  if (activeConfig.oidcIssuerUrl && !activeConfig.oidcClientId) {
    errors.push('OIDC_CLIENT_ID is required when OIDC_ISSUER_URL is set.');
  }

  if (activeConfig.oidcIssuerUrl && !activeConfig.oidcClientSecret) {
    errors.push('OIDC_CLIENT_SECRET is required when OIDC_ISSUER_URL is set.');
  }

  if (activeConfig.environment === 'production' && activeConfig.oidcIssuerUrl && !isHttpsUrl(activeConfig.oidcIssuerUrl)) {
    errors.push('OIDC_ISSUER_URL must use https in production.');
  }

  if (activeConfig.authIdentityRateLimitMaxRequests < 1) {
    errors.push('AUTH_IDENTITY_RATE_LIMIT_MAX_REQUESTS must be at least 1.');
  }

  if (activeConfig.authIdentityRateLimitMaxRequests > activeConfig.authRateLimitMaxRequests) {
    warnings.push('AUTH_IDENTITY_RATE_LIMIT_MAX_REQUESTS exceeds AUTH_RATE_LIMIT_MAX_REQUESTS.');
  }

  if (activeConfig.reportRateLimitMaxRequests < 1) {
    errors.push('REPORT_RATE_LIMIT_MAX_REQUESTS must be at least 1.');
  }

  if (activeConfig.reportRateLimitWindowMs < 1_000) {
    errors.push('REPORT_RATE_LIMIT_WINDOW_MS must be at least 1000.');
  }

  if (activeConfig.reportRateLimitMaxRequests > activeConfig.rateLimitMaxRequests) {
    warnings.push('REPORT_RATE_LIMIT_MAX_REQUESTS exceeds RATE_LIMIT_MAX_REQUESTS.');
  }

  if (!Array.isArray(activeConfig.complianceEvidenceAllowedMimeTypes) || activeConfig.complianceEvidenceAllowedMimeTypes.length === 0) {
    errors.push('COMPLIANCE_EVIDENCE_ALLOWED_MIME_TYPES must include at least one mime type.');
  }

  if (activeConfig.aiUploadMaxBytes < 1024) {
    errors.push('AI_UPLOAD_MAX_BYTES must be at least 1024 bytes.');
  }

  if (activeConfig.llmRequestTimeoutMs < 1000) {
    errors.push('LLM_REQUEST_TIMEOUT_MS must be at least 1000.');
  }

  if (activeConfig.llmDefaultMaxTokens < 64 || activeConfig.llmDefaultMaxTokens > 8192) {
    errors.push('LLM_DEFAULT_MAX_TOKENS must be between 64 and 8192.');
  }

  if (!['free', 'pro', 'enterprise'].includes(activeConfig.defaultTenantPlanTier)) {
    errors.push('DEFAULT_TENANT_PLAN_TIER must be one of free, pro, or enterprise.');
  }

  if (!isHttpOrHttpsUrl(activeConfig.openaiBaseUrl)) {
    errors.push('OPENAI_BASE_URL must be a valid http(s) URL.');
  }

  if (
    activeConfig.environment === 'production' &&
    activeConfig.llmProvider === 'openai' &&
    !isHttpsUrl(activeConfig.openaiBaseUrl) &&
    !(
      isLocalProductionValidation &&
      isLocalValidationServiceUrl(activeConfig.openaiBaseUrl)
    )
  ) {
    errors.push(
      'OPENAI_BASE_URL must use https in production unless LOCAL_PRODUCTION_VALIDATION=true and the service is local.'
    );
  }

  if (activeConfig.llmProvider === 'openai' && !activeConfig.openaiApiKey) {
    warnings.push('LLM_PROVIDER=openai but OPENAI_API_KEY is not set. LLM endpoints will fail with LLM_NOT_CONFIGURED.');
  }

  if (activeConfig.llmProvider === 'ollama' && !activeConfig.ollamaUrl) {
    warnings.push('LLM_PROVIDER=ollama but OLLAMA_URL is not set. LLM endpoints will fail with LLM_NOT_CONFIGURED.');
  }

  if (activeConfig.llmProvider === 'vllm' && !activeConfig.vllmBaseUrl) {
    warnings.push('LLM_PROVIDER=vllm but LLM_VLLM_BASE_URL is not set. LLM endpoints will fail with LLM_NOT_CONFIGURED.');
  }

  if (activeConfig.environment === 'production' && !isHttpsUrl(activeConfig.nvdFeedUrl)) {
    errors.push('NVD_FEED_URL must use https in production.');
  }

  if (activeConfig.nvdResultsPerPage < 1 || activeConfig.nvdResultsPerPage > 2000) {
    errors.push('NVD_RESULTS_PER_PAGE must be between 1 and 2000.');
  }

  if (activeConfig.nvdSyncMaxEntries < 1 || activeConfig.nvdSyncMaxEntries > 5000) {
    errors.push('NVD_SYNC_MAX_ENTRIES must be between 1 and 5000.');
  }

  if (activeConfig.nvdSyncBackoffBaseMs < 1_000) {
    errors.push('NVD_SYNC_BACKOFF_BASE_MS must be at least 1000.');
  }

  if (activeConfig.nvdSyncBackoffMaxMs < activeConfig.nvdSyncBackoffBaseMs) {
    errors.push('NVD_SYNC_BACKOFF_MAX_MS must be greater than or equal to NVD_SYNC_BACKOFF_BASE_MS.');
  }

  return {
    ok: errors.length === 0,
    errors,
    warnings,
  };
}

/**
 * P0-1: Production startup guard.
 * Must be called before the server starts listening.
 * Throws if critical configuration is missing in production.
 */
function enforceProductionStartupGuard(activeConfig) {
  if (activeConfig.environment !== 'production') {
    return; // Only enforce in production
  }

  const missing = [];

  if (!activeConfig.jwtSecret || activeConfig.jwtSecret.length < 32) {
    missing.push('JWT_SECRET (must be at least 32 characters)');
  }

  if (!activeConfig.databaseUrl) {
    missing.push('DATABASE_URL');
  }

  if (activeConfig.authMode === 'demo') {
    missing.push('AUTH_MODE cannot be "demo" in production');
  }

  if (activeConfig.allowInsecureDemoAuth) {
    missing.push('ALLOW_INSECURE_DEMO_AUTH must be false in production');
  }

  if (missing.length > 0) {
    const message = [
      '',
      '╔══════════════════════════════════════════════════════════════╗',
      '║  CYBERTRON — PRODUCTION STARTUP BLOCKED                    ║',
      '╚══════════════════════════════════════════════════════════════╝',
      '',
      'The following required configuration is missing or invalid:',
      '',
      ...missing.map(m => `  ✗ ${m}`),
      '',
      'Set these variables in your .env or environment before starting.',
      'Generate secrets with:',
      '  node -e "console.log(require(\'crypto\').randomBytes(64).toString(\'hex\'))"',
      '',
    ].join('\n');

    console.error(message);
    throw new Error(`Production startup blocked: ${missing.length} critical config issue(s).`);
  }
}

module.exports = {
  config,
  validateRuntimeConfig,
  enforceProductionStartupGuard,
};
