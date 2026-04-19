const http = require('node:http');
const os = require('node:os');
const crypto = require('node:crypto');
const { pipeline } = require('node:stream/promises');

const { config, validateRuntimeConfig, enforceProductionStartupGuard } = require('./config');
const { log } = require('./logger');
const { createSessionStore, parseBearerToken } = require('./session-store');
const { resolveTokenSession } = require('./auth-provider');
const { createRateLimiter } = require('./rate-limiter');
const {
  parseCookieHeader,
  buildAuthCookies,
  buildClearAuthCookies,
} = require('./auth-cookies');
const {
  normalizeRole,
  hasRoleAccess,
} = require('./platform-registry');
const { buildThreatSummary, buildThreatIncidents } = require('./threat-data');
const { fetchConnectorIncidents } = require('./threat-connectors');
const {
  listTenants,
  listUsers,
  listServiceRequests,
  listReports,
  listAuditLogs,
} = require('./business-data');
const {
  ServiceError,
  registerUser,
  loginWithPassword,
  rotateRefreshToken,
  revokeRefreshToken,
  requestPasswordReset,
  resetPassword,
  findOrCreateOAuthUser,
} = require('./auth-service');
const {
  isValidProvider: isValidOAuthProvider,
  generateOAuthState,
  generatePkceChallenge,
  supportsPkce,
  buildAuthorizationUrl,
  exchangeCodeForTokens,
  fetchUserProfile,
  fetchOidcDiscovery,
} = require('./oauth-provider');
const {
  listIncidents,
  createIncident,
  updateIncident,
  listIncidentTimeline,
  listIocs,
  createIoc,
  linkIocToIncident,
  createServiceRequest,
  updateServiceRequest,
  listServiceRequestComments,
  createReport,
  findReportByIdempotencyKey,
  findReportByChecksum,
  getReportById,
  logReportDownload,
  getConnectorsStatus,
  listTenantAnalysts,
} = require('./module-service');
const {
  listProducts,
  listTenantProducts,
  getTenantProduct,
  setTenantProductState,
} = require('./product-service');
const { runMigrations, closeDatabase, query } = require('./database');
const { appendAuditLog } = require('./audit-log');
const { markTokenHashRevoked, isTokenHashRevoked } = require('./revocation-store');
const { checkRedisHealth, closeRedisClient } = require('./redis-client');
const {
  listFeatureFlags,
  listTenantFeatureFlags,
  setTenantFeatureFlag,
} = require('./feature-flag-service');
const {
  recordUsageEvent,
  listUsageEvents,
  getCredits,
  getTenantPlan,
  setPlanForTenant,
  assertFeatureAllowed,
  assertUsageAllowed,
  PLAN_FEATURES,
} = require('./billing-service');
const {
  listRegisteredModules,
  getModuleById,
  getModuleByProductKey,
  buildAppFromModule,
} = require('./modules');
const { createAuthGuard } = require('./auth-guard');
const {
  isOriginAllowed,
  toRequestContext,
  baseHeaders,
  sendJson,
  sendNoContent,
  sendText,
  sendRedirect,
  sendError,
  sendMethodNotAllowed,
} = require('./http-utils');
const { toSafeInteger, sanitizeTenant, sanitizeRedirectPath } = require('./validators');
const {
  enforceUploadPolicy,
  normalizeIdempotencyKey,
  parseAllowedMimeTypes,
} = require('./validators/upload-policy');
const { parseMultipartForm } = require('./utils/multipart');
const { computeSha256Hex } = require('./utils/file-hash');
const { sniffMimeType } = require('./utils/mime-sniff');
const { createStorageAdapter } = require('./storage/storage-adapter');
const { buildOpenApiSpec } = require('./openapi');
const { parseAwsLogJsonBuffer } = require('./ai/aws-log-parser');
const { probeLlmRuntime } = require('./ai/llm-provider');
const { parseSiemLogJsonBuffer } = require('./siem-log-parser');
const {
  ingestAwsLogRecords,
  listRiskFindings,
  getRiskPortfolioSummary,
  createRiskReportRecord,
  getRiskReportRecord,
  updateRiskFindingTreatment,
} = require('./ai/risk-scoring-service');
const {
  generateRiskExplanation,
  buildLocalMitigationSuggestions,
} = require('./ai/risk-ai-service');
const {
  generateRiskReportPdf,
} = require('./ai/report-generator');
const {
  listSoc2Controls,
  listSoc2Status,
  upsertSoc2Status,
  createSoc2EvidenceRecord,
  listSoc2Evidence,
  createPolicyRecord,
  listPolicies,
  getPolicyRecord,
  updatePolicyStatus,
  createAuditPackageRecord,
  getAuditPackageRecord,
} = require('./ai/compliance-model');
const { computeComplianceGap } = require('./ai/compliance-gap-engine');
const { generatePolicyDraft } = require('./ai/policy-ai-service');
const { buildAuditPackage } = require('./ai/audit-export-service');
const {
  syncCveFeed,
  listTenantCveFeed,
  getCveRecord,
  saveCveSummary,
  getThreatDashboard,
} = require('./ai/threat-dashboard-service');
const { summarizeCveWithAi } = require('./ai/threat-ai-service');
const {
  listMitreTechniques,
  listIncidentMitreMappings,
  addIncidentMitreMapping,
  removeIncidentMitreMapping,
  getMitreHeatmap,
} = require('./mitre-service');
const {
  listPlaybooks,
  getPlaybookWithSteps,
  createPlaybook,
  updatePlaybook,
  addPlaybookStep,
  executePlaybook,
  listPlaybookExecutions,
  updatePlaybookStepResult,
  getExecutionStepResults,
} = require('./playbook-service');
const {
  listSiemAlerts,
  ingestSiemAlert,
  correlateAlertToIncident,
  getSiemAlertStats,
  updateAlertStatus,
  assignAlert,
  escalateAlertToIncident,
  bulkUpdateAlertStatus,
  getAlertSlaMetrics,
  getAlertTriageSuggestion,
  getAttackMapData,
  updateAlertNotes,
  listCorrelationRules,
  createCorrelationRule,
  updateCorrelationRule,
} = require('./siem-service');
const { runCorrelationEngine } = require('./correlation-engine');
const {
  listThreatHuntQueries,
  createThreatHuntQuery,
  updateThreatHuntQuery,
  deleteThreatHuntQuery,
  executeThreatHuntQuery,
} = require('./threat-hunt-service');
const {
  listComplianceFrameworks,
  getComplianceFramework,
  listFrameworkControls,
  listFrameworkControlStatus,
  upsertFrameworkControlStatus,
  computeFrameworkGap,
  getComplianceSummary,
} = require('./compliance-framework-service');
const {
  addClient: addSseClient,
  closeNotificationBus,
  getRecentEventsForTenant,
  getConnectedClientCount,
  getTotalConnectedClients,
  initRedisSubscriber,
  notifyIncidentCreated,
  notifyIncidentUpdated,
  notifyAlertIngested,
  notifyComplianceStatusChanged,
  notifyPlaybookExecuted,
  notifyAuditEvent,
} = require('./notification-service');
const { registerRoutes: registerRiskCopilotRoutes } = require('./modules/risk-copilot/routes');
const { registerRoutes: registerComplianceRoutes } = require('./modules/compliance-engine/routes');
const { registerRoutes: registerThreatIntelRoutes } = require('./modules/threat-intel/routes');
const { registerRoutes: registerAuthRoutes } = require('./routes/auth');
const { registerRoutes: registerSystemRoutes } = require('./routes/system');
const { registerRoutes: registerAdminRoutes } = require('./routes/admin');
const { registerRoutes: registerBillingCrudRoutes } = require('./routes/billing-crud');
const { registerRoutes: registerNotificationRoutes } = require('./routes/notifications');
const { registerRoutes: registerPlatformRoutes } = require('./routes/platform');
const { registerRoutes: registerGovernanceRoutes } = require('./routes/governance');
const { registerRoutes: registerReportRoutes } = require('./routes/reports');
const { registerRoutes: registerThreatRoutes } = require('./routes/threats');
const { extractContext, startRequestSpan, endRequestSpan } = require('./tracing');

const sessionStore = createSessionStore({
  ttlMs: config.authTokenTtlMs,
  allowDemoToken: config.allowInsecureDemoAuth,
  maxSessions: config.authMaxSessions,
  useRedis: Boolean(config.redisUrl),
  config,
  log,
});
const rateLimiter = createRateLimiter({
  name: 'global',
  windowMs: config.rateLimitWindowMs,
  maxRequests: config.rateLimitMaxRequests,
  useRedis: Boolean(config.redisUrl),
  allowFallback: config.environment !== 'production',
  config,
  log,
});
const authRateLimiter = createRateLimiter({
  name: 'auth-route',
  windowMs: config.authRateLimitWindowMs,
  maxRequests: config.authRateLimitMaxRequests,
  useRedis: Boolean(config.redisUrl),
  allowFallback: config.environment !== 'production',
  config,
  log,
});
const authIdentityRateLimiter = createRateLimiter({
  name: 'auth-identity',
  windowMs: config.authRateLimitWindowMs,
  maxRequests: config.authIdentityRateLimitMaxRequests,
  useRedis: Boolean(config.redisUrl),
  allowFallback: config.environment !== 'production',
  config,
  log,
});
const reportRateLimiter = createRateLimiter({
  name: 'reports',
  windowMs: config.reportRateLimitWindowMs,
  maxRequests: config.reportRateLimitMaxRequests,
  useRedis: Boolean(config.redisUrl),
  allowFallback: config.environment !== 'production',
  config,
  log,
});
const aiRateLimiter = createRateLimiter({
  name: 'ai-llm',
  windowMs: 60_000,
  maxRequests: 20,
  useRedis: Boolean(config.redisUrl),
  allowFallback: config.environment !== 'production',
  config,
  log,
});
const storageAdapter = createStorageAdapter(config, log);
const allowedReportMimeTypes = parseAllowedMimeTypes(config.reportUploadAllowedMimeTypes.join(','));
const allowedAwsLogMimeTypes = parseAllowedMimeTypes('application/json');
const allowedSiemLogMimeTypes = parseAllowedMimeTypes('application/json,text/plain');
const allowedComplianceEvidenceMimeTypes = parseAllowedMimeTypes(
  config.complianceEvidenceAllowedMimeTypes.join(',')
);
const authGuard = createAuthGuard({
  config,
  sendError,
  getSession: getSessionFromContext,
});

const metrics = {
  startedAt: Date.now(),
  totalRequests: 0,
  totalErrors: 0,
  inFlightRequests: 0,
  statusCodes: {},
};

const csrfExemptPaths = new Set([
  '/v1/auth/login',
  '/v1/auth/register',
  '/v1/auth/password/forgot',
  '/v1/auth/password/reset',
]);

function parseRequestCookies(request) {
  return parseCookieHeader(request.headers.cookie);
}

function getAccessTokenFromContext(context) {
  const bearer = parseBearerToken(context.request.headers.authorization);
  if (bearer) {
    return bearer;
  }

  const cookies = parseRequestCookies(context.request);
  const cookieToken = cookies[config.authAccessCookieName];
  return cookieToken ? String(cookieToken).trim() : null;
}

function getRefreshTokenFromContext(context) {
  const cookies = parseRequestCookies(context.request);
  const cookieToken = cookies[config.authRefreshCookieName];
  return cookieToken ? String(cookieToken).trim() : null;
}

function getCsrfTokenFromContext(context) {
  const cookies = parseRequestCookies(context.request);
  const cookieToken = cookies[config.csrfCookieName];
  return cookieToken ? String(cookieToken).trim() : '';
}

function resolveCsrfHeader(context) {
  const fromPrimary = context.request.headers['x-csrf-token'];
  if (typeof fromPrimary === 'string') {
    return fromPrimary.trim();
  }

  const fromSecondary = context.request.headers['x-xsrf-token'];
  if (typeof fromSecondary === 'string') {
    return fromSecondary.trim();
  }

  return '';
}

function requiresCsrfProtection(context) {
  if (!config.csrfEnabled) {
    return false;
  }

  if (context.method === 'GET' || context.method === 'HEAD' || context.method === 'OPTIONS') {
    return false;
  }

  if (csrfExemptPaths.has(context.path)) {
    return false;
  }

  const cookies = parseRequestCookies(context.request);
  return Boolean(cookies[config.authAccessCookieName] || cookies[config.authRefreshCookieName]);
}

function attachAuthCookies(extraHeaders, tokenPair) {
  const cookiePayload = buildAuthCookies(config, tokenPair);
  return {
    ...extraHeaders,
    'Set-Cookie': cookiePayload.cookies,
    'X-CSRF-Token': cookiePayload.csrfToken,
  };
}

function attachClearAuthCookies(extraHeaders) {
  return {
    ...extraHeaders,
    'Set-Cookie': buildClearAuthCookies(config),
  };
}

function hashAuthIdentity(value) {
  return crypto.createHash('sha256').update(String(value || '')).digest('hex');
}

async function resolveRateIdentity(context) {
  const token = getAccessTokenFromContext(context);
  if (!token) {
    return 'anonymous';
  }

  const resolved = await resolveTokenSession(token, sessionStore, config);
  if (resolved?.session?.user?.id) {
    return `user:${String(resolved.session.user.id).slice(0, 128)}`;
  }

  return `token:${hashAuthIdentity(token).slice(0, 64)}`;
}

function isCsrfValid(context) {
  const csrfCookie = getCsrfTokenFromContext(context);
  const csrfHeader = resolveCsrfHeader(context);
  if (!csrfCookie || !csrfHeader) return false;
  if (csrfCookie.length !== csrfHeader.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(csrfCookie), Buffer.from(csrfHeader));
  } catch {
    return false;
  }
}

function enforceCsrfProtection(context, response, baseExtraHeaders) {
  if (!requiresCsrfProtection(context)) {
    return true;
  }

  if (!isCsrfValid(context)) {
    sendError(
      response,
      context,
      config,
      403,
      'csrf_violation',
      'CSRF verification failed.',
      {
        header: 'x-csrf-token',
      },
      baseExtraHeaders
    );
    return false;
  }

  return true;
}

function checkJsonDepth(value, maxDepth = 20, currentDepth = 0) {
  if (currentDepth > maxDepth) {
    return false;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      if (item && typeof item === 'object' && !checkJsonDepth(item, maxDepth, currentDepth + 1)) {
        return false;
      }
    }
  } else if (value && typeof value === 'object') {
    for (const key of Object.keys(value)) {
      if (value[key] && typeof value[key] === 'object' && !checkJsonDepth(value[key], maxDepth, currentDepth + 1)) {
        return false;
      }
    }
  }
  return true;
}

const revokedAccessTokenHashes = new Map();

function nextHeaders(context, rateState) {
  return {
    'X-RateLimit-Limit': String(rateState.limit),
    'X-RateLimit-Remaining': String(rateState.remaining),
    'X-RateLimit-Reset': String(Math.floor(rateState.resetAt / 1000)),
    'X-Correlation-Id': context.requestId,
  };
}

function trackResponse(statusCode) {
  metrics.totalRequests += 1;
  const key = String(statusCode);
  metrics.statusCodes[key] = (metrics.statusCodes[key] || 0) + 1;

  if (statusCode >= 500) {
    metrics.totalErrors += 1;
  }
}

async function getSessionFromContext(context) {
  const token = getAccessTokenFromContext(context);
  if (!token) {
    return null;
  }

  if (await isRevokedAccessToken(token)) {
    return null;
  }

  const resolved = await resolveTokenSession(token, sessionStore, config);
  return resolved.session || null;
}

function hashAccessToken(token) {
  return crypto.createHash('sha256').update(String(token || '')).digest('hex');
}

function parseJwtExpiryMs(token, fallbackMs) {
  const fallback = Number.isFinite(Number(fallbackMs))
    ? Number(fallbackMs)
    : Date.now() + Math.max(60_000, Number(config.authTokenTtlMs || 3_600_000));

  try {
    const segments = String(token || '').split('.');
    if (segments.length !== 3) {
      return fallback;
    }

    const payloadRaw = Buffer.from(segments[1], 'base64url').toString('utf8');
    const payload = JSON.parse(payloadRaw);
    if (typeof payload.exp === 'number' && Number.isFinite(payload.exp)) {
      return payload.exp * 1000;
    }
  } catch {
    // fall through to fallback
  }

  return fallback;
}

const REVOKED_TOKEN_MAP_MAX_SIZE = 50_000;

function rememberRevokedAccessTokenHash(tokenHash, expiresAtMs) {
  if (!tokenHash) {
    return;
  }

  if (revokedAccessTokenHashes.size >= REVOKED_TOKEN_MAP_MAX_SIZE) {
    cleanupRevokedAccessTokenCache();
  }

  if (revokedAccessTokenHashes.size >= REVOKED_TOKEN_MAP_MAX_SIZE) {
    console.warn(`[auth] Revoked token cache at capacity (${REVOKED_TOKEN_MAP_MAX_SIZE}), skipping in-memory cache for token.`);
    return;
  }

  const fallbackExpiry = Date.now() + Math.max(60_000, Number(config.authTokenTtlMs || 3_600_000));
  const effectiveExpiry = Number.isFinite(Number(expiresAtMs)) ? Number(expiresAtMs) : fallbackExpiry;
  revokedAccessTokenHashes.set(String(tokenHash), effectiveExpiry);
}

function cleanupRevokedAccessTokenCache() {
  const now = Date.now();
  for (const [tokenHash, expiresAtMs] of revokedAccessTokenHashes.entries()) {
    if (Number(expiresAtMs) <= now) {
      revokedAccessTokenHashes.delete(tokenHash);
    }
  }
}

async function isRevokedAccessToken(token) {
  const tokenHash = hashAccessToken(token);
  const expiresAtMs = revokedAccessTokenHashes.get(tokenHash);
  if (expiresAtMs) {
    if (Number(expiresAtMs) <= Date.now()) {
      revokedAccessTokenHashes.delete(tokenHash);
    } else {
      return true;
    }
  }

  const revokedShared = await isTokenHashRevoked(config, tokenHash, log);
  if (!revokedShared) {
    return false;
  }

  const fallbackExpiry = parseJwtExpiryMs(token, Date.now() + config.authTokenTtlMs);
  rememberRevokedAccessTokenHash(tokenHash, fallbackExpiry);
  return true;
}

async function bootstrapRevokedAccessTokensFromDatabase() {
  if (!config.databaseUrl) {
    return;
  }

  const result = await query(
    config,
    `
      SELECT token_hash, expires_at
      FROM auth_access_token_revocations
      WHERE expires_at IS NULL OR expires_at > NOW()
    `
  );

  for (const row of result?.rows || []) {
    const tokenHash = String(row.token_hash || '').trim();
    if (!tokenHash) {
      continue;
    }
    const expiresAtMs = row.expires_at ? new Date(row.expires_at).getTime() : Date.now() + config.authTokenTtlMs;
    rememberRevokedAccessTokenHash(tokenHash, expiresAtMs);
    await markTokenHashRevoked(config, tokenHash, expiresAtMs, log);
  }
}

async function persistRevokedAccessToken({ session, tokenHash, expiresAtMs, contextMeta }) {
  if (!tokenHash) {
    return;
  }

  await markTokenHashRevoked(config, tokenHash, expiresAtMs, log);

  if (!config.databaseUrl) {
    return;
  }

  const tenantSlug = sanitizeTenant(session?.user?.tenant || 'global');
  const userSubject = session?.user?.id != null ? String(session.user.id) : null;
  const numericUserId = userSubject && /^\d+$/.test(userSubject) ? userSubject : null;
  await query(
    config,
    `
      INSERT INTO auth_access_token_revocations (
        tenant_slug,
        user_id,
        user_subject,
        token_hash,
        expires_at,
        ip_address,
        user_agent,
        trace_id
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
      ON CONFLICT (token_hash)
      DO UPDATE SET
        revoked_at = NOW(),
        expires_at = EXCLUDED.expires_at,
        user_subject = COALESCE(EXCLUDED.user_subject, auth_access_token_revocations.user_subject),
        ip_address = EXCLUDED.ip_address,
        user_agent = EXCLUDED.user_agent,
        trace_id = EXCLUDED.trace_id
    `,
    [
      tenantSlug,
      numericUserId,
      userSubject,
      tokenHash,
      new Date(expiresAtMs).toISOString(),
      contextMeta.ipAddress || null,
      contextMeta.userAgent || null,
      contextMeta.traceId || null,
    ]
  );

  await appendAuditLog(config, {
    tenantSlug,
    actorId: session?.user?.id ? String(session.user.id) : null,
    actorEmail: session?.user?.email || null,
    action: 'auth.access_token_revoked',
    targetType: 'access_token',
    targetId: tokenHash.slice(0, 16),
    ipAddress: contextMeta.ipAddress || null,
    userAgent: contextMeta.userAgent || null,
    traceId: contextMeta.traceId || null,
    payload: {},
  });
}

async function purgeExpiredRevokedAccessTokens() {
  cleanupRevokedAccessTokenCache();

  if (!config.databaseUrl) {
    return;
  }

  await query(
    config,
    `
      DELETE FROM auth_access_token_revocations
      WHERE expires_at IS NOT NULL
        AND expires_at < NOW() - INTERVAL '1 day'
    `
  );
}

async function resolveAuthRole(context, fallbackRole, sessionOverride = null) {
  const session = sessionOverride || (await getSessionFromContext(context));
  if (session && session.user && session.user.role) {
    return normalizeRole(session.user.role);
  }

  return normalizeRole(fallbackRole);
}

async function resolvePlatformRole(context, requestedRole, sessionOverride = null) {
  return resolveAuthRole(context, requestedRole, sessionOverride);
}

function isCrossTenantAllowedForRole(role, options = {}) {
  const allowCrossTenantRoles = Array.isArray(options.allowCrossTenantRoles)
    ? options.allowCrossTenantRoles
    : ['super_admin'];
  return allowCrossTenantRoles.some(required => hasRoleAccess(role, required));
}

function resolveRequestedRoleScope(
  session,
  requestedRole,
  context,
  response,
  baseExtraHeaders,
  options = {}
) {
  const sessionRole = normalizeRole(session?.user?.role || 'executive_viewer');
  if (!requestedRole) {
    return sessionRole;
  }

  const targetRole = normalizeRole(requestedRole);
  if (targetRole === sessionRole) {
    return targetRole;
  }

  const allowRolePreviewForSuperAdmin = options.allowRolePreviewForSuperAdmin !== false;
  const canPreview = allowRolePreviewForSuperAdmin && hasRoleAccess(sessionRole, 'super_admin');
  if (canPreview) {
    return targetRole;
  }

  sendError(
    response,
    context,
    config,
    403,
    'role_scope_denied',
    'Requested role scope is not permitted for this session.',
    {
      requestedRole: targetRole,
      effectiveRole: sessionRole,
    },
    baseExtraHeaders
  );
  return null;
}

async function resolveAuthTenant(
  context,
  fallbackTenant,
  sessionOverride = null,
  options = {},
  response = null,
  baseExtraHeaders = null
) {
  const session = sessionOverride || (await getSessionFromContext(context));
  if (session) {
    const sessionTenant = sanitizeTenant(session?.user?.tenant || fallbackTenant || 'global');
    const requestedTenant = sanitizeTenant(fallbackTenant || sessionTenant);
    if (requestedTenant === sessionTenant) {
      return sessionTenant;
    }

    const role = normalizeRole(session?.user?.role || 'executive_viewer');
    const canCrossTenant = isCrossTenantAllowedForRole(role, options);
    if (canCrossTenant) {
      return requestedTenant;
    }

    if (response) {
      sendError(
        response,
        context,
        config,
        403,
        'tenant_scope_denied',
        'Cross-tenant access is not allowed for this session.',
        {
          requestedTenant,
          effectiveTenant: sessionTenant,
        },
        baseExtraHeaders || {}
      );
    }
    return null;
  }

  return sanitizeTenant(fallbackTenant);
}

async function resolveTenantForRequest(
  context,
  response,
  baseExtraHeaders,
  session,
  requestedTenant,
  options = {}
) {
  return resolveAuthTenant(
    context,
    requestedTenant,
    session,
    options,
    response,
    baseExtraHeaders
  );
}

async function checkDatabaseDependency() {
  if (!config.databaseUrl) {
    return {
      configured: false,
      status: 'not_configured',
      latencyMs: 0,
    };
  }

  const startedAt = Date.now();
  try {
    await query(config, 'SELECT 1 AS ok');
    return {
      configured: true,
      status: 'healthy',
      latencyMs: Date.now() - startedAt,
    };
  } catch (error) {
    return {
      configured: true,
      status: 'unavailable',
      latencyMs: Date.now() - startedAt,
      message: error instanceof Error ? error.message : 'database probe failed',
    };
  }
}

async function checkStorageDependency() {
  const startedAt = Date.now();
  try {
    const result = await storageAdapter.healthCheck();
    return {
      configured: true,
      status: result.status,
      latencyMs: Date.now() - startedAt,
      details: result.details || {},
    };
  } catch (error) {
    return {
      configured: true,
      status: 'unavailable',
      latencyMs: Date.now() - startedAt,
      message: error instanceof Error ? error.message : 'storage probe failed',
    };
  }
}

async function buildDependencyStatus() {
  const [database, storage, redis] = await Promise.all([
    checkDatabaseDependency(),
    checkStorageDependency(),
    checkRedisHealth(config, log),
  ]);

  // P2-3: LLM health check
  let llm = { configured: false, status: 'not_configured', latencyMs: 0 };
  try {
    if (config.llmProvider && config.llmProvider !== 'none') {
      llm = await probeLlmRuntime(config);
      llm.status = llm.reachable ? 'healthy' : 'unavailable';
    }
  } catch {
    llm = { configured: true, status: 'unavailable', latencyMs: 0 };
  }

  return { database, storage, redis, llm };
}

function sanitizeDependencyStatusForResponse(dependencies) {
  const database = dependencies?.database || {};
  const storage = dependencies?.storage || {};
  const redis = dependencies?.redis || {};
  const llm = dependencies?.llm || {};

  // P3-4: DB pool stats
  const { getPool } = require('./database');
  const pool = getPool(config);
  const poolStats = pool ? {
    total: pool.totalCount || 0,
    idle: pool.idleCount || 0,
    waiting: pool.waitingCount || 0,
  } : null;

  return {
    database: {
      configured: Boolean(database.configured),
      status: String(database.status || 'unknown'),
      latencyMs: Number(database.latencyMs || 0),
      ...(poolStats ? { pool: poolStats } : {}),
    },
    storage: {
      configured: Boolean(storage.configured),
      status: String(storage.status || 'unknown'),
      latencyMs: Number(storage.latencyMs || 0),
    },
    redis: {
      configured: Boolean(redis.configured),
      status: String(redis.status || 'unknown'),
      latencyMs: Number(redis.latencyMs || 0),
    },
    llm: {
      configured: Boolean(llm.configured),
      status: String(llm.status || 'not_configured'),
      latencyMs: Number(llm.latencyMs || 0),
      provider: llm.provider || config.llmProvider || 'none',
    },
  };
}

function isDependencyRequired(name) {
  const dependency = String(name || '').toLowerCase();
  if (dependency === 'storage') {
    return true;
  }

  if (dependency === 'database') {
    return config.strictDependencies && Boolean(config.databaseUrl);
  }

  if (dependency === 'redis') {
    return config.strictDependencies && Boolean(config.redisUrl);
  }

  return false;
}

function deriveHealthStatus(baseStatus, dependencies) {
  const requiredDown =
    (isDependencyRequired('database') && dependencies.database.status !== 'healthy') ||
    (isDependencyRequired('storage') && dependencies.storage.status !== 'healthy') ||
    (isDependencyRequired('redis') && dependencies.redis.status !== 'healthy');
  if (requiredDown) {
    return 'degraded';
  }

  const optionalDown =
    dependencies.database.status === 'unavailable' ||
    dependencies.storage.status === 'unavailable' ||
    dependencies.redis.status === 'unavailable';
  if (optionalDown) {
    return 'degraded';
  }

  return baseStatus;
}

async function buildHealthPayload() {
  const memory = process.memoryUsage();
  const rssMb = Math.round(memory.rss / (1024 * 1024));
  const heapUsedMb = Math.round(memory.heapUsed / (1024 * 1024));

  const baseStatus = rssMb > 900 || metrics.inFlightRequests > config.maxConcurrentRequests * 0.92
    ? 'degraded'
    : 'ok';
  const dependencies = await buildDependencyStatus();
  const responseDependencies = sanitizeDependencyStatusForResponse(dependencies);
  const status = deriveHealthStatus(baseStatus, dependencies);
  const databaseConnected = dependencies.database.status === 'healthy';
  const redisConnected = dependencies.redis.status === 'healthy';
  const storageConnected = dependencies.storage.status === 'healthy';

  return {
    status,
    mode: config.environment,
    strictDependencies: Boolean(config.strictDependencies),
    uptimeSeconds: Math.floor(process.uptime()),
    region: config.region,
    version: config.appVersion,
    authMode: config.authMode,
    checkedAt: new Date().toISOString(),
    memoryRssMb: rssMb,
    heapUsedMb,
    inFlightRequests: metrics.inFlightRequests,
    dbConfigured: Boolean(dependencies.database.configured),
    dbConnected: databaseConnected,
    redisConfigured: Boolean(dependencies.redis.configured),
    redisConnected,
    storageConfigured: Boolean(dependencies.storage.configured),
    storageConnected,
    dependencies: responseDependencies,
  };
}

function buildMetricsPayload() {
  return {
    status: 'ok',
    service: 'cybertron-backend',
    environment: config.environment,
    host: os.hostname(),
    uptimeSeconds: Math.floor(process.uptime()),
    startedAt: new Date(metrics.startedAt).toISOString(),
    requests: {
      total: metrics.totalRequests,
      errors: metrics.totalErrors,
      inFlight: metrics.inFlightRequests,
      byStatus: metrics.statusCodes,
      rateLimit: {
        windowMs: config.rateLimitWindowMs,
        maxRequests: config.rateLimitMaxRequests,
      },
      overload: {
        maxConcurrentRequests: config.maxConcurrentRequests,
      },
    },
    sessions: sessionStore.getStats(),
    checkedAt: new Date().toISOString(),
  };
}

async function assertProductionRedisReady() {
  if (config.environment !== 'production' && !config.strictDependencies) {
    return;
  }

  const attempts = config.environment === 'production' ? 6 : 1;
  const delayMs = 1_000;
  let lastStatus = 'unknown';

  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const health = await checkRedisHealth(config, log);
    lastStatus = health.status || 'unknown';
    if (lastStatus === 'healthy') {
      return;
    }

    if (attempt < attempts) {
      await new Promise(resolve => setTimeout(resolve, delayMs));
    }
  }

  log('error', 'redis.required_unavailable', {
    environment: config.environment,
    strictDependencies: Boolean(config.strictDependencies),
    redisConfigured: Boolean(config.redisUrl),
    lastStatus,
    attempts,
  });

  if (config.environment === 'production') {
    process.exit(1);
  }
}

function buildPrometheusMetrics() {
  const lines = [];
  const now = Date.now();

  lines.push('# HELP cybertron_requests_total Total number of completed HTTP requests');
  lines.push('# TYPE cybertron_requests_total counter');
  lines.push(`cybertron_requests_total ${metrics.totalRequests}`);

  lines.push('# HELP cybertron_request_errors_total Total number of completed requests with 5xx');
  lines.push('# TYPE cybertron_request_errors_total counter');
  lines.push(`cybertron_request_errors_total ${metrics.totalErrors}`);

  lines.push('# HELP cybertron_requests_in_flight Current in-flight requests');
  lines.push('# TYPE cybertron_requests_in_flight gauge');
  lines.push(`cybertron_requests_in_flight ${metrics.inFlightRequests}`);

  lines.push('# HELP cybertron_rate_limit_max_requests Rate limit max requests per window');
  lines.push('# TYPE cybertron_rate_limit_max_requests gauge');
  lines.push(`cybertron_rate_limit_max_requests ${config.rateLimitMaxRequests}`);

  lines.push('# HELP cybertron_uptime_seconds Process uptime seconds');
  lines.push('# TYPE cybertron_uptime_seconds gauge');
  lines.push(`cybertron_uptime_seconds ${Math.floor(process.uptime())}`);

  lines.push('# HELP cybertron_sessions_active Active sessions in store');
  lines.push('# TYPE cybertron_sessions_active gauge');
  lines.push(`cybertron_sessions_active ${sessionStore.getStats().activeSessions}`);

  for (const [statusCode, count] of Object.entries(metrics.statusCodes)) {
    lines.push(`cybertron_responses_by_status_total{status="${statusCode}"} ${count}`);
  }

  lines.push('# HELP cybertron_metrics_generated_timestamp_ms Metrics generation timestamp in ms');
  lines.push('# TYPE cybertron_metrics_generated_timestamp_ms gauge');
  lines.push(`cybertron_metrics_generated_timestamp_ms ${now}`);

  return `${lines.join('\n')}\n`;
}

async function buildAppStatus(appId, tenant) {
  const startedAt = Date.now();
  const base = {
    appId,
    tenant,
    checkedAt: new Date().toISOString(),
  };

  if (!config.databaseUrl) {
    return {
      ...base,
      status: 'no_data',
      latencyMs: Date.now() - startedAt,
      message: 'Database is not configured. Configure DATABASE_URL for real module telemetry.',
    };
  }

  try {
    const moduleRuntime = getModuleByProductKey(appId) || getModuleById(appId);
    if (moduleRuntime?.service && typeof moduleRuntime.service.getStatus === 'function') {
      const statusPayload = await moduleRuntime.service.getStatus(config, tenant);
      return {
        ...base,
        ...statusPayload,
        latencyMs: Date.now() - startedAt,
      };
    }

    if (appId === 'threat-command') {
      const result = await query(
        config,
        `
          SELECT
            COUNT(*)::INT AS total_incidents,
            COUNT(*) FILTER (WHERE status IN ('open', 'investigating'))::INT AS active_incidents,
            COUNT(*) FILTER (
              WHERE status IN ('open', 'investigating')
              AND severity IN ('critical', 'high')
            )::INT AS high_priority_active,
            MAX(detected_at) AS last_detected_at
          FROM incidents
          WHERE tenant_slug = $1
        `,
        [tenant]
      );

      const row = result?.rows?.[0] || {};
      const total = Number(row.total_incidents || 0);
      if (!total) {
        return {
          ...base,
          status: 'no_data',
          latencyMs: Date.now() - startedAt,
          message: 'No incidents are stored yet for this tenant.',
        };
      }

      const highPriorityActive = Number(row.high_priority_active || 0);
      return {
        ...base,
        status: highPriorityActive > 0 ? 'degraded' : 'operational',
        latencyMs: Date.now() - startedAt,
        evidence: {
          totalIncidents: total,
          activeIncidents: Number(row.active_incidents || 0),
          highPriorityActive,
          lastDetectedAt: row.last_detected_at ? new Date(row.last_detected_at).toISOString() : null,
        },
      };
    }

    if (appId === 'identity-guardian') {
      const result = await query(
        config,
        `
          SELECT
            COUNT(*)::INT AS total_users,
            COUNT(*) FILTER (WHERE is_active = TRUE)::INT AS active_users,
            MAX(last_login_at) AS last_login_at
          FROM users
          WHERE tenant_slug = $1
        `,
        [tenant]
      );

      const row = result?.rows?.[0] || {};
      const total = Number(row.total_users || 0);
      if (!total) {
        return {
          ...base,
          status: 'no_data',
          latencyMs: Date.now() - startedAt,
          message: 'No users found for this tenant.',
        };
      }

      return {
        ...base,
        status: 'operational',
        latencyMs: Date.now() - startedAt,
        evidence: {
          totalUsers: total,
          activeUsers: Number(row.active_users || 0),
          lastLoginAt: row.last_login_at ? new Date(row.last_login_at).toISOString() : null,
        },
      };
    }

    if (appId === 'resilience-hq') {
      const result = await query(
        config,
        `
          SELECT
            COUNT(*)::INT AS total_audit_logs,
            COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours')::INT AS last_24h,
            MAX(created_at) AS latest_event_at
          FROM audit_logs
          WHERE tenant_slug = $1
        `,
        [tenant]
      );

      const row = result?.rows?.[0] || {};
      const total = Number(row.total_audit_logs || 0);
      if (!total) {
        return {
          ...base,
          status: 'no_data',
          latencyMs: Date.now() - startedAt,
          message: 'No audit logs are available yet for this tenant.',
        };
      }

      return {
        ...base,
        status: 'operational',
        latencyMs: Date.now() - startedAt,
        evidence: {
          totalAuditLogs: total,
          last24h: Number(row.last_24h || 0),
          latestEventAt: row.latest_event_at ? new Date(row.latest_event_at).toISOString() : null,
        },
      };
    }

    return {
      ...base,
      status: 'unavailable',
      latencyMs: Date.now() - startedAt,
      message: 'Unknown application status target.',
    };
  } catch (error) {
    return {
      ...base,
      status: 'unavailable',
      latencyMs: Date.now() - startedAt,
      message: error instanceof Error ? error.message : 'Status query failed',
    };
  }
}

async function listPlatformAppsForRole(tenant, role) {
  const tenantSlug = sanitizeTenant(tenant || 'global');
  const effectiveRole = normalizeRole(role || 'executive_viewer');
  let products = [];
  let productsCatalogFailed = false;
  try {
    products = await listTenantProducts(config, tenantSlug, effectiveRole);
  } catch (error) {
    productsCatalogFailed = true;
    log('warn', 'platform.apps_catalog_query_failed', {
      tenant: tenantSlug,
      role: effectiveRole,
      error: error instanceof Error ? error.message : 'unknown catalog query failure',
    });
  }

  const apps = [];
  for (const product of products) {
    if (!product.visible || !product.active) {
      continue;
    }

    const moduleRuntime = getModuleByProductKey(product.productKey);
    if (!moduleRuntime) {
      continue;
    }

    const app = buildAppFromModule(moduleRuntime.descriptor);
    apps.push({
      ...app,
      tenant: tenantSlug,
      product: {
        productId: product.productId,
        productKey: product.productKey,
        roleMin: product.roleMin,
        effectiveEnabled: product.effectiveEnabled,
      },
      featureFlags: Array.isArray(product.featureGate?.flags) ? product.featureGate.flags : [],
    });
  }

  if (productsCatalogFailed) {
    return [];
  }

  return apps;
}

async function resolveAccessibleAppForContext(appId, tenant, role) {
  const normalizedAppId = String(appId || '').trim().toLowerCase();
  const apps = await listPlatformAppsForRole(tenant, role);
  return apps.find(app => app.id === normalizedAppId) || null;
}

async function meterUsage(context, session, tenant, productKey, actionKey, units = 1, meta = {}) {
  if (!config.databaseUrl) {
    return;
  }

  try {
    await recordUsageEvent(config, {
      tenant,
      userId: session?.user?.id || null,
      productKey,
      actionKey,
      units,
      meta: {
        requestId: context.requestId,
        method: context.method,
        path: context.path,
        ...meta,
      },
    });
  } catch (error) {
    log('warn', 'billing.usage_record_failed', {
      requestId: context.requestId,
      productKey,
      actionKey,
      error: error instanceof Error ? error.message : 'unknown usage recording failure',
    });
  }
}

function getMetricsAuthorizationStatus(context) {
  if (!config.metricsRequireAuth) {
    return { allowed: true };
  }

  if (!config.metricsAuthToken) {
    return {
      allowed: false,
      statusCode: 503,
      code: 'metrics_unavailable',
      message: 'Metrics auth token is not configured',
    };
  }

  const bearerToken = parseBearerToken(context.request.headers.authorization);
  const provided = Buffer.from(String(bearerToken || ''));
  const expected = Buffer.from(String(config.metricsAuthToken || ''));
  const isValid =
    provided.length > 0 &&
    provided.length === expected.length &&
    crypto.timingSafeEqual(provided, expected);

  if (!isValid) {
    return {
      allowed: false,
      statusCode: 401,
      code: 'auth_required',
      message: 'Metrics endpoint requires valid bearer token',
    };
  }

  return { allowed: true };
}

function enforceOriginPolicy(context, response, baseExtraHeaders) {
  if (!config.enforceOriginValidation) {
    return true;
  }

  if (!context.origin) {
    return true;
  }

  if (isOriginAllowed(context.origin, config.allowedOrigins)) {
    return true;
  }

  sendError(
    response,
    context,
    config,
    403,
    'origin_not_allowed',
    'Request origin is not allowed',
    {
      origin: context.origin,
    },
    baseExtraHeaders
  );

  return false;
}

function sendRouteNotFound(context, response, baseExtraHeaders) {
  sendError(
    response,
    context,
    config,
    404,
    'not_found',
    'Route not found',
    {
      method: context.method,
      path: context.path,
    },
    baseExtraHeaders
  );
}

function sendAuthRequired(
  response,
  context,
  baseExtraHeaders,
  message = 'Missing or invalid authenticated session'
) {
  sendError(
    response,
    context,
    config,
    401,
    'auth_required',
    message,
    {
      loginPath: '/v1/auth/login',
    },
    baseExtraHeaders
  );
}

function isSensitiveAuthRoute(path) {
  return (
    path === '/v1/auth/login' ||
    path === '/v1/auth/register' ||
    path === '/v1/auth/token' ||
    path === '/v1/auth/password/forgot' ||
    path === '/v1/auth/password/reset'
  );
}

function isReportRoute(path) {
  return path === '/v1/reports/upload' || path === '/v1/reports' || /^\/v1\/reports\/[0-9]+/.test(path);
}

async function requireSession(context, response, baseExtraHeaders, message) {
  return authGuard.requireAuth(context, response, baseExtraHeaders, message);
}

async function buildReadinessPayload() {
  const validation = validateRuntimeConfig(config);
  const dependencies = await buildDependencyStatus();
  const responseDependencies = sanitizeDependencyStatusForResponse(dependencies);
  const dependencyErrors = [];

  const databaseRequired = isDependencyRequired('database');
  const redisRequired = isDependencyRequired('redis');
  const storageRequired = isDependencyRequired('storage');

  if (databaseRequired && dependencies.database.status !== 'healthy') {
    if (!dependencies.database.configured) {
      dependencyErrors.push('Database is required but DATABASE_URL is not configured.');
    } else {
      dependencyErrors.push('Database connectivity check failed.');
    }
  }

  if (storageRequired && dependencies.storage.status !== 'healthy') {
    dependencyErrors.push('Storage connectivity check failed.');
  }

  if (redisRequired && dependencies.redis.status !== 'healthy') {
    if (!dependencies.redis.configured) {
      dependencyErrors.push('Redis is required but REDIS_URL is not configured.');
    } else {
      dependencyErrors.push('Redis connectivity check failed.');
    }
  }

  const dependencyWarnings = [];
  if (!redisRequired && dependencies.redis.status !== 'healthy') {
    dependencyWarnings.push('Redis is running in degraded mode. Configure REDIS_URL for distributed controls.');
  }
  if (!databaseRequired && dependencies.database.status !== 'healthy') {
    dependencyWarnings.push('Database is running in degraded mode. Configure DATABASE_URL for full persistence.');
  }

  const ready = validation.ok && dependencyErrors.length === 0;

  return {
    status: ready ? 'ready' : 'not_ready',
    ready,
    mode: config.environment,
    strictDependencies: Boolean(config.strictDependencies),
    environment: config.environment,
    checkedAt: new Date().toISOString(),
    errors: [...validation.errors, ...dependencyErrors],
    warnings: [...validation.warnings, ...dependencyWarnings],
    dbConfigured: Boolean(dependencies.database.configured),
    dbConnected: dependencies.database.status === 'healthy',
    redisConfigured: Boolean(dependencies.redis.configured),
    redisConnected: dependencies.redis.status === 'healthy',
    storageConfigured: Boolean(dependencies.storage.configured),
    storageConnected: dependencies.storage.status === 'healthy',
    dependencies: responseDependencies,
  };
}

function buildPublicRuntimeConfig() {
  const apiBaseUrl = config.publicApiBaseUrl;

  return {
    apiBaseUrl,
    API_BASE_URL: apiBaseUrl,
    authMode: config.authMode,
    demoAuthEnabled: Boolean(config.allowInsecureDemoAuth && config.authMode === 'demo'),
    authTransport: 'cookie',
    csrfEnabled: Boolean(config.csrfEnabled),
    csrfHeaderName: 'x-csrf-token',
    csrfCookieName: config.csrfCookieName,
    authLoginPath: config.publicAuthLoginPath,
    authTokenPath: config.publicAuthTokenPath,
    authMePath: config.publicAuthMePath,
    authLogoutPath: config.publicAuthLogoutPath,
    tenantsPath: '/v1/tenants',
    productsPath: '/v1/products',
    tenantProductsPathTemplate: '/v1/tenants/{tenant}/products',
    tenantFeatureFlagsPathTemplate: '/v1/tenants/{tenant}/feature-flags',
    modulesPath: '/v1/modules',
    billingUsagePath: '/v1/billing/usage',
    billingCreditsPath: '/v1/billing/credits',
    threatSummaryPath: config.publicThreatSummaryPath,
    threatIncidentsPath: config.publicThreatIncidentsPath,
    systemHealthPath: config.publicSystemHealthPath,
    platformAppsPath: config.publicPlatformAppsPath,
    reportsPath: config.publicReportsPath,
    reportUploadPath: config.publicReportUploadPath,
    reportDownloadPathTemplate: config.publicReportDownloadPathTemplate,
    requireAuthForThreatEndpoints: config.requireAuthForThreatEndpoints,
    requireAuthForPlatformEndpoints: true,
    strictDependencies: Boolean(config.strictDependencies),
    analyticsEnabled: config.publicAnalyticsEnabled,
    enterpriseMode: Boolean(config.publicEnterpriseMode),
    publicBackendProbesEnabled: Boolean(config.publicBackendProbesEnabled),
    environment: config.environment,
    appVersion: config.appVersion,
    region: config.region,
  };
}

async function runReportRetentionCycle() {
  if (!config.databaseUrl || config.reportRetentionDays < 1) {
    return;
  }

  const batchSize = Math.max(1, config.reportRetentionBatchSize);
  const staleReports = await query(
    config,
    `
      SELECT id, tenant_slug, storage_path
      FROM reports
      WHERE report_date < (CURRENT_DATE - ($1::INT * INTERVAL '1 day'))
      ORDER BY report_date ASC, id ASC
      LIMIT $2
    `,
    [config.reportRetentionDays, batchSize]
  );

  const rows = staleReports?.rows || [];
  if (!rows.length) {
    return;
  }

  let purged = 0;
  for (const row of rows) {
    const reportId = Number(row.id);
    const tenantSlug = sanitizeTenant(row.tenant_slug);
    const storagePath = row.storage_path || null;

    if (storagePath && typeof storageAdapter.deleteFile === 'function') {
      try {
        await storageAdapter.deleteFile({ storagePath });
      } catch (error) {
        log('warn', 'report.retention_storage_delete_failed', {
          reportId,
          tenant: tenantSlug,
          storagePath,
          error: error instanceof Error ? error.message : 'unknown storage delete failure',
        });
      }
    }

    await query(
      config,
      `
        DELETE FROM reports
        WHERE id = $1 AND tenant_slug = $2
      `,
      [reportId, tenantSlug]
    );

    await appendAuditLog(config, {
      tenantSlug,
      action: 'report.retention_deleted',
      targetType: 'report',
      targetId: String(reportId),
      payload: {
        retentionDays: config.reportRetentionDays,
      },
    });

    purged += 1;
  }

  if (purged > 0) {
    log('info', 'report.retention_cycle_completed', {
      purged,
      retentionDays: config.reportRetentionDays,
      batchSize,
    });
  }
}

async function readRequestBody(request, maxBytes = 1_048_576) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let done = false;

    const finalize = (error, value) => {
      if (done) {
        return;
      }

      done = true;
      if (error) {
        reject(error);
        return;
      }

      resolve(value);
    };

    request.on('error', error => finalize(error));
    request.on('aborted', () => finalize(new Error('request_aborted')));
    request.on('data', chunk => {
      size += chunk.length;
      if (size > maxBytes) {
        finalize(new Error('payload_too_large'));
        request.destroy();
        return;
      }

      chunks.push(chunk);
    });
    request.on('end', () => {
      const body = chunks.length ? Buffer.concat(chunks).toString('utf8') : '';
      finalize(null, body);
    });
  });
}

async function parseJsonBody(context, response, baseExtraHeaders, options = {}) {
  const allowEmpty = Boolean(options.allowEmpty);
  const maxBytes = Number(options.maxBytes) > 0 ? Number(options.maxBytes) : 1_048_576;

  // Enforce Content-Type: application/json to prevent CSRF via simple-request content types
  const contentType = String(context.request.headers['content-type'] || '').toLowerCase();
  if (!contentType.startsWith('application/json') && !allowEmpty) {
    sendError(
      response,
      context,
      config,
      415,
      'unsupported_content_type',
      'Content-Type must be application/json.',
      null,
      baseExtraHeaders
    );
    return null;
  }

  try {
    const rawBody = await readRequestBody(context.request, maxBytes);
    if (!rawBody.trim()) {
      if (allowEmpty) {
        return {};
      }

      sendError(
        response,
        context,
        config,
        400,
        'invalid_json_body',
        'Request body is required.',
        null,
        baseExtraHeaders
      );
      return null;
    }

    try {
      const parsed = JSON.parse(rawBody);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        sendError(
          response,
          context,
          config,
          400,
          'invalid_json_body',
          'JSON body must be an object.',
          null,
          baseExtraHeaders
        );
        return null;
      }

      if (!checkJsonDepth(parsed)) {
        sendError(
          response,
          context,
          config,
          400,
          'json_depth_exceeded',
          'JSON body nesting depth exceeds maximum allowed limit.',
          null,
          baseExtraHeaders
        );
        return null;
      }

      return parsed;
    } catch {
      sendError(
        response,
        context,
        config,
        400,
        'invalid_json_body',
        'Malformed JSON request body.',
        null,
        baseExtraHeaders
      );
      return null;
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : '';
    if (message === 'payload_too_large') {
      sendError(
        response,
        context,
        config,
        413,
        'payload_too_large',
        'Request body exceeds size limit.',
        {
          maxBytes,
        },
        baseExtraHeaders
      );
      return null;
    }

    sendError(
      response,
      context,
      config,
      400,
      'invalid_request_body',
      'Request body could not be read.',
      null,
      baseExtraHeaders
    );
    return null;
  }
}

function validateBodyShape(context, response, baseExtraHeaders, payload, schema) {
  const required = Array.isArray(schema?.required) ? schema.required : [];
  const optional = Array.isArray(schema?.optional) ? schema.optional : [];
  const allowed = new Set([...required, ...optional]);
  const keys = Object.keys(payload || {});
  const unknown = keys.filter(key => !allowed.has(key));

  if (unknown.length) {
    sendError(
      response,
      context,
      config,
      400,
      'unknown_request_fields',
      'Request body contains unknown fields.',
      {
        unknownFields: unknown,
      },
      baseExtraHeaders
    );
    return false;
  }

  const missing = required.filter(field => payload[field] === undefined);
  if (missing.length) {
    sendError(
      response,
      context,
      config,
      400,
      'missing_required_fields',
      'Request body is missing required fields.',
      {
        missingFields: missing,
      },
      baseExtraHeaders
    );
    return false;
  }

  return true;
}

function buildAuthIdentityRateKey(context, path, payload) {
  const tenant = sanitizeTenant(payload?.tenant || 'global');
  const email =
    typeof payload?.email === 'string' ? payload.email.trim().toLowerCase() : '';
  const refreshToken =
    typeof payload?.refreshToken === 'string' ? payload.refreshToken.trim() : '';
  const resetToken =
    typeof payload?.resetToken === 'string' ? payload.resetToken.trim() : '';

  let identity = '';
  if (email) {
    identity = `email:${email.slice(0, 256)}`;
  } else if (refreshToken) {
    identity = `refresh:${hashAuthIdentity(refreshToken)}`;
  } else if (resetToken) {
    identity = `reset:${hashAuthIdentity(resetToken)}`;
  } else {
    identity = 'anonymous';
  }

  return `${context.ip}:auth_identity:${path}:${tenant}:${identity}`;
}

async function enforceAuthIdentityRateLimit(context, response, baseExtraHeaders, path, payload) {
  const rateState = await authIdentityRateLimiter.take(buildAuthIdentityRateKey(context, path, payload));
  if (rateState.allowed) {
    return true;
  }

  sendError(
    response,
    context,
    config,
    429,
    'auth_identity_rate_limited',
    'Too many attempts for this account identity. Retry shortly.',
    {
      retryAfterSeconds: Math.max(1, Math.ceil((rateState.resetAt - Date.now()) / 1000)),
    },
    {
      ...baseExtraHeaders,
      'Retry-After': String(Math.max(1, Math.ceil((rateState.resetAt - Date.now()) / 1000))),
    }
  );
  return false;
}

function requireDatabaseConfigured(context, response, baseExtraHeaders) {
  if (config.databaseUrl) {
    return true;
  }

  sendError(
    response,
    context,
    config,
    503,
    'database_not_configured',
    'Database is not configured. Set DATABASE_URL and run migrations before using this endpoint.',
    null,
    baseExtraHeaders
  );
  return false;
}

function actorMetaFromContext(context, session, extra = {}) {
  const actor = session?.user || {};
  return {
    actorUserId: actor.id || null,
    actorEmail: actor.email || null,
    ipAddress: context.ip || null,
    userAgent: context.request.headers['user-agent'] || null,
    traceId: context.requestId,
    ...extra,
  };
}

function sanitizeJsonObject(input, depth = 0) {
  if (depth > 8) {
    return {};
  }

  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return {};
  }

  const blockedKeys = new Set(['__proto__', 'constructor', 'prototype']);
  const output = {};
  for (const [key, value] of Object.entries(input)) {
    if (blockedKeys.has(key)) {
      continue;
    }

    if (value && typeof value === 'object' && !Array.isArray(value)) {
      output[key] = sanitizeJsonObject(value, depth + 1);
      continue;
    }

    if (Array.isArray(value)) {
      output[key] = value
        .slice(0, 100)
        .map(item => (item && typeof item === 'object' ? sanitizeJsonObject(item, depth + 1) : item));
      continue;
    }

    output[key] = value;
  }

  return output;
}

function parseMetadataField(rawValue) {
  if (!rawValue) {
    return {};
  }

  try {
    const parsed = JSON.parse(String(rawValue));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return {};
    }
    return sanitizeJsonObject(parsed);
  } catch {
    return {};
  }
}

function escapeContentDispositionFileName(fileName) {
  return String(fileName || 'report.bin')
    .replace(/[\r\n"]/g, '')
    .replace(/[^\x20-\x7E]/g, '_')
    .slice(0, 200);
}

function hasRole(session, requiredRole) {
  if (!session || !session.user) {
    return false;
  }

  const role = normalizeRole(session.user.role);
  return hasRoleAccess(role, requiredRole);
}

function requireRole(session, requiredRole, response, context, baseExtraHeaders, message) {
  return authGuard.requireRole(
    session,
    requiredRole,
    context,
    response,
    baseExtraHeaders,
    message
  );
}

async function isTenantFeatureEnabled(tenant, flagKey) {
  const tenantSlug = sanitizeTenant(tenant || 'global');
  const normalizedFlag = String(flagKey || '').trim();
  if (!normalizedFlag) {
    return false;
  }

  const flags = await listTenantFeatureFlags(config, tenantSlug);
  const match = flags.find(item => item.flagKey === normalizedFlag);
  return Boolean(match?.enabled);
}

async function requireFeatureFlagEnabled(
  context,
  response,
  baseExtraHeaders,
  tenant,
  flagKey,
  options = {}
) {
  const enabled = await isTenantFeatureEnabled(tenant, flagKey);
  if (enabled) {
    return true;
  }

  sendError(
    response,
    context,
    config,
    403,
    'feature_disabled',
    options.message || `Feature flag ${flagKey} is disabled for this tenant.`,
    {
      tenant: sanitizeTenant(tenant || 'global'),
      flagKey,
    },
    baseExtraHeaders
  );
  return false;
}

async function requireProductAccess(
  context,
  response,
  baseExtraHeaders,
  session,
  tenant,
  productKey,
  requiredRole,
  options = {}
) {
  const tenantSlug = sanitizeTenant(tenant || 'global');
  const role = normalizeRole(session?.user?.role || 'executive_viewer');
  const product = await getTenantProduct(config, tenantSlug, productKey, role);
  if (!product) {
    sendError(
      response,
      context,
      config,
      403,
      'product_disabled',
      options.disabledMessage || 'Product is disabled for this tenant.',
      {
        tenant: tenantSlug,
        productKey,
      },
      baseExtraHeaders
    );
    return null;
  }

  if (product.planAllowed === false) {
    sendError(
      response,
      context,
      config,
      403,
      'plan_upgrade_required',
      options.planMessage || `Module "${product.name || product.productKey}" is not included in the ${product.planLabel || product.planTier || 'current'} plan.`,
      {
        tenant: tenantSlug,
        productKey: product.productKey,
        currentTier: product.planTier || 'free',
      },
      baseExtraHeaders
    );
    return null;
  }

  if (!product.effectiveEnabled) {
    sendError(
      response,
      context,
      config,
      403,
      'product_disabled',
      options.disabledMessage || 'Product is disabled for this tenant.',
      {
        tenant: tenantSlug,
        productKey,
      },
      baseExtraHeaders
    );
    return null;
  }

  const roleForAction = requiredRole || product.roleMin || 'executive_viewer';
  if (!hasRoleAccess(role, roleForAction)) {
    sendError(
      response,
      context,
      config,
      403,
      'role_scope_denied',
      options.roleMessage || 'Role is not permitted for this action.',
      {
        role,
        requiredRole: roleForAction,
        productKey: product.productKey,
      },
      baseExtraHeaders
    );
    return null;
  }

  try {
    const allowance = await assertUsageAllowed(config, tenantSlug, 1);
    return {
      ...product,
      quotaEnforced: allowance.quotaEnforced,
      quotaRemainingUnits: allowance.quotaRemainingUnits,
      quotaLimitUnits: allowance.quotaLimitUnits,
      quotaExhausted: allowance.exhausted,
      quotaPeriodEndsAt: allowance.periodEndsAt,
    };
  } catch (error) {
    handleServiceFailure(error, response, context, baseExtraHeaders);
    return null;
  }
}

function normalizeUploadFileName(fileName, fallbackPrefix) {
  const safeBase = escapeContentDispositionFileName(fileName || '');
  if (safeBase && safeBase !== 'report.bin') {
    return safeBase;
  }
  const timestamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
  return `${fallbackPrefix || 'file'}-${timestamp}.bin`;
}

function handleServiceFailure(error, response, context, baseExtraHeaders) {
  if (error instanceof ServiceError) {
    sendError(
      response,
      context,
      config,
      error.statusCode,
      error.code,
      error.message,
      error.details || null,
      baseExtraHeaders
    );
    return;
  }

  const statusCode = Number(error?.statusCode);
  if (Number.isInteger(statusCode) && statusCode >= 400 && statusCode < 600) {
    sendError(
      response,
      context,
      config,
      statusCode,
      String(error?.code || 'service_error'),
      String(error?.message || 'Request failed'),
      error?.details || null,
      baseExtraHeaders
    );
    return;
  }

  throw error;
}

const phase3ModuleRouteHandlers = [];

function registerPhase3ModuleHandler(handler) {
  if (typeof handler === 'function') {
    phase3ModuleRouteHandlers.push(handler);
  }
}

function buildPhase3RouteDependencies() {
  return {
    config,
    log,
    pipeline,
    aiRateLimiter,
    sendJson,
    sendError,
    sendMethodNotAllowed,
    requireDatabaseConfigured,
    requireSession,
    resolveTenantForRequest,
    requireProductAccess,
    requireFeatureFlagEnabled,
    isTenantFeatureEnabled,
    parseMultipartForm,
    sniffMimeType,
    enforceUploadPolicy,
    allowedAwsLogMimeTypes,
    allowedSiemLogMimeTypes,
    allowedComplianceEvidenceMimeTypes,
    parseAwsLogJsonBuffer,
    parseSiemLogJsonBuffer,
    probeLlmRuntime,
    ingestAwsLogRecords,
    actorMetaFromContext,
    meterUsage,
    appendAuditLog,
    handleServiceFailure,
    parseJsonBody,
    validateBodyShape,
    toSafeInteger,
    listRiskFindings,
    getRiskPortfolioSummary,
    generateRiskExplanation,
    buildLocalMitigationSuggestions,
    generateRiskReportPdf,
    storageAdapter,
    normalizeUploadFileName,
    createRiskReportRecord,
    getRiskReportRecord,
    updateRiskFindingTreatment,
    escapeContentDispositionFileName,
    listSoc2Controls,
    listSoc2Status,
    computeComplianceGap,
    listSoc2Evidence,
    upsertSoc2Status,
    computeSha256Hex,
    createSoc2EvidenceRecord,
    generatePolicyDraft,
    createPolicyRecord,
    buildAuditPackage,
    listPolicies,
    getPolicyRecord,
    updatePolicyStatus,
    createAuditPackageRecord,
    getAuditPackageRecord,
    syncCveFeed,
    listTenantCveFeed,
    getCveRecord,
    summarizeCveWithAi,
    saveCveSummary,
    getThreatDashboard,
    // MITRE ATT&CK
    listMitreTechniques,
    listIncidentMitreMappings,
    addIncidentMitreMapping,
    removeIncidentMitreMapping,
    getMitreHeatmap,
    // Playbooks
    listPlaybooks,
    getPlaybookWithSteps,
    createPlaybook,
    updatePlaybook,
    addPlaybookStep,
    executePlaybook,
    listPlaybookExecutions,
    updatePlaybookStepResult,
    getExecutionStepResults,
    // SIEM
    listSiemAlerts,
    ingestSiemAlert,
    correlateAlertToIncident,
    getSiemAlertStats,
    updateAlertStatus,
    assignAlert,
    escalateAlertToIncident,
    bulkUpdateAlertStatus,
    getAlertSlaMetrics,
    getAlertTriageSuggestion,
    getAttackMapData,
    updateAlertNotes,
    listCorrelationRules,
    createCorrelationRule,
    updateCorrelationRule,
    // Threat Hunting
    listThreatHuntQueries,
    createThreatHuntQuery,
    updateThreatHuntQuery,
    deleteThreatHuntQuery,
    executeThreatHuntQuery,
    // Multi-Framework Compliance
    listComplianceFrameworks,
    getComplianceFramework,
    listFrameworkControls,
    listFrameworkControlStatus,
    upsertFrameworkControlStatus,
    computeFrameworkGap,
    getComplianceSummary,
    // Real-time Notifications
    notifyIncidentCreated,
    notifyIncidentUpdated,
    notifyAlertIngested,
    notifyComplianceStatusChanged,
    notifyPlaybookExecuted,
    notifyAuditEvent,
    // Connector Sync
    fetchConnectorIncidents,
    // Correlation Engine
    runCorrelationEngine,
    // Analyst List
    listTenantAnalysts,
  };
}

function registerPhase3ModuleRoutes() {
  const routerContext = {
    register: registerPhase3ModuleHandler,
    deps: buildPhase3RouteDependencies(),
  };

  registerRiskCopilotRoutes(routerContext);
  registerComplianceRoutes(routerContext);
  registerThreatIntelRoutes(routerContext);
}

registerPhase3ModuleRoutes();

// ── Core route modules (auth, system, crud) ──────────────────────────────
const coreRouteHandlers = [];

function registerCoreRouteHandler(handler) {
  if (typeof handler === 'function') {
    coreRouteHandlers.push(handler);
  }
}

function buildCoreRouteDependencies() {
  return {
    ...buildPhase3RouteDependencies(),
    // HTTP utilities
    sendNoContent,
    sendRedirect,
    sendText,
    baseHeaders,
    // Auth / session
    sessionStore,
    authGuard,
    getSessionFromContext,
    getAccessTokenFromContext,
    getRefreshTokenFromContext,
    attachAuthCookies,
    attachClearAuthCookies,
    parseRequestCookies,
    parseCookieHeader,
    enforceAuthIdentityRateLimit,
    sendAuthRequired,
    // Role / tenant
    normalizeRole,
    hasRoleAccess,
    sanitizeTenant,
    sanitizeRedirectPath,
    hasRole,
    requireRole,
    resolveRequestedRoleScope,
    // Auth service
    loginWithPassword,
    registerUser,
    rotateRefreshToken,
    revokeRefreshToken,
    requestPasswordReset,
    resetPassword,
    findOrCreateOAuthUser,
    ServiceError,
    // OAuth
    isValidOAuthProvider: isValidOAuthProvider,
    generateOAuthState,
    generatePkceChallenge,
    supportsPkce,
    buildAuthorizationUrl,
    exchangeCodeForTokens,
    fetchUserProfile,
    // Token revocation
    hashAccessToken,
    parseJwtExpiryMs,
    rememberRevokedAccessTokenHash,
    persistRevokedAccessToken,
    isRevokedAccessToken,
    // Health / metrics / system
    buildHealthPayload,
    buildReadinessPayload,
    buildPublicRuntimeConfig,
    buildMetricsPayload,
    buildPrometheusMetrics,
    getMetricsAuthorizationStatus,
    buildOpenApiSpec,
    // CRUD
    buildThreatSummary,
    buildThreatIncidents,
    getConnectorsStatus,
    listIncidents,
    createIncident,
    updateIncident,
    listIncidentTimeline,
    listIocs,
    createIoc,
    linkIocToIncident,
    createServiceRequest,
    updateServiceRequest,
    listServiceRequestComments,
    normalizeIdempotencyKey,
    findReportByIdempotencyKey,
    findReportByChecksum,
    createReport,
    getReportById,
    logReportDownload,
    allowedReportMimeTypes,
    parseMetadataField,
    buildAppStatus,
    listPlatformAppsForRole,
    resolveAccessibleAppForContext,
    listTenants,
    listUsers,
    listServiceRequests,
    listReports,
    listAuditLogs,
    listProducts,
    listTenantProducts,
    setTenantProductState,
    listTenantFeatureFlags,
    setTenantFeatureFlag,
    listUsageEvents,
    getCredits,
    getTenantPlan,
    setPlanForTenant,
    PLAN_FEATURES,
    assertFeatureAllowed,
    isTenantFeatureEnabled,
    listRegisteredModules,
    addSseClient,
    getRecentEventsForTenant,
    getConnectedClientCount,
    getTotalConnectedClients,
    notifyIncidentUpdated,
    // Database query for raw SQL access
    dbQuery: query,
  };
}

function registerCoreRoutes() {
  const routerContext = {
    register: registerCoreRouteHandler,
    deps: buildCoreRouteDependencies(),
  };

  registerAuthRoutes(routerContext);
  registerSystemRoutes(routerContext);
  registerAdminRoutes(routerContext);
  registerThreatRoutes(routerContext);
  registerReportRoutes(routerContext);
  registerBillingCrudRoutes(routerContext);
  registerGovernanceRoutes(routerContext);
  registerNotificationRoutes(routerContext);
  registerPlatformRoutes(routerContext);
}

registerCoreRoutes();

async function dispatchCoreRoutes(context, response, baseExtraHeaders) {
  for (const handler of coreRouteHandlers) {
    const handled = await handler({ context, response, baseExtraHeaders });
    if (handled) {
      return true;
    }
  }
  return false;
}

// Paths that invoke LLM calls and need stricter rate limiting
const AI_LLM_PATHS = new Set([
  '/v1/risk/score/compute',
  '/v1/risk/report/generate',
  '/v1/compliance/gap-analysis',
  '/v1/compliance/policy/generate',
  '/v1/threat-intel/cve/summarize',
]);

async function dispatchPhase3ModuleRoutes(context, response, baseExtraHeaders) {
  // Apply AI-specific rate limiting for LLM-invoking endpoints
  if (AI_LLM_PATHS.has(context.path) && context.method === 'POST') {
    const clientKey = context.clientIp || 'unknown';
    const aiResult = await aiRateLimiter.take(`ai:${clientKey}`);
    if (!aiResult.allowed) {
      sendError(response, context, config, 429, 'ai_rate_limit_exceeded',
        'AI request rate limit exceeded. Please wait before making another AI request.',
        baseExtraHeaders);
      return true;
    }
  }

  for (const handler of phase3ModuleRouteHandlers) {
    // Route handlers are registered from module route files.
    // eslint-disable-next-line no-await-in-loop
    const handled = await handler({ context, response, baseExtraHeaders });
    if (handled) {
      return true;
    }
  }

  return false;
}

async function handleRequest(context, response) {
  // Accept both direct backend routes (/v1/*, /config) and proxied frontend routes (/api/v1/*, /api/config).
  const normalizedPath =
    context.path === '/api'
      ? '/'
      : context.path.startsWith('/api/')
        ? context.path.slice(4) || '/'
        : context.path;

  if (normalizedPath !== context.path) {
    context = {
      ...context,
      path: normalizedPath,
    };
  }

  const rateIdentity = await resolveRateIdentity(context);
  const rateKey = `${context.ip}:${rateIdentity}:${context.path}:${context.method}`;
  const rateState = await rateLimiter.take(rateKey);
  const baseExtraHeaders = nextHeaders(context, rateState);

  response.on('finish', () => {
    trackResponse(response.statusCode || 0);

    log('info', 'request.complete', {
      requestId: context.requestId,
      method: context.method,
      path: context.path,
      statusCode: response.statusCode,
      durationMs: Date.now() - context.startAt,
      ip: context.ip,
      userAgent: context.request.headers['user-agent'] || 'unknown',
    });
  });

  if (!enforceOriginPolicy(context, response, baseExtraHeaders)) {
    return;
  }

  if (!rateState.allowed) {
    sendError(
      response,
      context,
      config,
      429,
      'rate_limited',
      'Rate limit exceeded',
      {
        retryAfterSeconds: Math.max(1, Math.ceil((rateState.resetAt - Date.now()) / 1000)),
      },
      {
        ...baseExtraHeaders,
        'Retry-After': String(Math.max(1, Math.ceil((rateState.resetAt - Date.now()) / 1000))),
      }
    );
    return;
  }

  if (context.method === 'OPTIONS') {
    sendNoContent(response, context, config, baseExtraHeaders);
    return;
  }

  if (!enforceCsrfProtection(context, response, baseExtraHeaders)) {
    return;
  }

  if (context.method === 'POST' && isSensitiveAuthRoute(context.path)) {
    const authRateState = await authRateLimiter.take(
      `${context.ip}:${rateIdentity}:auth:${context.path}`
    );
    if (!authRateState.allowed) {
      sendError(
        response,
        context,
        config,
        429,
        'auth_rate_limited',
        'Too many authentication attempts. Retry shortly.',
        {
          retryAfterSeconds: Math.max(1, Math.ceil((authRateState.resetAt - Date.now()) / 1000)),
        },
        {
          ...baseExtraHeaders,
          'Retry-After': String(Math.max(1, Math.ceil((authRateState.resetAt - Date.now()) / 1000))),
        }
      );
      return;
    }
  }

  if (isReportRoute(context.path)) {
    const reportRateState = await reportRateLimiter.take(
      `${context.ip}:${rateIdentity}:report:${context.path}:${context.method}`
    );
    if (!reportRateState.allowed) {
      sendError(
        response,
        context,
        config,
        429,
        'report_rate_limited',
        'Too many report operations. Retry shortly.',
        {
          retryAfterSeconds: Math.max(1, Math.ceil((reportRateState.resetAt - Date.now()) / 1000)),
        },
        {
          ...baseExtraHeaders,
          'Retry-After': String(Math.max(1, Math.ceil((reportRateState.resetAt - Date.now()) / 1000))),
        }
      );
      return;
    }
  }

  // ── Dispatch to extracted route modules ──────────────────────────────
  // OpenTelemetry span for request tracing
  const otelParentContext = extractContext(context.request);
  const { span: requestSpan } = startRequestSpan(otelParentContext, context.method, context.path);

  try {
    // Core routes: auth, system, crud
    const coreHandled = await dispatchCoreRoutes(context, response, baseExtraHeaders);
    if (coreHandled) {
      if (requestSpan) endRequestSpan(requestSpan, response.statusCode || 200);
      return;
    }

    // Phase3 module routes: risk-copilot, compliance-engine, threat-intel
    const phase3Handled = await dispatchPhase3ModuleRoutes(context, response, baseExtraHeaders);
    if (phase3Handled) {
      if (requestSpan) endRequestSpan(requestSpan, response.statusCode || 200);
      return;
    }

    sendRouteNotFound(context, response, baseExtraHeaders);
    if (requestSpan) endRequestSpan(requestSpan, 404);
  } catch (routeError) {
    if (requestSpan) endRequestSpan(requestSpan, 500, routeError instanceof Error ? routeError.message : 'unknown');
    throw routeError;
  }

}

function createServer() {
  return http.createServer((request, response) => {
    const context = toRequestContext(request, { trustProxy: config.trustProxy });
    metrics.inFlightRequests += 1;

    let finalized = false;
    const finalizeInFlight = () => {
      if (finalized) {
        return;
      }

      finalized = true;
      metrics.inFlightRequests = Math.max(0, metrics.inFlightRequests - 1);
    };

    response.on('finish', finalizeInFlight);
    response.on('close', finalizeInFlight);

    if (metrics.inFlightRequests > config.maxConcurrentRequests) {
      sendError(
        response,
        context,
        config,
        503,
        'server_overloaded',
        'Server is currently overloaded, retry shortly',
        {
          maxConcurrentRequests: config.maxConcurrentRequests,
        },
        {
          'Retry-After': '1',
        }
      );

      trackResponse(503);
      log('warn', 'request.overload_rejected', {
        requestId: context.requestId,
        path: context.path,
        method: context.method,
        inFlightRequests: metrics.inFlightRequests,
        maxConcurrentRequests: config.maxConcurrentRequests,
      });
      return;
    }

    Promise.resolve(handleRequest(context, response)).catch(error => {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';

      if (response.writableEnded || response.headersSent) {
        // Benign client-side aborts can surface after a streamed response has already started.
        // Avoid noisy false-positive error logs and never attempt to write a second response.
        if (errorMessage !== 'Premature close') {
          log('warn', 'request.aborted_after_headers', {
            requestId: context.requestId,
            error: errorMessage,
          });
        }
        return;
      }

      log('error', 'request.failure', {
        requestId: context.requestId,
        error: errorMessage,
      });

      sendError(
        response,
        context,
        config,
        500,
        'internal_error',
        'Unexpected backend error'
      );
    });
  });
}

async function startServer() {
  // P0-1: Block startup if critical production config is missing
  enforceProductionStartupGuard(config);

  const server = createServer();
  const validation = validateRuntimeConfig(config);

  const cleanupTimer = setInterval(() => {
    sessionStore.cleanup();
    rateLimiter.cleanup();
    authRateLimiter.cleanup();
    authIdentityRateLimiter.cleanup();
    reportRateLimiter.cleanup();
    purgeExpiredRevokedAccessTokens().catch(error => {
      log('warn', 'auth.revoked_access_token_cleanup_failed', {
        error: error instanceof Error ? error.message : 'unknown revoked token cleanup failure',
      });
    });
  }, 60_000);
  const retentionTimer = setInterval(() => {
    runReportRetentionCycle().catch(error => {
      log('warn', 'report.retention_cycle_failed', {
        error: error instanceof Error ? error.message : 'unknown retention failure',
      });
    });
  }, config.reportRetentionCleanupIntervalMs);

  cleanupTimer.unref();
  retentionTimer.unref();

  if (typeof server.requestTimeout === 'number') {
    server.requestTimeout = config.requestTimeoutMs;
  }
  if (typeof server.headersTimeout === 'number') {
    server.headersTimeout = config.headersTimeoutMs;
  }
  if (typeof server.keepAliveTimeout === 'number') {
    server.keepAliveTimeout = config.keepAliveTimeoutMs;
  }

  for (const warning of validation.warnings) {
    log('warn', 'config.warning', { warning });
  }

  if (!validation.ok) {
    log('error', 'config.invalid', {
      environment: config.environment,
      errors: validation.errors,
    });
    process.exit(1);
    return server;
  }

  await assertProductionRedisReady();

  if (config.dbAutoMigrate) {
    const maxMigrationAttempts = config.environment === 'production' ? 5 : 2;
    let migrationSuccess = false;
    for (let attempt = 1; attempt <= maxMigrationAttempts; attempt++) {
      try {
        await runMigrations(config, log);
        migrationSuccess = true;
        break;
      } catch (error) {
        log('warn', 'database.migration_attempt_failed', {
          attempt,
          maxAttempts: maxMigrationAttempts,
          error: error instanceof Error ? error.message : 'unknown migration failure',
        });
        if (attempt < maxMigrationAttempts) {
          await new Promise(resolve => setTimeout(resolve, 2000));
        }
      }
    }
    if (!migrationSuccess) {
      log('error', 'database.migration_failed', {
        attempts: maxMigrationAttempts,
      });
      process.exit(1);
      return server;
    }
  }

  if (config.databaseUrl) {
    try {
      await bootstrapRevokedAccessTokensFromDatabase();
    } catch (error) {
      log('warn', 'auth.revoked_access_token_bootstrap_failed', {
        error: error instanceof Error ? error.message : 'unknown revoked token bootstrap failure',
      });
    }

    try {
      await runReportRetentionCycle();
    } catch (error) {
      log('warn', 'report.retention_bootstrap_failed', {
        error: error instanceof Error ? error.message : 'unknown retention bootstrap failure',
      });
    }
  }

  await initRedisSubscriber(config, log);

  server.on('error', error => {
    const code = error && typeof error === 'object' && 'code' in error ? error.code : 'UNKNOWN';
    const message =
      code === 'EADDRINUSE'
        ? `Port ${config.port} is already in use`
        : error instanceof Error
          ? error.message
          : 'Unknown server startup error';

    log('error', 'backend.listen_failed', {
      host: config.host,
      port: config.port,
      code,
      message,
    });

    process.exit(1);
  });

  server.listen(config.port, config.host, () => {
    log('info', 'backend.started', {
      host: config.host,
      port: config.port,
      environment: config.environment,
      version: config.appVersion,
    });
  });

  function shutdown(signal) {
    log('info', 'backend.shutdown', { signal });
    clearInterval(cleanupTimer);
    clearInterval(retentionTimer);

    Promise.all([
      closeNotificationBus().catch(error => {
        log('warn', 'notification_bus.close_failed', {
          error: error instanceof Error ? error.message : 'unknown close failure',
        });
      }),
      closeDatabase().catch(error => {
        log('warn', 'database.close_failed', {
          error: error instanceof Error ? error.message : 'unknown close failure',
        });
      }),
      closeRedisClient().catch(error => {
        log('warn', 'redis.close_failed', {
          error: error instanceof Error ? error.message : 'unknown redis close failure',
        });
      }),
    ]).finally(() => {
      server.close(() => process.exit(0));
    });
    setTimeout(() => process.exit(1), 8_000).unref();
  }

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));

  process.on('uncaughtException', (error) => {
    log('error', 'process.uncaught_exception', {
      error: error instanceof Error ? error.message : 'unknown',
      stack: error instanceof Error ? error.stack : undefined,
    });
    shutdown('uncaughtException');
  });

  process.on('unhandledRejection', (reason) => {
    log('error', 'process.unhandled_rejection', {
      error: reason instanceof Error ? reason.message : String(reason || 'unknown'),
      stack: reason instanceof Error ? reason.stack : undefined,
    });
  });

  return server;
}

module.exports = {
  createServer,
  startServer,
};
