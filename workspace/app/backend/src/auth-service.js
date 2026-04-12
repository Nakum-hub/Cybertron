const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');

const { query, withClient } = require('./database');
const { normalizeRole, hasRoleAccess } = require('./platform-registry');
const { sanitizeTenant } = require('./validators');
const { appendAuditLog } = require('./audit-log');
const { isDisposableEmail } = require('./disposable-domains');

class ServiceError extends Error {
  constructor(statusCode, code, message, details = null) {
    super(message);
    this.name = 'ServiceError';
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
  }
}

function normalizeEmail(value) {
  if (typeof value !== 'string') {
    return '';
  }

  return value.trim().toLowerCase();
}

const RESERVED_PUBLIC_WORKSPACE_SLUGS = new Set(['global']);

function normalizePublicWorkspaceSlug(rawTenant, options = {}) {
  const requireExplicit = Boolean(options.requireExplicit);
  const allowReserved = Boolean(options.allowReserved);
  const rawValue = typeof rawTenant === 'string' ? rawTenant.trim() : '';

  if (requireExplicit && !rawValue) {
    throw new ServiceError(
      400,
      'workspace_slug_required',
      'Workspace slug is required for this authentication flow.'
    );
  }

  const tenantSlug = sanitizeTenant(rawValue || 'global');
  if (!allowReserved && RESERVED_PUBLIC_WORKSPACE_SLUGS.has(tenantSlug)) {
    throw new ServiceError(
      403,
      'reserved_workspace_slug',
      'This workspace slug is reserved for internal operations. Choose a different workspace slug.',
      {
        tenant: tenantSlug,
      }
    );
  }

  return tenantSlug;
}

function normalizeOAuthProvider(value) {
  const normalized = String(value || '').toLowerCase().trim();
  if (!/^[a-z0-9_-]{2,32}$/.test(normalized)) {
    throw new ServiceError(400, 'invalid_oauth_provider', 'OAuth provider is invalid.');
  }
  return normalized;
}

function normalizeOAuthProviderSubject(value) {
  const normalized = String(value || '').trim();
  if (!normalized || normalized.length > 191) {
    throw new ServiceError(400, 'invalid_oauth_subject', 'OAuth provider subject is invalid.');
  }
  return normalized;
}

function normalizeOptionalBoolean(value) {
  if (value === undefined || value === null) {
    return null;
  }
  if (typeof value === 'boolean') {
    return value;
  }
  return null;
}

function normalizePublicFingerprint(value) {
  const normalized = String(value || '').trim();
  if (!normalized) {
    return null;
  }

  if (normalized.length < 16 || normalized.length > 191) {
    return null;
  }

  if (!/^[a-z0-9._:-]+$/i.test(normalized)) {
    return null;
  }

  return normalized;
}

function isLoopbackAddress(value) {
  const normalized = String(value || '').trim().toLowerCase();
  if (!normalized) {
    return true;
  }

  return (
    normalized === '127.0.0.1' ||
    normalized === '::1' ||
    normalized === '::ffff:127.0.0.1' ||
    normalized === 'localhost'
  );
}

function hashWorkspaceBootstrapMarker(config, namespace, value) {
  const secret = String(config.jwtSecret || 'cybertron-workspace-bootstrap-control');
  return crypto
    .createHmac('sha256', secret)
    .update(`${namespace}:${String(value || '').trim()}`)
    .digest('hex');
}

function buildWorkspaceBootstrapRetryAfterSeconds(rows, windowMs) {
  const firstCreatedAt = rows?.[0]?.created_at ? new Date(rows[0].created_at).getTime() : 0;
  if (!firstCreatedAt || !Number.isFinite(firstCreatedAt)) {
    return null;
  }

  const remainingMs = Math.max(0, firstCreatedAt + windowMs - Date.now());
  return Math.max(1, Math.ceil(remainingMs / 1000));
}

function toBase64UrlJson(input) {
  return Buffer.from(JSON.stringify(input)).toString('base64url');
}

function buildJwt(payload, config) {
  const alg = config.jwtAlgorithm === 'RS256' ? 'RS256' : 'HS256';
  const headerPart = toBase64UrlJson({ alg, typ: 'JWT' });
  const payloadPart = toBase64UrlJson(payload);
  const signingInput = `${headerPart}.${payloadPart}`;

  let signature;
  if (alg === 'RS256') {
    const signer = crypto.createSign('RSA-SHA256');
    signer.update(signingInput);
    signature = signer.sign(config.jwtPrivateKey, 'base64url');
  } else {
    signature = crypto
      .createHmac('sha256', config.jwtSecret)
      .update(signingInput)
      .digest('base64url');
  }

  return `${signingInput}.${signature}`;
}

function buildAccessToken(user, config) {
  const now = Math.floor(Date.now() / 1000);
  const ttlSeconds = Math.max(300, Math.floor(config.authTokenTtlMs / 1000));
  const exp = now + ttlSeconds;

  const payload = {
    sub: String(user.id),
    email: user.email,
    role: user.role,
    tenant: user.tenant_slug,
    name: user.display_name || user.email,
    iat: now,
    exp,
  };

  if (config.jwtIssuer) {
    payload.iss = config.jwtIssuer;
  }
  if (config.jwtAudience) {
    payload.aud = config.jwtAudience;
  }

  return {
    accessToken: buildJwt(payload, config),
    expiresAt: new Date(exp * 1000).toISOString(),
    expiresInSeconds: ttlSeconds,
  };
}

function createOpaqueToken(sizeBytes = 36) {
  return crypto.randomBytes(sizeBytes).toString('base64url');
}

function hashOpaqueToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

function asIso(value) {
  return new Date(value).toISOString();
}

async function ensureTenant(config, tenantSlug) {
  await ensureTenantWithExecutor(
    {
      query: (text, values) => query(config, text, values),
    },
    tenantSlug
  );
}

async function ensureTenantWithExecutor(executor, tenantSlug) {
  await executor.query(
    `
      INSERT INTO tenants (slug, name)
      VALUES ($1, $2)
      ON CONFLICT (slug) DO NOTHING
    `,
    [tenantSlug, tenantSlug === 'global' ? 'Global Tenant' : `Tenant ${tenantSlug}`]
  );
}

async function lockTenantRow(executor, tenantSlug) {
  await executor.query(
    `
      SELECT slug
      FROM tenants
      WHERE slug = $1
      FOR UPDATE
    `,
    [tenantSlug]
  );
}

async function findUserByEmail(config, tenantSlug, email) {
  return findUserByEmailWithExecutor(
    {
      query: (text, values) => query(config, text, values),
    },
    tenantSlug,
    email
  );
}

async function findUserByEmailWithExecutor(executor, tenantSlug, email) {
  const result = await executor.query(
    `
      SELECT
        id,
        tenant_slug,
        email,
        display_name,
        role,
        is_active,
        password_hash,
        failed_login_count,
        locked_until
      FROM users
      WHERE tenant_slug = $1 AND email = $2
      LIMIT 1
    `,
    [tenantSlug, email]
  );

  if (!result || !result.rows.length) {
    return null;
  }

  return result.rows[0];
}

async function countUsersForTenant(executor, tenantSlug) {
  const result = await executor.query(
    `
      SELECT COUNT(*)::INT AS cnt
      FROM users
      WHERE tenant_slug = $1
    `,
    [tenantSlug]
  );

  return Number(result?.rows?.[0]?.cnt || 0);
}

async function listOtherTenantMembershipsByEmail(executor, email, tenantSlug) {
  const result = await executor.query(
    `
      SELECT DISTINCT u.tenant_slug
      FROM users u
      WHERE u.email = $1
        AND u.tenant_slug <> $2
      ORDER BY u.tenant_slug ASC
      LIMIT 5
    `,
    [email, tenantSlug]
  );

  return (result?.rows || []).map(row => String(row.tenant_slug || '').trim()).filter(Boolean);
}

async function findUserByIdWithExecutor(executor, tenantSlug, userId) {
  const result = await executor.query(
    `
      SELECT
        id,
        tenant_slug,
        email,
        display_name,
        role,
        is_active,
        password_hash,
        failed_login_count,
        locked_until
      FROM users
      WHERE tenant_slug = $1 AND id = $2
      LIMIT 1
    `,
    [tenantSlug, Number(userId)]
  );

  if (!result || !result.rows.length) {
    return null;
  }

  return result.rows[0];
}

async function findExternalIdentityWithExecutor(executor, provider, providerSubject) {
  const result = await executor.query(
    `
      SELECT
        id,
        provider,
        provider_subject,
        user_id,
        tenant_slug,
        email,
        email_verified,
        created_at,
        last_login_at
      FROM auth_external_identities
      WHERE provider = $1 AND provider_subject = $2
      LIMIT 1
    `,
    [provider, providerSubject]
  );

  if (!result || !result.rows.length) {
    return null;
  }

  return result.rows[0];
}

async function upsertExternalIdentityWithExecutor(executor, payload) {
  const result = await executor.query(
    `
      INSERT INTO auth_external_identities (
        provider,
        provider_subject,
        user_id,
        tenant_slug,
        email,
        email_verified,
        last_login_at
      )
      VALUES ($1,$2,$3,$4,$5,$6,NOW())
      ON CONFLICT (provider, provider_subject)
      DO UPDATE SET
        email = EXCLUDED.email,
        email_verified = COALESCE(EXCLUDED.email_verified, auth_external_identities.email_verified),
        last_login_at = NOW()
      RETURNING
        id,
        provider,
        provider_subject,
        user_id,
        tenant_slug,
        email,
        email_verified,
        created_at,
        last_login_at
    `,
    [
      payload.provider,
      payload.providerSubject,
      Number(payload.userId),
      payload.tenantSlug,
      payload.email,
      payload.emailVerified,
    ]
  );

  return result?.rows?.[0] || null;
}

async function markSuccessfulLoginWithExecutor(executor, userId) {
  await executor.query(
    `
      UPDATE users
      SET
        failed_login_count = 0,
        locked_until = NULL,
        last_login_at = NOW()
      WHERE id = $1
    `,
    [Number(userId)]
  );
}

function normalizeDefaultTenantPlanTier(value) {
  const normalized = String(value || 'free').trim().toLowerCase();
  if (normalized === 'pro') {
    return 'pro';
  }
  if (normalized === 'enterprise') {
    return 'enterprise';
  }
  return 'free';
}

async function seedDefaultTenantEntitlements(executor, tenantSlug, config = {}) {
  const defaultTier = normalizeDefaultTenantPlanTier(config.defaultTenantPlanTier);
  await executor.query(
    `
      INSERT INTO tenant_plans (tenant_slug, tier, active_since)
      VALUES ($1, $2, NOW())
      ON CONFLICT (tenant_slug) DO NOTHING
    `,
    [tenantSlug, defaultTier]
  );

  await executor.query(
    `
      INSERT INTO credits (tenant_slug, balance_units)
      VALUES ($1, 0)
      ON CONFLICT (tenant_slug) DO NOTHING
    `,
    [tenantSlug]
  );
}

function buildTenantJoinError(tenantSlug) {
  return new ServiceError(
    403,
    'tenant_join_invite_required',
    'This workspace already exists. Public self-service signup cannot join an existing tenant.',
    {
      tenant: tenantSlug,
      suggestedAction: 'Ask your tenant administrator to provision your account or invite you.',
    }
  );
}

function buildWorkspaceLimitError(email, tenantSlug, existingTenants) {
  return new ServiceError(
    409,
    'self_service_workspace_limit_reached',
    'This email already belongs to another Cybertron workspace. Sign in to that workspace or contact support to consolidate billing.',
    {
      email,
      tenant: tenantSlug,
      existingTenants,
      upgradeUrl: '/pricing',
    }
  );
}

function buildExternalIdentityWorkspaceLimitError(provider, tenantSlug) {
  return new ServiceError(
    409,
    'external_identity_workspace_limit_reached',
    'This external identity is already linked to another Cybertron workspace. Sign in to the original workspace or contact support to consolidate billing.',
    {
      provider,
      tenant: tenantSlug,
    }
  );
}

function resolveRegistrationTenant(rawTenant, contextMeta = {}) {
  if (!contextMeta.isAdmin) {
    return normalizePublicWorkspaceSlug(rawTenant, {
      requireExplicit: true,
    });
  }

  const actorRole = normalizeRole(contextMeta.actorRole || 'executive_viewer');
  const actorTenant = sanitizeTenant(contextMeta.actorTenant || rawTenant || 'global');
  const requestedTenant = sanitizeTenant(rawTenant || actorTenant);

  if (!hasRoleAccess(actorRole, 'super_admin') && requestedTenant !== actorTenant) {
    throw new ServiceError(
      403,
      'tenant_scope_denied',
      'Tenant administrators can only provision accounts inside their own workspace.',
      {
        actorRole,
        actorTenant,
        requestedTenant,
      }
    );
  }

  return requestedTenant;
}

function assertAdminCanAssignRole(contextMeta = {}, targetRole) {
  if (!contextMeta.isAdmin) {
    return;
  }

  const actorRole = normalizeRole(contextMeta.actorRole || 'executive_viewer');
  const requestedRole = normalizeRole(targetRole || 'executive_viewer');
  if (hasRoleAccess(actorRole, requestedRole)) {
    return;
  }

  throw new ServiceError(
    403,
    'role_not_allowed',
    'This session cannot assign the requested role.',
    {
      actorRole,
      requestedRole,
    }
  );
}

async function listWorkspaceBootstrapEventsWithExecutor(executor, columnName, markerHash, windowStart, limit) {
  if (!markerHash || !windowStart || !limit || limit < 1) {
    return [];
  }

  const allowedColumns = new Set(['fingerprint_hash', 'network_hash']);
  if (!allowedColumns.has(columnName)) {
    throw new Error(`Unsupported workspace bootstrap column: ${columnName}`);
  }

  const result = await executor.query(
    `
      SELECT created_at
      FROM auth_workspace_bootstrap_events
      WHERE ${columnName} = $1
        AND created_at >= $2
      ORDER BY created_at ASC
      LIMIT $3
    `,
    [markerHash, windowStart.toISOString(), limit]
  );

  return result?.rows || [];
}

async function assertWorkspaceBootstrapAllowedWithExecutor(config, executor, contextMeta = {}) {
  const windowMs = Math.max(60_000, Number(config.fingerprintWindowMs || 24 * 60 * 60 * 1000));
  const windowStart = new Date(Date.now() - windowMs);
  const publicFingerprint = normalizePublicFingerprint(contextMeta.publicFingerprint);
  const networkAddress = String(contextMeta.ipAddress || '').trim();
  const maxPerFingerprint = Math.max(1, Number(config.maxRegistrationsPerFingerprint || 1));
  const maxPerNetwork = Math.max(1, Number(config.maxWorkspaceBootstrapsPerNetwork || 3));

  const fingerprintHash = publicFingerprint
    ? hashWorkspaceBootstrapMarker(config, 'fingerprint', publicFingerprint)
    : null;
  const networkHash =
    networkAddress && !isLoopbackAddress(networkAddress)
      ? hashWorkspaceBootstrapMarker(config, 'network', networkAddress)
      : null;

  if (fingerprintHash) {
    const recentFingerprintRows = await listWorkspaceBootstrapEventsWithExecutor(
      executor,
      'fingerprint_hash',
      fingerprintHash,
      windowStart,
      maxPerFingerprint
    );

    if (recentFingerprintRows.length >= maxPerFingerprint) {
      throw new ServiceError(
        429,
        'workspace_creation_device_limit_reached',
        'Too many new workspaces were created from this browser recently. Sign in to your existing workspace or try again later.',
        {
          retryAfterSeconds: buildWorkspaceBootstrapRetryAfterSeconds(recentFingerprintRows, windowMs),
          maxWorkspaces: maxPerFingerprint,
          upgradeUrl: '/pricing',
          windowMs,
        }
      );
    }
  }

  if (networkHash) {
    const recentNetworkRows = await listWorkspaceBootstrapEventsWithExecutor(
      executor,
      'network_hash',
      networkHash,
      windowStart,
      maxPerNetwork
    );

    if (recentNetworkRows.length >= maxPerNetwork) {
      throw new ServiceError(
        429,
        'workspace_creation_network_limit_reached',
        'Too many new workspaces were created from this network recently. Sign in to an existing workspace or contact support to continue.',
        {
          retryAfterSeconds: buildWorkspaceBootstrapRetryAfterSeconds(recentNetworkRows, windowMs),
          maxWorkspaces: maxPerNetwork,
          upgradeUrl: '/pricing',
          windowMs,
        }
      );
    }
  }

  return {
    fingerprintHash,
    networkHash,
  };
}

async function recordWorkspaceBootstrapEventWithExecutor(executor, payload) {
  await executor.query(
    `
      INSERT INTO auth_workspace_bootstrap_events (
        tenant_slug,
        user_id,
        email,
        bootstrap_mode,
        provider,
        fingerprint_hash,
        network_hash
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7)
    `,
    [
      payload.tenantSlug,
      Number(payload.userId),
      payload.email,
      payload.bootstrapMode,
      payload.provider || null,
      payload.fingerprintHash || null,
      payload.networkHash || null,
    ]
  );
}

async function findUserById(config, tenantSlug, userId) {
  return findUserByIdWithExecutor(
    {
      query: (text, values) => query(config, text, values),
    },
    tenantSlug,
    userId
  );
}

async function markFailedLogin(config, userId, lockoutMs, maxAttempts) {
  await query(
    config,
    `
      UPDATE users
      SET
        failed_login_count = failed_login_count + 1,
        last_failed_login_at = NOW(),
        locked_until = CASE
          WHEN failed_login_count + 1 >= $2 THEN NOW() + ($3::text || ' milliseconds')::interval
          ELSE locked_until
        END
      WHERE id = $1
    `,
    [Number(userId), maxAttempts, Math.max(1, lockoutMs)]
  );
}

async function markSuccessfulLogin(config, userId) {
  await markSuccessfulLoginWithExecutor(
    {
      query: (text, values) => query(config, text, values),
    },
    userId
  );
}

async function storeRefreshToken(config, payload) {
  await query(
    config,
    `
      INSERT INTO auth_refresh_tokens (
        user_id,
        tenant_slug,
        token_hash,
        expires_at,
        created_ip,
        user_agent
      )
      VALUES ($1,$2,$3,$4,$5,$6)
    `,
    [
      Number(payload.userId),
      payload.tenantSlug,
      payload.tokenHash,
      payload.expiresAt,
      payload.ipAddress || null,
      payload.userAgent || null,
    ]
  );
}

async function revokeRefreshTokenHash(config, tokenHash, replacementTokenHash = null) {
  await query(
    config,
    `
      UPDATE auth_refresh_tokens
      SET revoked_at = NOW(), replaced_by_token_hash = COALESCE($2, replaced_by_token_hash)
      WHERE token_hash = $1 AND revoked_at IS NULL
    `,
    [tokenHash, replacementTokenHash]
  );
}

async function withOptionalExecutor(config, executor, fn) {
  if (executor && typeof executor.query === 'function') {
    return fn(executor);
  }

  return withClient(config, fn);
}

async function issueTokenPair(
  config,
  user,
  contextMeta,
  existingRefreshTokenHash = null,
  executor = null
) {
  if (!config.jwtSecret && config.jwtAlgorithm !== 'RS256') {
    throw new ServiceError(
      503,
      'auth_unavailable',
      'JWT secret is missing. Configure JWT_SECRET to issue access tokens.'
    );
  }

  if (config.jwtAlgorithm === 'RS256' && !config.jwtPrivateKey) {
    throw new ServiceError(
      503,
      'auth_unavailable',
      'JWT private key is missing. Configure JWT_PRIVATE_KEY to issue RS256 access tokens.'
    );
  }

  const access = buildAccessToken(user, config);
  const refreshToken = createOpaqueToken(42);
  const refreshTokenHash = hashOpaqueToken(refreshToken);
  const refreshTtlMs = Math.max(15 * 60_000, Number(config.refreshTokenTtlMs || 1000 * 60 * 60 * 24 * 30));
  const refreshExpiresAt = new Date(Date.now() + refreshTtlMs).toISOString();

  await withOptionalExecutor(config, executor, async client => {
    await client.query('BEGIN');

    try {
      await client.query(
        `
          INSERT INTO auth_refresh_tokens (
            user_id,
            tenant_slug,
            token_hash,
            expires_at,
            created_ip,
            user_agent
          )
          VALUES ($1,$2,$3,$4,$5,$6)
        `,
        [
          Number(user.id),
          user.tenant_slug,
          refreshTokenHash,
          refreshExpiresAt,
          contextMeta.ipAddress || null,
          contextMeta.userAgent || null,
        ]
      );

      if (existingRefreshTokenHash) {
        await client.query(
          `
            UPDATE auth_refresh_tokens
            SET revoked_at = NOW(), replaced_by_token_hash = $2
            WHERE token_hash = $1 AND revoked_at IS NULL
          `,
          [existingRefreshTokenHash, refreshTokenHash]
        );
      }

      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    }
  });

  return {
    accessToken: access.accessToken,
    accessTokenExpiresAt: access.expiresAt,
    accessTokenExpiresInSeconds: access.expiresInSeconds,
    refreshToken,
    refreshTokenExpiresAt: refreshExpiresAt,
    tokenType: 'Bearer',
  };
}

async function registerUser(config, payload, contextMeta = {}) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new ServiceError(400, 'invalid_request_body', 'Request body must be an object.');
  }

  if (typeof payload.email !== 'string' || typeof payload.password !== 'string') {
    throw new ServiceError(400, 'invalid_request_body', 'Email and password must be strings.');
  }

  if (payload.displayName !== undefined && typeof payload.displayName !== 'string') {
    throw new ServiceError(400, 'invalid_request_body', 'Display name must be a string.');
  }

  if (payload.role !== undefined && typeof payload.role !== 'string') {
    throw new ServiceError(400, 'invalid_request_body', 'Role must be a string.');
  }

  const tenantSlug = resolveRegistrationTenant(payload.tenant, contextMeta);
  const email = normalizeEmail(payload.email);
  const password = String(payload.password || '');
  const displayName = String(payload.displayName || '').trim() || email;
  const role = normalizeRole(payload.role || 'executive_viewer');

  if (!email || !email.includes('@')) {
    throw new ServiceError(400, 'invalid_email', 'A valid email address is required.');
  }

  if (isDisposableEmail(email)) {
    throw new ServiceError(
      422,
      'disposable_email',
      'Disposable or temporary email addresses are not allowed. Please use a permanent email address.'
    );
  }

  if (password.length < 10) {
    throw new ServiceError(400, 'weak_password', 'Password must be at least 10 characters long.');
  }

  if (!config.allowPublicRegistration && !contextMeta.isAdmin) {
    throw new ServiceError(
      403,
      'registration_disabled',
      'Public registration is disabled. An administrator must create accounts.'
    );
  }

  const passwordHash = await bcrypt.hash(password, Math.max(10, Number(config.passwordHashRounds || 12)));
  const registrationResult = await withClient(config, async client => {
    await client.query('BEGIN');

    try {
      await ensureTenantWithExecutor(client, tenantSlug);
      await lockTenantRow(client, tenantSlug);

      const existing = await findUserByEmailWithExecutor(client, tenantSlug, email);
      if (existing) {
        throw new ServiceError(
          409,
          'registration_failed',
          'Registration could not be completed. If you already have an account, try logging in.'
        );
      }

      const userCount = await countUsersForTenant(client, tenantSlug);
      const isFirstUser = userCount === 0;
      let bootstrapMarkers = {
        fingerprintHash: null,
        networkHash: null,
      };

      if (!contextMeta.isAdmin && !isFirstUser) {
        throw buildTenantJoinError(tenantSlug);
      }

      if (!contextMeta.isAdmin) {
        const existingTenants = await listOtherTenantMembershipsByEmail(client, email, tenantSlug);
        if (existingTenants.length > 0) {
          throw buildWorkspaceLimitError(email, tenantSlug, existingTenants);
        }
      }

      if (!contextMeta.isAdmin && isFirstUser) {
        bootstrapMarkers = await assertWorkspaceBootstrapAllowedWithExecutor(
          config,
          client,
          contextMeta
        );
      }

      let effectiveRole = role;
      if (isFirstUser) {
        effectiveRole = 'tenant_admin';
      } else if (!contextMeta.isAdmin && role !== 'executive_viewer') {
        throw new ServiceError(
          403,
          'role_not_allowed',
          'Only administrators can assign elevated roles.'
        );
      }
      assertAdminCanAssignRole(contextMeta, effectiveRole);

      const inserted = await client.query(
        `
          INSERT INTO users (
            tenant_slug,
            email,
            display_name,
            role,
            is_active,
            password_hash
          )
          VALUES ($1,$2,$3,$4,TRUE,$5)
          RETURNING id, tenant_slug, email, display_name, role, is_active
        `,
        [tenantSlug, email, displayName.slice(0, 191), effectiveRole, passwordHash]
      );

      if (isFirstUser) {
        await seedDefaultTenantEntitlements(client, tenantSlug, config);
        if (!contextMeta.isAdmin) {
          await recordWorkspaceBootstrapEventWithExecutor(client, {
            tenantSlug,
            userId: inserted.rows[0].id,
            email,
            bootstrapMode: 'password',
            provider: 'password',
            fingerprintHash: bootstrapMarkers.fingerprintHash,
            networkHash: bootstrapMarkers.networkHash,
          });
        }
      }

      await client.query('COMMIT');
      return {
        user: inserted.rows[0],
        isFirstUser,
      };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    }
  });

  const user = registrationResult.user;

  await appendAuditLog(config, {
    tenantSlug,
    actorId: contextMeta.actorUserId,
    actorEmail: contextMeta.actorEmail || email,
    action: 'auth.user_registered',
    targetType: 'user',
    targetId: String(user.id),
    ipAddress: contextMeta.ipAddress,
    userAgent: contextMeta.userAgent,
    traceId: contextMeta.traceId,
    payload: {
      role: user.role,
      tenant: tenantSlug,
      bootstrapped: registrationResult.isFirstUser,
      publicRegistration: Boolean(config.allowPublicRegistration),
      defaultPlanSeeded: registrationResult.isFirstUser,
    },
  });

  return {
    id: String(user.id),
    tenant: user.tenant_slug,
    email: user.email,
    displayName: user.display_name,
    role: user.role,
    active: Boolean(user.is_active),
  };
}

async function loginWithPassword(config, payload, contextMeta = {}) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new ServiceError(400, 'invalid_request_body', 'Request body must be an object.');
  }

  if (typeof payload.email !== 'string' || typeof payload.password !== 'string') {
    throw new ServiceError(400, 'invalid_request_body', 'Email and password must be strings.');
  }

  const tenantSlug = normalizePublicWorkspaceSlug(payload.tenant, {
    requireExplicit: true,
    allowReserved: true,
  });
  const email = normalizeEmail(payload.email);
  const password = String(payload.password || '');

  if (!email || !password) {
    throw new ServiceError(400, 'invalid_credentials', 'Email and password are required.');
  }

  const user = await findUserByEmail(config, tenantSlug, email);
  if (!user || !user.is_active || !user.password_hash) {
    await appendAuditLog(config, {
      tenantSlug,
      actorEmail: email || null,
      action: 'auth.login_failed',
      targetType: 'user',
      targetId: null,
      ipAddress: contextMeta.ipAddress,
      userAgent: contextMeta.userAgent,
      traceId: contextMeta.traceId,
      payload: {
        reason: 'unknown_or_inactive_user',
      },
    });
    throw new ServiceError(401, 'invalid_credentials', 'Invalid email or password.');
  }

  if (user.locked_until && new Date(user.locked_until).getTime() > Date.now()) {
    throw new ServiceError(429, 'account_locked', 'Account is temporarily locked after failed attempts.', {
      lockedUntil: asIso(user.locked_until),
    });
  }

  const isValidPassword = await bcrypt.compare(password, user.password_hash);
  if (!isValidPassword) {
    await markFailedLogin(config, user.id, config.authLockoutMs, config.authMaxFailedAttempts);
    await appendAuditLog(config, {
      tenantSlug,
      actorEmail: email,
      action: 'auth.login_failed',
      targetType: 'user',
      targetId: String(user.id),
      ipAddress: contextMeta.ipAddress,
      userAgent: contextMeta.userAgent,
      traceId: contextMeta.traceId,
      payload: {
        reason: 'invalid_password',
      },
    });
    throw new ServiceError(401, 'invalid_credentials', 'Invalid email or password.');
  }

  await markSuccessfulLogin(config, user.id);
  const tokens = await issueTokenPair(config, user, contextMeta, null, contextMeta.dbExecutor || null);

  await appendAuditLog(config, {
    tenantSlug,
    actorId: String(user.id),
    actorEmail: user.email,
    action: 'auth.login_success',
    targetType: 'user',
    targetId: String(user.id),
    ipAddress: contextMeta.ipAddress,
    userAgent: contextMeta.userAgent,
    traceId: contextMeta.traceId,
    payload: {
      role: user.role,
    },
  });

  return {
    user: {
      id: String(user.id),
      tenant: user.tenant_slug,
      email: user.email,
      displayName: user.display_name,
      role: user.role,
    },
    tokens,
  };
}

async function rotateRefreshToken(config, payload, contextMeta = {}) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new ServiceError(400, 'invalid_request_body', 'Request body must be an object.');
  }

  if (typeof payload.refreshToken !== 'string') {
    throw new ServiceError(400, 'invalid_refresh_token', 'Refresh token must be a string.');
  }

  const refreshToken = String(payload.refreshToken || '').trim();
  if (!refreshToken) {
    throw new ServiceError(400, 'invalid_refresh_token', 'Refresh token is required.');
  }

  const tokenHash = hashOpaqueToken(refreshToken);
  const rowResult = await query(
    config,
    `
      SELECT
        rt.id,
        rt.user_id,
        rt.tenant_slug,
        rt.expires_at,
        rt.revoked_at,
        rt.created_ip,
        rt.user_agent AS stored_user_agent,
        u.id AS user_id_ref,
        u.email,
        u.display_name,
        u.role,
        u.is_active
      FROM auth_refresh_tokens rt
      INNER JOIN users u ON u.id = rt.user_id
      WHERE rt.token_hash = $1
      LIMIT 1
    `,
    [tokenHash]
  );

  if (!rowResult || !rowResult.rows.length) {
    throw new ServiceError(401, 'invalid_refresh_token', 'Refresh token is invalid.');
  }

  const row = rowResult.rows[0];
  if (!row.is_active) {
    throw new ServiceError(401, 'invalid_refresh_token', 'Refresh token is invalid.');
  }

  if (row.revoked_at) {
    throw new ServiceError(401, 'invalid_refresh_token', 'Refresh token was revoked.');
  }

  if (new Date(row.expires_at).getTime() <= Date.now()) {
    throw new ServiceError(401, 'invalid_refresh_token', 'Refresh token has expired.');
  }

  // MED-05: Log warning when refresh token is used from a different client
  if (row.created_ip && contextMeta.ipAddress && row.created_ip !== contextMeta.ipAddress) {
    console.warn(`[auth] Refresh token for user ${row.user_id} used from different IP: original=${row.created_ip}, current=${contextMeta.ipAddress}`);
  }
  if (row.stored_user_agent && contextMeta.userAgent && row.stored_user_agent !== contextMeta.userAgent) {
    console.warn(`[auth] Refresh token for user ${row.user_id} used from different user-agent: original="${row.stored_user_agent}", current="${contextMeta.userAgent}"`);
  }

  const user = {
    id: row.user_id,
    tenant_slug: row.tenant_slug,
    email: row.email,
    display_name: row.display_name,
    role: row.role,
  };

  const tokens = await issueTokenPair(config, user, contextMeta, tokenHash);

  await appendAuditLog(config, {
    tenantSlug: row.tenant_slug,
    actorId: String(row.user_id),
    actorEmail: row.email,
    action: 'auth.refresh_rotated',
    targetType: 'user',
    targetId: String(row.user_id),
    ipAddress: contextMeta.ipAddress,
    userAgent: contextMeta.userAgent,
    traceId: contextMeta.traceId,
    payload: {
      refreshTokenId: row.id,
    },
  });

  return {
    user: {
      id: String(row.user_id),
      tenant: row.tenant_slug,
      email: row.email,
      displayName: row.display_name,
      role: row.role,
    },
    tokens,
  };
}

async function revokeRefreshToken(config, payload, contextMeta = {}) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return;
  }

  if (payload.refreshToken !== undefined && typeof payload.refreshToken !== 'string') {
    throw new ServiceError(400, 'invalid_refresh_token', 'Refresh token must be a string.');
  }

  const refreshToken = String(payload.refreshToken || '').trim();
  if (!refreshToken) {
    return;
  }

  const tokenHash = hashOpaqueToken(refreshToken);
  await revokeRefreshTokenHash(config, tokenHash);

  await appendAuditLog(config, {
    tenantSlug: sanitizeTenant(payload.tenant || 'global'),
    actorId: contextMeta.actorUserId,
    actorEmail: contextMeta.actorEmail,
    action: 'auth.refresh_revoked',
    targetType: 'refresh_token',
    targetId: tokenHash.slice(0, 16),
    ipAddress: contextMeta.ipAddress,
    userAgent: contextMeta.userAgent,
    traceId: contextMeta.traceId,
    payload: {},
  });
}

async function requestPasswordReset(config, payload, contextMeta = {}) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new ServiceError(400, 'invalid_request_body', 'Request body must be an object.');
  }

  if (typeof payload.email !== 'string') {
    throw new ServiceError(400, 'invalid_email', 'Email must be a string.');
  }

  const tenantSlug = normalizePublicWorkspaceSlug(payload.tenant, {
    requireExplicit: true,
    allowReserved: true,
  });
  const email = normalizeEmail(payload.email);
  if (!email) {
    throw new ServiceError(400, 'invalid_email', 'Email is required.');
  }

  const user = await findUserByEmail(config, tenantSlug, email);
  if (!user || !user.is_active) {
    return {
      accepted: true,
      message: 'If the account exists, a reset token has been issued.',
    };
  }

  const rawResetToken = createOpaqueToken(30);
  const resetTokenHash = hashOpaqueToken(rawResetToken);
  const ttlMs = Math.max(5 * 60_000, Number(config.passwordResetTokenTtlMs || 30 * 60_000));
  const expiresAt = new Date(Date.now() + ttlMs).toISOString();

  await query(
    config,
    `
      INSERT INTO password_reset_tokens (
        user_id,
        tenant_slug,
        token_hash,
        expires_at,
        created_ip,
        user_agent
      )
      VALUES ($1,$2,$3,$4,$5,$6)
    `,
    [user.id, tenantSlug, resetTokenHash, expiresAt, contextMeta.ipAddress || null, contextMeta.userAgent || null]
  );

  await appendAuditLog(config, {
    tenantSlug,
    actorId: String(user.id),
    actorEmail: user.email,
    action: 'auth.password_reset_requested',
    targetType: 'user',
    targetId: String(user.id),
    ipAddress: contextMeta.ipAddress,
    userAgent: contextMeta.userAgent,
    traceId: contextMeta.traceId,
    payload: {},
  });

  return {
    accepted: true,
    message: 'If the account exists, a reset token has been issued.',
    // For local/dev only. In production callers should integrate with email provider.
    resetToken: config.environment === 'production' ? undefined : rawResetToken,
    expiresAt: config.environment === 'production' ? undefined : expiresAt,
  };
}

async function resetPassword(config, payload, contextMeta = {}) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new ServiceError(400, 'invalid_request_body', 'Request body must be an object.');
  }

  if (typeof payload.resetToken !== 'string' || typeof payload.newPassword !== 'string') {
    throw new ServiceError(
      400,
      'invalid_request_body',
      'Reset token and newPassword must be strings.'
    );
  }

  const tenantSlug = normalizePublicWorkspaceSlug(payload.tenant, {
    requireExplicit: true,
    allowReserved: true,
  });
  const resetToken = String(payload.resetToken || '').trim();
  const nextPassword = String(payload.newPassword || '');

  if (!resetToken) {
    throw new ServiceError(400, 'invalid_reset_token', 'Reset token is required.');
  }
  if (nextPassword.length < 10) {
    throw new ServiceError(400, 'weak_password', 'Password must be at least 10 characters long.');
  }

  const tokenHash = hashOpaqueToken(resetToken);
  const tokenResult = await query(
    config,
    `
      SELECT id, user_id, tenant_slug, expires_at, consumed_at
      FROM password_reset_tokens
      WHERE token_hash = $1 AND tenant_slug = $2
      LIMIT 1
    `,
    [tokenHash, tenantSlug]
  );

  if (!tokenResult || !tokenResult.rows.length) {
    throw new ServiceError(400, 'invalid_reset_token', 'Reset token is invalid.');
  }

  const tokenRow = tokenResult.rows[0];
  if (tokenRow.consumed_at) {
    throw new ServiceError(400, 'invalid_reset_token', 'Reset token has already been used.');
  }
  if (new Date(tokenRow.expires_at).getTime() <= Date.now()) {
    throw new ServiceError(400, 'invalid_reset_token', 'Reset token has expired.');
  }

  const passwordHash = await bcrypt.hash(nextPassword, Math.max(10, Number(config.passwordHashRounds || 12)));

  await withClient(config, async client => {
    await client.query('BEGIN');
    try {
      await client.query(
        `
          UPDATE users
          SET
            password_hash = $2,
            failed_login_count = 0,
            locked_until = NULL
          WHERE id = $1
        `,
        [tokenRow.user_id, passwordHash]
      );

      await client.query(
        `
          UPDATE password_reset_tokens
          SET consumed_at = NOW()
          WHERE id = $1
        `,
        [tokenRow.id]
      );

      await client.query(
        `
          UPDATE auth_refresh_tokens
          SET revoked_at = NOW()
          WHERE user_id = $1 AND revoked_at IS NULL
        `,
        [tokenRow.user_id]
      );

      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    }
  });

  const user = await findUserById(config, tenantSlug, tokenRow.user_id);

  await appendAuditLog(config, {
    tenantSlug,
    actorId: String(tokenRow.user_id),
    actorEmail: user?.email || null,
    action: 'auth.password_reset_completed',
    targetType: 'user',
    targetId: String(tokenRow.user_id),
    ipAddress: contextMeta.ipAddress,
    userAgent: contextMeta.userAgent,
    traceId: contextMeta.traceId,
    payload: {},
  });

  return {
    success: true,
    message: 'Password has been reset.',
  };
}

async function findOrCreateOAuthUser(config, payload, contextMeta = {}) {
  const tenantSlug = contextMeta.isAdmin
    ? sanitizeTenant(payload.tenant || 'global')
    : normalizePublicWorkspaceSlug(payload.tenant, {
        requireExplicit: true,
      });
  const email = normalizeEmail(payload.email);
  const displayName = String(payload.displayName || '').trim() || email;
  const provider = normalizeOAuthProvider(payload.provider);
  const providerId = normalizeOAuthProviderSubject(payload.providerId);
  const emailVerified = normalizeOptionalBoolean(payload.emailVerified);

  if (!email || !email.includes('@')) {
    throw new ServiceError(400, 'invalid_email', 'A valid email address is required from OAuth provider.');
  }

  if (emailVerified === false) {
    throw new ServiceError(
      403,
      'oauth_email_not_verified',
      'The external identity provider did not confirm a verified email address. Use a verified provider email before signing in.'
    );
  }

  if (isDisposableEmail(email)) {
    throw new ServiceError(
      422,
      'disposable_email',
      'Disposable or temporary email addresses are not allowed.'
    );
  }

  if (!config.allowPublicRegistration && !contextMeta.isAdmin) {
    throw new ServiceError(
      403,
      'registration_disabled',
      'Public registration is disabled. An administrator must create accounts.'
    );
  }

  const oauthResult = await withOptionalExecutor(config, contextMeta.dbExecutor, async client => {
    await client.query('BEGIN');

    try {
      const existingIdentity = await findExternalIdentityWithExecutor(client, provider, providerId);
      if (existingIdentity) {
        if (String(existingIdentity.tenant_slug) !== tenantSlug) {
          throw buildExternalIdentityWorkspaceLimitError(provider, String(existingIdentity.tenant_slug));
        }

        const linkedUser = await findUserByIdWithExecutor(client, tenantSlug, existingIdentity.user_id);
        if (!linkedUser) {
          throw new ServiceError(
            409,
            'external_identity_conflict',
            'This external identity is linked to an unavailable account. Contact support to restore access.'
          );
        }

        if (!linkedUser.is_active) {
          throw new ServiceError(403, 'account_deactivated', 'Account is deactivated.');
        }

        if (linkedUser.locked_until && new Date(linkedUser.locked_until).getTime() > Date.now()) {
          throw new ServiceError(
            429,
            'account_locked',
            'Account is temporarily locked after failed attempts.',
            {
              lockedUntil: linkedUser.locked_until,
            }
          );
        }

        await upsertExternalIdentityWithExecutor(client, {
          provider,
          providerSubject: providerId,
          userId: linkedUser.id,
          tenantSlug,
          email,
          emailVerified,
        });
        await markSuccessfulLoginWithExecutor(client, linkedUser.id);
        await client.query('COMMIT');
        return {
          created: false,
          user: linkedUser,
          isFirstUser: false,
        };
      }

      await ensureTenantWithExecutor(client, tenantSlug);
      await lockTenantRow(client, tenantSlug);

      const existing = await findUserByEmailWithExecutor(client, tenantSlug, email);
      if (existing) {
        if (!existing.is_active) {
          throw new ServiceError(403, 'account_deactivated', 'Account is deactivated.');
        }

        if (existing.locked_until && new Date(existing.locked_until).getTime() > Date.now()) {
          throw new ServiceError(
            429,
            'account_locked',
            'Account is temporarily locked after failed attempts.',
            {
              lockedUntil: existing.locked_until,
            }
          );
        }

        await upsertExternalIdentityWithExecutor(client, {
          provider,
          providerSubject: providerId,
          userId: existing.id,
          tenantSlug,
          email,
          emailVerified,
        });
        await markSuccessfulLoginWithExecutor(client, existing.id);
        await client.query('COMMIT');
        return {
          created: false,
          user: existing,
          isFirstUser: false,
        };
      }

      const userCount = await countUsersForTenant(client, tenantSlug);
      const isFirstUser = userCount === 0;
      let bootstrapMarkers = {
        fingerprintHash: null,
        networkHash: null,
      };

      if (!contextMeta.isAdmin && !isFirstUser) {
        throw buildTenantJoinError(tenantSlug);
      }

      if (!contextMeta.isAdmin) {
        const existingTenants = await listOtherTenantMembershipsByEmail(client, email, tenantSlug);
        if (existingTenants.length > 0) {
          throw buildWorkspaceLimitError(email, tenantSlug, existingTenants);
        }
      }

      if (!contextMeta.isAdmin && isFirstUser) {
        bootstrapMarkers = await assertWorkspaceBootstrapAllowedWithExecutor(
          config,
          client,
          contextMeta
        );
      }

      const role = isFirstUser ? 'tenant_admin' : 'executive_viewer';
      const inserted = await client.query(
        `
          INSERT INTO users (
            tenant_slug,
            email,
            display_name,
            role,
            is_active,
            password_hash
          )
          VALUES ($1,$2,$3,$4,TRUE,NULL)
          RETURNING id, tenant_slug, email, display_name, role, is_active
        `,
        [tenantSlug, email, displayName.slice(0, 191), role]
      );

      if (isFirstUser) {
        await seedDefaultTenantEntitlements(client, tenantSlug, config);
        if (!contextMeta.isAdmin) {
          await recordWorkspaceBootstrapEventWithExecutor(client, {
            tenantSlug,
            userId: inserted.rows[0].id,
            email,
            bootstrapMode: 'oauth',
            provider,
            fingerprintHash: bootstrapMarkers.fingerprintHash,
            networkHash: bootstrapMarkers.networkHash,
          });
        }
      }

      await upsertExternalIdentityWithExecutor(client, {
        provider,
        providerSubject: providerId,
        userId: inserted.rows[0].id,
        tenantSlug,
        email,
        emailVerified,
      });

      await client.query('COMMIT');
      return {
        created: true,
        user: inserted.rows[0],
        isFirstUser,
      };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    }
  });

  const user = oauthResult.user;
  const tokens = await issueTokenPair(config, user, contextMeta);

  await appendAuditLog(config, {
    tenantSlug,
    actorId: String(user.id),
    actorEmail: user.email,
    action: oauthResult.created ? 'auth.oauth_register' : 'auth.oauth_login',
    targetType: 'user',
    targetId: String(user.id),
    ipAddress: contextMeta.ipAddress,
    userAgent: contextMeta.userAgent,
    traceId: contextMeta.traceId,
    payload: {
      provider,
      providerId,
      role: user.role,
      bootstrapped: oauthResult.isFirstUser,
      defaultPlanSeeded: oauthResult.isFirstUser,
    },
  }, contextMeta.dbExecutor || null);

  return {
    user: {
      id: String(user.id),
      tenant: user.tenant_slug,
      email: user.email,
      displayName: user.display_name,
      role: user.role,
    },
    tokens,
    created: oauthResult.created,
  };
}

module.exports = {
  ServiceError,
  registerUser,
  loginWithPassword,
  rotateRefreshToken,
  revokeRefreshToken,
  requestPasswordReset,
  resetPassword,
  findOrCreateOAuthUser,
  __test__: {
    normalizeEmail,
    normalizePublicWorkspaceSlug,
    normalizeOAuthProvider,
    normalizeOAuthProviderSubject,
    normalizeOptionalBoolean,
    normalizePublicFingerprint,
    isLoopbackAddress,
    hashWorkspaceBootstrapMarker,
    buildWorkspaceBootstrapRetryAfterSeconds,
    buildTenantJoinError,
    buildWorkspaceLimitError,
    buildExternalIdentityWorkspaceLimitError,
    normalizeDefaultTenantPlanTier,
    resolveRegistrationTenant,
    assertAdminCanAssignRole,
  },
};
