function registerRoutes(routerContext) {
  const register = routerContext?.register;
  if (typeof register !== 'function') {
    throw new Error('auth routes require routerContext.register(handler)');
  }

  const deps = routerContext.deps || {};
  const {
    config,
    log,
    sendJson,
    sendError,
    sendNoContent,
    sendRedirect,
    sendMethodNotAllowed,
    requireDatabaseConfigured,
    requireSession,
    parseJsonBody,
    validateBodyShape,
    handleServiceFailure,
    actorMetaFromContext,
    getSessionFromContext,
    getAccessTokenFromContext,
    getRefreshTokenFromContext,
    attachAuthCookies,
    attachClearAuthCookies,
    parseRequestCookies,
    enforceAuthIdentityRateLimit,
    sendAuthRequired,
    baseHeaders,
    sessionStore,
    authGuard,
    normalizeRole,
    hasRoleAccess,
    sanitizeTenant,
    sanitizeRedirectPath,
    hasRole,
    loginWithPassword,
    registerUser,
    rotateRefreshToken,
    revokeRefreshToken,
    requestPasswordReset,
    resetPassword,
    findOrCreateOAuthUser,
    ServiceError,
    isValidOAuthProvider,
    generateOAuthState,
    generatePkceChallenge,
    supportsPkce,
    buildAuthorizationUrl,
    exchangeCodeForTokens,
    fetchUserProfile,
    hashAccessToken,
    parseJwtExpiryMs,
    rememberRevokedAccessTokenHash,
    persistRevokedAccessToken,
    isRevokedAccessToken,
    parseCookieHeader,
    appendAuditLog,
  } = deps;

  const RESERVED_PUBLIC_WORKSPACE_SLUGS = new Set(['global']);
  const PUBLIC_FINGERPRINT_COOKIE_NAME = 'ct_public_fp';

  function buildAuthErrorLocation(errorCode, providerName, message, tenant) {
    const params = new URLSearchParams();
    params.set('error', errorCode || 'oauth_error');
    if (providerName) {
      params.set('provider', providerName);
    }
    if (message) {
      params.set('message', message);
    }
    if (tenant) {
      params.set('tenant', tenant);
    }
    return `/auth/error?${params.toString()}`;
  }

  function resolvePublicOAuthTenant(rawTenant) {
    const requestedTenant = String(rawTenant || '').trim();
    if (!requestedTenant) {
      throw new ServiceError(
        400,
        'workspace_slug_required',
        'Workspace slug is required before continuing with social sign-in.'
      );
    }

    const tenant = sanitizeTenant(requestedTenant);
    if (RESERVED_PUBLIC_WORKSPACE_SLUGS.has(tenant)) {
      throw new ServiceError(
        403,
        'reserved_workspace_slug',
        'This workspace slug is reserved for internal operations. Choose a different workspace slug.'
      );
    }

    return tenant;
  }

  function resolvePublicAuthFingerprint(context) {
    const headerValue = String(
      context?.request?.headers?.['x-cybertron-public-fingerprint'] || ''
    ).trim();
    if (headerValue) {
      return headerValue;
    }

    const cookies = parseRequestCookies(context.request);
    const cookieValue = String(cookies?.[PUBLIC_FINGERPRINT_COOKIE_NAME] || '').trim();
    return cookieValue || null;
  }

  // ── Auth routes ──
  register(async ({ context, response, baseExtraHeaders }) => {

    // ── POST /v1/auth/login (+ GET for demo mode) ──
    if (context.path === '/v1/auth/login') {
      if (context.method === 'GET') {
        if (config.environment === 'production') {
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
          return true;
        }

        if (config.authMode !== 'demo') {
          sendError(
            response,
            context,
            config,
            503,
            'auth_provider_required',
            'External identity provider login must be configured for this environment.',
            {
              authMode: config.authMode,
            },
            baseExtraHeaders
          );
          return true;
        }

        if (!config.allowInsecureDemoAuth) {
          sendError(
            response,
            context,
            config,
            503,
            'auth_provider_required',
            'Demo auth is disabled. Configure external identity provider before production use.',
            null,
            baseExtraHeaders
          );
          return true;
        }

        const role = normalizeRole(context.url.searchParams.get('role'));
        const tenant = sanitizeTenant(context.url.searchParams.get('tenant'));
        const redirectTarget = sanitizeRedirectPath(context.url.searchParams.get('redirect'));

        const session = await sessionStore.createSession({ role, tenant });
        const callbackUrl = `${config.frontendOrigin}/auth/callback?token=${encodeURIComponent(
          session.token
        )}&redirect=${encodeURIComponent(redirectTarget)}`;

        sendRedirect(response, context, config, callbackUrl);
        return true;
      }

      if (context.method !== 'POST') {
        const allowedMethods = config.environment === 'production' ? ['POST'] : ['GET', 'POST'];
        sendMethodNotAllowed(response, context, config, allowedMethods, baseExtraHeaders);
        return true;
      }

      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }

      const payload = await parseJsonBody(context, response, baseExtraHeaders);
      if (!payload) {
        return true;
      }

      if (
        !validateBodyShape(context, response, baseExtraHeaders, payload, {
          required: ['email', 'password'],
          optional: ['tenant'],
        })
      ) {
        return true;
      }

      if (!(await enforceAuthIdentityRateLimit(context, response, baseExtraHeaders, context.path, payload))) {
        return true;
      }

      try {
        const authResult = await loginWithPassword(config, payload, actorMetaFromContext(context, null));
        sendJson(response, context, config, 200, authResult, attachAuthCookies(baseExtraHeaders, authResult.tokens));
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // ── POST /v1/auth/register ──
    if (context.path === '/v1/auth/register') {
      if (context.method !== 'POST') {
        sendMethodNotAllowed(response, context, config, ['POST'], baseExtraHeaders);
        return true;
      }

      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }

      const payload = await parseJsonBody(context, response, baseExtraHeaders);
      if (!payload) {
        return true;
      }

      if (
        !validateBodyShape(context, response, baseExtraHeaders, payload, {
          required: ['email', 'password'],
          optional: ['tenant', 'displayName', 'role'],
        })
      ) {
        return true;
      }

      if (!(await enforceAuthIdentityRateLimit(context, response, baseExtraHeaders, context.path, payload))) {
        return true;
      }

      const session = await getSessionFromContext(context);
      const isAdmin = hasRole(session, 'tenant_admin');

      try {
        const createdUser = await registerUser(
          config,
          payload,
          actorMetaFromContext(context, session, {
            isAdmin,
            actorRole: session?.user?.role || null,
            actorTenant: session?.user?.tenant || null,
            publicFingerprint: resolvePublicAuthFingerprint(context),
          })
        );
        sendJson(response, context, config, 201, createdUser, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // ── OAuth initiation: GET /v1/auth/oauth/:provider ──
    const oauthInitMatch = context.path.match(/^\/v1\/auth\/oauth\/([a-z]+)$/);
    if (oauthInitMatch && !context.path.includes('/callback')) {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }

      const providerName = oauthInitMatch[1];
      if (!isValidOAuthProvider(providerName)) {
        sendError(response, context, config, 400, 'invalid_oauth_provider', `Unknown OAuth provider: ${providerName}`, null, baseExtraHeaders);
        return true;
      }

      let tenant;
      try {
        tenant = resolvePublicOAuthTenant(context.url.searchParams.get('tenant'));
      } catch (error) {
        if (error instanceof ServiceError) {
          response.writeHead(302, {
            ...baseHeaders(context, config, baseExtraHeaders),
            Location: buildAuthErrorLocation(error.code, providerName, error.message),
            'Cache-Control': 'no-store',
          });
          response.end();
          return true;
        }
        handleServiceFailure(error, response, context, baseExtraHeaders);
        return true;
      }
      const rawReturnTo = String(context.url.searchParams.get('returnTo') || '/platform/threat-command').trim();
      const returnTo = sanitizeRedirectPath(rawReturnTo) || '/platform/threat-command';
      const state = generateOAuthState();
      const redirectUri = `${config.oauthCallbackBaseUrl}/api/v1/auth/oauth/${providerName}/callback`;

      const pkce = supportsPkce(providerName) ? generatePkceChallenge() : null;

      const secureSuffix = config.authCookieSecure ? '; Secure' : '';
      const oauthCookies = [
        `ct_oauth_state=${state}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600${secureSuffix}`,
        `ct_oauth_tenant=${tenant}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600${secureSuffix}`,
        `ct_oauth_return=${encodeURIComponent(returnTo)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600${secureSuffix}`,
      ];
      if (pkce) {
        oauthCookies.push(`ct_oauth_pkce=${pkce.verifier}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600${secureSuffix}`);
      }

      try {
        const authResult = await buildAuthorizationUrl(config, providerName, redirectUri, state, pkce ? pkce.challenge : null);
        if (authResult.nonce) {
          oauthCookies.push(`ct_oauth_nonce=${authResult.nonce}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600${secureSuffix}`);
        }
        response.writeHead(302, {
          ...baseHeaders(context, config, baseExtraHeaders),
          Location: authResult.url,
          'Set-Cookie': oauthCookies,
          'Cache-Control': 'no-store',
        });
        response.end();
      } catch (error) {
        if (error instanceof ServiceError) {
          response.writeHead(302, {
            ...baseHeaders(context, config, baseExtraHeaders),
            Location: buildAuthErrorLocation(
              error.code || 'oauth_error',
              providerName,
              error.message || 'OAuth provider is not configured.',
              tenant
            ),
            'Cache-Control': 'no-store',
          });
          response.end();
          return true;
        }
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // ── OAuth callback: GET /v1/auth/oauth/:provider/callback ──
    const oauthCallbackMatch = context.path.match(/^\/v1\/auth\/oauth\/([a-z]+)\/callback$/);
    if (oauthCallbackMatch) {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }

      const providerName = oauthCallbackMatch[1];
      if (!isValidOAuthProvider(providerName)) {
        sendError(response, context, config, 400, 'invalid_oauth_provider', `Unknown OAuth provider: ${providerName}`, null, baseExtraHeaders);
        return true;
      }

      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }

      const code = String(context.url.searchParams.get('code') || '').trim();
      const returnedState = String(context.url.searchParams.get('state') || '').trim();
      const errorParam = String(context.url.searchParams.get('error') || '').trim();

      if (errorParam) {
        response.writeHead(302, {
          ...baseHeaders(context, config, baseExtraHeaders),
          Location: buildAuthErrorLocation(errorParam, providerName),
          'Cache-Control': 'no-store',
        });
        response.end();
        return true;
      }

      const cookies = parseRequestCookies(context.request);
      const savedState = String(cookies.ct_oauth_state || '').trim();
      const savedTenantRaw = String(cookies.ct_oauth_tenant || '').trim();
      const savedReturnTo = decodeURIComponent(String(cookies.ct_oauth_return || '/platform/threat-command').trim());
      const savedPkceVerifier = String(cookies.ct_oauth_pkce || '').trim() || null;
      const savedNonce = String(cookies.ct_oauth_nonce || '').trim() || null;

      let savedTenant;
      try {
        savedTenant = resolvePublicOAuthTenant(savedTenantRaw);
      } catch (error) {
        if (error instanceof ServiceError) {
          response.writeHead(302, {
            ...baseHeaders(context, config, baseExtraHeaders),
            Location: buildAuthErrorLocation(error.code, providerName, error.message),
            'Cache-Control': 'no-store',
          });
          response.end();
          return true;
        }
        handleServiceFailure(error, response, context, baseExtraHeaders);
        return true;
      }

      if (!code || !returnedState || returnedState !== savedState) {
        response.writeHead(302, {
          ...baseHeaders(context, config, baseExtraHeaders),
          Location: buildAuthErrorLocation('oauth_state_mismatch', providerName, null, savedTenant),
          'Cache-Control': 'no-store',
        });
        response.end();
        return true;
      }

      try {
        const redirectUri = `${config.oauthCallbackBaseUrl}/api/v1/auth/oauth/${providerName}/callback`;
        const providerTokens = await exchangeCodeForTokens(config, providerName, code, redirectUri, savedPkceVerifier);
        const profile = await fetchUserProfile(config, providerName, providerTokens.accessToken, providerTokens.idToken, savedNonce);

        if (!profile.email) {
          response.writeHead(302, {
            ...baseHeaders(context, config, baseExtraHeaders),
            Location: buildAuthErrorLocation('no_email_from_provider', providerName, null, savedTenant),
            'Cache-Control': 'no-store',
          });
          response.end();
          return true;
        }

        const result = await findOrCreateOAuthUser(config, {
          tenant: savedTenant,
          email: profile.email,
          displayName: profile.displayName,
          provider: providerName,
          providerId: profile.providerId,
          emailVerified: profile.emailVerified,
        }, actorMetaFromContext(context, null, {
          isAdmin: false,
          publicFingerprint: resolvePublicAuthFingerprint(context),
        }));

        const authHeaders = attachAuthCookies(baseExtraHeaders, result.tokens);
        const clearSecureSuffix = config.authCookieSecure ? '; Secure' : '';
        const clearStateCookie = `ct_oauth_state=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${clearSecureSuffix}`;
        const clearTenantCookie = `ct_oauth_tenant=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${clearSecureSuffix}`;
        const clearReturnCookie = `ct_oauth_return=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${clearSecureSuffix}`;
        const clearPkceCookie = `ct_oauth_pkce=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${clearSecureSuffix}`;
        const existingCookies = Array.isArray(authHeaders['Set-Cookie']) ? authHeaders['Set-Cookie'] : [authHeaders['Set-Cookie']].filter(Boolean);

        const role = result.user.role || 'executive_viewer';
        const sanitizedReturnTo = sanitizeRedirectPath(savedReturnTo) || '/platform/threat-command';
        const targetUrl = `${sanitizedReturnTo}${sanitizedReturnTo.includes('?') ? '&' : '?'}tenant=${encodeURIComponent(savedTenant)}&role=${role}`;

        response.writeHead(302, {
          ...baseHeaders(context, config, authHeaders),
          'Set-Cookie': [...existingCookies, clearStateCookie, clearTenantCookie, clearReturnCookie, clearPkceCookie],
          Location: targetUrl,
          'Cache-Control': 'no-store',
        });
        response.end();
      } catch (error) {
        if (error instanceof ServiceError) {
          response.writeHead(302, {
            ...baseHeaders(context, config, baseExtraHeaders),
            Location: buildAuthErrorLocation(
              error.code || 'oauth_error',
              providerName,
              error.message || 'Authentication failed.',
              savedTenant
            ),
            'Cache-Control': 'no-store',
          });
          response.end();
          return true;
        }
        const fallbackMessage = 'An unexpected error occurred during authentication. Please try again.';
        response.writeHead(302, {
          ...baseHeaders(context, config, baseExtraHeaders),
          Location: buildAuthErrorLocation(
            'oauth_internal_error',
            providerName,
            fallbackMessage,
            savedTenant
          ),
          'Cache-Control': 'no-store',
        });
        response.end();
      }
      return true;
    }

    // ── POST /v1/auth/token ──
    if (context.path === '/v1/auth/token') {
      if (context.method !== 'POST') {
        sendMethodNotAllowed(response, context, config, ['POST'], baseExtraHeaders);
        return true;
      }

      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }

      const payload = await parseJsonBody(context, response, baseExtraHeaders);
      if (!payload) {
        return true;
      }

      if (
        !validateBodyShape(context, response, baseExtraHeaders, payload, {
          required: ['grantType'],
          optional: ['refreshToken'],
        })
      ) {
        return true;
      }

      const grantType = String(payload.grantType || 'refresh_token').toLowerCase().trim();
      if (grantType !== 'refresh_token') {
        sendError(
          response,
          context,
          config,
          400,
          'invalid_grant_type',
          'Only refresh_token grant is supported.',
          null,
          baseExtraHeaders
        );
        return true;
      }

      const refreshTokenFromCookie = getRefreshTokenFromContext(context);
      const refreshToken = String(payload.refreshToken || refreshTokenFromCookie || '').trim();
      if (!refreshToken) {
        sendError(
          response,
          context,
          config,
          401,
          'invalid_refresh_token',
          'Refresh token is required.',
          null,
          baseExtraHeaders
        );
        return true;
      }

      const identityPayload = {
        ...payload,
        refreshToken,
      };
      if (!(await enforceAuthIdentityRateLimit(context, response, baseExtraHeaders, context.path, identityPayload))) {
        return true;
      }

      try {
        const rotated = await rotateRefreshToken(
          config,
          {
            grantType: 'refresh_token',
            refreshToken,
          },
          actorMetaFromContext(context, null)
        );
        sendJson(response, context, config, 200, rotated, attachAuthCookies(baseExtraHeaders, rotated.tokens));
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // ── POST /v1/auth/password/forgot ──
    if (context.path === '/v1/auth/password/forgot') {
      if (context.method !== 'POST') {
        sendMethodNotAllowed(response, context, config, ['POST'], baseExtraHeaders);
        return true;
      }

      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }

      const payload = await parseJsonBody(context, response, baseExtraHeaders);
      if (!payload) {
        return true;
      }

      if (
        !validateBodyShape(context, response, baseExtraHeaders, payload, {
          required: ['email'],
          optional: ['tenant'],
        })
      ) {
        return true;
      }

      if (!(await enforceAuthIdentityRateLimit(context, response, baseExtraHeaders, context.path, payload))) {
        return true;
      }

      try {
        const resetRequest = await requestPasswordReset(config, payload, actorMetaFromContext(context, null));
        sendJson(response, context, config, 200, resetRequest, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // ── POST /v1/auth/password/reset ──
    if (context.path === '/v1/auth/password/reset') {
      if (context.method !== 'POST') {
        sendMethodNotAllowed(response, context, config, ['POST'], baseExtraHeaders);
        return true;
      }

      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }

      const payload = await parseJsonBody(context, response, baseExtraHeaders);
      if (!payload) {
        return true;
      }

      if (
        !validateBodyShape(context, response, baseExtraHeaders, payload, {
          required: ['tenant', 'resetToken', 'newPassword'],
          optional: [],
        })
      ) {
        return true;
      }

      if (!(await enforceAuthIdentityRateLimit(context, response, baseExtraHeaders, context.path, payload))) {
        return true;
      }

      try {
        const resetResult = await resetPassword(config, payload, actorMetaFromContext(context, null));
        sendJson(response, context, config, 200, resetResult, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // ── GET /v1/auth/me ──
    if (context.path === '/v1/auth/me') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }

      const session = await requireSession(context, response, baseExtraHeaders);
      if (!session) {
        return true;
      }

      sendJson(
        response,
        context,
        config,
        200,
        {
          ...session.user,
          expiresAt: new Date(session.expiresAt).toISOString(),
        },
        baseExtraHeaders
      );
      return true;
    }

    // ── POST /v1/auth/logout ──
    if (context.path === '/v1/auth/logout') {
      if (context.method !== 'POST') {
        sendMethodNotAllowed(response, context, config, ['POST'], baseExtraHeaders);
        return true;
      }

      const payload = await parseJsonBody(context, response, baseExtraHeaders, { allowEmpty: true });
      if (!payload) {
        return true;
      }

      if (
        !validateBodyShape(context, response, baseExtraHeaders, payload, {
          required: [],
          optional: ['refreshToken', 'tenant'],
        })
      ) {
        return true;
      }

      const session = await getSessionFromContext(context);
      const refreshTokenFromCookie = getRefreshTokenFromContext(context);
      const refreshToken = String(payload.refreshToken || refreshTokenFromCookie || '').trim();
      if (!session && !refreshToken) {
        sendAuthRequired(response, context, baseExtraHeaders, 'Missing bearer token or refresh token for logout');
        return true;
      }

      if (session && config.authMode === 'demo') {
        await sessionStore.invalidateSession(session.token);
      }

      const accessToken = getAccessTokenFromContext(context);
      if (session && accessToken && session.authType === 'jwt') {
        const contextMeta = actorMetaFromContext(context, session);
        const fallbackExpiry = Number(session.expiresAt) || Date.now() + config.authTokenTtlMs;
        const expiresAtMs = parseJwtExpiryMs(accessToken, fallbackExpiry);
        const tokenHash = hashAccessToken(accessToken);

        rememberRevokedAccessTokenHash(tokenHash, expiresAtMs);
        try {
          await persistRevokedAccessToken({
            session,
            tokenHash,
            expiresAtMs,
            contextMeta,
          });
        } catch (error) {
          log('warn', 'auth.access_token_revoke_persist_failed', {
            error: error instanceof Error ? error.message : 'unknown revoke persistence failure',
            requestId: context.requestId,
          });
        }
      }

      if (refreshToken) {
        if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
          return true;
        }

        try {
          await revokeRefreshToken(
            config,
            {
              refreshToken,
              tenant: payload.tenant || session?.user?.tenant || 'global',
            },
            actorMetaFromContext(context, session)
          );
        } catch (error) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
          return true;
        }
      }

      // SECURITY FIX: Audit log the logout event
      if (appendAuditLog) {
        const meta = actorMetaFromContext(context, session);
        appendAuditLog(config, {
          tenantSlug: session?.user?.tenant || 'global',
          actorId: session?.user?.id || meta?.actorId || 'unknown',
          actorEmail: session?.user?.email || meta?.actorEmail || 'unknown',
          action: 'auth.logout',
          targetType: 'session',
          targetId: session?.user?.id || 'unknown',
          ipAddress: meta?.ipAddress || context.ip,
          userAgent: meta?.userAgent || '',
          traceId: context.requestId,
          payload: {},
        }).catch(() => {});
      }

      sendNoContent(response, context, config, attachClearAuthCookies(baseExtraHeaders));
      return true;
    }

    return false;
  });
}

module.exports = { registerRoutes };
