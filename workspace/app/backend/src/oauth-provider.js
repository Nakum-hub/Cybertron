/**
 * OAuth2 provider abstraction for Google, Microsoft, GitHub, and generic OIDC.
 *
 * Handles authorization URL construction, code exchange, and profile
 * fetching.  Fail-closed: all operations throw ServiceError when the
 * provider is not configured.
 *
 * OIDC provider uses OpenID Connect Discovery to resolve endpoints at
 * runtime from the issuer URL, enabling integration with any compliant
 * IdP (Auth0, Okta, Keycloak, Azure AD, etc.).
 */

'use strict';

const crypto = require('node:crypto');
const { ServiceError } = require('./auth-service');

// ── OIDC discovery cache (keyed by issuerUrl for multi-tenant support) ──

const OIDC_CACHE_TTL_MS = 300_000;
const OIDC_CACHE_MAX_ENTRIES = 50;
const oidcDiscoveryCache = new Map(); // key: normalized issuerUrl, value: { config, fetchedAt }

async function fetchOidcDiscovery(issuerUrl) {
    const now = Date.now();
    const cacheKey = issuerUrl.replace(/\/+$/, '');
    const cached = oidcDiscoveryCache.get(cacheKey);
    if (cached && now - cached.fetchedAt < OIDC_CACHE_TTL_MS) {
        return cached.config;
    }

    const wellKnownUrl = `${cacheKey}/.well-known/openid-configuration`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);

    try {
        const response = await fetch(wellKnownUrl, {
            headers: { Accept: 'application/json' },
            signal: controller.signal,
        });

        if (!response.ok) {
            throw new ServiceError(
                502,
                'oidc_discovery_failed',
                `OIDC discovery request failed: ${response.status}`
            );
        }

        const data = await response.json();
        if (!data.authorization_endpoint || !data.token_endpoint) {
            throw new ServiceError(
                502,
                'oidc_discovery_invalid',
                'OIDC discovery document is missing required endpoints.'
            );
        }

        // Evict oldest entry if cache is full
        if (oidcDiscoveryCache.size >= OIDC_CACHE_MAX_ENTRIES) {
            const oldestKey = oidcDiscoveryCache.keys().next().value;
            oidcDiscoveryCache.delete(oldestKey);
        }

        oidcDiscoveryCache.set(cacheKey, { config: data, fetchedAt: now });
        return data;
    } finally {
        clearTimeout(timeout);
    }
}

// ── provider definitions ──

const PROVIDERS = {
    google: {
        authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
        tokenUrl: 'https://oauth2.googleapis.com/token',
        profileUrl: 'https://www.googleapis.com/oauth2/v2/userinfo',
        scope: 'openid email profile',
        envClientId: 'GOOGLE_CLIENT_ID',
        envClientSecret: 'GOOGLE_CLIENT_SECRET',
    },
    microsoft: {
        authorizeUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
        tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
        profileUrl: 'https://graph.microsoft.com/v1.0/me',
        scope: 'openid email profile User.Read',
        envClientId: 'MICROSOFT_CLIENT_ID',
        envClientSecret: 'MICROSOFT_CLIENT_SECRET',
    },
    github: {
        authorizeUrl: 'https://github.com/login/oauth/authorize',
        tokenUrl: 'https://github.com/login/oauth/access_token',
        profileUrl: 'https://api.github.com/user',
        emailsUrl: 'https://api.github.com/user/emails',
        scope: 'read:user user:email',
        envClientId: 'GITHUB_CLIENT_ID',
        envClientSecret: 'GITHUB_CLIENT_SECRET',
    },
};

const VALID_PROVIDERS = new Set([...Object.keys(PROVIDERS), 'oidc']);

function isValidProvider(name) {
    return VALID_PROVIDERS.has(String(name || '').toLowerCase().trim());
}

function getProviderDef(name) {
    const key = String(name || '').toLowerCase().trim();
    if (key === 'oidc') {
        return { key: 'oidc' };
    }
    const def = PROVIDERS[key];
    if (!def) {
        throw new ServiceError(400, 'invalid_oauth_provider', `Unknown OAuth provider: ${key}`);
    }
    return { key, ...def };
}

function getProviderCredentials(config, providerKey) {
    if (providerKey === 'oidc') {
        const clientId = config.oidcClientId || '';
        const clientSecret = config.oidcClientSecret || '';
        if (!clientId || !clientSecret) {
            throw new ServiceError(
                503,
                'oidc_not_configured',
                'OIDC is not configured. Set OIDC_ISSUER_URL, OIDC_CLIENT_ID, and OIDC_CLIENT_SECRET environment variables.'
            );
        }
        return { clientId, clientSecret };
    }

    const def = PROVIDERS[providerKey];
    if (!def) {
        throw new ServiceError(400, 'invalid_oauth_provider', `Unknown OAuth provider: ${providerKey}`);
    }

    const clientId = config[`${providerKey}ClientId`] || process.env[def.envClientId] || '';
    const clientSecret = config[`${providerKey}ClientSecret`] || process.env[def.envClientSecret] || '';

    if (!clientId || !clientSecret) {
        throw new ServiceError(
            503,
            'oauth_not_configured',
            `${providerKey} OAuth is not configured. Set ${def.envClientId} and ${def.envClientSecret} environment variables.`
        );
    }

    return { clientId, clientSecret };
}

// ── state management ──

function generateOAuthState() {
    return crypto.randomBytes(32).toString('hex');
}

// ── PKCE support ──

function generatePkceChallenge() {
    const verifier = crypto.randomBytes(32).toString('base64url');
    const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
    return { verifier, challenge };
}

// Providers that support PKCE (GitHub does not)
const PKCE_PROVIDERS = new Set(['google', 'microsoft', 'oidc']);

function supportsPkce(providerKey) {
    return PKCE_PROVIDERS.has(providerKey);
}

// ── authorization URL ──

async function buildAuthorizationUrl(config, providerName, redirectUri, state, pkceChallenge) {
    const provider = getProviderDef(providerName);
    const { clientId } = getProviderCredentials(config, provider.key);

    let authorizeUrl;
    let scope;

    if (provider.key === 'oidc') {
        if (!config.oidcIssuerUrl) {
            throw new ServiceError(503, 'oidc_not_configured', 'OIDC_ISSUER_URL is not set.');
        }
        const discovery = await fetchOidcDiscovery(config.oidcIssuerUrl);
        authorizeUrl = discovery.authorization_endpoint;
        scope = config.oidcScopes || 'openid email profile';
    } else {
        authorizeUrl = provider.authorizeUrl;
        scope = provider.scope;
    }

    const params = new URLSearchParams({
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope,
        state,
    });

    // Google: prompt for account selection
    if (provider.key === 'google') {
        params.set('prompt', 'select_account');
        params.set('access_type', 'offline');
    }

    // Microsoft: prompt for account selection
    if (provider.key === 'microsoft') {
        params.set('prompt', 'select_account');
        params.set('response_mode', 'query');
    }

    // OIDC: request nonce for ID token validation
    let nonce;
    if (provider.key === 'oidc') {
        nonce = crypto.randomBytes(16).toString('hex');
        params.set('nonce', nonce);
    }

    // PKCE: attach code_challenge for providers that support it
    if (pkceChallenge && supportsPkce(provider.key)) {
        params.set('code_challenge', pkceChallenge);
        params.set('code_challenge_method', 'S256');
    }

    return { url: `${authorizeUrl}?${params.toString()}`, nonce: nonce || null };
}

// ── code exchange ──

async function exchangeCodeForTokens(config, providerName, code, redirectUri, codeVerifier) {
    const provider = getProviderDef(providerName);
    const { clientId, clientSecret } = getProviderCredentials(config, provider.key);

    let tokenUrl;
    if (provider.key === 'oidc') {
        if (!config.oidcIssuerUrl) {
            throw new ServiceError(503, 'oidc_not_configured', 'OIDC_ISSUER_URL is not set.');
        }
        const discovery = await fetchOidcDiscovery(config.oidcIssuerUrl);
        tokenUrl = discovery.token_endpoint;
    } else {
        tokenUrl = provider.tokenUrl;
    }

    const body = new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        code,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code',
    });

    // PKCE: attach code_verifier if available
    if (codeVerifier && supportsPkce(provider.key)) {
        body.set('code_verifier', codeVerifier);
    }

    const headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
    };

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15_000);

    let response;
    try {
        response = await fetch(tokenUrl, {
            method: 'POST',
            headers,
            body: body.toString(),
            signal: controller.signal,
        });
    } catch (err) {
        if (err.name === 'AbortError') {
            throw new ServiceError(504, 'oauth_token_exchange_timeout', `Token exchange with ${provider.key} timed out.`);
        }
        throw err;
    } finally {
        clearTimeout(timeout);
    }

    if (!response.ok) {
        const errorText = await response.text().catch(() => '');
        throw new ServiceError(
            502,
            'oauth_token_exchange_failed',
            `Failed to exchange authorization code with ${provider.key}: ${response.status} ${errorText.slice(0, 200)}`
        );
    }

    const data = await response.json();
    return {
        accessToken: data.access_token || '',
        refreshToken: data.refresh_token || '',
        idToken: data.id_token || '',
        tokenType: data.token_type || 'Bearer',
        expiresIn: Number(data.expires_in || 3600),
    };
}

// ── profile fetching ──

const PROFILE_TIMEOUT_MS = 10_000;

async function fetchGoogleProfile(accessToken) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), PROFILE_TIMEOUT_MS);
    try {
        const response = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
            headers: { Authorization: `Bearer ${accessToken}` },
            signal: controller.signal,
        });

        if (!response.ok) {
            throw new ServiceError(502, 'oauth_profile_failed', 'Failed to fetch Google profile.');
        }

        const data = await response.json();
        return {
            email: String(data.email || '').toLowerCase().trim(),
            displayName: data.name || '',
            avatarUrl: data.picture || '',
            providerId: String(data.id || ''),
            emailVerified: typeof data.verified_email === 'boolean' ? data.verified_email : null,
        };
    } catch (err) {
        if (err.name === 'AbortError') {
            throw new ServiceError(504, 'oauth_profile_timeout', 'Google profile request timed out.');
        }
        throw err;
    } finally {
        clearTimeout(timeout);
    }
}

async function fetchMicrosoftProfile(accessToken) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), PROFILE_TIMEOUT_MS);
    try {
        const response = await fetch('https://graph.microsoft.com/v1.0/me', {
            headers: { Authorization: `Bearer ${accessToken}` },
            signal: controller.signal,
        });

        if (!response.ok) {
            throw new ServiceError(502, 'oauth_profile_failed', 'Failed to fetch Microsoft profile.');
        }

        const data = await response.json();
        return {
            email: String(data.mail || data.userPrincipalName || '').toLowerCase().trim(),
            displayName: data.displayName || '',
            avatarUrl: '',
            providerId: String(data.id || ''),
            emailVerified: null,
        };
    } catch (err) {
        if (err.name === 'AbortError') {
            throw new ServiceError(504, 'oauth_profile_timeout', 'Microsoft profile request timed out.');
        }
        throw err;
    } finally {
        clearTimeout(timeout);
    }
}

async function fetchGithubProfile(accessToken) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), PROFILE_TIMEOUT_MS);
    try {
        const ghHeaders = {
            Authorization: `Bearer ${accessToken}`,
            Accept: 'application/vnd.github+json',
            'User-Agent': 'Cybertron-Auth',
        };
        const [profileResponse, emailsResponse] = await Promise.all([
            fetch('https://api.github.com/user', { headers: ghHeaders, signal: controller.signal }),
            fetch('https://api.github.com/user/emails', { headers: ghHeaders, signal: controller.signal }),
        ]);

        if (!profileResponse.ok) {
            throw new ServiceError(502, 'oauth_profile_failed', 'Failed to fetch GitHub profile.');
        }

        const profile = await profileResponse.json();
        let email = '';
        let emailVerified = false;

        // GitHub may not return email in the profile; fetch from emails endpoint
        if (emailsResponse.ok) {
            const emails = await emailsResponse.json();
            if (Array.isArray(emails)) {
                const primary = emails.find(e => e.primary && e.verified);
                const verified = emails.find(e => e.verified);
                const selected = primary || verified || null;
                email = String(selected?.email || '').toLowerCase().trim();
                emailVerified = Boolean(selected?.verified);
            }
        }

        return {
            email,
            displayName: profile.name || profile.login || '',
            avatarUrl: profile.avatar_url || '',
            providerId: String(profile.id || ''),
            emailVerified,
        };
    } catch (err) {
        if (err.name === 'AbortError') {
            throw new ServiceError(504, 'oauth_profile_timeout', 'GitHub profile request timed out.');
        }
        throw err;
    } finally {
        clearTimeout(timeout);
    }
}

async function fetchOidcProfile(config, accessToken, idToken, expectedNonce) {
    // Always fetch from the userinfo endpoint for verified claims.
    // The ID token signature cannot be verified without a JWKS library,
    // so we do not trust its claims. We only inspect it for nonce validation.
    if (idToken && expectedNonce) {
        try {
            const [, payloadB64] = idToken.split('.');
            if (payloadB64) {
                const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
                if (payload.nonce !== expectedNonce) {
                    throw new ServiceError(401, 'oidc_nonce_mismatch', 'OIDC nonce does not match. Possible replay attack.');
                }
            }
        } catch (err) {
            if (err instanceof ServiceError) throw err;
            // ID token parsing failed — continue to userinfo
        }
    }

    // Fetch verified claims from userinfo endpoint
    if (!config.oidcIssuerUrl) {
        throw new ServiceError(502, 'oidc_profile_failed', 'Cannot fetch OIDC profile without issuer URL.');
    }

    const discovery = await fetchOidcDiscovery(config.oidcIssuerUrl);
    if (!discovery.userinfo_endpoint) {
        throw new ServiceError(502, 'oidc_profile_failed', 'OIDC provider does not expose a userinfo endpoint.');
    }

    const oidcController = new AbortController();
    const oidcTimeout = setTimeout(() => oidcController.abort(), PROFILE_TIMEOUT_MS);

    try {
        const response = await fetch(discovery.userinfo_endpoint, {
            headers: { Authorization: `Bearer ${accessToken}` },
            signal: oidcController.signal,
        });

        if (!response.ok) {
            throw new ServiceError(502, 'oidc_profile_failed', `Failed to fetch OIDC userinfo: ${response.status}`);
        }

        const data = await response.json();
        return {
            email: String(data.email || '').toLowerCase().trim(),
            displayName: data.name || data.preferred_username || '',
            avatarUrl: data.picture || '',
            providerId: String(data.sub || ''),
            emailVerified: typeof data.email_verified === 'boolean' ? data.email_verified : null,
        };
    } catch (err) {
        if (err.name === 'AbortError') {
            throw new ServiceError(504, 'oauth_profile_timeout', 'OIDC userinfo request timed out.');
        }
        throw err;
    } finally {
        clearTimeout(oidcTimeout);
    }
}

async function fetchUserProfile(config, providerName, accessToken, idToken, expectedNonce) {
    const provider = getProviderDef(providerName);

    switch (provider.key) {
        case 'google':
            return fetchGoogleProfile(accessToken);
        case 'microsoft':
            return fetchMicrosoftProfile(accessToken);
        case 'github':
            return fetchGithubProfile(accessToken);
        case 'oidc':
            return fetchOidcProfile(config, accessToken, idToken, expectedNonce);
        default:
            throw new ServiceError(400, 'invalid_oauth_provider', `Unknown provider: ${provider.key}`);
    }
}

module.exports = {
    isValidProvider,
    generateOAuthState,
    generatePkceChallenge,
    supportsPkce,
    buildAuthorizationUrl,
    exchangeCodeForTokens,
    fetchUserProfile,
    fetchOidcDiscovery,
    VALID_PROVIDERS,
};
