const crypto = require('node:crypto');
const { normalizeRole } = require('./platform-registry');
const { sanitizeTenant } = require('./validators');

function fromBase64Url(input) {
  const value = String(input || '').replace(/-/g, '+').replace(/_/g, '/');
  const padding = (4 - (value.length % 4)) % 4;
  return Buffer.from(value + '='.repeat(padding), 'base64');
}

function parseJsonSegment(segment) {
  try {
    return JSON.parse(fromBase64Url(segment).toString('utf8'));
  } catch {
    return null;
  }
}

function isAudienceMatch(tokenAudience, expectedAudience) {
  if (!expectedAudience) {
    // If no audience is configured, accept tokens without audience or with any audience,
    // but REJECT tokens that explicitly claim an audience (prevents cross-service replay).
    return tokenAudience === undefined || tokenAudience === null;
  }

  if (typeof tokenAudience === 'string') {
    return tokenAudience === expectedAudience;
  }

  return Array.isArray(tokenAudience) && tokenAudience.includes(expectedAudience);
}

function verifyJwtHs256(token, config) {
  if (!config.jwtSecret) {
    return { session: null, reason: 'missing_jwt_secret' };
  }

  const parts = String(token || '').split('.');
  if (parts.length !== 3) {
    return { session: null, reason: 'malformed_jwt' };
  }

  const [headerPart, payloadPart, signaturePart] = parts;
  const header = parseJsonSegment(headerPart);
  const payload = parseJsonSegment(payloadPart);

  if (!header || !payload) {
    return { session: null, reason: 'invalid_jwt_json' };
  }

  if (header.alg !== 'HS256') {
    return { session: null, reason: 'unsupported_jwt_alg' };
  }

  const signingInput = `${headerPart}.${payloadPart}`;
  const expectedSignature = crypto
    .createHmac('sha256', config.jwtSecret)
    .update(signingInput)
    .digest();
  const tokenSignature = fromBase64Url(signaturePart);

  if (
    expectedSignature.length !== tokenSignature.length ||
    !crypto.timingSafeEqual(expectedSignature, tokenSignature)
  ) {
    return { session: null, reason: 'invalid_jwt_signature' };
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  const skew = Math.max(0, Number(config.jwtClockSkewSeconds || 0));

  if (typeof payload.nbf === 'number' && nowSeconds + skew < payload.nbf) {
    return { session: null, reason: 'jwt_not_yet_valid' };
  }

  // SECURITY: Require exp claim -- tokens without expiration are rejected
  if (typeof payload.exp !== 'number') {
    return { session: null, reason: 'missing_jwt_exp' };
  }

  if (nowSeconds - skew >= payload.exp) {
    return { session: null, reason: 'jwt_expired' };
  }

  if (config.jwtIssuer && payload.iss !== config.jwtIssuer) {
    return { session: null, reason: 'invalid_jwt_issuer' };
  }

  // When no issuer is configured, reject tokens that claim one (prevents cross-service replay)
  if (!config.jwtIssuer && payload.iss) {
    return { session: null, reason: 'unexpected_jwt_issuer' };
  }

  if (!isAudienceMatch(payload.aud, config.jwtAudience)) {
    return { session: null, reason: 'invalid_jwt_audience' };
  }

  const role = normalizeRole(payload.role || payload['https://cybertron.io/role']);
  const tenant = sanitizeTenant(payload.tenant || payload.org || payload['https://cybertron.io/tenant']);
  const userId = String(payload.sub || payload.uid || `user-${tenant}-${role}`);

  return {
    session: {
      token,
      createdAt: typeof payload.iat === 'number' ? payload.iat * 1000 : Date.now(),
      expiresAt: payload.exp * 1000,
      user: {
        id: userId,
        name: payload.name || 'Cybertron User',
        email: payload.email || `${role}.${tenant}@cybertron.local`,
        role,
        tenant,
        createdAt:
          typeof payload.iat === 'number'
            ? new Date(payload.iat * 1000).toISOString()
            : new Date().toISOString(),
      },
      authType: 'jwt',
    },
    reason: null,
  };
}

function verifyJwtRs256(token, config) {
  if (!config.jwtPublicKey) {
    return { session: null, reason: 'missing_jwt_public_key' };
  }

  const parts = String(token || '').split('.');
  if (parts.length !== 3) {
    return { session: null, reason: 'malformed_jwt' };
  }

  const [headerPart, payloadPart, signaturePart] = parts;
  const header = parseJsonSegment(headerPart);
  const payload = parseJsonSegment(payloadPart);

  if (!header || !payload) {
    return { session: null, reason: 'invalid_jwt_json' };
  }

  if (header.alg !== 'RS256') {
    return { session: null, reason: 'unsupported_jwt_alg' };
  }

  const signingInput = `${headerPart}.${payloadPart}`;
  const tokenSignature = fromBase64Url(signaturePart);

  try {
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(signingInput);
    const valid = verifier.verify(config.jwtPublicKey, tokenSignature);
    if (!valid) {
      return { session: null, reason: 'invalid_jwt_signature' };
    }
  } catch {
    return { session: null, reason: 'invalid_jwt_signature' };
  }

  // Reuse the same claim validation logic
  const nowSeconds = Math.floor(Date.now() / 1000);
  const skew = Math.max(0, Number(config.jwtClockSkewSeconds || 0));

  if (typeof payload.nbf === 'number' && nowSeconds + skew < payload.nbf) {
    return { session: null, reason: 'jwt_not_yet_valid' };
  }

  // SECURITY: Require exp claim -- tokens without expiration are rejected
  if (typeof payload.exp !== 'number') {
    return { session: null, reason: 'missing_jwt_exp' };
  }

  if (nowSeconds - skew >= payload.exp) {
    return { session: null, reason: 'jwt_expired' };
  }

  if (config.jwtIssuer && payload.iss !== config.jwtIssuer) {
    return { session: null, reason: 'invalid_jwt_issuer' };
  }

  if (!config.jwtIssuer && payload.iss) {
    return { session: null, reason: 'unexpected_jwt_issuer' };
  }

  if (!isAudienceMatch(payload.aud, config.jwtAudience)) {
    return { session: null, reason: 'invalid_jwt_audience' };
  }

  const role = normalizeRole(payload.role || payload['https://cybertron.io/role']);
  const tenant = sanitizeTenant(payload.tenant || payload.org || payload['https://cybertron.io/tenant']);
  const userId = String(payload.sub || payload.uid || `user-${tenant}-${role}`);

  return {
    session: {
      token,
      createdAt: typeof payload.iat === 'number' ? payload.iat * 1000 : Date.now(),
      expiresAt: payload.exp * 1000,
      user: {
        id: userId,
        name: payload.name || 'Cybertron User',
        email: payload.email || `${role}.${tenant}@cybertron.local`,
        role,
        tenant,
        createdAt:
          typeof payload.iat === 'number'
            ? new Date(payload.iat * 1000).toISOString()
            : new Date().toISOString(),
      },
      authType: 'jwt',
    },
    reason: null,
  };
}

async function resolveTokenSession(token, sessionStore, config) {
  if (!token) {
    return { session: null, reason: 'missing_token' };
  }

  if (config.authMode === 'jwt_hs256') {
    // SECURITY FIX: Always use server-configured algorithm, never trust token header.
    // This prevents JWT algorithm confusion attacks (e.g., RS256/HS256 substitution).
    if (config.jwtAlgorithm === 'RS256') {
      return verifyJwtRs256(token, config);
    }
    return verifyJwtHs256(token, config);
  }

  // In demo mode, prefer in-memory sessions but still accept JWT tokens
  const jwtLike = String(token).split('.').length === 3;
  if (jwtLike) {
    // SECURITY FIX: Use server config to choose algorithm, not token header
    if (config.jwtAlgorithm === 'RS256' && config.jwtPublicKey) {
      const rs256Session = verifyJwtRs256(token, config);
      if (rs256Session.session) {
        return rs256Session;
      }
    }
    if (config.jwtAlgorithm !== 'RS256' && config.jwtSecret) {
      const jwtSession = verifyJwtHs256(token, config);
      if (jwtSession.session) {
        return jwtSession;
      }
    }
  }

  return {
    session: await sessionStore.getSession(token),
    reason: null,
  };
}

module.exports = {
  resolveTokenSession,
};
