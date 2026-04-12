const crypto = require('node:crypto');

function parseCookieHeader(cookieHeader) {
  const header = String(cookieHeader || '');
  if (!header.trim()) {
    return {};
  }

  const cookies = {};
  const parts = header.split(';');
  for (const part of parts) {
    const [name, ...rawValueParts] = part.trim().split('=');
    if (!name) {
      continue;
    }

    const rawValue = rawValueParts.join('=').trim();
    try {
      cookies[name] = decodeURIComponent(rawValue);
    } catch {
      cookies[name] = rawValue;
    }
  }

  return cookies;
}

function serializeCookie(name, value, options = {}) {
  const safeName = String(name || '').trim();
  if (!safeName) {
    throw new Error('cookie_name_required');
  }

  const parts = [`${safeName}=${encodeURIComponent(String(value || ''))}`];

  const path = String(options.path || '/').trim() || '/';
  parts.push(`Path=${path}`);

  if (options.maxAgeSeconds !== undefined) {
    parts.push(`Max-Age=${Math.max(0, Math.floor(Number(options.maxAgeSeconds) || 0))}`);
  }

  if (options.expires instanceof Date) {
    parts.push(`Expires=${options.expires.toUTCString()}`);
  }

  const sameSite = String(options.sameSite || 'lax').toLowerCase();
  if (sameSite === 'strict') {
    parts.push('SameSite=Strict');
  } else if (sameSite === 'none') {
    parts.push('SameSite=None');
  } else {
    parts.push('SameSite=Lax');
  }

  if (options.domain) {
    parts.push(`Domain=${String(options.domain).trim()}`);
  }

  if (options.secure) {
    parts.push('Secure');
  }

  if (options.httpOnly) {
    parts.push('HttpOnly');
  }

  return parts.join('; ');
}

function buildCookieSecurityOptions(config) {
  return {
    sameSite: config.authCookieSameSite,
    secure: Boolean(config.authCookieSecure),
    domain: config.authCookieDomain || undefined,
    path: config.authCookiePath || '/',
  };
}

function buildAuthCookies(config, tokenPair) {
  const security = buildCookieSecurityOptions(config);
  const accessExpirySeconds = Math.max(1, Math.floor(Number(tokenPair.accessTokenExpiresInSeconds) || 1));
  const refreshExpirySeconds = Math.max(
    1,
    Math.floor((new Date(tokenPair.refreshTokenExpiresAt).getTime() - Date.now()) / 1000)
  );
  const csrfToken = crypto.randomBytes(24).toString('base64url');

  const cookies = [
    serializeCookie(config.authAccessCookieName, tokenPair.accessToken, {
      ...security,
      httpOnly: true,
      maxAgeSeconds: accessExpirySeconds,
    }),
    serializeCookie(config.authRefreshCookieName, tokenPair.refreshToken, {
      ...security,
      httpOnly: true,
      maxAgeSeconds: refreshExpirySeconds,
    }),
    serializeCookie(config.csrfCookieName, csrfToken, {
      ...security,
      httpOnly: false,
      maxAgeSeconds: refreshExpirySeconds,
    }),
  ];

  return {
    cookies,
    csrfToken,
  };
}

function buildClearAuthCookies(config) {
  const security = buildCookieSecurityOptions(config);
  const expires = new Date(0);

  return [
    serializeCookie(config.authAccessCookieName, '', {
      ...security,
      httpOnly: true,
      maxAgeSeconds: 0,
      expires,
    }),
    serializeCookie(config.authRefreshCookieName, '', {
      ...security,
      httpOnly: true,
      maxAgeSeconds: 0,
      expires,
    }),
    serializeCookie(config.csrfCookieName, '', {
      ...security,
      httpOnly: false,
      maxAgeSeconds: 0,
      expires,
    }),
  ];
}

module.exports = {
  parseCookieHeader,
  buildAuthCookies,
  buildClearAuthCookies,
};
