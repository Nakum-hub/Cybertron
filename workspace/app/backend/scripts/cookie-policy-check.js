#!/usr/bin/env node

const { buildAuthCookies } = require('../src/auth-cookies');

function assertCondition(condition, label) {
  if (!condition) {
    throw new Error(`Assertion failed: ${label}`);
  }

  process.stdout.write(`PASS: ${label}\n`);
}

function includesCaseInsensitive(value, expected) {
  return String(value || '').toLowerCase().includes(String(expected || '').toLowerCase());
}

function run() {
  const config = {
    authCookieSameSite: 'strict',
    authCookieSecure: true,
    authCookieDomain: '',
    authCookiePath: '/',
    authAccessCookieName: 'ct_access',
    authRefreshCookieName: 'ct_refresh',
    csrfCookieName: 'ct_csrf',
  };

  const tokenPair = {
    accessToken: 'access-token-value',
    accessTokenExpiresInSeconds: 900,
    refreshToken: 'refresh-token-value',
    refreshTokenExpiresAt: new Date(Date.now() + 86_400_000).toISOString(),
  };

  const payload = buildAuthCookies(config, tokenPair);
  const cookies = payload.cookies || [];

  assertCondition(Array.isArray(cookies) && cookies.length === 3, 'auth cookie payload includes access, refresh, csrf');
  assertCondition(Boolean(payload.csrfToken), 'csrf token generated');

  const accessCookie = cookies.find(cookie => String(cookie).startsWith('ct_access=')) || '';
  const refreshCookie = cookies.find(cookie => String(cookie).startsWith('ct_refresh=')) || '';
  const csrfCookie = cookies.find(cookie => String(cookie).startsWith('ct_csrf=')) || '';

  assertCondition(Boolean(accessCookie), 'access cookie generated');
  assertCondition(Boolean(refreshCookie), 'refresh cookie generated');
  assertCondition(Boolean(csrfCookie), 'csrf cookie generated');

  assertCondition(includesCaseInsensitive(accessCookie, 'HttpOnly'), 'access cookie HttpOnly enabled');
  assertCondition(includesCaseInsensitive(refreshCookie, 'HttpOnly'), 'refresh cookie HttpOnly enabled');
  assertCondition(!includesCaseInsensitive(csrfCookie, 'HttpOnly'), 'csrf cookie readable for double-submit');

  assertCondition(includesCaseInsensitive(accessCookie, 'Secure'), 'access cookie secure flag enabled');
  assertCondition(includesCaseInsensitive(refreshCookie, 'Secure'), 'refresh cookie secure flag enabled');
  assertCondition(includesCaseInsensitive(csrfCookie, 'Secure'), 'csrf cookie secure flag enabled');

  assertCondition(includesCaseInsensitive(accessCookie, 'SameSite=Strict'), 'access cookie strict SameSite');
  assertCondition(includesCaseInsensitive(refreshCookie, 'SameSite=Strict'), 'refresh cookie strict SameSite');
  assertCondition(includesCaseInsensitive(csrfCookie, 'SameSite=Strict'), 'csrf cookie strict SameSite');

  process.stdout.write('Cookie policy checks passed.\n');
}

try {
  run();
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}
