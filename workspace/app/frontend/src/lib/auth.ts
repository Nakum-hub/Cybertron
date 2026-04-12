const LOGOUT_KEY = 'isLoggedOutManual';
const LEGACY_LOGOUT_KEY = 'isLougOutManual';
const SESSION_HINT_KEY = 'cybertronSessionHint';
const PUBLIC_FINGERPRINT_KEY = 'cybertronPublicFingerprint';
const PUBLIC_FINGERPRINT_COOKIE = 'ct_public_fp';
const DEFAULT_CSRF_COOKIE_NAME = 'ct_csrf';

let accessTokenMemory: string | null = null;
let refreshTokenMemory: string | null = null;

function canUseStorage(): boolean {
  return typeof window !== 'undefined' && typeof window.localStorage !== 'undefined';
}

function setManualLogoutFlag(manual: boolean): void {
  if (!canUseStorage()) {
    return;
  }

  const value = manual ? 'true' : 'false';
  window.localStorage.setItem(LOGOUT_KEY, value);
  window.localStorage.setItem(LEGACY_LOGOUT_KEY, value);
}

function setSessionHint(active: boolean): void {
  if (!canUseStorage()) {
    return;
  }

  window.localStorage.setItem(SESSION_HINT_KEY, active ? 'true' : 'false');
}

function isValidPublicFingerprint(value: string | null | undefined): value is string {
  const normalized = String(value || '').trim();
  return normalized.length >= 16 && normalized.length <= 191 && /^[a-z0-9._:-]+$/i.test(normalized);
}

function generatePublicFingerprint(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return `fp-${crypto.randomUUID()}`;
  }

  const fallback = Math.random().toString(36).slice(2);
  return `fp-${Date.now().toString(36)}-${fallback}`;
}

function persistPublicFingerprint(value: string): void {
  if (typeof document !== 'undefined') {
    document.cookie = `${PUBLIC_FINGERPRINT_COOKIE}=${encodeURIComponent(value)}; Path=/; SameSite=Lax; Max-Age=31536000`;
  }

  if (canUseStorage()) {
    window.localStorage.setItem(PUBLIC_FINGERPRINT_KEY, value);
  }
}

export function getAccessToken(): string | null {
  return accessTokenMemory;
}

export function hasAccessToken(): boolean {
  return Boolean(accessTokenMemory);
}

export function getRefreshToken(): string | null {
  return refreshTokenMemory;
}

export function setAccessToken(token: string): void {
  accessTokenMemory = String(token || '').trim() || null;
  refreshTokenMemory = null;
  setManualLogoutFlag(false);
  setSessionHint(Boolean(accessTokenMemory));
}

export function setAuthTokens(accessToken: string, refreshToken?: string): void {
  accessTokenMemory = String(accessToken || '').trim() || null;
  refreshTokenMemory = refreshToken ? String(refreshToken).trim() : null;
  setManualLogoutFlag(false);
  setSessionHint(Boolean(accessTokenMemory || refreshTokenMemory));
}

export function clearAccessToken(manual = false): void {
  accessTokenMemory = null;
  refreshTokenMemory = null;
  setSessionHint(false);
  if (manual) {
    setManualLogoutFlag(true);
    return;
  }

  setManualLogoutFlag(false);
}

export function isManualLogout(): boolean {
  if (!canUseStorage()) {
    return false;
  }

  return (
    window.localStorage.getItem(LOGOUT_KEY) === 'true' ||
    window.localStorage.getItem(LEGACY_LOGOUT_KEY) === 'true'
  );
}

export function hasSessionHint(): boolean {
  if (accessTokenMemory || refreshTokenMemory) {
    return true;
  }

  if (!canUseStorage()) {
    return false;
  }

  return window.localStorage.getItem(SESSION_HINT_KEY) === 'true';
}

export function markSessionHintActive(): void {
  setManualLogoutFlag(false);
  setSessionHint(true);
}

export function readCookie(cookieName: string): string | null {
  if (typeof document === 'undefined') {
    return null;
  }

  const target = String(cookieName || '').trim();
  if (!target) {
    return null;
  }

  const segments = String(document.cookie || '').split(';');
  for (const segment of segments) {
    const [name, ...rest] = segment.trim().split('=');
    if (name !== target) {
      continue;
    }

    const rawValue = rest.join('=');
    if (!rawValue) {
      return '';
    }

    try {
      return decodeURIComponent(rawValue);
    } catch {
      return rawValue;
    }
  }

  return null;
}

export function getPublicSignupFingerprint(): string {
  const fromCookie = readCookie(PUBLIC_FINGERPRINT_COOKIE);
  if (isValidPublicFingerprint(fromCookie)) {
    persistPublicFingerprint(fromCookie);
    return fromCookie;
  }

  if (canUseStorage()) {
    const fromStorage = window.localStorage.getItem(PUBLIC_FINGERPRINT_KEY);
    if (isValidPublicFingerprint(fromStorage)) {
      persistPublicFingerprint(fromStorage);
      return fromStorage;
    }
  }

  const created = generatePublicFingerprint();
  persistPublicFingerprint(created);
  return created;
}

export function getCsrfToken(cookieName = DEFAULT_CSRF_COOKIE_NAME): string {
  return readCookie(cookieName) || '';
}
