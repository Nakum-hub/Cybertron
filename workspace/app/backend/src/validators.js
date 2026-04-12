function toSafeInteger(value, fallback, minimum, maximum) {
  const parsed = Number(value);

  if (!Number.isFinite(parsed)) {
    return fallback;
  }

  const integer = Math.floor(parsed);
  if (integer < minimum || integer > maximum) {
    return fallback;
  }

  return integer;
}

function sanitizeTenant(value) {
  if (typeof value !== 'string') {
    return 'global';
  }

  const normalized = value.toLowerCase().trim();
  if (!normalized) {
    return 'global';
  }

  const safe = normalized.replace(/[^a-z0-9-]/g, '').slice(0, 64);
  return safe || 'global';
}

function sanitizeRedirectPath(value) {
  const normalized = String(value || '/').trim();

  if (!normalized.startsWith('/')) {
    return '/';
  }

  // Block protocol-relative URLs: //, /\, /%5c (backslash-based open redirect vectors)
  if (normalized.startsWith('//') || normalized.startsWith('/\\') || normalized.toLowerCase().startsWith('/%5c')) {
    return '/';
  }

  // Block embedded protocol handlers
  if (/[:\s]/i.test(normalized.slice(0, 20))) {
    return '/';
  }

  return normalized;
}

module.exports = {
  toSafeInteger,
  sanitizeTenant,
  sanitizeRedirectPath,
};
