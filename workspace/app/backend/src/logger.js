const SENSITIVE_KEY_PATTERN = /(authorization|token|secret|password|api[_-]?key|cookie|set-cookie)/i;

function sanitizeStringValue(value) {
  const text = String(value || '');
  if (!text) {
    return text;
  }

  if (/^bearer\s+/i.test(text)) {
    return 'Bearer [REDACTED]';
  }

  return text;
}

function redactValue(value, key = '') {
  if (SENSITIVE_KEY_PATTERN.test(String(key || ''))) {
    return '[REDACTED]';
  }

  if (Array.isArray(value)) {
    return value.map(item => redactValue(item));
  }

  if (value && typeof value === 'object') {
    const output = {};
    for (const [childKey, childValue] of Object.entries(value)) {
      output[childKey] = redactValue(childValue, childKey);
    }
    return output;
  }

  if (typeof value === 'string') {
    return sanitizeStringValue(value);
  }

  return value;
}

function log(level, message, metadata = {}) {
  const record = {
    timestamp: new Date().toISOString(),
    level,
    message,
    ...redactValue(metadata),
  };

  const line = JSON.stringify(record);

  if (level === 'error') {
    console.error(line);
    return;
  }

  console.log(line);
}

module.exports = {
  log,
};
