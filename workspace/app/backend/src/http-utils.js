const crypto = require('node:crypto');

function normalizePath(pathname) {
  const value = String(pathname || '/');

  if (value === '/api') {
    return '/';
  }

  if (value.startsWith('/api/')) {
    return value.slice(4);
  }

  if (value.length > 1 && value.endsWith('/')) {
    return value.slice(0, -1);
  }

  return value;
}

function getClientIp(request, trustProxy = false) {
  const forwarded = request.headers['x-forwarded-for'];

  if (trustProxy && typeof forwarded === 'string' && forwarded.trim()) {
    return forwarded.split(',')[0].trim();
  }

  return request.socket.remoteAddress || 'unknown';
}

function toRequestContext(request, options = {}) {
  const trustProxy = Boolean(options.trustProxy);
  const host = request.headers.host || 'localhost';
  const url = new URL(request.url || '/', `http://${host}`);
  const incomingRequestId = String(request.headers['x-request-id'] || '').trim();
  const requestId =
    /^[a-zA-Z0-9._:-]{8,80}$/.test(incomingRequestId) ? incomingRequestId : crypto.randomUUID();

  return {
    request,
    url,
    method: request.method || 'GET',
    path: normalizePath(url.pathname),
    requestId,
    origin: request.headers.origin || '',
    ip: getClientIp(request, trustProxy),
    startAt: Date.now(),
  };
}

function setCorsHeaders(headers, origin, allowedOrigins) {
  if (!origin) {
    return;
  }

  if (isOriginAllowed(origin, allowedOrigins)) {
    headers['Access-Control-Allow-Origin'] = origin;
    headers['Vary'] = 'Origin';
    headers['Access-Control-Allow-Methods'] = 'GET,POST,PATCH,PUT,DELETE,OPTIONS';
    headers['Access-Control-Allow-Headers'] =
      'Content-Type,Authorization,X-Request-Id,X-Correlation-Id,X-CSRF-Token,X-XSRF-Token,Idempotency-Key';
    headers['Access-Control-Allow-Credentials'] = 'false';
    headers['Access-Control-Max-Age'] = '600';
  }
}

function isOriginAllowed(origin, allowedOrigins) {
  if (!origin) {
    return true;
  }

  return allowedOrigins.includes('*') || allowedOrigins.includes(origin);
}

function baseHeaders(context, config, extraHeaders = {}) {
  const headers = {
    'X-Request-Id': context.requestId,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-site',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    'Cache-Control': 'no-store',
    ...extraHeaders,
  };

  if (config.environment === 'production') {
    headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload';
  }

  setCorsHeaders(headers, context.origin, config.allowedOrigins);
  return headers;
}

function sendJson(response, context, config, statusCode, payload, extraHeaders = {}) {
  response.writeHead(statusCode, {
    ...baseHeaders(context, config, {
      'Content-Type': 'application/json; charset=utf-8',
      ...extraHeaders,
    }),
  });
  response.end(JSON.stringify(payload));
}

function sendNoContent(response, context, config, extraHeaders = {}) {
  response.writeHead(204, baseHeaders(context, config, extraHeaders));
  response.end();
}

function sendText(response, context, config, statusCode, payload, extraHeaders = {}) {
  response.writeHead(statusCode, {
    ...baseHeaders(context, config, {
      'Content-Type': 'text/plain; charset=utf-8',
      ...extraHeaders,
    }),
  });
  response.end(String(payload || ''));
}

function sendRedirect(response, context, config, location) {
  response.writeHead(302, {
    ...baseHeaders(context, config),
    Location: location,
  });
  response.end();
}

function sendError(
  response,
  context,
  config,
  statusCode,
  code,
  message,
  details,
  extraHeaders = {}
) {
  sendJson(
    response,
    context,
    config,
    statusCode,
    {
      error: {
        code,
        message,
        details: details || null,
        requestId: context.requestId,
      },
    },
    extraHeaders
  );
}

function sendMethodNotAllowed(response, context, config, allowedMethods, extraHeaders = {}) {
  sendError(
    response,
    context,
    config,
    405,
    'method_not_allowed',
    'HTTP method is not allowed for this endpoint',
    { allowedMethods },
    {
      Allow: allowedMethods.join(', '),
      ...extraHeaders,
    }
  );
}

module.exports = {
  baseHeaders,
  isOriginAllowed,
  toRequestContext,
  sendJson,
  sendNoContent,
  sendText,
  sendRedirect,
  sendError,
  sendMethodNotAllowed,
};
