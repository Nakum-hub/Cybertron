/**
 * OpenTelemetry distributed tracing integration.
 * Uses @opentelemetry/api which is a no-op by default if no SDK is registered.
 * To enable, install @opentelemetry/sdk-node and configure before requiring this module.
 */

let api;
try {
  api = require('@opentelemetry/api');
} catch {
  // OpenTelemetry not installed - provide no-op implementations
  api = null;
}

const SERVICE_NAME = 'cybertron-backend';

function getTracer() {
  if (!api) return null;
  return api.trace.getTracer(SERVICE_NAME);
}

function extractContext(request) {
  if (!api) return null;
  try {
    const propagator = api.propagation;
    const carrier = {};
    // Extract from incoming headers
    if (request.headers.traceparent) carrier.traceparent = request.headers.traceparent;
    if (request.headers.tracestate) carrier.tracestate = request.headers.tracestate;
    return propagator.extract(api.context.active(), carrier);
  } catch {
    return api.context.active();
  }
}

function startRequestSpan(context, method, path) {
  const tracer = getTracer();
  if (!tracer) {
    return { span: null, context: null };
  }

  const parentContext = context || api.context.active();
  const span = tracer.startSpan(
    `HTTP ${method} ${path}`,
    {
      kind: api.SpanKind.SERVER,
      attributes: {
        'http.method': method,
        'http.target': path,
        'service.name': SERVICE_NAME,
      },
    },
    parentContext
  );

  const spanContext = api.trace.setSpan(parentContext, span);
  return { span, context: spanContext };
}

function endRequestSpan(span, statusCode, error) {
  if (!span || !api) return;

  span.setAttribute('http.status_code', statusCode);

  if (statusCode >= 500) {
    span.setStatus({ code: api.SpanStatusCode.ERROR, message: error || `HTTP ${statusCode}` });
  } else {
    span.setStatus({ code: api.SpanStatusCode.OK });
  }

  span.end();
}

function startSpan(name, attributes) {
  const tracer = getTracer();
  if (!tracer) return null;

  return tracer.startSpan(name, { attributes });
}

function getActiveTraceId() {
  if (!api) return null;
  const span = api.trace.getActiveSpan();
  if (!span) return null;
  const ctx = span.spanContext();
  return ctx.traceId || null;
}

function injectTraceHeaders(headers) {
  if (!api) return headers;
  try {
    api.propagation.inject(api.context.active(), headers);
  } catch {
    // ignore propagation failures
  }
  return headers;
}

module.exports = {
  extractContext,
  startRequestSpan,
  endRequestSpan,
  startSpan,
  getActiveTraceId,
  injectTraceHeaders,
  SERVICE_NAME,
};
