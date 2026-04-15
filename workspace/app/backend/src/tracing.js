/**
 * OpenTelemetry distributed tracing integration.
 * Uses @opentelemetry/api which is a no-op by default if no SDK is registered.
 *
 * P3-1: When OTEL_ENABLED=true, this module will attempt to initialize the
 * OpenTelemetry Node SDK with an OTLP/HTTP trace exporter. Install optional
 * dependencies to activate:
 *   npm install @opentelemetry/sdk-node @opentelemetry/exporter-trace-otlp-http @opentelemetry/auto-instrumentations-node
 */

let api;
try {
  api = require('@opentelemetry/api');
} catch {
  // OpenTelemetry not installed - provide no-op implementations
  api = null;
}

const SERVICE_NAME = process.env.OTEL_SERVICE_NAME || 'cybertron-backend';

// P3-1: Auto-initialize SDK when OTEL_ENABLED=true
let _sdkInitialized = false;
if (api && process.env.OTEL_ENABLED === 'true') {
  try {
    const { NodeSDK } = require('@opentelemetry/sdk-node');
    const { OTLPTraceExporter } = require('@opentelemetry/exporter-trace-otlp-http');
    const { Resource } = require('@opentelemetry/resources');

    // Optional: auto-instrumentations (HTTP, Express, pg, etc.)
    let instrumentations = [];
    try {
      const { getNodeAutoInstrumentations } = require('@opentelemetry/auto-instrumentations-node');
      instrumentations = getNodeAutoInstrumentations({
        '@opentelemetry/instrumentation-fs': { enabled: false },
      });
    } catch {
      // Auto-instrumentations not installed — proceed with manual spans only
    }

    const otlpEndpoint = process.env.OTEL_EXPORTER_OTLP_ENDPOINT || 'http://localhost:4318';

    const sdk = new NodeSDK({
      resource: new Resource({ 'service.name': SERVICE_NAME }),
      traceExporter: new OTLPTraceExporter({
        url: `${otlpEndpoint}/v1/traces`,
      }),
      instrumentations,
    });

    sdk.start();
    _sdkInitialized = true;

    process.on('SIGTERM', () => {
      sdk.shutdown().catch(() => {});
    });

    // eslint-disable-next-line no-console
    console.log(`[tracing] OpenTelemetry SDK initialized (endpoint: ${otlpEndpoint})`);
  } catch (err) {
    // SDK packages not installed — tracing remains no-op
    // eslint-disable-next-line no-console
    console.warn('[tracing] OTEL_ENABLED=true but SDK packages not installed:', err.message);
  }
}

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
  isOtelEnabled: _sdkInitialized,
  SERVICE_NAME,
};
