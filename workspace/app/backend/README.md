# Cybertron Backend

Production-oriented backend for Cybertron platform and landing integrations.

## Design Goals
- Preserve frontend API contracts and runtime config handshake.
- Return truthful cybersecurity data only (never deterministic mock values).
- Support real persistence (PostgreSQL) and optional external connectors.
- Enforce secure defaults and fail fast on invalid production config.

## Runtime
- Default host: `0.0.0.0`
- Default port: `8001`
- API prefix accepted: direct (`/v1/...`) and proxied (`/api/v1/...`)
- Frontend runtime config endpoint: `GET /api/config`

## Commands
- `npm run dev` start backend server
- `npm run start` start backend server
- `npm run db:migrate` apply SQL migrations
- `npm run qa:smoke` run backend contract smoke checks
- `npm run qa:red-team` run red-team checks (`RED_TEAM_REQUIRE_DATABASE=true` to fail if DB-backed checks cannot run)
- `npm run qa:failure` run dependency failure-injection checks (DB/storage readiness degradation)
- `npm run qa:load` run sustained backend load profile (default 5 minutes, clamped to 5-15 with `LOAD_DURATION_MS`; use `LOAD_ALLOW_SHORT=true` only for quick local debugging; set `LOAD_REQUIRE_DATABASE=true` to fail when DB-backed load targets are unavailable)
- `npm run qa:strict:embedded` run strict DB-backed backend QA using embedded Postgres-compatible socket DB (no local Docker/Postgres required)

## Environment Variables
### Core
- `PORT` default `8001`
- `HOST` default `0.0.0.0`
- `NODE_ENV` default `development`
- `APP_VERSION` default `0.3.0-dev`
- `REGION` default `local-dev`
- `FRONTEND_ORIGIN` default `http://localhost:3000`
- `CORS_ALLOWED_ORIGINS` default `http://localhost:3000,http://127.0.0.1:3000`

### Auth / Security
- `AUTH_MODE` one of `demo` or `jwt_hs256` (production should use `jwt_hs256`)
- `JWT_SECRET` required when `AUTH_MODE=jwt_hs256`
- `JWT_ISSUER`, `JWT_AUDIENCE`, `JWT_CLOCK_SKEW_SECONDS`
- `ALLOW_INSECURE_DEMO_AUTH` default `false` in production, else `true`
- `REQUIRE_AUTH_FOR_THREAT_ENDPOINTS` default `true` in production
- `REQUIRE_AUTH_FOR_PLATFORM_ENDPOINTS` default `true` in production
- `METRICS_REQUIRE_AUTH` default `true` in production
- `METRICS_AUTH_TOKEN` required when `METRICS_REQUIRE_AUTH=true`
- Production config fails fast if `REQUIRE_AUTH_FOR_THREAT_ENDPOINTS`, `REQUIRE_AUTH_FOR_PLATFORM_ENDPOINTS`, or `METRICS_REQUIRE_AUTH` are disabled.

### Runtime Limits
- `AUTH_TOKEN_TTL_MS` default `28800000`
- `REFRESH_TOKEN_TTL_MS` default `2592000000` (30 days)
- `PASSWORD_RESET_TOKEN_TTL_MS` default `1800000` (30 minutes)
- `PASSWORD_HASH_ROUNDS` default `12`
- `AUTH_MAX_FAILED_ATTEMPTS` default `5`
- `AUTH_LOCKOUT_MS` default `900000` (15 minutes)
- `AUTH_MAX_SESSIONS` default `50000`
- `ALLOW_PUBLIC_REGISTRATION` default `false`
- `RATE_LIMIT_WINDOW_MS` default `60000`
- `RATE_LIMIT_MAX_REQUESTS` default `200`
- `AUTH_RATE_LIMIT_WINDOW_MS` default `60000`
- `AUTH_RATE_LIMIT_MAX_REQUESTS` default `25`
- `AUTH_IDENTITY_RATE_LIMIT_MAX_REQUESTS` default `8` (email/token identity limiter for auth routes)
- `REPORT_RATE_LIMIT_WINDOW_MS` default `60000`
- `REPORT_RATE_LIMIT_MAX_REQUESTS` default `80` (tight limiter for report upload/download/list/get routes)
- `MAX_CONCURRENT_REQUESTS` default `2000`
- `REQUEST_TIMEOUT_MS` default `15000`
- `HEADERS_TIMEOUT_MS` default `16000`
- `KEEP_ALIVE_TIMEOUT_MS` default `5000`

### QA Strictness Toggles
- `RED_TEAM_REQUIRE_DATABASE` when `true`, `qa:red-team` fails if `DATABASE_URL` is missing.
- `LOAD_REQUIRE_DATABASE` when `true`, `qa:load` fails if `DATABASE_URL` is missing.
- `LOAD_ALLOW_SHORT` set to `true` only for local debug runs shorter than 5 minutes.
- `EMBEDDED_DB_PORT` optional port for `qa:strict:embedded` (default `55432`)
- `EMBEDDED_DB_PATH` optional database target for `qa:strict:embedded` (default `memory://`)
- `EMBEDDED_DB_SKIP_LOAD` set `true` to skip load phase in `qa:strict:embedded`
- `EMBEDDED_DB_VERBOSE` set `true` to print embedded DB server logs during `qa:strict:embedded`

### Public Runtime Config (`/api/config`)
- `PUBLIC_API_BASE_URL` default `/api`
- `PUBLIC_AUTH_LOGIN_PATH` default `/v1/auth/login`
- `PUBLIC_AUTH_TOKEN_PATH` default `/v1/auth/token`
- `PUBLIC_AUTH_ME_PATH` default `/v1/auth/me`
- `PUBLIC_AUTH_LOGOUT_PATH` default `/v1/auth/logout`
- `PUBLIC_THREAT_SUMMARY_PATH` default `/v1/threats/summary`
- `PUBLIC_THREAT_INCIDENTS_PATH` default `/v1/threats/incidents`
- `PUBLIC_SYSTEM_HEALTH_PATH` default `/v1/system/health`
- `PUBLIC_PLATFORM_APPS_PATH` default `/v1/platform/apps`
- `PUBLIC_REPORTS_PATH` default `/v1/reports`
- `PUBLIC_REPORT_UPLOAD_PATH` default `/v1/reports/upload`
- `PUBLIC_REPORT_DOWNLOAD_PATH_TEMPLATE` default `/v1/reports/{reportId}/download`
- `PUBLIC_ANALYTICS_ENABLED` default `true`

### Persistence
- `DATABASE_URL` Postgres connection string
- `DB_SSL_MODE` (`disable` or `require`)
- `DB_POOL_MAX` default `20`
- `DB_IDLE_TIMEOUT_MS` default `30000`
- `DB_CONNECT_TIMEOUT_MS` default `5000`
- `DB_STATEMENT_TIMEOUT_MS` default `10000`
- `DB_AUTO_MIGRATE` default `true`

### Report File Pipeline
- `REPORT_STORAGE_DRIVER` `local` or `s3`
- `REPORT_STORAGE_LOCAL_PATH` local root path for report binaries
- `REPORT_UPLOAD_MAX_BYTES` max upload size in bytes
- `REPORT_UPLOAD_ALLOWED_MIME_TYPES` comma-separated allowlist
- `REPORT_RETENTION_DAYS` number of days to keep report binaries + metadata before cleanup
- `REPORT_RETENTION_CLEANUP_INTERVAL_MS` retention cleanup schedule interval
- `REPORT_RETENTION_BATCH_SIZE` max records cleaned per retention cycle
- `REPORT_STORAGE_S3_BUCKET`, `REPORT_STORAGE_S3_REGION`, `REPORT_STORAGE_S3_ENDPOINT`
- `REPORT_STORAGE_S3_ACCESS_KEY_ID`, `REPORT_STORAGE_S3_SECRET_ACCESS_KEY`
- `REPORT_STORAGE_S3_FORCE_PATH_STYLE`

### Optional Threat Connectors
- `WAZUH_API_URL`, `WAZUH_API_TOKEN`
- `MISP_API_URL`, `MISP_API_KEY`
- `OPENCTI_API_URL`, `OPENCTI_API_TOKEN`
- `THEHIVE_API_URL`, `THEHIVE_API_TOKEN`
- `CONNECTOR_TIMEOUT_MS` default `6000`

### AI / LLM
- `LLM_PROVIDER` one of `none`, `openai`, or `ollama`
- `OPENAI_API_KEY`, `OPENAI_MODEL`
- `OPENAI_BASE_URL` default `https://api.openai.com/v1` and can point to a local OpenAI-compatible server such as vLLM
- `OLLAMA_URL`, `OLLAMA_MODEL`
- `LLM_REQUEST_TIMEOUT_MS`, `LLM_RATE_LIMIT_WINDOW_MS`, `LLM_RATE_LIMIT_MAX_CALLS`

### Threat Intel Feeds
- `NVD_FEED_URL`, `NVD_API_KEY`, `NVD_REQUEST_TIMEOUT_MS`
- `NVD_RESULTS_PER_PAGE`, `NVD_SYNC_MAX_ENTRIES`, `NVD_SYNC_BACKOFF_BASE_MS`, `NVD_SYNC_BACKOFF_MAX_MS`
- `URLHAUS_ENABLED`, `URLHAUS_REQUEST_TIMEOUT_MS`

## Implemented API Contracts
- `GET /v1/auth/login`
- `POST /v1/auth/login`
- `GET /v1/auth/me`
- `POST /v1/auth/logout`
- `POST /v1/auth/register`
- `POST /v1/auth/token`
- `POST /v1/auth/password/forgot`
- `POST /v1/auth/password/reset`
- `GET /v1/threats/summary`
- `GET /v1/threats/incidents`
- `GET /v1/connectors/status`
- `GET /v1/incidents`
- `POST /v1/incidents`
- `PATCH /v1/incidents/:incidentId`
- `GET /v1/incidents/:incidentId/timeline`
- `POST /v1/incidents/:incidentId/iocs/:iocId`
- `GET /v1/iocs`
- `POST /v1/iocs`
- `GET /v1/service-requests`
- `POST /v1/service-requests`
- `PATCH /v1/service-requests/:requestId`
- `GET /v1/service-requests/:requestId/comments`
- `POST /v1/service-requests/:requestId/comments`
- `GET /v1/reports/:reportId`
- `POST /v1/reports/upload`
- `GET /v1/reports/:reportId/download`
- `GET /v1/system/health`
- `GET /v1/system/liveness`
- `GET /v1/system/readiness`
- `GET /v1/system/config`
- `GET /api/config`
- `GET /v1/system/metrics`
- `GET /v1/system/metrics/prometheus`
- `GET /v1/system/openapi`
- `GET /v1/platform/apps`
- `GET /v1/apps/:appId/status`

## Data Integrity Policy
- If Postgres and connectors are not configured, threat endpoints return empty payloads truthfully.
- No deterministic or fabricated tenant signal data is returned.

## Security / Operations Baseline
- Request ID and correlation headers (`X-Request-Id`, `X-Correlation-Id`)
- Security headers (`X-Content-Type-Options`, `X-Frame-Options`, etc.)
- Origin validation allow-list gate
- In-memory rate limiting and overload shedding
- Auth route identity-based rate limiting (`AUTH_IDENTITY_RATE_LIMIT_MAX_REQUESTS`)
- Config fail-fast validation in production
- Startup DB migrations
- OpenAPI contract endpoint and Prometheus metrics endpoint
- Structured JSON request logging
