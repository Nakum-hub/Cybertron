# Production Readiness Audit

## What Is In Place

### Infrastructure & Deployment
- Full stack containerized with `docker-compose.prod.yml` (Postgres 16, Redis 7, backend, frontend).
- CI quality gates in `.github/workflows/ci.yml` with blocking security audit.
- Trivy container image scanning (CRITICAL/HIGH severity) in CI pipeline.
- npm dependency audit (`npm audit --audit-level=high`) blocking on both backend and frontend.
- Docker healthchecks on all services (Redis, Postgres, backend readiness probe).

### Authentication & Session Management
- JWT HS256 authentication with issuer/audience validation.
- JWT_SECRET enforced: minimum 32 characters in production, blocks default dev value.
- OAuth2 social login: Google, Microsoft, GitHub.
- Generic OIDC provider via OpenID Connect Discovery — compatible with Auth0, Okta, Keycloak, Azure AD, and any compliant IdP.
- Demo auth force-disabled in production (`ALLOW_INSECURE_DEMO_AUTH=false` enforced).
- Distributed session store backed by Redis (required in production via `REDIS_URL`).
- Distributed rate limiting backed by Redis with per-endpoint policies.
- Password hashing with bcrypt (12 rounds), failed-login lockout, exponential backoff.
- CSRF protection with double-submit cookie pattern.
- Secure cookie configuration enforced in production (Secure, SameSite=strict, HttpOnly).

### API Security
- Auth-required threat and platform endpoints in production.
- CORS origin validation enforced in production.
- Request/headers/keepalive timeouts hardened.
- Overload shedding via `MAX_CONCURRENT_REQUESTS`.
- Per-endpoint rate limiting (global, auth, identity, reports).

### Observability
- Readiness endpoint: `GET /v1/system/readiness`.
- Liveness endpoint: `GET /v1/system/liveness`.
- Prometheus metrics endpoint: `GET /v1/system/metrics/prometheus` (auth-gated).
- OpenAPI endpoint: `GET /v1/system/openapi`.
- Structured JSON logging throughout.

### Application
- Runtime config validation with fail-fast on unsafe production settings.
- Frontend error boundary to prevent full white-screen crashes.
- Database migrations auto-applied at startup with versioned SQL.
- Report storage with S3 and local driver support, retention policies, MIME validation.
- AI/LLM integration fail-closed (503) when provider not configured.
- Threat connector integrations (Wazuh, MISP, OpenCTI, TheHive) with timeout and normalization.

## Pre-Launch Checklist

Before public production launch, operators must:

1. **Set a strong JWT_SECRET** — minimum 32 characters of cryptographic randomness. The backend will refuse to start with the default dev value or a short secret.
2. **Configure Redis** — set `REDIS_URL` to a managed Redis instance. The backend requires Redis for distributed sessions and rate limiting in production.
3. **Configure the database** — set `DATABASE_URL` to a managed PostgreSQL instance with SSL (`DB_SSL_MODE=require`).
4. **Configure an identity provider** — set `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, and `OIDC_CLIENT_SECRET` for enterprise SSO, or configure one of the social OAuth providers (Google/Microsoft/GitHub).
5. **Set `FRONTEND_ORIGIN` and `CORS_ALLOWED_ORIGINS`** to the actual public domain.
6. **Set `METRICS_AUTH_TOKEN`** to a strong random value for Prometheus scraping.
7. **Configure TLS termination** — via a reverse proxy (nginx, Caddy, ALB) or CDN/WAF (Cloudflare, AWS CloudFront).
8. **Run load tests** — use the existing load test scripts at expected peak traffic to validate RPS/latency/error targets.
9. **Configure LLM provider** (optional) — set `LLM_PROVIDER=openai` and `OPENAI_API_KEY` for hosted OpenAI, or point `OPENAI_BASE_URL` at a local OpenAI-compatible server such as vLLM running on the GPU host.
10. **Configure threat connectors** (optional) — set Wazuh/MISP/OpenCTI/TheHive credentials if external threat feeds are desired.
11. **Run the go-live gate** — `npm run qa:go-live --prefix workspace -- --env-file .env --base-url https://app.your-domain.com --email "<admin-email>" --password "<strong-password>"`. This blocks local-only env templates, placeholder secrets, local storage/LLM endpoints, and a still-active default bootstrap admin.
12. **Probe configured connectors honestly** — `npm run qa:connectors --prefix workspace -- --env-file .env --require-healthy`. This validates that Wazuh, MISP, OpenCTI, and TheHive are not just configured on paper but actually reachable and authenticated.

## Recommended for Scale

These are not blocking for launch but recommended for high-scale deployments:

- Background job/queue system for async work (report generation, CVE ingestion).
- Full observability stack (APM tracing, centralized log aggregation, alerting, SLO dashboards).
- WAF/CDN for global edge caching and DDoS mitigation.
- Multi-region deployment with database replication for disaster recovery.
- Horizontal pod autoscaling with Kubernetes or ECS.
