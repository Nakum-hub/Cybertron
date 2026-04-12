# Infrastructure / DevOps / Deployment — Audit Report

**Date:** 2026-03-10
**Auditor:** Claude Opus 4.6 (automated)
**Scope:** Repository structure, Docker/containerization, Compose orchestration, startup/boot/readiness/shutdown, database/cache/storage, reverse proxy/TLS, CI/CD, config validation, security hardening, stale files

---

## 1. Pre-Audit Score: 6.8 / 10

### What was already working well

| Area | Status |
|------|--------|
| Docker multi-stage builds | Backend uses 2-stage build (deps → prod). Frontend uses 3-stage build (build → default/tls). Both use alpine bases |
| Production compose hardening | `no-new-privileges:true`, `cap_drop: ALL`, `read_only: true`, `tmpfs` mounts, and resource limits on all services |
| Config validation | 50+ validation rules in `config.js` with `validateRuntimeConfig()` fail-fast. JWT, OIDC, cookie, rate limit, and database settings all validated |
| Health/readiness/liveness separation | Three distinct endpoints: `/v1/system/health` (always 200), `/v1/system/readiness` (200/503 based on deps), `/v1/system/liveness` (static 200) |
| Graceful shutdown | `SIGINT`/`SIGTERM` → close DB+Redis in parallel → `server.close()` → 8s hard kill timeout |
| Redis reconnect strategy | Linear backoff `200 + retries*120` ms, max 4 retries, configurable via env vars |
| Nginx security headers | X-Frame-Options, X-Content-Type-Options, CSP, Referrer-Policy, Permissions-Policy, CORP, COOP on all responses |
| TLS configuration | TLSv1.2+1.3 only, strong cipher suite, HSTS with includeSubDomains+preload, OCSP stapling, session tickets disabled |
| Dependency startup ordering | All compose files use `depends_on` with `condition: service_healthy` |
| Non-root containers | Backend runs as `node` user, frontend uses `nginx-unprivileged` base |

### What was broken

| ID | Gap | Severity | Impact |
|----|-----|----------|--------|
| I1 | Backend Dockerfile HEALTHCHECK used wrong path (`/api/v1/system/health` via proxy) and installed curl unnecessarily | HIGH | Healthcheck would fail — container never reaches healthy state. Docker would restart the backend in a loop |
| I2 | Frontend Dockerfile `target` not specified in any compose file — Docker defaults to last stage (TLS), which requires cert volume mounts | HIGH | Default `docker-compose up` builds the TLS stage, fails without SSL certificates. No compose file explicitly requested the HTTP-only default stage |
| I3 | `isDependencyRequired()` always returned `true` for all dependencies | HIGH | Readiness endpoint returned 503 in dev without DB/Redis, even though backend supports in-memory fallbacks. Breaks local development |
| I4 | No database migration retry at startup — immediate exit on transient DB unavailability | MEDIUM | A temporary network hiccup during container startup causes the entire backend to crash with no recovery |
| I5 | Stale `pnpm-lock.yaml` in frontend alongside active `package-lock.json` | MEDIUM | Confuses contributors about which package manager to use. Could cause dependency resolution conflicts |
| I6 | Dead CI workflow at `workspace/.github/workflows/ci.yml` — GitHub cannot reach nested `.github/` directories | MEDIUM | Security audit (npm audit) and container scanning (Trivy) jobs were defined but never executed. False sense of CI coverage |
| I7 | `METRICS_AUTH_TOKEN` not validated against placeholder patterns | MEDIUM | Production could start with `CHANGE_ME` as the metrics auth token — effectively leaving metrics endpoint unprotected |
| I8 | TLS nginx config missing rate limiting directives (HTTP config had them) | MEDIUM | TLS deployments had no nginx-level rate limiting on API endpoints, while HTTP deployments did. Auth endpoints completely unprotected at proxy level |
| I9 | Stale tracked files: `nul` (Windows artifact), `tmp_test.js` (forgotten debug file) | LOW | Repository hygiene issue. Not harmful but indicates cleanup gaps |

---

## 2. Fix Log

### I1: Backend Dockerfile Healthcheck Path

**File:** `app/backend/Dockerfile`

- Changed HEALTHCHECK from `curl -f http://localhost:8001/api/v1/system/health` to `wget --quiet --tries=1 --spider http://localhost:8001/v1/system/readiness`
- Removed `curl` package installation (wget already available in alpine)
- Changed CMD from `["npm", "run", "start"]` to `["node", "server.js"]` (faster startup, avoids PID1 issues)

### I2: Frontend Build Target in Compose Files

**Files:** `docker-compose.yml`, `docker-compose.dev.yml`, `docker-compose.prod.yml`

- Added `target: default` to frontend build in all 3 compose files
- Removed port `443:8443` and cert volume mount from base compose (belonged to TLS stage only)

### I3: isDependencyRequired Respects strictDependencies

**File:** `app/backend/src/server.js`

- Storage: always required (unchanged)
- Database: now returns `config.strictDependencies && Boolean(config.databaseUrl)`
- Redis: now returns `config.strictDependencies && Boolean(config.redisUrl)`
- Unknown dependencies: return `false`

### I4: Database Migration Retry at Startup

**File:** `app/backend/src/server.js`

- Production: 5 attempts with 2s delay between retries
- Non-production: 2 attempts with 2s delay
- Each failed attempt logged as `database.migration_attempt_failed` with attempt number
- Final failure logged as `database.migration_failed` → `process.exit(1)`

### I5: Remove Stale pnpm-lock.yaml

**Deleted:** `app/frontend/pnpm-lock.yaml`

### I6: Merge Dead Workspace CI into Root CI

**Modified:** `.github/workflows/ci.yml`
**Deleted:** `workspace/.github/workflows/ci.yml` (and empty `.github/` directory tree)

- Added `permissions: { contents: read, security-events: write }` to root CI
- Ported `security-audit` job: npm audit at `--audit-level=high` for both backend and frontend
- Ported `container-scan` job: Trivy scanner for both backend and frontend images (CRITICAL+HIGH severity, exit-code 1)
- Container scan depends on `quality-gate` (no point scanning if QA fails)
- Frontend image built with `--target default` to match compose configuration

### I7: Validate METRICS_AUTH_TOKEN Against Placeholder Pattern

**File:** `app/backend/src/config.js`

- Added validation: if `metricsRequireAuth` is true and `metricsAuthToken` matches `/^change.?me/i`, push error with secure token generation command

### I8: Add Rate Limiting to TLS Nginx Config

**File:** `app/frontend/nginx/default-tls.conf`

- Added `limit_req_zone` directives: `api_global` (30r/s), `api_auth` (5r/s)
- Added separate `location /api/v1/auth/` block with `api_auth` zone, burst=10, 429 status
- Added `limit_req zone=api_global burst=50 nodelay` to general `/api/` block
- Now has full parity with HTTP nginx config

### I9: Remove Stale Tracked Files

**Deleted:** `nul` (Windows artifact), `tmp_test.js` (forgotten debug file)

---

## 3. Post-Audit Score: 8.6 / 10

| Area | Before | After | Notes |
|------|--------|-------|-------|
| Docker build correctness | 4/10 | 9/10 | Healthcheck path fixed, build target specified, CMD uses node directly |
| Compose orchestration | 5/10 | 9/10 | Target aligned, port exposure corrected, healthchecks consistent |
| Startup resilience | 5/10 | 9/10 | Migration retries, isDependencyRequired respects config, boot sequence robust |
| CI/CD coverage | 4/10 | 9/10 | Security audit + Trivy container scanning now in active CI pipeline |
| Config validation | 8/10 | 9/10 | METRICS_AUTH_TOKEN placeholder rejection added |
| Nginx rate limiting | 6/10 | 9/10 | TLS config now has full rate limiting parity with HTTP config |
| Security headers | 9/10 | 9/10 | Already strong — CSP, HSTS, OCSP, all present |
| Production hardening | 9/10 | 9/10 | Already strong — no-new-privileges, cap_drop, read_only, resource limits |
| Repository hygiene | 6/10 | 8/10 | Stale files removed, dead CI deleted, pnpm lockfile removed |

---

## 4. Infrastructure Defensibility Assessment

### Defensible Infrastructure

1. **Container security**: Alpine bases, non-root users, `no-new-privileges`, `cap_drop: ALL`, `read_only: true`, resource limits. Production-grade.

2. **Config validation**: 50+ rules with fail-fast. JWT secret, OIDC, cookies, rate limits, database, metrics token all validated before server starts.

3. **Health/readiness separation**: Health (always 200) for liveness probes, readiness (200/503) for load balancer routing, liveness (static 200) for kubelet. Three distinct semantics.

4. **Graceful shutdown**: Signal handlers close dependencies in parallel, drain connections, hard-kill after 8s. Production-grade.

5. **TLS configuration**: TLSv1.2+ only, strong ciphers, HSTS, OCSP stapling, session tickets disabled. Follows Mozilla modern compatibility guidelines.

6. **CI pipeline**: Quality gate (full QA with Postgres+Redis services), security audit (npm audit), container scanning (Trivy). All enforced on PRs.

### Infrastructure With Known Limitations

1. **No Kubernetes manifests**: Compose-based deployment only. K8s would provide HPA, pod disruption budgets, network policies. This is a deployment choice, not a deficiency.

2. **Single-replica architecture**: No horizontal scaling configured in compose. Would require a load balancer and session affinity at scale.

3. **No container image registry**: CI builds images but doesn't push to a registry. Manual build-and-deploy workflow.

4. **No log aggregation**: Structured logging exists but no centralized log shipping (Fluentd, Loki, etc.) configured.

5. **Database backups**: No automated backup strategy in compose files. `postgres_data` volume is persistent but not backed up.

---

## 5. Test Coverage

**File:** `tests/infra-hardening.test.js`
**Tests:** 84
**Suites:** 16 describe blocks

| Category | Tests |
|----------|-------|
| I1: Dockerfile healthcheck path | 6 |
| I2: Frontend build target in compose | 5 |
| I3: isDependencyRequired behavior | 4 |
| I4: Migration retry at startup | 7 |
| I5: No stale pnpm lockfile | 2 |
| I6: CI workflow consolidation | 7 |
| I7: METRICS_AUTH_TOKEN validation | 3 |
| I8: TLS nginx rate limiting | 9 |
| I9: No stale tracked files | 2 |
| Compose production hardening | 6 |
| Backend Dockerfile security | 4 |
| Frontend Dockerfile security | 3 |
| Nginx security headers | 15 |
| Config validation rules | 5 |
| Server boot sequence | 4 |
| Compose healthcheck alignment | 2 |

**Full suite:** 1075 / 1075 passing (zero regressions)

---

## 6. What Was Already Strong (Not Fixed — Not Broken)

- **Production compose hardening**: `no-new-privileges`, `cap_drop: ALL`, `read_only: true`, tmpfs mounts, resource limits on all services
- **Config fail-fast**: 50+ validation rules catch misconfigurations before the server starts listening
- **Graceful shutdown**: Clean parallel teardown of DB+Redis connections with hard-kill timeout
- **Redis reconnect**: Linear backoff strategy with configurable retries
- **Nginx security headers**: Full set on both HTTP and TLS configs (CSP, HSTS, CORP, COOP, etc.)
- **Non-root execution**: Backend as `node`, frontend as `nginx-unprivileged`
- **Dependency startup ordering**: `service_healthy` conditions in all compose files

---

## 7. Remaining Gaps (Honest)

| # | Gap | Severity | Why Not Fixed |
|---|-----|----------|---------------|
| 1 | No automated database backup strategy | LOW | Operational concern outside compose scope — requires cloud provider backup or cron-based pg_dump |
| 2 | No centralized log aggregation configured | LOW | Infrastructure/DevOps choice — structured logging exists, shipping is a deployment decision |
| 3 | No container image registry push in CI | LOW | Depends on hosting platform (Docker Hub, ECR, GCR, etc.) |
| 4 | Single-replica compose architecture | LOW | Horizontal scaling requires load balancer + session strategy — architectural decision |
| 5 | CVE trend bar chart O(n^2) max computation in frontend | LOW | Performance issue (also noted in dashboard audit). Dataset is small (30 days); not impactful |
