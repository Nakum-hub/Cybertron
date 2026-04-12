# Cybertron Application - Comprehensive Test Report

**Date:** 2026-03-06
**Scope:** Full-stack exhaustive audit of the Cybertron cybersecurity platform
**Testing Areas:** Backend API, Frontend UI, Database, Security, Infrastructure, API Contracts

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Testing Methodology](#2-testing-methodology)
3. [Critical Issues (Must Fix Before Deployment)](#3-critical-issues)
4. [High Severity Issues](#4-high-severity-issues)
5. [Medium Severity Issues](#5-medium-severity-issues)
6. [Low Severity Issues](#6-low-severity-issues)
7. [Informational / Best Practice](#7-informational--best-practice)
8. [Build & Lint Results](#8-build--lint-results)
9. [QA Script Results](#9-qa-script-results)
10. [What Is Working Correctly](#10-what-is-working-correctly)
11. [Suggestions: New Features & Improvements](#11-suggestions-new-features--improvements)
12. [Fix Priority Roadmap](#12-fix-priority-roadmap)

---

## 1. Executive Summary

The Cybertron platform is a feature-rich cybersecurity application with a well-structured architecture. The codebase demonstrates strong security fundamentals (CSRF protection, rate limiting, cookie-based auth with HttpOnly tokens, PKCE for OAuth, security headers via nginx). However, exhaustive testing uncovered **4 critical**, **4 high**, **14 medium**, and **11 low** severity issues, plus **13 informational** observations.

The critical issues include runtime crashes (undefined `context.query` in OAuth, broken database import in compliance service), copy-paste error codes in auth handlers, and a TLS configuration that is never deployed. These must be resolved before any production deployment.

**Overall Assessment:** The application is approximately 85% production-ready. The architecture and security design are sound, but specific implementation bugs and configuration gaps need to be addressed.

---

## 2. Testing Methodology

Testing was conducted across 6 parallel audit tracks:

| Track | Method | Status |
|---|---|---|
| Backend API Routes | Static analysis + code path tracing of all HTTP handlers in server.js (~5200 lines) | Completed |
| Database & Migrations | Schema analysis of 14 migration files + service query consistency checks | Completed |
| Infrastructure & Config | Docker, nginx, env vars, build pipeline analysis | Completed |
| Frontend Routes & UI | Route verification, component imports, API client analysis | Completed |
| Security Audit | Auth flow analysis, CSRF, XSS, injection, cookie policy, OAuth flows | Completed |
| Execution Tests | ESLint, frontend build, all backend QA scripts | Completed |

---

## 3. Critical Issues

### CRIT-01: `context.query` is undefined in OAuth initiation route

**File:** `app/backend/src/server.js:2467-2468`
**Impact:** OAuth login flow crashes with `TypeError: Cannot read properties of undefined` for all providers (Google, Microsoft, GitHub, OIDC)

```javascript
// BROKEN - context.query does not exist on the raw HTTP context object
const tenant = sanitizeTenant(context.query.tenant || 'global');
const rawReturnTo = String(context.query.returnTo || '/platform/threat-command').trim();
```

**Fix:** Replace `context.query.X` with `context.url.searchParams.get('X')`:
```javascript
const tenant = sanitizeTenant(context.url.searchParams.get('tenant') || 'global');
const rawReturnTo = String(context.url.searchParams.get('returnTo') || '/platform/threat-command').trim();
```

---

### CRIT-02: `compliance-framework-service.js` imports `query` from config instead of database

**File:** `app/backend/src/compliance-framework-service.js:9`
**Impact:** Every compliance framework API endpoint throws `TypeError: query is not a function` at runtime

```javascript
// BROKEN - config does not have a query property
const { query } = config;
```

**Fix:** Import from the database module:
```javascript
const { query } = require('./database');
```

---

### CRIT-03: Copy-paste error codes in login and register error handlers

**File:** `app/backend/src/server.js:2373-2386` (login) and `server.js:2431-2450` (register)
**Impact:** If these dead-code branches were ever triggered, auth endpoints would return nonsensical error codes (`risk_report_file_not_found` in login, `audit_package_file_not_found` in register)

**Login handler (line 2374):**
```javascript
// Returns "risk_report_file_not_found" in a LOGIN handler
if (message === 'storage_file_not_found' || message === 'storage_path_missing') {
    sendError(response, context, config, 404, 'risk_report_file_not_found',
              'Risk report file is unavailable in storage.', null, baseExtraHeaders);
```

**Register handler (line 2435):**
```javascript
// Returns "audit_package_file_not_found" in a REGISTER handler
if (message === 'storage_file_not_found' || message === 'storage_path_missing') {
    sendError(response, context, config, 404, 'audit_package_file_not_found',
              'Audit package file is unavailable in storage.', null, baseExtraHeaders);
```

**Fix:** Remove these dead-code branches entirely. `loginWithPassword` and `registerUser` never throw storage-related errors.

---

### CRIT-04: TLS nginx config is never deployed into Docker image

**File:** `app/frontend/nginx/default-tls.conf` (exists on disk)
**File:** `app/frontend/Dockerfile:13` (only copies `default.conf`)
**Impact:** The TLS configuration is an orphan file. Docker-compose maps port 443:8443 and mounts `./certs:/etc/nginx/ssl:ro`, but without the TLS config in the image, HTTPS will not work.

```dockerfile
# Only default.conf is copied - default-tls.conf is ignored
COPY app/frontend/nginx/default.conf /etc/nginx/conf.d/default.conf
```

**Fix:** Either:
- A) Add a second COPY for the TLS config and update nginx to include it when certs are present
- B) Use a reverse proxy (Traefik, Caddy) in front of nginx for TLS termination and remove the orphan file
- C) Create a separate Dockerfile target for TLS builds

---

## 4. High Severity Issues

### HIGH-01: No `pool.on('error')` handler in database connection pool

**File:** `app/backend/src/database.js:30-39`
**Impact:** If an idle PostgreSQL connection receives an error (e.g., database restart, network interruption), the unhandled error event will crash the entire Node.js process.

**Fix:** Add after pool creation:
```javascript
pool.on('error', (err) => {
    console.error('[database] Idle client error:', err.message);
});
```

---

### HIGH-02: `auth_access_token_revocations.user_id` type mismatch

**File:** `app/backend/migrations/004_access_token_revocations.sql:4`
**Impact:** `user_id` is `VARCHAR(191)` while `users.id` is `BIGINT`. No foreign key constraint exists. This allows orphaned/inconsistent revocation records and prevents efficient joins.

**Fix:** Add a migration to:
1. ALTER `user_id` column to `BIGINT`
2. Add a foreign key constraint: `REFERENCES users(id) ON DELETE CASCADE`

---

### HIGH-03: OAuth race condition on concurrent registration

**File:** `app/backend/src/auth-service.js:877-892`
**Impact:** Two concurrent OAuth callbacks for the same new user both pass `findUserByEmail` check (both see no user), then both INSERT. Depending on whether a UNIQUE constraint on `(tenant_slug, email)` exists: either a duplicate key error (500 to user) or silently created duplicate accounts.

**Fix:** Change the INSERT to use `ON CONFLICT`:
```sql
INSERT INTO users (tenant_slug, email, display_name, role, is_active, password_hash)
VALUES ($1,$2,$3,$4,TRUE,NULL)
ON CONFLICT (tenant_slug, email) DO UPDATE SET last_login_at = NOW()
RETURNING id, tenant_slug, email, display_name, role, is_active
```

---

### HIGH-04: OAuth login bypasses account lockout and clears it

**File:** `app/backend/src/auth-service.js:824-831`
**Impact:** A user locked out due to failed password attempts can bypass the lockout by logging in via OAuth. Worse, `markSuccessfulLogin()` (line 830) resets `failed_login_count = 0` and `locked_until = NULL`, clearing the lockout entirely.

**Fix:** Add a lockout check in `findOrCreateOAuthUser` before calling `markSuccessfulLogin`:
```javascript
if (existing.locked_until && new Date(existing.locked_until).getTime() > Date.now()) {
    throw new ServiceError(429, 'account_locked', 'Account is temporarily locked.');
}
```

---

## 5. Medium Severity Issues

### MED-01: OIDC ID token is parsed but never signature-verified

**File:** `app/backend/src/oauth-provider.js:407-424`
**Impact:** The OIDC profile is extracted from the ID token by decoding the JWT payload without verifying the signature. A malicious token relay or tampered token could inject arbitrary claims.

**Recommendation:** Either verify the ID token signature using the OIDC provider's JWKS endpoint, or always fetch from the userinfo endpoint instead.

---

### MED-02: OIDC nonce generated but never validated

**File:** `app/backend/src/oauth-provider.js:208`
**Impact:** A nonce is added to the authorization URL, but it's never stored server-side and never checked against the returned ID token's `nonce` claim. This defeats replay protection.

**Fix:** Store the nonce in the OAuth state cookie and validate it against the ID token's nonce claim during callback processing.

---

### MED-03: ILIKE queries don't escape SQL wildcard characters

**Files:**
- `app/backend/src/module-service.js:205-206, 467-468`
- `app/backend/src/threat-hunt-service.js:197-207`

**Impact:** User search inputs containing `%` or `_` produce unexpected results (`%` matches any string, `_` matches any single character). Not an injection risk (queries are parameterized), but a functional bug.

**Fix:** Add a helper to escape wildcards before interpolation:
```javascript
function escapeLikePattern(str) {
    return str.replace(/[%_\\]/g, '\\$&');
}
```

---

### MED-04: In-memory revoked token map has no size cap

**File:** `app/backend/src/server.js:408`
**Impact:** While expired entries are cleaned every 60 seconds, there is no hard cap on the Map size. A mass revocation event could cause high memory usage until the next cleanup cycle. Additionally, `bootstrapRevokedAccessTokensFromDatabase()` loads ALL non-expired revoked tokens into memory at startup.

**Recommendation:** Add a max-size check (e.g., 50,000 entries) and consider using Redis for revocation checks in production.

---

### MED-05: Refresh tokens not bound to client fingerprint

**File:** `app/backend/src/auth-service.js:519-538`
**Impact:** Refresh tokens store `created_ip` and `user_agent` at creation but never validate them during rotation. A stolen refresh token works from any IP/browser.

**Recommendation:** During `rotateRefreshToken`, optionally compare the current client's IP/user-agent against stored values. At minimum, log a warning on mismatch.

---

### MED-06: Missing SSE/WebSocket upgrade headers in nginx proxy

**File:** `app/frontend/nginx/default.conf:41-52`
**Impact:** The `/api/` proxy location sets `proxy_http_version 1.1` but lacks `Upgrade` and `Connection` headers. WebSocket connections through nginx will fail. SSE may work partially.

**Fix:** Add to the `/api/` location block:
```nginx
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
```

---

### MED-07: `.env.example` uses `PUBLIC_` prefix instead of `VITE_`

**File:** `.env.example:63-76`
**Impact:** The `.env.example` documents frontend variables with `PUBLIC_` prefix, but Vite requires `VITE_` prefix for client-side exposure. Developers copying `.env.example` for local development will get wrong variable names.

**Fix:** Add `VITE_`-prefixed versions to `.env.example` alongside the backend `PUBLIC_` ones, or add a comment explaining the naming convention.

---

### MED-08: 14 VITE_ variables used by frontend but undocumented

**File:** `app/frontend/src/lib/config.ts:90-134`
**Impact:** The following variables have no documentation in `.env.example`:
- `VITE_REQUEST_TIMEOUT_MS`, `VITE_API_RETRY_COUNT`, `VITE_API_RETRY_BASE_DELAY_MS`
- `VITE_ENABLE_API_OBSERVABILITY`, `VITE_AUTH_LOGIN_URL`, `VITE_AUTH_TRANSPORT`
- `VITE_CSRF_HEADER_NAME`, `VITE_CSRF_COOKIE_NAME`
- `VITE_TENANTS_PATH`, `VITE_PRODUCTS_PATH`, `VITE_MODULES_PATH`
- `VITE_BILLING_USAGE_PATH`, `VITE_BILLING_CREDITS_PATH`
- `VITE_TENANT_PRODUCTS_PATH_TEMPLATE`, `VITE_TENANT_FEATURE_FLAGS_PATH_TEMPLATE`

**Fix:** Add these to `.env.example` with sensible defaults and descriptions.

---

### MED-09: Weak default `POSTGRES_PASSWORD` in base docker-compose.yml

**File:** `docker-compose.yml:8`
**Impact:** Default password is `changeme`. If the base compose file is used without `.env`, the database runs with a well-known password.

```yaml
POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-changeme}
```

**Fix:** Change to use required variable syntax like the production compose file:
```yaml
POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?set_POSTGRES_PASSWORD}
```

---

### MED-10: Missing indexes on frequently queried columns

**Files:** Various migration files
**Impact:** Several columns used in WHERE clauses lack indexes:

| Table | Column(s) | Used By |
|---|---|---|
| `playbook_templates` | `category`, `mitre_tactic_id` | Playbook filtering and search |
| `playbook_instances` | `tenant_slug, status` | Status-based queries |
| `mitre_techniques` | `tactic_id` | Technique lookup by tactic |
| `auth_access_token_revocations` | `user_id`, `expires_at` | Revocation checks and cleanup |

**Fix:** Add a new migration with indexes on these columns.

---

### MED-11: No tenant foreign key enforcement anywhere

**Files:** Various migration files (001-014)
**Impact:** Multiple tables have `tenant_slug VARCHAR(64)` columns used for multi-tenant data isolation, but none have a foreign key to a `tenants` table. Data integrity relies entirely on application-layer enforcement.

**Recommendation:** If a `tenants` table exists, add FK constraints. If not, consider creating one.

---

### MED-12: Silent auth degradation on empty token refresh

**File:** `app/frontend/src/lib/api.ts:148-149`
**Impact:** If the token refresh endpoint returns an empty `accessToken` string, `tryRefreshAccessToken()` returns `true` (success) but stores a null access token. Subsequent API calls proceed without authentication, resulting in 401 errors.

**Fix:** Check that the accessToken is non-empty before declaring success:
```typescript
if (!data.accessToken) {
    clearAccessToken();
    return false;
}
```

---

### MED-13: Docker compose base healthcheck uses /v1/system/liveness instead of /v1/system/readiness

**File:** `docker-compose.yml` (backend healthcheck)
**Impact:** Liveness only confirms the process is running, not that dependencies (database, Redis) are connected. The readiness endpoint returns 503 when required dependencies are unhealthy, which is more appropriate for container orchestration.

**Recommendation:** Use `/v1/system/readiness` for Docker healthchecks (as the production compose file already does).

---

### MED-14: `axios` is a listed dependency but appears unused

**File:** `app/frontend/package.json`
**Impact:** The API client (`api.ts`) uses native `fetch()`. If axios is not used elsewhere, it adds ~35KB gzipped to node_modules without purpose.

**Fix:** Verify axios is not imported anywhere; if confirmed unused, remove it.

---

## 6. Low Severity Issues

### LOW-01: `@types/three` is in dependencies instead of devDependencies

**File:** `app/frontend/package.json:53`
**Impact:** Type packages are development-only tools. Including them in `dependencies` causes unnecessary installation in production builds.

---

### LOW-02: Pre-release ESLint plugin dependency

**File:** `app/frontend/package.json:91`
**Impact:** `eslint-plugin-react-hooks: ^5.1.0-rc.0` is a release candidate. Stable 5.x versions are available.

---

### LOW-03: Potential version skew in TypeScript ESLint configuration

**File:** `app/frontend/package.json:99-100`
**Impact:** `typescript-eslint: ^8.0.1` alongside `@typescript-eslint/eslint-plugin: ^8.42.0` and `@typescript-eslint/parser: ^8.42.0` may cause version resolution conflicts.

---

### LOW-04: Vite version is behind current release line

**File:** `app/frontend/package.json`
**Impact:** `vite: ^5.4.1` - Vite 6.x is the current major version. 5.4.x is on the maintenance branch. No immediate security risk but should be tracked.

---

### LOW-05: Database singleton pool ignores config differences

**File:** `app/backend/src/database.js:21-40`
**Impact:** `getPool()` creates a pool on first call and returns the same pool on subsequent calls regardless of config changes. In practice this is fine (config doesn't change at runtime), but it means unit tests cannot easily switch database configs.

---

### LOW-06: `next-themes` package used in a non-Next.js app

**File:** `app/frontend/package.json`
**Impact:** `next-themes` is designed for Next.js. While it may work in Vite/React-Router apps, it is an unusual dependency that could cause subtle issues with SSR-specific code paths.

---

### LOW-07: Legacy typo in logout key maintained for backward compatibility

**File:** `app/frontend/src/lib/auth.ts:2`
**Impact:** `LEGACY_LOGOUT_KEY = 'isLougOutManual'` (typo: "Loug" → "Log"). Both the old key and new key `isLogOutManual` are written by `setManualLogoutFlag()`. Harmless but should be cleaned up eventually.

---

### LOW-08: Revocation store "fails open" without Redis

**File:** `app/backend/src/server.js`
**Impact:** When Redis is unavailable, the in-memory revocation map is lost on process restart. Previously revoked tokens may temporarily be accepted until the database bootstrap completes.

---

### LOW-09: Session store unbounded growth under load

**File:** `app/backend/src/server.js:215`
**Impact:** The in-memory session store has cleanup but no hard maximum on active sessions. Under extreme load or a session creation attack, memory usage could grow significantly.

---

### LOW-10: Postgres connection string password embedded in compose env

**File:** `docker-compose.prod.yml:111`
**Impact:** `DATABASE_URL` embeds `${POSTGRES_PASSWORD}` which may be logged if Docker inspects the environment.

---

### LOW-11: PostCSS version may have known CVEs

**File:** `app/frontend/package.json`
**Impact:** `postcss: ^8.4.47` - Ensure lockfile resolves to 8.4.49+ which includes relevant security patches.

---

## 7. Informational / Best Practice

| # | Area | Observation |
|---|---|---|
| INFO-01 | Frontend | API observability is enabled by default (`enableApiObservability: true`) and exposes `window.__cybertronApiObservations` in production. Consider disabling in production builds. |
| INFO-02 | Frontend | `environment` config defaults to `'development'` if `MODE` env var is unset. A misconfigured production build could fall back to dev mode behavior. |
| INFO-03 | Frontend | `/api/config` endpoint is fetched unauthenticated at startup. This could leak configuration paths and feature flags to unauthenticated users. |
| INFO-04 | Backend | Health check endpoint (`/v1/system/health`) always returns HTTP 200 even when dependencies are degraded. Status is indicated only in the response body. Monitoring tools may not catch degraded states if they only check HTTP status codes. |
| INFO-05 | Frontend | `/diagnostics` and `/status` are aliases for the same `StatusPage` component. Intentional, but may confuse users or documentation. |
| INFO-06 | Docker | Production compose file healthcheck uses `wget` which may not be available in all Node.js base images. The base compose file uses a different approach. Inconsistency between files. |
| INFO-07 | Security | JWT uses HS256 (symmetric HMAC). For multi-service architectures, RS256/ES256 (asymmetric) would be more appropriate as only the auth service needs the private key. |
| INFO-08 | Backend | The monolithic `server.js` file is ~5200 lines. While functional, this makes maintenance, testing, and code review difficult. |
| INFO-09 | Backend | N+1 query patterns exist in at least 4 service files where lists are fetched and then individual items are enriched in loops. |
| INFO-10 | Security | OIDC audience validation is not performed on ID tokens. The `OIDC_AUDIENCE` env var exists but is never checked against the token's `aud` claim. |
| INFO-11 | Backend | No request body size limit is enforced at the Node.js HTTP server level (only nginx enforces `client_max_body_size 20m`). Direct access to the backend bypasses this. |
| INFO-12 | Frontend | React 18.3.x is used. React 19 is available. No immediate action needed but should be planned. |
| INFO-13 | Config | No `.env.production.example` exists with all required production variables documented in one place. The `.env.example` contains development defaults that are inappropriate for production. |

---

## 8. Build & Lint Results

### Frontend Build
```
Status: SUCCESS
Chunk sizes:
  - three-vendor: 1066.07 kB (gzipped: ~340 kB) - Three.js vendor chunk
  - Main bundle: within limits
  - Warning: chunk size exceeds 1000 kB limit (configured to 1100 kB)
```

### ESLint
```
Status: PASS
Errors: 0
Warnings: 23 (non-blocking)
```

### TypeScript
```
Status: Compiled successfully (strict mode)
```

---

## 9. QA Script Results

All backend QA scripts passed:

| Script | Result |
|---|---|
| `qa:cookie-policy` | PASS - Cookie policy checks passed |
| `qa:distributed-auth` | PASS - Distributed auth flow verified |
| `qa:failure` | PASS - Failure mode handling verified |
| `qa:load` (load-smoke)  | PASS - Load smoke test completed |
| `qa:phase3` (phase3-ai) | PASS - Phase 3 AI checks passed |

---

## 10. What Is Working Correctly

The following were verified to be properly implemented:

- **All 19 frontend routes** resolve correctly with no broken imports or missing components
- **Lazy loading** with React.lazy/Suspense works for all page components
- **Three.js code splitting** into a separate vendor chunk
- **OAuth PKCE** for Google, Microsoft, and OIDC providers
- **CSRF double-submit pattern** with configurable cookie names
- **Cookie-based auth transport** with HttpOnly, Secure, SameSite=Lax cookies
- **Rate limiting** with both in-memory and Redis-backed stores
- **Account lockout** after configurable failed attempts (password login)
- **Token refresh** with concurrent request deduplication (single in-flight refresh)
- **API retry logic** with exponential backoff for transient errors (408, 429, 5xx)
- **Request timeouts** on both frontend (AbortController) and backend (OAuth calls)
- **Security headers** in nginx (X-Frame-Options, CSP, COOP, CORP, etc.)
- **Health/readiness endpoints** checking database, Redis, and storage connectivity
- **14 database migrations** with transactional execution and versioning
- **Report upload/download** pipeline with S3 and local storage drivers
- **Report retention** with configurable cleanup intervals
- **Input validation** with length limits, email normalization, tenant sanitization
- **Open redirect prevention** via `sanitizeRedirectPath` on OAuth returnTo
- **JWT placeholder detection** in production mode (rejects "CHANGE_ME" secrets)
- **Graceful shutdown** handling for database and Redis connections
- **API observability** with request tracking and error correlation

---

## 11. Suggestions: New Features & Improvements

### 11.1 Architecture Improvements

1. **Split `server.js` into route modules** - The 5200-line monolith should be broken into separate route files (auth-routes.js, threat-routes.js, report-routes.js, etc.) for maintainability.

2. **Add a request validation middleware layer** - Use a schema-based validation library (e.g., Zod, Joi) for request body/query parameter validation instead of manual string checks.

3. **Implement structured logging** - Replace `console.log`/`console.error` with a structured logger (pino or winston) that outputs JSON with consistent fields (timestamp, level, requestId, tenantSlug).

4. **Add database connection pooling metrics** - Export pool stats (active, idle, waiting) to the health endpoint for monitoring.

### 11.2 Security Enhancements

5. **Implement OIDC ID token signature verification** - Fetch the JWKS from the OIDC discovery document and verify the JWT signature before trusting claims.

6. **Add OIDC audience validation** - The `OIDC_AUDIENCE` env var exists but is never checked. Validate the `aud` claim matches.

7. **Bind refresh tokens to client fingerprint** - During token rotation, compare IP/user-agent against stored values. Log a security event on mismatch.

8. **Add Content Security Policy nonce for inline scripts** - If future features require inline scripts, use nonce-based CSP instead of `unsafe-inline`.

9. **Implement security event audit log table** - Track login attempts, OAuth events, password changes, role changes, and admin actions in a dedicated audit table.

10. **Add brute-force protection for OAuth** - While OAuth doesn't have passwords to brute-force, rate-limit OAuth initiation per IP to prevent abuse.

### 11.3 Feature Additions

11. **Email verification flow** - Add email verification for new registrations (password and OAuth) before granting full access.

12. **User management admin panel** - Add admin UI pages for user listing, role management, account activation/deactivation, and session management.

13. **Multi-factor authentication (MFA)** - Add TOTP-based MFA support for password-authenticated users.

14. **Password reset flow** - The `PASSWORD_RESET_TOKEN_TTL_MS` env var exists in config but verify the full reset flow (email send, token validation, password update) is complete.

15. **API key authentication** - For programmatic/integration access, add API key generation and validation alongside cookie/JWT auth.

16. **WebSocket support** - Add WebSocket connection support for real-time threat alerts, incident updates, and system notifications.

17. **Dark mode toggle persistence** - Verify that `next-themes` (or a replacement) properly persists theme preference across sessions.

18. **Pagination component** - Add cursor-based or offset-based pagination for large data sets (incidents, reports, users).

19. **Export functionality** - Add PDF/CSV export for threat summaries, incident reports, and compliance frameworks.

20. **Activity dashboard** - Add a real-time dashboard showing recent user activity, active sessions, and system metrics.

### 11.4 DevOps & Infrastructure

21. **Add a CI/CD pipeline configuration** - Create GitHub Actions (or equivalent) workflows for: lint, typecheck, unit tests, integration tests, Docker build, and deployment.

22. **Database backup strategy** - Add a backup sidecar or cron job for PostgreSQL dumps with S3 upload.

23. **Container image security scanning** - Add Trivy or Snyk scanning to the Docker build pipeline.

24. **Add Prometheus metrics endpoint** - The `/v1/metrics` infrastructure exists but could be expanded with RED metrics (Rate, Error, Duration) per route.

25. **Implement blue-green or canary deployment** - Add Docker Compose profiles or Kubernetes manifests for zero-downtime deployments.

---

## 12. Fix Priority Roadmap

### Phase 1: Pre-Deployment Blockers (Fix Immediately)
| Issue | ID | Effort |
|---|---|---|
| Fix `context.query` crash in OAuth route | CRIT-01 | Small |
| Fix compliance service database import | CRIT-02 | Small |
| Remove copy-paste error code branches | CRIT-03 | Small |
| Fix or remove TLS config deployment | CRIT-04 | Medium |
| Add `pool.on('error')` handler | HIGH-01 | Small |
| Fix access token revocations type mismatch | HIGH-02 | Medium |
| Add ON CONFLICT to OAuth user creation | HIGH-03 | Small |
| Add lockout check to OAuth login | HIGH-04 | Small |

### Phase 2: Security Hardening (Fix Before Public Access)
| Issue | ID | Effort |
|---|---|---|
| Verify OIDC ID token signature | MED-01 | Medium |
| Validate OIDC nonce | MED-02 | Medium |
| Escape ILIKE wildcards | MED-03 | Small |
| Cap revocation map size | MED-04 | Small |
| Add missing nginx WebSocket headers | MED-06 | Small |
| Fix silent auth degradation | MED-12 | Small |

### Phase 3: Configuration & Documentation (Fix Before Team Onboarding)
| Issue | ID | Effort |
|---|---|---|
| Fix env variable naming (PUBLIC_ vs VITE_) | MED-07 | Medium |
| Document all VITE_ variables | MED-08 | Medium |
| Strengthen compose defaults | MED-09 | Small |
| Add missing database indexes | MED-10 | Medium |
| Clean up unused dependencies | MED-14 | Small |

### Phase 4: Quality & Maintenance (Post-Deployment)
| Issue | ID | Effort |
|---|---|---|
| Bind refresh tokens to fingerprint | MED-05 | Medium |
| Fix tenant FK enforcement | MED-11 | Large |
| Fix all LOW issues | LOW-01 to LOW-11 | Medium |
| Address INFO items | INFO-01 to INFO-13 | Ongoing |

---

*End of Report*

*Generated by exhaustive automated testing and static analysis across all application layers.**
