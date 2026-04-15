# 🛡️ CYBERTRON — COMPLETE ENGINEERING AUDIT + MASTER LAUNCH FIX PROMPT
### For 50-Member IIT/MIT Engineering Task Force
**Prepared: April 2026 | Audit Level: Pre-Launch, YC-Grade**

---

## PART 1 — CONTINUED AUDIT FINDINGS (DEEP DIVE)

### 1.1 TEST SUITE — REALITY CHECK

The repository **does have a `tests/` directory** with 19 test files. However:

- **All 19 tests are static source-code assertion tests.** They open `.ts` and `.js` source files as text strings and run `assert.ok(source.includes('someString'))`.
- **Zero tests make HTTP requests.** No integration tests hit a running server.
- **Zero tests insert/query a real database.** No DB-level validation.
- **Zero tests mock and unit-test individual service functions.**
- The CI pipeline runs `npm run coverage` but coverage is 0% of actual runtime paths — it counts the static string checks.

**Verdict:** These tests function as a _regression guard against source code changes_, not as a functional test suite. An investor doing technical due diligence, or a new engineer breaking an API contract, will get no signal from these tests.

---

### 1.2 MISSING PAGES — COMPLETE LIST

The following pages **do not exist** but are needed for a real product:

| Page | Route | Why Needed |
|---|---|---|
| Admin Dashboard | `/admin` or `/platform/admin` | Tenant/user/product management UI for `tenant_admin` role |
| Onboarding / Workspace Setup | `/onboarding` | New user flow after registration — workspace creation wizard |
| Checkout / Upgrade | `/checkout` | Stripe payment page for plan upgrades |
| Subscription Management | `/account/billing` | View current plan, usage, invoices, cancel |
| Invite / Team Management | `/account/team` | Invite users to a workspace, set roles |
| Email Verification | `/auth/verify-email` | Post-registration email confirmation page |
| Password Reset Form | `/auth/reset-password` | UI form to enter new password after receiving reset link |
| 2FA / MFA Setup | `/account/security` | TOTP setup, recovery codes |
| Connector Setup | `/platform/connectors` | Configure Wazuh / MISP / OpenCTI connections per tenant |
| Notification Preferences | `/account/notifications` | Email and in-app notification settings |
| API Keys Management | `/account/api-keys` | Generate/revoke API keys for programmatic access |
| Release Notes / Changelog | `/changelog` | Shows product version history to users |

---

### 1.3 MISSING BACKEND ROUTES

These backend routes are **called from the frontend** but **do not exist** in `crud.js` or any module:

| Frontend Call | Expected Route | Status |
|---|---|---|
| `fetchPolicies()` | `GET /v1/compliance/policies` | ✅ Exists in compliance module |
| Stripe checkout initiation | `POST /v1/billing/checkout` | ❌ MISSING |
| Stripe webhook receiver | `POST /v1/webhooks/stripe` | ❌ MISSING |
| Email verification | `POST /v1/auth/verify-email` | ❌ MISSING |
| Resend verification email | `POST /v1/auth/resend-verification` | ❌ MISSING |
| Invite user to workspace | `POST /v1/tenants/:slug/invites` | ❌ MISSING |
| Accept invite | `GET /v1/invites/:token/accept` | ❌ MISSING |
| API key management | `GET/POST/DELETE /v1/api-keys` | ❌ MISSING |
| Connector config CRUD | `GET/POST/PATCH /v1/connectors/config` | ❌ MISSING |
| 2FA setup/verify | `POST /v1/auth/2fa/setup`, `/verify` | ❌ MISSING |
| Notification prefs | `GET/PATCH /v1/notifications/preferences` | ❌ MISSING |
| Changelog / version feed | `GET /v1/system/changelog` | ❌ MISSING |

---

### 1.4 FRONTEND ↔ BACKEND WIRING GAPS (ADDITIONAL)

| Component | Issue |
|---|---|
| `PricingSection.tsx` → `navigateToPlanAction()` | Sends user to `/account?mode=register&plan=pro` — account page does not read `plan` param or initiate checkout |
| `AccountPage.tsx` — "forgot password" flow | Calls `requestPasswordReset()` which works, but the email with reset link is never sent. The token comes back in the API response in dev mode only. Users are stuck. |
| `Platform.tsx` — billing credits display | Shows credits fetched from `GET /v1/billing/credits`. If database is not configured, this silently shows 0 with no error. Users think they have no credits. |
| `PlatformGovernancePanel.tsx` | Calls `fetchAuditLogs()` and `fetchServiceRequests()` — these work but `fetchServiceRequests` is not defined in `backend.ts`, only `fetchServiceRequests` with tenant param — potential undefined call. |
| `NotificationBell.tsx` | Subscribes to SSE at `/v1/notifications/stream` — this works, but max 50 clients per tenant in-memory. In production with >50 concurrent users on one tenant, new connections silently drop. |
| `AttackMapPanel.tsx` | Calls `fetchAttackMapData()` → `GET /v1/threat-intel/siem/attack-map`. Returns geo data only when Wazuh/connector is configured. Default state: empty map with no user guidance on how to connect a data source. |
| `AiAgentsPanel.tsx` | Renders a panel showing "AI agent status" but there is no agent execution endpoint. The panel displays status cards but clicking any agent does nothing actionable. |
| `products/RiskCopilotPage.tsx` vs `pages/RiskCopilotPage.tsx` | Two different files both render Risk Copilot content. The products/ version is a `ProductPageShell` wrapper. Neither is clearly the canonical one. Routes in `App.tsx` point to `pages/RiskCopilotPage.tsx`. The `products/` variants are unreachable dead code. |

---

### 1.5 ARCHITECTURAL GAPS NOT PREVIOUSLY LISTED

**1. No email transport anywhere in the codebase**
`requestPasswordReset()` generates a token and stores the hash. The API returns the raw token in dev mode. In production, `resetToken` is explicitly set to `undefined`. No SMTP client, no HTTP mail API (Resend, SendGrid, Postmark) exists anywhere in the backend source. This is a complete omission, not a misconfiguration.

**2. Stripe is entirely absent**
Not a single file references `stripe`, `payment_intent`, `checkout_session`, or any payment SDK. The billing service only does internal DB metering. The pricing page CTAs send users to the register page with a `?plan=` query param that does nothing.

**3. ML model has no deployment path**
The `ml/` directory has a full LoRA fine-tuning pipeline (Unsloth, vLLM, Lightning AI). Training data is present. But:
- There is no API endpoint to route requests to the fine-tuned model
- The `llm-provider.js` only supports `openai` or `ollama` — neither of which is the fine-tuned model
- No vLLM OpenAI-compatible server config is wired into the Docker Compose setup

**4. Multi-tenant RLS is correct in schema but not enforced for all write paths**
Row-Level Security policies exist in migrations. `queryWithTenant()` sets `app.current_tenant`. However several write paths in `crud.js` use the base `query()` function (no tenant context), meaning those writes bypass RLS as the session variable is not set.

**5. No global error handling for unhandled promise rejections**
The `server.js` entry point does not register `process.on('unhandledRejection', ...)` or `process.on('uncaughtException', ...)`. A single unhandled promise in any route will crash the Node.js process silently in production.

**6. Cookie SameSite configuration**
`COOKIE_SAME_SITE` defaults to `lax`. For cross-origin deployments (frontend on `app.cybertron.io`, backend on `api.cybertron.io`), `lax` will break authentication. Must be `none` with `secure: true` for cross-origin production setups.

**7. No health check for LLM provider**
The `/v1/system/health` endpoint checks DB, Redis, and storage. It does not probe the LLM provider. In production, the LLM can go down silently and no alerting fires.

**8. Duplicate Page Files (Dead Code)**
```
src/pages/RiskCopilotPage.tsx        ← USED in App.tsx routing
src/pages/ComplianceEnginePage.tsx   ← USED in App.tsx routing
src/pages/ThreatIntelPage.tsx        ← USED in App.tsx routing
src/pages/products/RiskCopilotPage.tsx    ← DEAD — no route points here
src/pages/products/ComplianceEnginePage.tsx  ← DEAD
src/pages/products/ThreatIntelPage.tsx       ← DEAD
src/pages/products/ProductPageShell.tsx      ← DEAD
```

---

## PART 2 — COMPLETE FEATURE → BACKEND → DB TRUTH MAP

```
Feature                          UI   API              DB    Real?
─────────────────────────────────────────────────────────────────
Login (JWT)                      ✅   POST /v1/auth/login          ✅    ✅ WORKS
Register                         ✅   POST /v1/auth/register       ✅    ✅ WORKS (with DB)
OAuth (Google/GitHub)            ✅   GET /v1/auth/oauth/:p        ✅    ✅ WORKS (with keys)
Password Reset Request           ✅   POST /v1/auth/password/forgot ✅   ⚠️  TOKEN NOT EMAILED
Password Reset Submit            ✅   POST /v1/auth/password/reset  ✅   ⚠️  WORKS if token known
Email Verification               ❌   ❌ MISSING                   ❌    ❌ NOT BUILT
2FA / MFA                        ❌   ❌ MISSING                   ❌    ❌ NOT BUILT
Session refresh                  ✅   POST /v1/auth/token          ✅    ✅ WORKS
Logout + token revocation        ✅   POST /v1/auth/logout         ✅    ✅ WORKS
─────────────────────────────────────────────────────────────────
Platform dashboard               ✅   GET /v1/platform/apps        ✅    ✅ WORKS
App status cards                 ✅   GET /v1/apps/:id/status      ✅    ✅ WORKS
Threat summary                   ✅   GET /v1/threats/summary      ✅    ✅ WORKS (with DB)
Threat incidents                 ✅   GET /v1/threats/incidents    ✅    ✅ WORKS (with DB)
Connector status                 ✅   GET /v1/connectors/status    ✅    ⚠️  EMPTY without connectors
Incident CRUD                    ✅   GET/POST /v1/incidents       ✅    ✅ WORKS
Incident timeline                ✅   GET /v1/incidents/:id/timeline ✅  ✅ WORKS
IOC management                   ✅   GET/POST /v1/iocs            ✅    ✅ WORKS
Service requests                 ✅   GET/POST /v1/service-requests ✅   ✅ WORKS
─────────────────────────────────────────────────────────────────
SIEM alert ingestion             ✅   POST /v1/threat-intel/siem/upload ✅ ✅ WORKS
SIEM alert list                  ✅   GET /v1/threat-intel/siem/alerts  ✅ ✅ WORKS
SIEM alert stats                 ✅   GET /v1/threat-intel/siem/alerts/stats ✅ ✅ WORKS
Alert status update              ✅   PATCH /v1/threat-intel/siem/alerts/:id/status ✅ ✅
Alert assignment                 ✅   PATCH /v1/threat-intel/siem/alerts/:id/assign ✅ ✅
Alert escalation                 ✅   POST /v1/threat-intel/siem/alerts/:id/escalate ✅ ✅
Alert bulk ops                   ✅   POST /v1/threat-intel/siem/alerts/bulk-status ✅ ✅
SLA metrics                      ✅   GET /v1/threat-intel/siem/alerts/sla-metrics ✅ ✅
Triage suggestion (AI)           ✅   GET /v1/threat-intel/siem/alerts/:id/triage-suggestion ✅ ⚠️ STUB without LLM
Correlation rules                ✅   GET/POST/PUT /v1/threat-intel/siem/correlation-rules ✅ ✅
Attack map                       ✅   GET /v1/threat-intel/siem/attack-map ✅ ⚠️ EMPTY without connectors
CVE sync                         ✅   POST /v1/threat-intel/cve/sync ✅   ⚠️ Needs NVD_API_KEY
CVE feed                         ✅   GET /v1/threat-intel/cve/feed  ✅   ✅ WORKS (post-sync)
CVE summarize (AI)               ✅   POST /v1/threat-intel/cve/:id/summarize ✅ ❌ FAKE without LLM
MITRE techniques                 ✅   GET /v1/threat-intel/mitre/techniques ✅ ✅ WORKS
MITRE heatmap                    ✅   GET /v1/threat-intel/mitre/heatmap ✅ ✅ WORKS
MITRE incident mapping           ✅   POST /v1/threat-intel/mitre/incidents/:id ✅ ✅ WORKS
Playbooks CRUD                   ✅   GET/POST/PUT /v1/threat-intel/playbooks ✅ ✅ WORKS
Playbook execution               ✅   POST /v1/threat-intel/playbooks/:id/execute ✅ ✅ WORKS
Threat hunting                   ✅   GET/POST/PUT/DELETE/POST /v1/threat-intel/hunts ✅ ✅ WORKS
─────────────────────────────────────────────────────────────────
Risk findings                    ✅   GET /v1/risk/findings         ✅    ✅ WORKS
Risk score compute               ✅   POST /v1/risk/score/compute   ✅    ⚠️ AI-enhanced requires LLM
AWS log ingest                   ✅   POST /v1/risk/ingest/aws-logs ✅    ✅ WORKS
Risk finding treatment           ✅   PATCH /v1/risk/findings/:id/treatment ✅ ✅ WORKS
Risk report generate             ✅   POST /v1/risk/report/generate  ✅    ⚠️ AI summary requires LLM
Risk report download             ✅   GET /v1/risk/report/:id/download ✅  ✅ WORKS (PDF local/S3)
─────────────────────────────────────────────────────────────────
SOC2 controls                    ✅   GET /v1/compliance/soc2/controls ✅  ✅ WORKS
SOC2 status                      ✅   GET /v1/compliance/soc2/status   ✅  ✅ WORKS
SOC2 evidence upload             ✅   POST /v1/compliance/soc2/evidence/upload ✅ ✅ WORKS
Multi-framework compliance       ✅   GET /v1/compliance/frameworks    ✅  ✅ WORKS
Compliance summary               ✅   GET /v1/compliance/summary       ✅  ✅ WORKS
Policy generate (AI)             ✅   POST /v1/compliance/policy/generate ✅ ❌ FAKE without LLM
Audit package generate           ✅   POST /v1/compliance/audit-package/generate ✅ ⚠️ Partial without LLM
Policy approval workflow         ✅   PATCH /v1/compliance/policies/:id/status ✅ ✅ WORKS
─────────────────────────────────────────────────────────────────
Report upload                    ✅   POST /v1/reports/upload          ✅    ✅ WORKS
Report list                      ✅   GET /v1/reports                  ✅    ✅ WORKS
Report download                  ✅   GET /v1/reports/:id/download     ✅    ✅ WORKS
─────────────────────────────────────────────────────────────────
Billing credits                  ✅   GET /v1/billing/credits          ✅    ✅ WORKS
Billing usage                    ✅   GET /v1/billing/usage            ✅    ✅ WORKS
Billing plan                     ✅   GET /v1/billing/plan             ✅    ✅ WORKS
Billing checkout (Stripe)        ✅UI  ❌ MISSING                       ❌    ❌ NOT BUILT
Stripe webhook                   N/A  ❌ MISSING                       ❌    ❌ NOT BUILT
─────────────────────────────────────────────────────────────────
Users list                       ✅   GET /v1/users                    ✅    ✅ WORKS (admin)
Tenants list                     ✅   GET /v1/tenants                  ✅    ✅ WORKS (admin)
Audit logs                       ✅   GET /v1/audit-logs               ✅    ✅ WORKS (admin)
Product toggle (admin)           ✅   PATCH /v1/products/:key/state    ✅    ✅ WORKS (admin)
Feature flags                    ✅   GET/PATCH /v1/feature-flags      ✅    ✅ WORKS (admin)
Module registry                  ✅   GET /v1/modules                  ✅    ✅ WORKS
─────────────────────────────────────────────────────────────────
SSE Notifications                ✅   GET /v1/notifications/stream     N/A   ✅ WORKS (in-memory)
Admin Dashboard page             ❌   N/A                              N/A   ❌ NOT BUILT
Onboarding wizard                ❌   N/A                              N/A   ❌ NOT BUILT
Email transport                  ❌   N/A                              N/A   ❌ NOT BUILT
Workspace invite system          ❌   ❌ MISSING                       ❌    ❌ NOT BUILT
API key management               ❌   ❌ MISSING                       ❌    ❌ NOT BUILT
Connector configuration UI       ❌   ❌ MISSING                       ❌    ❌ NOT BUILT
Fine-tuned LLM deployment        N/A  ❌ MISSING                       N/A   ❌ NOT BUILT
```

---

## PART 3 — COMPLETE MASTER FIXING PROMPT

> **INSTRUCTIONS FOR THE TASK FORCE:**
> Copy this entire Part 3 as a system prompt to your AI coding assistant (Cursor, GitHub Copilot, Claude Code, etc.), or use it as the engineering spec for your 50-member team. Every section maps to a specific engineer or squad. Execute in strict Priority order: P0 → P1 → P2 → P3.

---

```
╔══════════════════════════════════════════════════════════════════════════╗
║         CYBERTRON — COMPLETE PRODUCTION LAUNCH FIX SPECIFICATION        ║
║         For: 50-Member IIT/MIT Engineering Task Force                   ║
║         Standard: YC Launch Quality / Production Grade                  ║
╚══════════════════════════════════════════════════════════════════════════╝

PROJECT: Cybertron — B2B Cybersecurity SaaS Platform
REPO:    https://github.com/Nakum-hub/Cybertron.git
STACK:   Node.js backend (no framework), React/TypeScript frontend, 
         PostgreSQL, Redis, Docker Compose

GROUND RULES FOR ALL ENGINEERS:
1. Do NOT add features not in this spec. Fix what is broken first.
2. Every code change must preserve existing working behavior.
3. Do NOT use any `any` type in TypeScript. Explicit types only.
4. All new API routes must be added to /workspace/app/backend/src/openapi.js.
5. All new environment variables must be added to .env.example with comments.
6. All new DB changes must be a new numbered migration (026_xxx.sql, etc).
7. Security fixes ship BEFORE features — P0 is non-negotiable.
8. Tests must verify runtime behavior, not just source file contents.

════════════════════════════════════════════════════════════════════════════
P0 — CRITICAL SECURITY FIXES (Ship in 24 hours. Nothing else matters first.)
════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────────
P0-1: HARDEN DEFAULT ENVIRONMENT CONFIGURATION
File: workspace/app/backend/.env.example
File: workspace/app/backend/src/config.js
──────────────────────────────────────────────────────────────────────────

CHANGE these defaults in .env.example:
  AUTH_MODE=jwt_hs256                    (was: demo)
  ALLOW_INSECURE_DEMO_AUTH=false         (was: true)
  REQUIRE_AUTH_FOR_THREAT_ENDPOINTS=true (was: false)
  REQUIRE_AUTH_FOR_PLATFORM_ENDPOINTS=true (was: false)
  DB_SSL_MODE=require                    (was: disable)

ADD to .env.example (required, no default):
  # REQUIRED: Generate with: node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
  JWT_SECRET=
  # REQUIRED: Generate with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
  POSTGRES_PASSWORD=
  # REQUIRED: Generate with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
  REDIS_PASSWORD=

In src/config.js, add a startup guard:
  If NODE_ENV === 'production':
    - If JWT_SECRET is empty or shorter than 32 chars → throw Error and exit 1
    - If DATABASE_URL is empty → throw Error and exit 1
    - If authMode === 'demo' → throw Error and exit 1
    - If allowInsecureDemoAuth === true → throw Error and exit 1
  Log the list of missing required variables before throwing, so operators 
  know exactly what to set.

──────────────────────────────────────────────────────────────────────────
P0-2: FIX UNHANDLED PROMISE REJECTIONS (prevents silent process crashes)
File: workspace/app/backend/server.js
──────────────────────────────────────────────────────────────────────────

At the top of server.js, before startServer(), add:

  process.on('unhandledRejection', (reason, promise) => {
    console.error('[fatal] Unhandled Promise Rejection:', reason);
    // Do NOT exit — log and continue, but alert via structured log
  });

  process.on('uncaughtException', (error) => {
    console.error('[fatal] Uncaught Exception:', error);
    process.exit(1); // This one IS fatal
  });

──────────────────────────────────────────────────────────────────────────
P0-3: FIX QUERY-WITHOUT-TENANT ON WRITE PATHS
File: workspace/app/backend/src/routes/crud.js
──────────────────────────────────────────────────────────────────────────

Audit every INSERT/UPDATE/DELETE in crud.js.
Any path that writes tenant-scoped data must use queryWithTenant(config, tenant, ...) 
not the bare query(config, ...).

Search for:  await query(config,
Replace with: await queryWithTenant(config, tenant, 
...for all mutation paths (incidents, iocs, service-requests, reports, 
siem-alerts, risk-findings, compliance-status, audit-log writes).

READ paths (SELECT) are lower risk but should also be reviewed.

──────────────────────────────────────────────────────────────────────────
P0-4: HARDEN REDIS DOCKER CONFIGURATION
File: workspace/docker-compose.yml
File: workspace/docker-compose.prod.yml
──────────────────────────────────────────────────────────────────────────

In docker-compose.yml, change Redis command to:
  command: redis-server --appendonly yes --maxmemory 256mb 
           --maxmemory-policy allkeys-lru 
           --requirepass ${REDIS_PASSWORD:?Set REDIS_PASSWORD in .env}

Remove the ${REDIS_PASSWORD:-} fallback everywhere — the empty fallback 
means Redis runs without auth when REDIS_PASSWORD is unset.

════════════════════════════════════════════════════════════════════════════
P1 — EMAIL SERVICE (Required for user account recovery)
════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────────
P1-1: IMPLEMENT EMAIL TRANSPORT SERVICE
New file: workspace/app/backend/src/email-service.js
──────────────────────────────────────────────────────────────────────────

Use the Resend SDK (npm install resend) as the default provider.
Provide fallback to SMTP (nodemailer) for self-hosted deployments.
Provide a null/console transport for development.

Add to .env.example:
  # Email: choose one provider
  EMAIL_PROVIDER=console         # console | resend | smtp
  EMAIL_FROM_ADDRESS=noreply@cybertron.io
  EMAIL_FROM_NAME=Cybertron
  RESEND_API_KEY=
  SMTP_HOST=
  SMTP_PORT=587
  SMTP_USER=
  SMTP_PASS=
  SMTP_SECURE=false

Implement these functions in email-service.js:
  async function sendPasswordResetEmail(config, { to, resetUrl, tenantName })
  async function sendWelcomeEmail(config, { to, displayName, loginUrl })
  async function sendWorkspaceInviteEmail(config, { to, inviterName, workspaceName, inviteUrl })
  async function sendAlertEscalationEmail(config, { to, alertTitle, severity, alertUrl })

Each function must:
  - Log a warning and return gracefully if EMAIL_PROVIDER=console or unconfigured
  - Throw a ServiceError(503, 'email_unavailable', ...) if provider is configured 
    but the send fails after 2 retries

──────────────────────────────────────────────────────────────────────────
P1-2: WIRE EMAIL INTO PASSWORD RESET FLOW
File: workspace/app/backend/src/auth-service.js
──────────────────────────────────────────────────────────────────────────

In requestPasswordReset():
  1. After the token is saved to DB, call sendPasswordResetEmail() with:
     resetUrl = `${config.frontendOrigin}/auth/reset-password?token=${rawResetToken}&tenant=${tenantSlug}`
  2. Remove the dev-mode leak: resetToken must NEVER appear in the API response.
     Return only: { accepted: true, message: 'If that email exists, a reset link was sent.' }
     (Same response for found and not-found emails, to prevent email enumeration)

──────────────────────────────────────────────────────────────────────────
P1-3: BUILD PASSWORD RESET FORM PAGE
New file: workspace/app/frontend/src/pages/PasswordResetPage.tsx
Route: /auth/reset-password
──────────────────────────────────────────────────────────────────────────

Page reads ?token= and ?tenant= from URL query params.
Shows a form with:
  - New password field (min 8 chars, show/hide toggle)
  - Confirm password field
  - Submit button

On submit, calls resetPassword({ tenant, resetToken: token, newPassword }).
On success: redirect to /account with a success toast.
On error: display specific error message (expired token, already used, etc).
On missing token/tenant in URL: show "Invalid or expired link" state with 
  link back to /account?mode=forgot.

Add route in App.tsx:
  <Route path="/auth/reset-password" element={<PasswordResetPage />} />

════════════════════════════════════════════════════════════════════════════
P1 — STRIPE PAYMENT INTEGRATION
════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────────
P1-4: STRIPE BACKEND INTEGRATION
New file: workspace/app/backend/src/stripe-service.js
New migration: workspace/app/backend/migrations/026_stripe_subscriptions.sql
──────────────────────────────────────────────────────────────────────────

Install: npm install stripe (in workspace/app/backend)

Add to .env.example:
  STRIPE_SECRET_KEY=
  STRIPE_WEBHOOK_SECRET=
  STRIPE_PRICE_ID_PRO_MONTHLY=
  STRIPE_PRICE_ID_PRO_ANNUAL=
  STRIPE_PRICE_ID_ENTERPRISE_MONTHLY=

Migration 026_stripe_subscriptions.sql — add to tenants table:
  ALTER TABLE tenants ADD COLUMN IF NOT EXISTS 
    stripe_customer_id VARCHAR(64);
  ALTER TABLE tenants ADD COLUMN IF NOT EXISTS 
    stripe_subscription_id VARCHAR(64);
  ALTER TABLE tenants ADD COLUMN IF NOT EXISTS 
    stripe_subscription_status VARCHAR(32) DEFAULT 'none';

Implement in stripe-service.js:
  async function createCheckoutSession(config, { tenant, priceId, successUrl, cancelUrl })
    → Creates Stripe Checkout Session, saves stripe_customer_id to tenant row
    → Returns { sessionId, url }

  async function handleWebhookEvent(config, rawBody, signature)
    → Validates Stripe webhook signature using STRIPE_WEBHOOK_SECRET
    → Handles events: checkout.session.completed, customer.subscription.updated,
      customer.subscription.deleted, invoice.payment_failed
    → On checkout.session.completed: update tenant plan to pro/enterprise
    → On subscription deleted/failed: revert tenant to free plan

  async function getSubscriptionStatus(config, tenant)
    → Returns current subscription status from DB (not live Stripe call)

Add routes to crud.js (or new stripe-routes.js):
  POST /v1/billing/checkout
    → requireSession, validate plan param, call createCheckoutSession()
    → Return { sessionUrl }

  POST /v1/webhooks/stripe
    → NO auth — Stripe calls this endpoint directly
    → Validate signature before processing
    → Call handleWebhookEvent()
    → Always return 200 OK to Stripe (retry logic depends on it)

──────────────────────────────────────────────────────────────────────────
P1-5: STRIPE FRONTEND CHECKOUT FLOW
File: workspace/app/frontend/src/lib/backend.ts
File: workspace/app/frontend/src/components/PricingSection.tsx
File: workspace/app/frontend/src/pages/PricingPage.tsx
──────────────────────────────────────────────────────────────────────────

Add to backend.ts:
  export async function createBillingCheckout(payload: {
    tenant: string;
    planKey: 'pro' | 'enterprise';
    billingCycle: 'monthly' | 'annual';
    returnTo?: string;
  }): Promise<{ sessionUrl: string }>

In PricingSection.tsx, update navigateToPlanAction():
  - For free plan: keep current flow (redirect to /account?mode=register)
  - For pro/enterprise: 
    1. If user is not authenticated: redirect to /account?mode=register&plan=pro
    2. If user IS authenticated:
       const { sessionUrl } = await createBillingCheckout({ tenant, planKey, billingCycle });
       window.location.assign(sessionUrl);  // Stripe handles the rest
  - Show loading spinner on button during checkout creation
  - Handle errors with a toast notification

Add success/cancel routes in App.tsx:
  <Route path="/billing/success" element={<BillingSuccessPage />} />
  <Route path="/billing/cancel" element={<BillingCancelPage />} />

Create BillingSuccessPage.tsx — shows "Subscription activated!" with link to platform.
Create BillingCancelPage.tsx — shows "Checkout cancelled" with link back to pricing.

════════════════════════════════════════════════════════════════════════════
P1 — ADMIN DASHBOARD (Required for tenant operations)
════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────────
P1-6: BUILD ADMIN DASHBOARD PAGE
New file: workspace/app/frontend/src/pages/AdminPage.tsx
Route: /admin (protected: requires tenant_admin role)
──────────────────────────────────────────────────────────────────────────

AdminPage is a dedicated page, NOT embedded in Platform.tsx.
Add to App.tsx:
  <Route path="/admin" element={<AdminPage />} />

AdminPage renders four tabs:
  TAB 1 — Users
    - Table of users fetched from GET /v1/users?tenant=X
    - Columns: email, displayName, role, active, createdAt
    - Action: deactivate/reactivate user (PATCH /v1/users/:id via new route)
    - Show invite button (links to future invite flow)
    
  TAB 2 — Products
    - List of tenant products from GET /v1/products?tenant=X
    - Toggle enabled/disabled using existing updateTenantProductState()
    - Show plan-gated badge if product requires paid plan
    
  TAB 3 — Feature Flags
    - List of feature flags from GET /v1/feature-flags?tenant=X
    - Toggle each flag using existing updateTenantFeatureFlag()
    
  TAB 4 — Audit Log
    - Paginated table of audit log entries
    - Filter by actor email, action, date range
    - Already backed by GET /v1/audit-logs

Add new backend route (in crud.js or admin-routes.js):
  PATCH /v1/users/:userId/status
    → requireSession, requireRole('tenant_admin')
    → Accepts: { active: boolean }
    → Updates users.is_active for the given userId within the session tenant
    → Appends audit log entry
    → Returns updated user record

Add link to /admin in Platform.tsx top nav for tenant_admin role users.

────────────────────────────────────────────────────────────────────────
P1-7: BUILD ONBOARDING WIZARD
New file: workspace/app/frontend/src/pages/OnboardingPage.tsx
Route: /onboarding
────────────────────────────────────────────────────────────────────────

Triggered after first-time registration (redirect from /account on new 
account creation with `?firstLogin=true` param).

3-step wizard:
  STEP 1 — Workspace Setup
    - Input: Workspace/company name
    - Input: Workspace slug (auto-generated from name, editable)
    - Calls existing registration/workspace bootstrap flow

  STEP 2 — Connect Your First Data Source (optional, skippable)
    - Show cards for: Wazuh, MISP, OpenCTI, TheHive, Manual Upload
    - Each card links to /platform/connectors (future page) or shows config snippet
    - "Skip for now" button

  STEP 3 — Invite Your Team (optional, skippable)
    - Email input to invite first team member
    - Role selector (security_analyst, executive_viewer, tenant_admin)
    - "Finish & Open Platform" button → redirects to /platform

════════════════════════════════════════════════════════════════════════════
P1 — WORKSPACE INVITE SYSTEM
════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────────
P1-8: BUILD WORKSPACE INVITE BACKEND
New migration: workspace/app/backend/migrations/027_workspace_invites.sql
New file: workspace/app/backend/src/invite-service.js
──────────────────────────────────────────────────────────────────────────

Migration 027_workspace_invites.sql:
  CREATE TABLE IF NOT EXISTS workspace_invites (
    id           BIGSERIAL PRIMARY KEY,
    tenant_slug  VARCHAR(64) NOT NULL,
    email        VARCHAR(191) NOT NULL,
    role         VARCHAR(32) NOT NULL DEFAULT 'executive_viewer',
    token_hash   VARCHAR(128) NOT NULL UNIQUE,
    invited_by   BIGINT REFERENCES users(id),
    expires_at   TIMESTAMPTZ NOT NULL,
    accepted_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  CREATE INDEX ON workspace_invites (tenant_slug, email);
  CREATE INDEX ON workspace_invites (token_hash);

invite-service.js — implement:
  async function createInvite(config, { tenant, email, role, invitedByUserId })
    → Generates opaque token, hashes and stores it
    → Calls sendWorkspaceInviteEmail() with invite URL
    → Returns { inviteId, expiresAt }

  async function acceptInvite(config, { token, acceptingUserId })
    → Validates token hash, checks expiry
    → Sets accepted_at on invite
    → If acceptingUserId is given: adds user to workspace
    → If not: creates user account and sends welcome email

Add routes in crud.js (or new invites-routes.js):
  POST /v1/tenants/:slug/invites     → requireSession + tenant_admin role
  GET  /v1/tenants/:slug/invites     → requireSession + tenant_admin role  
  GET  /v1/invites/:token/accept     → PUBLIC (no auth, link from email)
  DELETE /v1/tenants/:slug/invites/:id → requireSession + tenant_admin role

──────────────────────────────────────────────────────────────────────────
P1-9: BUILD INVITE UI IN ACCOUNT/TEAM PAGE
New file: workspace/app/frontend/src/pages/TeamPage.tsx
Route: /account/team
──────────────────────────────────────────────────────────────────────────

Add to App.tsx: <Route path="/account/team" element={<TeamPage />} />

TeamPage renders:
  - Current members table (from GET /v1/users)
  - "Invite Member" form: email input + role selector + Send Invite button
  - Pending invites list with revoke button
  - Link back to /account

Add to backend.ts:
  export async function createWorkspaceInvite(tenant: string, payload: {
    email: string; role: string;
  }): Promise<{ inviteId: string; expiresAt: string }>

  export async function listWorkspaceInvites(tenant: string): Promise<InviteRecord[]>
  export async function revokeWorkspaceInvite(tenant: string, inviteId: string): Promise<void>

════════════════════════════════════════════════════════════════════════════
P1 — CONNECTOR CONFIGURATION UI
════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────────
P1-10: BUILD CONNECTOR CONFIGURATION PAGE
New file: workspace/app/frontend/src/pages/ConnectorsPage.tsx
Route: /platform/connectors
New migration: workspace/app/backend/migrations/028_connector_configs.sql
──────────────────────────────────────────────────────────────────────────

Migration 028_connector_configs.sql:
  CREATE TABLE IF NOT EXISTS connector_configs (
    id           BIGSERIAL PRIMARY KEY,
    tenant_slug  VARCHAR(64) NOT NULL,
    connector    VARCHAR(32) NOT NULL,  -- wazuh | misp | opencti | thehive
    api_url      TEXT NOT NULL,
    api_token    TEXT,                  -- store encrypted (see below)
    enabled      BOOLEAN NOT NULL DEFAULT false,
    last_sync_at TIMESTAMPTZ,
    last_sync_status VARCHAR(16),       -- ok | error | never
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_slug, connector)
  );

SECURITY: api_token values must be stored encrypted at rest.
  Use AES-256-GCM with a key derived from a new env var: CONNECTOR_SECRETS_KEY
  Encrypt on write, decrypt on read in connector-config-service.js.
  Never return the raw api_token in API responses — return only a masked value.

Add routes:
  GET    /v1/connectors/config         → list connector configs for tenant
  POST   /v1/connectors/config         → create/update connector config
  DELETE /v1/connectors/config/:connector → delete connector config
  POST   /v1/connectors/config/:connector/test → test connectivity

ConnectorsPage.tsx shows:
  - A card for each connector: Wazuh, MISP, OpenCTI, TheHive
  - Each card shows: status (configured/not configured), last sync, error if any
  - Edit form: API URL + API Token (masked) + Enable toggle
  - Test Connection button (calls the /test route)
  - Save button

Add to App.tsx: <Route path="/platform/connectors" element={<ConnectorsPage />} />

════════════════════════════════════════════════════════════════════════════
P1 — REMOVE DEAD CODE + FIX DUPLICATE PAGES
════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────────
P1-11: REMOVE DEAD PRODUCT PAGE DUPLICATES
──────────────────────────────────────────────────────────────────────────

DELETE these files entirely:
  workspace/app/frontend/src/pages/products/RiskCopilotPage.tsx
  workspace/app/frontend/src/pages/products/ComplianceEnginePage.tsx
  workspace/app/frontend/src/pages/products/ThreatIntelPage.tsx
  workspace/app/frontend/src/pages/products/ProductPageShell.tsx
  (and the entire workspace/app/frontend/src/pages/products/ directory)

Verify: App.tsx routes only point to top-level pages/*.tsx files. Confirm 
by running: grep -r "products/" src/App.tsx and ensuring no remaining imports.

════════════════════════════════════════════════════════════════════════════
P1 — REAL FUNCTIONAL TESTS
════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────────
P1-12: REPLACE STATIC TESTS WITH RUNTIME INTEGRATION TESTS
Directory: workspace/app/backend/tests/integration/
──────────────────────────────────────────────────────────────────────────

The existing tests in workspace/app/backend/tests/ are static string checks.
Keep them (they have value as regression guards) but ADD real integration tests.

Create workspace/app/backend/tests/integration/ directory.
Tests use the existing Node.js built-in test runner (no Jest needed).
Each integration test:
  1. Starts the real server against a test DB (use DATABASE_URL pointing to test DB)
  2. Makes real HTTP calls using node:http or undici
  3. Asserts response status, response body shape, and DB state

Required integration test files:

  tests/integration/auth.test.js
    ✓ POST /v1/auth/register → 201 + creates user in DB
    ✓ POST /v1/auth/login (correct creds) → 200 + valid JWT
    ✓ POST /v1/auth/login (wrong password) → 401
    ✓ GET /v1/auth/me (with valid token) → 200 + user profile
    ✓ GET /v1/auth/me (no token) → 401
    ✓ POST /v1/auth/logout → 204 + token revoked
    ✓ POST /v1/auth/password/forgot → 200 (email accepted, no token in response)
    ✓ Rate limit: 9 rapid login attempts → 429 on 9th

  tests/integration/incidents.test.js  
    ✓ POST /v1/incidents → 201 + incident in DB
    ✓ GET /v1/incidents → 200 + list includes created incident
    ✓ Tenant isolation: GET /v1/incidents for tenant B cannot see tenant A data
    ✓ PATCH /v1/incidents/:id (analyst role) → 200
    ✓ PATCH /v1/incidents/:id (viewer role) → 403

  tests/integration/billing.test.js
    ✓ GET /v1/billing/credits → 200 (returns balance)
    ✓ POST /v1/billing/checkout → 200 when Stripe configured
    ✓ POST /v1/webhooks/stripe (valid signature) → 200
    ✓ POST /v1/webhooks/stripe (invalid signature) → 400

  tests/integration/reports.test.js
    ✓ POST /v1/reports/upload (PDF) → 201
    ✓ GET /v1/reports → 200 + includes uploaded report
    ✓ GET /v1/reports/:id/download → 200 + file bytes

  tests/integration/threat-intel.test.js
    ✓ POST /v1/threat-intel/siem/upload (JSON) → 201
    ✓ GET /v1/threat-intel/siem/alerts → 200 + includes ingested alert
    ✓ PATCH /v1/threat-intel/siem/alerts/:id/status → 200
    ✓ POST /v1/threat-intel/cve/sync → 202 (queued)

Add npm script in workspace/app/backend/package.json:
  "test:integration": "node --test tests/integration/*.test.js"

Update CI workflow to run integration tests:
  - name: Run Integration Tests
    run: npm run test:integration --prefix workspace/app/backend
    env:
      DATABASE_URL: postgresql://cybertron:cybertron_ci_password@127.0.0.1:5432/cybertron

════════════════════════════════════════════════════════════════════════════
P2 — ARCHITECTURE REFACTOR (Improves maintainability and scalability)
════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────────
P2-1: BREAK UP THE 2,700-LINE crud.js ROUTER
──────────────────────────────────────────────────────────────────────────

Move route blocks from crud.js into domain-specific route files:

  src/routes/notifications.js   ← /v1/notifications/* routes
  src/routes/threats.js         ← /v1/threats/* and /v1/incidents/* routes
  src/routes/reports.js         ← /v1/reports/* routes
  src/routes/platform.js        ← /v1/platform/apps, /v1/modules, /v1/tenants routes
  src/routes/billing.js         ← /v1/billing/*, /v1/webhooks/stripe routes
  src/routes/admin.js           ← /v1/users, /v1/audit-logs, /v1/products routes
  src/routes/connectors.js      ← /v1/connectors/* routes
  src/routes/invites.js         ← /v1/invites/*, /v1/tenants/:slug/invites routes

Each file exports { registerRoutes(routerContext) } — same pattern as existing.
Register all from src/server.js in the same order they exist in crud.js today.
After split, verify ALL existing static tests still pass (they check source 
for function names and patterns — reorganization will require updating some).

──────────────────────────────────────────────────────────────────────────
P2-2: MOVE @electric-sql/pglite TO devDependencies
File: workspace/app/backend/package.json
──────────────────────────────────────────────────────────────────────────

  Move "@electric-sql/pglite" from dependencies → devDependencies
  Move "@electric-sql/pglite-socket" → already in devDependencies (confirm)
  
  Rebuild Docker image and verify production image does not include pglite.
  Run: docker build -f workspace/app/backend/Dockerfile workspace -t test-size
       docker images test-size --format "{{.Size}}"
  This should reduce image size by 200-400MB.

──────────────────────────────────────────────────────────────────────────
P2-3: ADD LLM PROVIDER HEALTH CHECK
File: workspace/app/backend/src/routes/system.js (or wherever /v1/system/health is)
File: workspace/app/backend/src/ai/llm-provider.js
──────────────────────────────────────────────────────────────────────────

Add to llm-provider.js:
  async function probeLlmHealth(config)
    → If LLM_PROVIDER=none: return { configured: false, status: 'not_configured' }
    → If openai: GET https://api.openai.com/v1/models with auth, timeout 3s
      → Return { configured: true, status: 'ok', latencyMs } or { status: 'error', message }
    → If ollama: GET {OLLAMA_BASE_URL}/api/version, timeout 3s
      → Return { configured: true, status: 'ok', latencyMs } or { status: 'error', message }

Add to /v1/system/health response:
  dependencies: {
    ...existingDeps,
    llm: await probeLlmHealth(config)
  }

──────────────────────────────────────────────────────────────────────────
P2-4: ADD API KEY MANAGEMENT
New migration: workspace/app/backend/migrations/029_api_keys.sql
New file: workspace/app/backend/src/api-key-service.js
New file: workspace/app/frontend/src/pages/ApiKeysPage.tsx
──────────────────────────────────────────────────────────────────────────

Migration 029_api_keys.sql:
  CREATE TABLE IF NOT EXISTS api_keys (
    id           BIGSERIAL PRIMARY KEY,
    tenant_slug  VARCHAR(64) NOT NULL,
    user_id      BIGINT REFERENCES users(id) ON DELETE CASCADE,
    name         VARCHAR(128) NOT NULL,
    key_hash     VARCHAR(128) NOT NULL UNIQUE,
    key_prefix   VARCHAR(12) NOT NULL,  -- First 8 chars, for display
    last_used_at TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ,
    scopes       TEXT[] NOT NULL DEFAULT '{}',
    revoked      BOOLEAN NOT NULL DEFAULT false,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  CREATE INDEX ON api_keys (tenant_slug, user_id);
  CREATE INDEX ON api_keys (key_hash);

api-key-service.js:
  async function createApiKey(config, { tenant, userId, name, scopes, expiresIn })
    → Generates: cyk_live_{random48chars} formatted key
    → Stores hash, returns RAW key ONCE (never stored)
    
  async function verifyApiKey(config, rawKey)
    → Hashes key, looks up in DB, checks revoked and expiry
    → Returns { tenant, userId, scopes } or null
    
  async function listApiKeys(config, tenant, userId)
    → Returns all keys (with prefix only, never full key)
    
  async function revokeApiKey(config, keyId, requestingUserId)

Add routes:
  GET    /v1/api-keys     → list user's API keys
  POST   /v1/api-keys     → create new key (returns key ONCE in response)
  DELETE /v1/api-keys/:id → revoke key

In auth-guard.js: extend token resolution to also check API key header:
  Authorization: Bearer cyk_live_xxxxx → verifyApiKey() → create session context

ApiKeysPage.tsx at /account/api-keys:
  - List of existing keys (prefix, name, scopes, last used, expires)
  - "Create API Key" form: name input + scopes checkboxes
  - On create: show modal with the full key (warn: shown once only)
  - Revoke button per key

════════════════════════════════════════════════════════════════════════════
P2 — ML MODEL DEPLOYMENT PATH
════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────────
P2-5: WIRE FINE-TUNED MODEL INTO LLM PROVIDER
File: workspace/app/backend/src/ai/llm-provider.js
File: workspace/docker-compose.prod.yml
──────────────────────────────────────────────────────────────────────────

The ml/ directory has a complete LoRA training pipeline targeting vLLM serving.
The ml/start_vllm_openai_lora.sh script shows the vLLM server starts on port 8000
with an OpenAI-compatible API.

In llm-provider.js, add a third provider type:
  if (normalized === 'vllm') return 'vllm';

Add env vars to .env.example:
  # Fine-tuned model via vLLM (OpenAI-compatible endpoint)
  LLM_VLLM_BASE_URL=http://vllm:8000/v1
  LLM_VLLM_MODEL=cybertron-lora

In llm-provider.js, when provider === 'vllm':
  - Use same OpenAI-compatible HTTP call structure as the 'openai' provider
  - Point to LLM_VLLM_BASE_URL instead of api.openai.com
  - Use LLM_VLLM_MODEL as model name

In docker-compose.prod.yml, add a vllm service (commented out, opt-in):
  # vllm:  # Uncomment to use fine-tuned Cybertron model
  #   image: vllm/vllm-openai:latest
  #   runtime: nvidia
  #   volumes:
  #     - ./ml/bundles/lightning-train:/models
  #   command: --model /models --enable-lora --port 8000
  #   deploy:
  #     resources:
  #       reservations:
  #         devices:
  #           - driver: nvidia
  #             count: 1
  #             capabilities: [gpu]

════════════════════════════════════════════════════════════════════════════
P2 — UX & NAVIGATION FIXES
════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────────
P2-6: FIX PRICING PAGE CTA FLOW FOR AUTHENTICATED USERS
File: workspace/app/frontend/src/components/PricingSection.tsx
──────────────────────────────────────────────────────────────────────────

Current behavior: clicking "Get Pro" sends all users to /account?mode=register
regardless of auth state. Authenticated users should go to Stripe checkout.

Fix navigateToPlanAction():
  1. Import useAuthStatus hook (or pass authStatus + profile as props)
  2. If not authenticated: send to /account?mode=register&plan={planKey}
  3. If authenticated AND plan is free: do nothing (already on free)
  4. If authenticated AND plan is pro/enterprise: 
     → Call createBillingCheckout() (see P1-5)
     → Redirect to Stripe checkout URL

After successful registration via free plan CTA:
  In AccountPage.tsx, after registerAccount() succeeds:
  Check if ?plan= param is set. If so, redirect to /pricing?tenant={newTenant}
  so user can then upgrade after creating their workspace.

──────────────────────────────────────────────────────────────────────────
P2-7: FIX ATTACK MAP EMPTY STATE
File: workspace/app/frontend/src/components/platform/AttackMapPanel.tsx
──────────────────────────────────────────────────────────────────────────

When fetchAttackMapData() returns empty array:
  Currently: blank/empty panel with no guidance.
  Fix: Show a "No live data sources connected" empty state with:
    - Icon (MapPinned or Globe)
    - Heading: "Connect a data source to see live threat activity"
    - Body: "Wazuh, MISP, OpenCTI, or TheHive connections will populate this map."
    - CTA Button: "Configure Connectors" → links to /platform/connectors

──────────────────────────────────────────────────────────────────────────
P2-8: FIX AI PANELS EMPTY STATE (Risk Copilot, CVE Summarize, Policy AI)
Files: RiskCopilotConsole.tsx, ThreatCommandConsole.tsx, 
       ComplianceEnginePage.tsx (AI policy generation button)
──────────────────────────────────────────────────────────────────────────

When any AI feature returns status: 'not_configured' or an LLM-related error:
  Do NOT show a blank panel or silent failure.
  Show a clear state:
    - Icon: BrainCircuit or Bot
    - Heading: "AI analysis requires an LLM provider"
    - Body: "Configure OPENAI_API_KEY (or Ollama) in your backend environment 
      to enable AI-powered insights."
    - If role is tenant_admin: Add link to docs or connector setup
    - If role is not admin: "Contact your workspace administrator."

This applies to:
  ✗ Risk Copilot findings (when LLM returns stub)
  ✗ CVE AI summarize button (disable button + show tooltip)
  ✗ Compliance AI policy generate button (disable + tooltip)
  ✗ Threat triage suggestion (show "AI unavailable" badge)

──────────────────────────────────────────────────────────────────────────
P2-9: ADD NOTIFICATION PREFERENCES PAGE  
New file: workspace/app/frontend/src/pages/NotificationsPage.tsx
New route: /account/notifications
──────────────────────────────────────────────────────────────────────────

Add to App.tsx: <Route path="/account/notifications" element={<NotificationsPage />} />

New backend route:
  GET  /v1/notifications/preferences   → returns user notification preferences
  PATCH /v1/notifications/preferences  → update preferences

New migration 030_notification_preferences.sql:
  CREATE TABLE IF NOT EXISTS notification_preferences (
    user_id           BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    email_on_critical BOOLEAN NOT NULL DEFAULT true,
    email_on_high     BOOLEAN NOT NULL DEFAULT false,
    email_on_resolved BOOLEAN NOT NULL DEFAULT false,
    in_app_all        BOOLEAN NOT NULL DEFAULT true,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );

NotificationsPage shows toggles for each preference category.

════════════════════════════════════════════════════════════════════════════
P3 — OBSERVABILITY, PERFORMANCE & SCALE
════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────────
P3-1: WIRE OPENTELEMETRY TRACING TO A COLLECTOR
File: workspace/app/backend/src/tracing.js
──────────────────────────────────────────────────────────────────────────

src/tracing.js exists with tracing stubs. Wire it to export spans to:
  - OTLP HTTP collector (via OTEL_EXPORTER_OTLP_ENDPOINT env var)
  - Fallback to console if not configured

Add to .env.example:
  OTEL_EXPORTER_OTLP_ENDPOINT=
  OTEL_SERVICE_NAME=cybertron-backend

Add to docker-compose.prod.yml a Grafana Tempo or Jaeger service 
(commented out, opt-in) to collect traces locally.

──────────────────────────────────────────────────────────────────────────
P3-2: ADD SSE SCALE-OUT VIA REDIS PUB/SUB
File: workspace/app/backend/src/notification-service.js
──────────────────────────────────────────────────────────────────────────

The current SSE implementation uses in-memory Maps (tenantClients).
In a multi-instance deployment, events from instance A cannot reach 
clients connected to instance B.

Fix: When Redis is configured, use Redis Pub/Sub to fan out events:
  - On notifyIncidentCreated/Updated: publish to Redis channel `events:{tenant}`
  - Each instance subscribes to Redis channels for tenants with connected clients
  - On Redis message: push to local in-memory clients for that tenant

When Redis is NOT configured: keep existing in-memory behavior (dev mode).
This makes the SSE system scale-out ready without breaking single-instance use.

The in-memory 50-clients-per-tenant limit remains per-instance.

──────────────────────────────────────────────────────────────────────────
P3-3: ADD RATE LIMIT HEADERS TO ALL RESPONSES
File: workspace/app/backend/src/rate-limiter.js
──────────────────────────────────────────────────────────────────────────

After rate limit check, add headers to every response:
  X-RateLimit-Limit: {maxRequests}
  X-RateLimit-Remaining: {remaining}
  X-RateLimit-Reset: {resetTimestamp}

These are industry standard and required for good API client behavior.

──────────────────────────────────────────────────────────────────────────
P3-4: DATABASE CONNECTION POOL MONITORING
File: workspace/app/backend/src/database.js
──────────────────────────────────────────────────────────────────────────

Add pool event listeners to surface DB connection health:
  pool.on('connect', () => log('debug', 'db.pool.connect', { total: pool.totalCount }));
  pool.on('remove', () => log('debug', 'db.pool.remove', { idle: pool.idleCount }));
  pool.on('error', (err) => log('error', 'db.pool.error', { message: err.message }));

Expose pool stats in /v1/system/health:
  database: {
    ...existing,
    poolTotal: pool.totalCount,
    poolIdle: pool.idleCount,
    poolWaiting: pool.waitingCount
  }

──────────────────────────────────────────────────────────────────────────
P3-5: OPTIMIZE BUNDLE SIZE
File: workspace/app/frontend/vite.config.ts
──────────────────────────────────────────────────────────────────────────

Add manual chunk splitting to vite.config.ts:
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          'react-vendor': ['react', 'react-dom', 'react-router-dom'],
          'query-vendor': ['@tanstack/react-query'],
          'ui-vendor': ['@radix-ui/react-dialog', '@radix-ui/react-dropdown-menu', 
                        '@radix-ui/react-tabs', /* other radix */],
          'three-vendor': ['three', '@react-three/fiber', '@react-three/drei'],
          'chart-vendor': ['recharts'],
        }
      }
    },
    chunkSizeWarningLimit: 600,
  }

Three.js + React Three Fiber are heavy (~1.5MB). 
Lazy-load CyberShieldScene.tsx only when the landing page is in viewport:
  Replace <CyberShieldScene /> with a dynamic import + IntersectionObserver trigger.

════════════════════════════════════════════════════════════════════════════
COMPLETE NEW FILE CHECKLIST
════════════════════════════════════════════════════════════════════════════

BACKEND — New files to create:
  ✦ src/email-service.js                         (P1-1)
  ✦ src/stripe-service.js                        (P1-4)
  ✦ src/invite-service.js                        (P1-8)
  ✦ src/api-key-service.js                       (P2-4)
  ✦ src/connector-config-service.js              (P1-10)
  ✦ src/routes/billing.js                        (P2-1)
  ✦ src/routes/invites.js                        (P1-8 + P2-1)
  ✦ src/routes/connectors.js                     (P1-10 + P2-1)
  ✦ src/routes/api-keys.js                       (P2-4 + P2-1)
  ✦ src/routes/notifications.js                  (P2-1)
  ✦ src/routes/threats.js                        (P2-1)
  ✦ src/routes/reports.js                        (P2-1)
  ✦ src/routes/platform.js                       (P2-1)
  ✦ src/routes/admin.js                          (P1-6 + P2-1)
  ✦ tests/integration/auth.test.js               (P1-12)
  ✦ tests/integration/incidents.test.js          (P1-12)
  ✦ tests/integration/billing.test.js            (P1-12)
  ✦ tests/integration/reports.test.js            (P1-12)
  ✦ tests/integration/threat-intel.test.js       (P1-12)

BACKEND — New migrations:
  ✦ migrations/026_stripe_subscriptions.sql      (P1-4)
  ✦ migrations/027_workspace_invites.sql         (P1-8)
  ✦ migrations/028_connector_configs.sql         (P1-10)
  ✦ migrations/029_api_keys.sql                  (P2-4)
  ✦ migrations/030_notification_preferences.sql  (P2-9)

FRONTEND — New pages to create:
  ✦ src/pages/PasswordResetPage.tsx              (P1-3)
  ✦ src/pages/AdminPage.tsx                      (P1-6)
  ✦ src/pages/OnboardingPage.tsx                 (P1-7)
  ✦ src/pages/TeamPage.tsx                       (P1-9)
  ✦ src/pages/ConnectorsPage.tsx                 (P1-10)
  ✦ src/pages/ApiKeysPage.tsx                    (P2-4)
  ✦ src/pages/NotificationsPage.tsx              (P2-9)
  ✦ src/pages/BillingSuccessPage.tsx             (P1-5)
  ✦ src/pages/BillingCancelPage.tsx              (P1-5)

FRONTEND — New routes in App.tsx:
  ✦ /auth/reset-password     → PasswordResetPage
  ✦ /onboarding              → OnboardingPage
  ✦ /admin                   → AdminPage (requireSession + tenant_admin)
  ✦ /account/team            → TeamPage  (requireSession)
  ✦ /account/api-keys        → ApiKeysPage (requireSession)
  ✦ /account/notifications   → NotificationsPage (requireSession)
  ✦ /platform/connectors     → ConnectorsPage (requireSession)
  ✦ /billing/success         → BillingSuccessPage
  ✦ /billing/cancel          → BillingCancelPage

FRONTEND — Pages to DELETE:
  ✗ src/pages/products/RiskCopilotPage.tsx
  ✗ src/pages/products/ComplianceEnginePage.tsx
  ✗ src/pages/products/ThreatIntelPage.tsx
  ✗ src/pages/products/ProductPageShell.tsx

════════════════════════════════════════════════════════════════════════════
LAUNCH VERIFICATION CHECKLIST (Run before declaring production-ready)
════════════════════════════════════════════════════════════════════════════

AUTH FLOWS:
  □ User can register with email + password + workspace slug
  □ User receives welcome email after registration
  □ User can log in and reaches /platform
  □ User can request password reset → receives email with link
  □ User clicks email link → /auth/reset-password → can set new password → can log in
  □ OAuth login (Google or GitHub) works end-to-end
  □ Logout clears cookies and revokes tokens
  □ Demo mode (AUTH_MODE=demo) is blocked in NODE_ENV=production

BILLING:
  □ Pricing page CTAs work for unauthenticated users (sends to register)
  □ Authenticated user on free plan can click "Upgrade" and reach Stripe checkout
  □ Successful Stripe checkout → tenant plan updated → platform shows upgraded features
  □ Failed payment → tenant plan NOT changed
  □ Stripe webhook signature validation blocks unsigned requests

PLATFORM:
  □ All 4 platform modules load without blank panels or console errors
  □ SIEM alert ingestion works via file upload
  □ Incident creation and timeline works
  □ Compliance SOC2 controls show and can be marked
  □ Risk findings show after AWS log upload
  □ Platform works without LLM configured (shows clear "AI unavailable" states)
  □ Platform with LLM configured shows real AI outputs

ADMIN:
  □ tenant_admin role can reach /admin
  □ Users tab shows user list and deactivate works
  □ Products tab can toggle product enabled state
  □ Audit log tab shows recent events

SECURITY:
  □ JWT_SECRET empty → server refuses to start in production
  □ No token in password reset response (even in dev)
  □ REQUIRE_AUTH_FOR_PLATFORM_ENDPOINTS=true blocks unauthenticated access
  □ Tenant A cannot read Tenant B's incidents/data
  □ Rate limiting blocks >8 rapid login attempts
  □ Stripe webhook rejects requests without valid signature

DEPLOYMENT:
  □ docker compose -f docker-compose.prod.yml up builds and starts cleanly
  □ /v1/system/health returns { status: 'ok' } with all deps green
  □ /v1/system/readiness returns { ready: true }
  □ All integration tests pass in CI
  □ npm audit shows no high/critical vulnerabilities

════════════════════════════════════════════════════════════════════════════
SQUAD ASSIGNMENTS (50-member team allocation)
════════════════════════════════════════════════════════════════════════════

SQUAD 1 — Security Hardening (5 engineers, 48h)
  P0-1: Config hardening + startup guard
  P0-2: Unhandled rejection fix
  P0-3: queryWithTenant audit across all write paths
  P0-4: Redis password enforcement
  P1-12: Integration test suite (auth + security tests)

SQUAD 2 — Email + Auth Completion (4 engineers, 72h)
  P1-1: Email transport service (Resend + SMTP)
  P1-2: Wire email into password reset
  P1-3: PasswordResetPage frontend
  P2-9: Notification preferences backend + page

SQUAD 3 — Stripe / Billing (6 engineers, 1 week)
  P1-4: Stripe backend (checkout + webhook)
  P1-5: Stripe frontend (CTA flow + success/cancel pages)
  P2-6: Fix pricing page CTA flow for authenticated users

SQUAD 4 — Admin Dashboard (4 engineers, 72h)
  P1-6: AdminPage (users, products, feature flags, audit log)
  New PATCH /v1/users/:id/status backend route
  Link from Platform.tsx nav

SQUAD 5 — Onboarding + Invites (5 engineers, 1 week)
  P1-7: OnboardingPage wizard (3 steps)
  P1-8: Workspace invite backend (service + routes + migration)
  P1-9: TeamPage frontend
  Post-registration flow in AccountPage

SQUAD 6 — Connectors (4 engineers, 1 week)
  P1-10: ConnectorsPage frontend
  connector-config-service.js backend
  migrations/028 + encrypted token storage
  API route for connector config CRUD + test

SQUAD 7 — API Keys + ML Deploy (4 engineers, 1 week)
  P2-4: API key backend service + routes + migration
  ApiKeysPage frontend
  P2-5: vLLM provider type in llm-provider.js + docker-compose snippet

SQUAD 8 — Architecture Refactor (6 engineers, 1 week)
  P2-1: Split crud.js into domain route files
  P2-2: Move pglite to devDependencies + rebuild verification
  P2-3: LLM health check in /v1/system/health

SQUAD 9 — UX Fixes + Empty States (4 engineers, 48h)
  P2-7: AttackMap empty state
  P2-8: AI panels empty state (all 4 panels)
  P1-11: Delete dead products/ page directory
  Fix duplicate page imports and verify all routes resolve

SQUAD 10 — Testing + CI + Observability (8 engineers, ongoing)
  P1-12: Complete integration test suite (all 5 test files)
  P3-1: OpenTelemetry wiring
  P3-2: SSE Redis pub/sub scale-out
  P3-3: Rate limit headers
  P3-4: DB pool monitoring
  P3-5: Bundle optimization + Three.js lazy load
  CI pipeline updates (integration test step, coverage gating)

════════════════════════════════════════════════════════════════════════════
DEFINITION OF DONE (DoD) — A feature is DONE when:
════════════════════════════════════════════════════════════════════════════

  1. It works end-to-end in the Docker Compose stack on a clean machine
  2. All new API routes are documented in openapi.js
  3. All new env vars are in .env.example with a description comment
  4. All new DB changes have a numbered migration file
  5. There is at least one integration test covering the happy path
  6. There is at least one integration test covering auth failure (401/403)
  7. TypeScript compiles with zero errors (tsc --noEmit)
  8. eslint passes with zero warnings (npm run lint)
  9. The CI pipeline passes
  10. A peer engineer can reproduce the feature with only the README + .env.example

════════════════════════════════════════════════════════════════════════════
FINAL SCORE PROJECTION (if all fixes are applied correctly)
════════════════════════════════════════════════════════════════════════════

  Current State:                    44 / 100  — NOT DEPLOYABLE
  After P0 fixes only:              58 / 100  — Minimally safe
  After P0 + P1 fixes:              76 / 100  — Beta-launch quality
  After P0 + P1 + P2 fixes:        88 / 100  — Production quality
  After P0 + P1 + P2 + P3 fixes:   95 / 100  — YC-demo quality

  Target for YC application: 88+   Achievable in 3-4 weeks with 50 engineers.

╔══════════════════════════════════════════════════════════════════════════╗
║  END OF MASTER FIX SPECIFICATION                                        ║
║  Prepared by: Engineering Audit Task Force (IIT/MIT Level Review)       ║
╚══════════════════════════════════════════════════════════════════════════╝
```
