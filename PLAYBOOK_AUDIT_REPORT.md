# Playbook / Response Automation Audit Report

**Audited by:** Strike Team (Detection Engineer, SOC Architect, Backend/Frontend Engineer, Schema Reviewer, AI Safety Auditor)
**Date:** 2026-03-10
**Scope:** Playbook definitions, execution lifecycle, step state machine, tenant isolation, audit trail, SOAR auto-trigger, route validation, frontend types, execution detail UI, result summary

---

## Executive Summary

The Cybertron Playbook / Response Automation module was audited across ten dimensions: playbook CRUD, step management, execution lifecycle, step state machine, tenant isolation, audit trail integrity, SOAR auto-trigger from correlation engine, route validation, frontend type safety, and analyst execution visibility.

**Pre-audit score: 6.2 / 10**
**Post-hardening score: 8.4 / 10**

The module had a solid foundation: transactional execution with BEGIN/COMMIT/ROLLBACK, parameterized queries throughout, sanitizeTenant on all tenant inputs, CHECK constraints on all enum columns, RLS policies on playbooks and playbook_executions, and a full REST API with RBAC. The gaps found were operational integrity and visibility issues — a critical tenant isolation hole, broken SOAR auto-trigger code path, missing audit trail data, no execution detail UI, and unpopulated result summaries.

**Honesty note:** This is fundamentally a **manual checklist tracker**, not a real automation engine. The four action types (manual, automated, notification, approval) have no behavioral differentiation — all steps require manual status updates via the UI. No actual automation, notification dispatch, or approval workflow exists. The "automated" and "notification" action types are labels only. Presenting this as SOAR automation capability would be misleading.

---

## Phase 1: Audit Findings

### Files Audited

| File | Lines | Role |
|------|-------|------|
| `src/playbook-service.js` | 514 | Core playbook CRUD, execution lifecycle, step result updates, auto-completion |
| `src/modules/threat-intel/routes.js` | ~2080 | REST endpoints for 9 playbook routes with RBAC, audit logging |
| `src/correlation-engine.js` | 486 | Alert correlation with SOAR auto-trigger for playbooks |
| `frontend/.../PlaybookPanel.tsx` | ~430 | Playbook management UI: creation, steps, executions, execution detail |
| `frontend/src/lib/backend.ts` | types | PlaybookRecord, PlaybookStep, PlaybookExecution, PlaybookStepResult, 10 API functions |
| `migrations/013_mitre_attack_and_playbooks.sql` | ~130 | Core tables: playbooks, playbook_steps, playbook_executions, playbook_step_results |
| `migrations/017_rls_fk_indexes_dedup.sql` | ~230 | RLS policies, FK constraints, indexes |
| `migrations/019_soc_remaining_gaps.sql` | ~15 | auto_trigger, severity_trigger, category_trigger columns |

### What Was Already Good (Pre-Audit)

1. **Transaction-safe execution:** `executePlaybook` uses `withClient` with explicit BEGIN/COMMIT/ROLLBACK. Step results are atomically created alongside the execution record.
2. **Parameterized queries everywhere:** No string interpolation in SQL. All user inputs flow through `$N` parameters.
3. **Input validation:** Name capped at 255 chars, description at 2000, category at 64, timeout clamped 1-1440 minutes, action type validated against enum.
4. **CHECK constraints on all enums:** severity_filter, action_type, execution status, step result status — all enforced at DB level.
5. **RLS policies:** `tenant_isolation_playbooks` and `tenant_isolation_playbook_executions` via migration 017.
6. **Audit logging:** playbook.created, playbook.updated, playbook.executed events with actor context.
7. **Auto-increment step order:** When stepOrder not provided, queries MAX(step_order) and increments.
8. **Incident timeline integration:** Executing a playbook against an incident creates timeline entry with `playbook_executed` event.
9. **Paginated listing:** Both playbooks and executions support limit/offset with capped maximums (200).
10. **No-DB safety:** All service functions gracefully return empty/null when `config.databaseUrl` is missing.

### Identified Gaps

| ID | Gap | Severity | Status |
|----|-----|----------|--------|
| P1 | Missing tenant check on addPlaybookStep — any analyst could add steps to any tenant's playbook | **HIGH** | **Fixed** |
| P2 | No validateBodyShape on PUT /playbooks/:id — arbitrary fields accepted in update payload | Medium | **Fixed** |
| P3 | Step result update audit log missing previousStatus — no transition audit trail | **HIGH** | **Fixed** |
| P4 | SOAR auto-trigger uses non-existent `triggered_by` column, creates no step results, no audit/notify | **HIGH** | **Fixed** |
| P5 | PlaybookRecord frontend type missing auto_trigger/severity_trigger/category_trigger fields | Medium | **Fixed** |
| P6 | result_summary JSONB never populated on execution auto-complete — empty after all steps done | Medium | **Fixed** |
| P7 | stepResultMutation defined but never wired to any UI control — dead code | **HIGH** | **Fixed** |
| P8 | No execution detail view — can't see step-by-step progress or act on individual steps | Medium | **Fixed** |

---

## Phase 2: Hardening — Fix Log

### P1: Tenant Isolation on Step Creation (HIGH)

**Problem:** `addPlaybookStep` accepted a `playbookId` but never verified it belonged to the caller's tenant. Route handler at line ~839 called `addPlaybookStep(config, playbookId, { ... })` without passing `auth.tenant`. Any authenticated analyst could add steps to any tenant's playbook by guessing/knowing the playbook ID.

**Fix:**
- Service: `addPlaybookStep` now accepts `tenantSlug` as 4th parameter. When provided, performs `SELECT id FROM playbooks WHERE id = $1 AND tenant_slug = $2` before insertion. Throws `ServiceError(404, 'playbook_not_found')` if playbook doesn't belong to tenant.
- Route: Passes `auth.tenant` as last argument: `addPlaybookStep(config, playbookId, { ... }, auth.tenant)`.

**Files changed:** `playbook-service.js`, `modules/threat-intel/routes.js`

### P2: Body Validation on Playbook Update (Medium)

**Problem:** PUT /playbooks/:id accepted any JSON body without shape validation. Fields not handled by `updatePlaybook` were silently ignored, but unexpected fields could indicate client bugs or tampering.

**Fix:** Added `validateBodyShape(context, response, baseExtraHeaders, payload, { required: [], optional: ['name', 'description', 'severityFilter', 'category', 'isActive'] })` before the update call. Unknown fields now return 400.

**Files changed:** `modules/threat-intel/routes.js`

### P3: Previous Status in Audit Trail (HIGH)

**Problem:** Step result update audit log recorded `status` (new) but not the previous status. Impossible to reconstruct state transitions from audit trail alone. For regulatory compliance and incident forensics, knowing "pending → in_progress" vs "failed → in_progress" is critical.

**Fix:**
- Service: Added SELECT query before UPDATE to fetch `psr.status AS previous_status`. After update, attaches `updated.previousStatus = previousStatus`.
- Route: Audit log payload now includes `previousStatus: result.previousStatus || null`.

**Files changed:** `playbook-service.js`, `modules/threat-intel/routes.js`

### P4: SOAR Auto-Trigger Column Mismatch (HIGH)

**Problem:** Correlation engine's auto-trigger code (lines 396-475) inserted directly into `playbook_executions` with `triggered_by = 'auto_soar'` — but the `triggered_by` column doesn't exist in any migration. The schema has `started_by BIGINT`. This INSERT would **fail at the database level** every time, silently swallowed by the catch block.

Additionally: the fallback path created no `playbook_step_results` rows (no step tracking), and no audit log or notification on auto-trigger.

**Fix:**
- Changed `runCorrelationEngine` function signature to accept `{ notifyIncidentCreated, executePlaybook }` options.
- When `executePlaybook` callback is available, delegates to the full service function (which creates step results, timeline entries, and uses valid schema).
- Fallback direct INSERT uses valid columns (`started_by = NULL` instead of non-existent `triggered_by`).
- Route passes `executePlaybook` to `runCorrelationEngine`: `runCorrelationEngine(config, auth.tenant, log, { notifyIncidentCreated, executePlaybook })`.

**Files changed:** `correlation-engine.js`, `modules/threat-intel/routes.js`

### P5: Frontend PlaybookRecord Auto-Trigger Types (Medium)

**Problem:** `PlaybookRecord` interface in `backend.ts` was missing `auto_trigger`, `severity_trigger`, and `category_trigger` fields added in migration 019. Frontend couldn't access or display auto-trigger configuration.

**Fix:**
- Added `auto_trigger: boolean`, `severity_trigger: string | null`, `category_trigger: string | null` to `PlaybookRecord`.
- Updated all SELECT and RETURNING clauses in `playbook-service.js` to include these three columns.

**Files changed:** `backend.ts`, `playbook-service.js`

### P6: Result Summary Population (Medium)

**Problem:** When all steps in an execution reach terminal states (completed/skipped/failed), the execution auto-completes. But `result_summary` JSONB column was never populated — always null after completion.

**Fix:** Added step outcome aggregation query (`COUNT(*) FILTER (WHERE status = 'completed')`, etc.) and builds structured `resultSummary` object with `totalSteps`, `completed`, `failed`, `skipped`, `outcome`, and `completedAt`. Saved as `result_summary = $3` in the auto-complete UPDATE.

**Files changed:** `playbook-service.js`

### P7: Step Result Update Controls (HIGH)

**Problem:** `stepResultMutation` was defined in `PlaybookPanel.tsx` (line 102-108) but **never called from any UI element**. Dead code. Analysts had no way to update step statuses through the UI — the entire step workflow was non-functional.

**Fix:**
- Connected mutation to step result controls in execution detail view.
- **Pending steps:** "Start" button transitions to `in_progress`.
- **In-progress steps:** "Complete", "Fail", and "Skip" buttons for terminal transitions.
- Controls disabled during mutation pending state.
- Controls hidden for terminal step states (completed/skipped/failed).
- Mutation now invalidates both execution list and step results queries.

**Files changed:** `PlaybookPanel.tsx`

### P8: Execution Detail View (Medium)

**Problem:** Execution list showed only playbook name, status, and timestamp. No way to see step-by-step progress within an execution. No drill-down capability.

**Fix:**
- **Backend:** Added `getExecutionStepResults` service function — JOINs `playbook_step_results` with `playbook_steps` and `playbook_executions` for enriched output (step title, order, action type, assigned role, timeout). Tenant-isolated via `pe.tenant_slug`.
- **Route:** Added GET `/v1/threat-intel/playbooks/executions/:execId/steps` endpoint.
- **Frontend API:** Added `fetchExecutionStepResults` function and extended `PlaybookStepResult` interface with optional step metadata fields.
- **UI:** Execution list items are now clickable. Selecting an execution reveals step-by-step progress panel with status badges, timestamps, notes, and action controls (P7).

**Files changed:** `playbook-service.js`, `modules/threat-intel/routes.js`, `backend.ts`, `PlaybookPanel.tsx`

---

## Safety Boundary Report

### What This System Actually Does

| Capability | Reality |
|-----------|---------|
| Playbook definitions | Real. Stored in DB with validated fields and tenant isolation. |
| Step ordering | Real. Auto-increment or explicit, stored as step_order. |
| Execution tracking | Real. Transaction-safe creation with step result initialization. |
| Step status updates | Real (post-P7). Manual transitions via UI controls. |
| Auto-completion | Real (post-P6). Execution auto-closes when all steps terminal. |
| Result summaries | Real (post-P6). Step outcome counts stored as JSONB. |
| SOAR auto-trigger | Real (post-P4). Playbooks auto-fire from correlation engine. |
| Incident timeline | Real. Execution creates timeline entry when linked to incident. |

### What This System Does NOT Do

| Claimed/Implied | Reality |
|----------------|---------|
| "Automated" action type | **Label only.** No code dispatches automated actions. All steps require manual status updates regardless of action_type. |
| "Notification" action type | **Label only.** No notification is sent when a step has type `notification`. No email, webhook, or Slack integration. |
| "Approval" action type | **Label only.** No approval workflow exists. No approval request is sent. No approval gate blocks execution. |
| Automated response | **Does not exist.** The system tracks manual checklists, not automated responses. |
| Step timeout enforcement | **Not enforced.** `timeout_minutes` is stored but never checked. No timer. No escalation on timeout. |
| Rollback/recovery | **Does not exist.** No undo capability for step actions. No compensation logic. |
| AI-assisted response suggestions | **Does not exist.** No AI generates playbook steps or response recommendations. |

### Unsafe Action Prevention

No unsafe automated actions are possible because **no automation exists**. All step transitions are manual, require authentication, and are tenant-isolated. The SOAR auto-trigger only creates execution records (checklists) — it doesn't execute any response actions.

---

## AI Safety Assessment

| Dimension | Finding |
|-----------|---------|
| AI in playbook execution | None. All step transitions are manual. |
| AI-generated steps | None. All steps are analyst-authored. |
| AI triage suggestions | Not in playbook module. Exists separately in siem-service.js with `automated: true` label. |
| Automation maturity claims | Action types are labels only. No behavioral differentiation. |
| Unsafe escalation | Not possible. No automated escalation or response dispatch. |

**Verdict:** No AI safety risk in the playbook module. The primary risk is **misleading automation maturity** — the four action types suggest differentiated behavior that doesn't exist.

---

## Test Coverage

**New tests:** 164
**Total suite:** 795/795 passing (0 failures)

| Test Category | Count |
|---------------|-------|
| Service constants and validation | 5 |
| Playbook CRUD input validation | 7 |
| P1 — Step creation tenant isolation | 9 |
| Execution model — transaction safety | 6 |
| Step result state machine | 6 |
| P3 — Audit trail previousStatus | 4 |
| P6 — Execution auto-completion and result_summary | 5 |
| P7/P8 — Execution step results query | 6 |
| Route wiring (9 endpoints) | 9 |
| P2 — Body shape validation | 2 |
| Route auth and RBAC | 3 |
| Route audit logging | 5 |
| P4 — SOAR auto-trigger | 8 |
| DB schema — tables and constraints | 8 |
| DB schema — RLS policies | 2 |
| DB schema — auto-trigger columns | 2 |
| P5 — Frontend PlaybookRecord types | 5 |
| Frontend PlaybookStep types | 3 |
| Frontend PlaybookExecution types | 4 |
| Frontend PlaybookStepResult types | 3 |
| Frontend API functions | 10 |
| P7/P8 — Execution detail view UI | 5 |
| P7 — Step result controls UI | 11 |
| Step status styling | 1 |
| Playbook listing pagination | 4 |
| Execution listing filters | 4 |
| Service module exports | 9 |
| Route dependencies | 4 |
| Select clauses — auto-trigger fields | 4 |
| No-DB safety | 7 |
| KPI cards | 3 |

---

## Completion Score

**Post-hardening: 8.4 / 10**

### What Moved the Score

| Before | After | Delta | Reason |
|--------|-------|-------|--------|
| Cross-tenant step injection possible | Tenant ownership verified before step insertion | +0.5 | Critical security fix |
| SOAR auto-trigger broken (non-existent column) | Uses executePlaybook service with valid schema | +0.4 | Auto-trigger code path actually works now |
| No execution detail view | Step-by-step drill-down with status/timestamps/controls | +0.4 | Analysts can track execution progress |
| stepResultMutation was dead code | Wired to Start/Complete/Fail/Skip controls | +0.3 | Step workflow is functional |
| No previousStatus in audit log | Captured before update, included in audit payload | +0.2 | State transitions are auditable |
| result_summary always null | Step outcome counts stored as structured JSON | +0.2 | Execution outcomes are recorded |
| No body validation on playbook update | validateBodyShape with allowed field list | +0.1 | Rejects unknown fields |
| Frontend types missing auto_trigger fields | All three auto_trigger columns in PlaybookRecord | +0.1 | Type-safe frontend access |

### What Prevents 10/10

| Remaining Gap | Impact | Priority |
|---------------|--------|----------|
| Action types are labels only — no behavioral differentiation | HIGH | P1 |
| No notification dispatch for "notification" steps | HIGH | P1 |
| No approval workflow for "approval" steps | HIGH | P1 |
| No step timeout enforcement or escalation | Medium | P2 |
| No playbook_step_results RLS policy (no tenant_slug column) | Medium | P2 |
| No playbook versioning or change history | Medium | P2 |
| No playbook delete/archive capability | Medium | P3 |
| No bulk step reorder endpoint | Low | P3 |
| No playbook template/clone functionality | Low | P3 |
| No execution cancellation with step cleanup | Medium | P2 |
| No parallel step execution (all sequential) | Low | P4 |
| No rollback/compensation for failed executions | Medium | P3 |
| No integration with external tools (JIRA, PagerDuty, Slack) | Medium | P2 |
| No AI-assisted playbook step suggestions | Low | P4 |

---

## Files Changed Summary

| File | Action | Description |
|------|--------|-------------|
| `src/playbook-service.js` | Modified | P1: tenantSlug param on addPlaybookStep; P3: previousStatus tracking; P5: auto_trigger in SELECT/RETURNING; P6: result_summary on auto-complete; P7/P8: getExecutionStepResults function |
| `src/modules/threat-intel/routes.js` | Modified | P1: auth.tenant passed to addPlaybookStep; P2: validateBodyShape on PUT; P3: previousStatus in audit; P4: executePlaybook passed to correlation engine; P7/P8: GET execution steps route, getExecutionStepResults in deps |
| `src/correlation-engine.js` | Modified | P4: executePlaybook callback, removed non-existent column, valid fallback |
| `frontend/src/lib/backend.ts` | Modified | P5: auto_trigger fields in PlaybookRecord; P7/P8: enriched PlaybookStepResult, fetchExecutionStepResults API |
| `frontend/.../PlaybookPanel.tsx` | Modified | P7: step result controls wired to UI; P8: execution detail view with drill-down |
| `tests/playbook-hardening.test.js` | Created | 164 tests covering all hardening changes |
| `tests/soc-remaining-gaps.test.js` | Modified | Updated P4 test to match new executePlaybook pattern |
