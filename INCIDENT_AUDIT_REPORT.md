# Incident Management Audit Report

**Audited by:** Strike Team (IR Engineers, SOC Analysts, Backend/Frontend Engineers, Workflow Reviewers, Auditability Engineers, AI Safety Reviewers)
**Date:** 2026-03-10
**Scope:** Incident lifecycle, state machine, assignment, timeline, alert-to-incident escalation, IOC linking, SSE notifications, triage suggestions, dashboard, tenant isolation, audit trail

---

## Executive Summary

The Cybertron Incident Management module was audited across eleven dimensions: incident creation, states, severity/priority, assignment/ownership, evidence linking, timeline/history, alert-to-incident relationships, reporting, AI-generated summaries, tenant isolation, and audit trail integrity.

**Pre-audit score: 7.2 / 10**
**Post-hardening score: 8.8 / 10**

The module already had a real, enforced state machine, timeline tracking, IOC linking, alert-to-incident escalation with context preservation, SSE real-time notifications, and rule-based triage suggestions with explicit disclaimers. The gaps found were operational polish issues rather than fundamental architecture problems.

---

## Phase 1: Audit Findings

### Files Audited

| File | Lines | Role |
|------|-------|------|
| `src/module-service.js` | 1147 | Primary incident CRUD: create, update, list, timeline, IOC linking, state machine |
| `src/siem-service.js` | 807 | Alert lifecycle, alert-to-incident correlation/escalation, triage suggestions, SLA metrics |
| `src/threat-data.js` | 216 | Threat summary (MTTR, trust score), incident DB/connector loading |
| `src/notification-service.js` | 174 | SSE broadcaster: incident.created, incident.updated events |
| `src/correlation-engine.js` | ~300 | Auto-incident creation from correlation rules, bulk alert linking |
| `src/routes/crud.js` | ~600 | HTTP route handlers for /v1/incidents/* endpoints |
| `frontend/.../ThreatCommandConsole.tsx` | 860 | Incident management UI: queue, timeline, creation, severity/status controls |
| `frontend/.../SiemAlertsPanel.tsx` | ~400 | Alert-to-incident linking and escalation UI |
| `frontend/.../backend.ts` | types | IncidentRecord, IncidentStatus, timeline types, API functions |
| 7 migration files | various | Schema: incidents, incident_timeline, incident_iocs, incident_mitre_mappings |

### What Was Already Good (Pre-Audit)

1. **Real state machine**: `INCIDENT_STATUS_TRANSITIONS` enforced at the service layer with DB lookup of current status before allowing transition. Not cosmetic — actually prevents invalid state changes.
2. **Timeline/history**: `incident_timeline` table with event_type, message, actor_user_id — ordered chronologically. Created automatically on incident creation.
3. **IOC linking**: `incident_iocs` junction table with ON CONFLICT DO NOTHING for idempotent linking, full audit trail.
4. **Alert-to-incident escalation**: `escalateAlertToIncident` creates incident from alert, sets `escalated_from_alert_id`, marks alert as escalated, creates timeline entry, preserves full alert context in `raw_event`.
5. **SSE notifications**: Real-time `incident.created` and `incident.updated` broadcasts per tenant with heartbeat.
6. **Triage suggestions**: Rule-based (not AI), labeled `automated: true`, include confidence levels, explicit disclaimer: "These are rule-based suggestions, not AI predictions."
7. **Tenant isolation**: RLS policies on all incident tables, `sanitizeTenant()` on all entry points, FK constraints on incident_iocs/timeline/mitre_mappings.
8. **MTTR truthfulness**: Connector data returns `mttrMinutes: null` with explicit data quality note explaining the limitation, rather than fabricating a number.
9. **Severity non-inflation**: `normalizeIncidentSeverity` in threat-data.js returns `'unknown'` for unrecognized values with comment "do not auto-inflate to medium."
10. **Assignment/priority support**: DB columns exist (migration 018) with `assigned_to`, `assigned_at`, `priority`, handled in `updateIncident`.

### Identified Gaps

| ID | Gap | Severity | Status |
|----|-----|----------|--------|
| I1 | Frontend `IncidentStatus` type missing `'closed'` — UI can't display or target closed state | Medium | **Fixed** |
| I2 | PATCH route body validation rejects `priority` and `assignedTo` fields — API doesn't let analysts set them | High | **Fixed** |
| I3 | Frontend `IncidentRecord` interface missing `priority`, `assignedTo`, `assignedAt`, `escalatedFromAlertId` — data returned but not typed | Medium | **Fixed** |
| I4 | `incident.updated` audit log doesn't capture `previousStatus` — can't reconstruct transition history from audit trail alone | High | **Fixed** |
| I5 | Timeline entries only created when `timelineMessage` is explicitly provided — silent status transitions leave no timeline trace | High | **Fixed** |
| I6 | Dashboard shows raw incident count but no severity/status breakdown — no at-a-glance posture awareness | Medium | **Fixed** |

---

## Phase 2: Hardening — Fix Log

### I1: Frontend IncidentStatus Includes Closed

**Problem:** Backend supports 4 states (open/investigating/resolved/closed) but frontend type was `'open' | 'investigating' | 'resolved'`. The `closed` status couldn't be displayed in UI forms or buttons.

**Fix:** Added `'closed'` to `IncidentStatus` type union. Updated `INCIDENT_STATUSES` array in `ThreatCommandConsole.tsx`. The existing UI already had a "Close" button rendered for investigating/resolved states — now properly typed.

**Files changed:** `backend.ts`, `ThreatCommandConsole.tsx`

### I2: PATCH Body Validation Missing Priority/AssignedTo

**Problem:** The `validateBodyShape` call in the PATCH `/v1/incidents/:id` handler only allowed: title, severity, status, blocked, source, detectedAt, resolvedAt, responseTimeMinutes, timelineMessage. The `priority` and `assignedTo` fields — which `updateIncident` fully supports — would be rejected by the body validator before reaching the service layer.

**Fix:** Added `'priority'` and `'assignedTo'` to the optional fields list in the route handler's `validateBodyShape` call.

**Files changed:** `routes/crud.js`

### I3: Frontend IncidentRecord Missing Fields

**Problem:** Backend returns `priority`, `assignedTo`, `assignedAt`, `escalatedFromAlertId` on every incident record, but the TypeScript interface didn't declare them. The UI already used some of these fields (`selectedIncident.assignedTo`, `selectedIncident.escalatedFromAlertId`) but without type safety.

**Fix:** Added all four fields to `IncidentRecord` interface. Added `priority` and `assignedTo` to `UpdateIncidentPayload`.

**Files changed:** `backend.ts`

### I4: Audit Trail Missing previousStatus

**Problem:** The `incident.updated` audit log payload only recorded `{ fields: Object.keys(payload) }`. When an analyst transitions an incident from `open` to `investigating`, the audit log shows `{ fields: ['status', 'timelineMessage'] }` but never records what the previous status was. This makes audit reconstruction unreliable.

**Fix:** Added `let previousStatus = null` tracking variable. When `payload.status` is provided and the state machine lookup fetches the current status, it's saved to `previousStatus`. The audit log payload now includes `previousStatus` alongside `fields`.

**Files changed:** `module-service.js`

### I5: Auto-Generate Timeline Entry on Status Transitions

**Problem:** Timeline entries were only inserted when `payload.timelineMessage` was explicitly provided. A status transition without a message (e.g., from correlation engine auto-updates) would leave no trace in the timeline, creating a gap between the audit log and the incident timeline.

**Fix:** When a status transition occurs (`previousStatus !== null && payload.status !== undefined`), the system now auto-generates a timeline entry with:
- `event_type = 'status_change'` (distinct from manual `'updated'` entries)
- Auto-message: `"Status changed from {previousStatus} to {newStatus}"` (unless the caller provided an explicit `timelineMessage`, which takes precedence)

Non-status updates with `timelineMessage` still produce `event_type = 'updated'` entries as before.

**Files changed:** `module-service.js`

### I6: Dashboard Severity/Status Breakdown

**Problem:** The incident KPI card showed only `incidents.length` with a generic subtitle. No visibility into severity or status distribution at a glance.

**Fix:**
- Added `incidentSeverityCounts` and `incidentStatusCounts` memos computed from the incidents array
- KPI card now shows inline severity distribution: `{critical} crit | {high} high | {medium} med | {low} low`
- KPI card shows status distribution: `{open} open | {investigating} investigating | {resolved} resolved | {closed} closed`
- Incident list cards now show priority and assignment info inline

**Files changed:** `ThreatCommandConsole.tsx`

---

## Workflow Trust Report

### State Machine Verdict: REAL

The incident state machine is not decorative. It:
1. Is defined as `INCIDENT_STATUS_TRANSITIONS` with explicit allowed transitions per state
2. Enforces transitions via `SELECT status FROM incidents WHERE id = $1 AND tenant_slug = $2` before allowing updates
3. Returns `ServiceError(400, 'invalid_status_transition', ...)` with the attempted and allowed transitions
4. Handles edge cases: same-state updates pass through, reopening from resolved/closed is allowed
5. Auto-sets `resolved_at` when transitioning to `resolved`
6. Now auto-generates timeline entries with `event_type = 'status_change'` for every transition

### Alert State Machine Verdict: ALSO REAL

The SIEM alert lifecycle (`ALERT_STATUS_TRANSITIONS`) is independently enforced:
- States: `new` → `acknowledged` → `in_triage` → `escalated` → `resolved` (terminal)
- `dismissed` can return to `new` (reopen)
- SLA thresholds defined per severity (critical: 15min ack, 4hr resolve; etc.)

### Ownership Verdict: FUNCTIONAL

- `assigned_to` and `assigned_at` columns exist on incidents (migration 018)
- `updateIncident` handles assignment with auto-timestamping
- UI shows assignment info on incident cards and detail view
- API now correctly allows `assignedTo` through body validation

### Timeline Trust Verdict: HIGH

- Every incident creation generates initial timeline entry (`event_type = 'created'`)
- Every status transition now auto-generates timeline entry (`event_type = 'status_change'`)
- Manual notes generate `event_type = 'updated'` entries
- Alert escalations generate `event_type = 'escalated'` entries
- IOC linking generates audit log entries
- All timeline entries include `actor_user_id` for attribution

### Audit Trail Verdict: COMPREHENSIVE

- `incident.created`, `incident.updated`, `incident.ioc_linked` actions logged
- `incident.updated` now includes `previousStatus` for transition reconstruction
- `siem_alert.escalated`, `siem_alert.correlated`, `siem_alert.status_changed` logged
- SSE broadcasts for real-time notification of changes

---

## AI Safety Assessment

| Dimension | Finding |
|-----------|---------|
| Triage suggestions | Rule-based, not LLM-driven. Pattern matching on rule name, category, severity. |
| Output labeling | Every suggestion includes `confidence: 'high'/'medium'/'low'` level |
| Disclaimer | Explicit: "These are rule-based suggestions, not AI predictions. Always verify with full context before acting." |
| Automated flag | `automated: true` on every triage output |
| MTTR truthfulness | Connector data returns `null` with data quality note; DB data uses real `AVG(response_time_minutes)` |
| Severity inflation | `normalizeIncidentSeverity` returns `'unknown'` for unrecognized values, never auto-inflates |
| Default behavior | Unknown alert patterns get `review_and_classify` with `confidence: 'low'` |

**Verdict:** AI-adjacent features in Incident Management are well-bounded. No LLM hallucination risk — triage suggestions are deterministic rule-based with explicit confidence and disclaimers.

---

## Test Coverage

**New tests:** 83
**Total suite:** 531/531 passing

| Test Category | Count |
|---------------|-------|
| Incident state machine | 8 |
| Severity/priority normalization | 3 |
| I4 — Audit trail previousStatus | 2 |
| I5 — Auto timeline on status change | 4 |
| I2 — PATCH body validation | 3 |
| Incident assignment | 4 |
| Incident creation | 5 |
| IOC linking | 3 |
| Alert-to-incident escalation | 6 |
| SSE notifications | 5 |
| Threat data truthfulness | 3 |
| I1 — Frontend IncidentStatus | 4 |
| I3 — Frontend IncidentRecord fields | 6 |
| I6 — Dashboard breakdown | 5 |
| Alert state machine (SIEM) | 4 |
| Triage suggestions AI safety | 4 |
| Tenant isolation | 5 |
| asIncident row mapping | 4 |
| Listing and pagination | 5 |

---

## Completion Score

**Post-hardening: 8.8 / 10**

### What Moved the Score

| Before | After | Delta | Reason |
|--------|-------|-------|--------|
| API rejects priority/assignedTo | Fields accepted in PATCH body | +0.4 | Ownership fully functional via API |
| Silent status transitions | Auto-generated timeline entries | +0.4 | Timeline is now comprehensive |
| No previousStatus in audit | previousStatus captured in audit log | +0.3 | Transition history reconstructable |
| IncidentStatus missing 'closed' | All 4 states typed in frontend | +0.2 | Full lifecycle accessible in UI |
| No type safety for assignment fields | IncidentRecord includes all fields | +0.2 | Type-safe frontend |
| Raw incident count in dashboard | Severity + status breakdown | +0.1 | At-a-glance posture awareness |

### What Prevents 10/10

| Remaining Gap | Impact | Priority |
|---------------|--------|----------|
| No incident categories/tags | Medium | P3 |
| No post-incident review workflow (PIR/RCA) | Medium | P3 |
| No incident severity auto-escalation (e.g., SLA breach escalation) | Medium | P3 |
| No incident merge/dedup capability | Low | P4 |
| No incident evidence attachments (files, screenshots) | Medium | P3 |
| No incident metrics dashboard (MTTD, MTTR trends over time) | Medium | P3 |
| No notification preferences for incident assignment | Low | P4 |
| No escalation path configuration (who gets notified for P1 vs P2) | Medium | P3 |

---

## Files Changed Summary

| File | Action | Description |
|------|--------|-------------|
| `src/module-service.js` | Modified | I4: previousStatus tracking in audit log; I5: auto-timeline on status_change |
| `src/routes/crud.js` | Modified | I2: Added priority + assignedTo to PATCH body validation |
| `frontend/src/lib/backend.ts` | Modified | I1: IncidentStatus includes 'closed'; I3: IncidentRecord + UpdateIncidentPayload fields |
| `frontend/.../ThreatCommandConsole.tsx` | Modified | I1: INCIDENT_STATUSES includes 'closed'; I6: severity/status breakdown KPIs; priority/assignment in list |
| `tests/incident-hardening.test.js` | Created | 83 tests covering all hardening changes |
