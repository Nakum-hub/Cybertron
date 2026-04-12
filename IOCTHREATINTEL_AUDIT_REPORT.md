# IOC / Threat Intel Audit Report

**Audited by:** Strike Team (Detection Engineer, Intel Analyst, Backend/Frontend Engineer, Schema Reviewer, AI Safety Auditor)
**Date:** 2026-03-10
**Scope:** IOC schema, ingestion/deduplication, confidence scoring, severity derivation, source attribution, analyst search/filter, dashboard truthfulness, frontend types, route validation, tenant isolation, connector normalization, correlation engine, CVE sync

---

## Executive Summary

The Cybertron IOC / Threat Intel module was audited across twelve dimensions: IOC schema, create/upsert deduplication, confidence scoring, severity derivation, source attribution, analyst search and filter, dashboard visibility, tag management, frontend type safety, route wiring and validation, tenant isolation, and external connector integration.

**Pre-audit score: 6.8 / 10**
**Post-hardening score: 8.6 / 10**

The module already had solid IOC CRUD with upsert deduplication (GREATEST for confidence, COALESCE for source), tenant isolation via RLS and parameterized queries, audit trail logging, external connector adapters with SSRF protection, a 4-type correlation engine, and CVE feed sync with backoff retry. The gaps found were operational polish and analyst visibility issues rather than fundamental architecture problems.

---

## Phase 1: Audit Findings

### Files Audited

| File | Lines | Role |
|------|-------|------|
| `src/module-service.js` | 1160+ | IOC CRUD: createIoc (upsert), listIocs (paginated), linkIocToIncident, normalizeIocType, asIoc mapper |
| `src/routes/crud.js` | ~640 | HTTP route handlers for /v1/iocs endpoints with RBAC and body validation |
| `src/threat-connectors.js` | 344 | External connector adapters: Wazuh, MISP, OpenCTI, TheHive with SSRF protection |
| `src/correlation-engine.js` | 473 | Alert correlation with 4 rule types, auto-incident creation, SOAR playbook trigger |
| `src/siem-service.js` | 807 | SIEM alert lifecycle, triage suggestions, attack map with IP fields |
| `src/modules/threat-intel/routes.js` | ~2050 | CVE sync/feed/summarize, MITRE ATT&CK, playbooks, SIEM alerts, correlation rules |
| `src/modules/threat-intel/service.js` | 39 | Threat intel status summary (read-only aggregate metrics) |
| `src/modules/threat-intel/model.js` | 29 | SQL aggregation query for incident metrics |
| `frontend/.../ThreatCommandConsole.tsx` | 950+ | IOC management UI: creation, listing, linking, dashboard KPIs |
| `frontend/.../backend.ts` | types | IocRecord, IocType, CreateIocPayload, API functions |
| 6 migration files | various | Schema: iocs, incident_iocs, cves, tenant_cve_views, cve_summaries, cve_sync_state |

### What Was Already Good (Pre-Audit)

1. **Real upsert deduplication**: `ON CONFLICT (tenant_slug, ioc_type, value)` with intelligent merge strategy — `GREATEST` for confidence (never decreases), `COALESCE` for source (prefers new non-null), `COALESCE` for last_seen_at.
2. **Strict type validation**: `normalizeIocType()` enforces exactly 4 types (ip, domain, url, hash) with lowercase normalization and `ServiceError` on invalid input.
3. **Input sanitization**: Value capped at 1024 chars, source at 128 chars, tags limited to 20 items × 64 chars each, LIKE patterns escaped.
4. **Audit trail**: `ioc.upserted` action logged on every create/upsert with actor context. `incident.ioc_linked` logged with `created` boolean distinguishing new links from no-ops.
5. **Idempotent linking**: `incident_iocs` uses `ON CONFLICT DO NOTHING` — re-linking is silently safe.
6. **Tenant isolation**: RLS policies on `iocs` and `incident_iocs` tables. `sanitizeTenant()` on all entry points. FK constraints on junction tables.
7. **DB schema quality**: Confidence CHECK (0-100), ioc_type CHECK enum, UNIQUE constraints, proper indexes on tenant+type and tenant+last_seen.
8. **External connectors**: SSRF protection via `isPrivateHostname()`, severity normalization that returns `'unknown'` for unrecognized values (no inflation).
9. **Correlation engine**: 4 real rule evaluators (threshold, sequence, aggregation, anomaly), auto-creates incidents, bulk marks alerts as correlated, triggers SOAR playbooks.
10. **CVE sync**: NVD feed with backoff retry, failure counting, tenant-scoped views via `tenant_cve_views`, AI summarization with grounding verification.

### Identified Gaps

| ID | Gap | Severity | Status |
|----|-----|----------|--------|
| T1 | Route `VALID_IOC_TYPES` included phantom types (`email`, `file`, `cve`) not in DB CHECK constraint — silent filter failures, DB error on creation | High | **Fixed** |
| T2 | No IOC table/list view — IOCs shown only as a count and a dropdown, no visibility into individual records | High | **Fixed** |
| T3 | No IOC search/filter UI — `fetchIocs` supports search/type params but UI never used them | Medium | **Fixed** |
| T4 | IOC confidence, source, tags, timestamps not displayed anywhere in UI | Medium | **Fixed** |
| T5 | No `minConfidence` filter — analysts can't filter out low-confidence IOCs | Medium | **Fixed** |
| T6 | IOC creation form missing tags input — `CreateIocPayload` supports tags but UI didn't expose them | Medium | **Fixed** |
| T7 | No IOC severity derivation — IOCs have confidence but no at-a-glance severity level | Medium | **Fixed** |
| T8 | Dashboard shows only raw IOC count — no type or severity distribution breakdown | Medium | **Fixed** |

---

## Phase 2: Hardening — Fix Log

### T1: Route IOC Type Allowlist Fix

**Problem:** The `VALID_IOC_TYPES` constant in `routes/crud.js` was `['ip', 'domain', 'url', 'hash', 'email', 'file', 'cve']` — three phantom types that don't exist in the DB CHECK constraint `(ioc_type IN ('ip', 'domain', 'url', 'hash'))`. Filtering by `email`, `file`, or `cve` would silently return empty results. Creating an IOC with those types would pass route validation but throw a DB constraint violation.

**Fix:** Reduced `VALID_IOC_TYPES` to `['ip', 'domain', 'url', 'hash']` — matching the DB constraint exactly.

**Files changed:** `routes/crud.js`

### T2: IOC Vault Table View

**Problem:** IOCs were only displayed in two places: a count card showing `iocs.length` and a dropdown showing `{type}:{value}`. No way for analysts to see individual IOC records with their attributes.

**Fix:** Added a full IOC Vault table section with columns: Type, Value, Source, Confidence, Severity, Tags, First Seen, Last Seen. Each row renders appropriate formatting — confidence with color-coded severity thresholds, tags as compact badges, timestamps formatted via `formatTime()`.

**Files changed:** `ThreatCommandConsole.tsx`

### T3: IOC Search and Filter UI

**Problem:** The `fetchIocs` API function already supported `search` and `iocType` query parameters, but the UI always called `fetchIocs(tenant, { limit: 50 })` with no filters.

**Fix:** Added `iocSearchTerm` and `iocTypeFilter` state variables. The `iocsQuery` now includes these in its query key and passes them to `fetchIocs`. Added search input and type filter dropdown above the IOC table.

**Files changed:** `ThreatCommandConsole.tsx`

### T4: IOC Detail Display (Confidence, Source, Tags, Timestamps)

**Problem:** IOC records carry confidence, source, tags, firstSeenAt, lastSeenAt, and createdAt — but none were rendered anywhere in the UI.

**Fix:** All fields are now displayed in the IOC table. Confidence is color-coded (red >= 90%, orange >= 70%, amber >= 40%, grey < 40%). Source shows the originating system. Tags render as compact badges (first 3 shown, overflow counted). Timestamps use the existing `formatTime()` utility.

**Files changed:** `ThreatCommandConsole.tsx`

### T5: minConfidence Filter in Service Layer

**Problem:** `listIocs` had type and search filters but no way to filter by minimum confidence level. Analysts reviewing IOC data had to mentally filter out low-confidence entries.

**Fix:** Added `options.minConfidence` support to `listIocs` — generates `confidence >= $N` WHERE clause. Route handler extracts `minConfidence` query parameter and passes it through. Frontend `fetchIocs` type signature updated to accept `minConfidence`.

**Files changed:** `module-service.js`, `routes/crud.js`, `backend.ts`

### T6: Tags Input in IOC Creation Form

**Problem:** `CreateIocPayload` supports `tags` and the service layer validates/stores them (max 20 items × 64 chars), but the UI creation form had no tag input.

**Fix:** Added tag input with Enter-to-add, tag display as removable badges, max 20 tag limit enforced client-side. Tags are passed to `createIoc` mutation and cleared on success.

**Files changed:** `ThreatCommandConsole.tsx`

### T7: IOC Severity Derivation from Confidence

**Problem:** IOCs had a `confidence` score (0-100) but no severity classification. Analysts couldn't get an at-a-glance threat assessment. Unlike incidents and CVEs which have explicit severity fields, IOCs had nothing.

**Fix:**
- Added `iocConfidenceToSeverity()` function in `module-service.js` with thresholds matching the risk scoring pattern:
  - >= 90: critical
  - >= 70: high
  - >= 40: medium
  - < 40: low
- `asIoc` row mapper now includes a derived `severity` field
- Added `IocSeverity` type to `backend.ts`
- `IocRecord` interface includes `severity: IocSeverity`

**Files changed:** `module-service.js`, `backend.ts`

### T8: IOC Dashboard KPI Enhancement

**Problem:** The IOC KPI card showed only `iocs.length` with a static subtitle. No visibility into type or severity distribution.

**Fix:**
- Added `iocTypeCounts` memo: counts per type (ip, domain, url, hash)
- Added `iocSeverityCounts` memo: counts per derived severity (critical, high, medium, low)
- KPI card shows severity distribution: `{critical} crit | {high} high | {medium} med | {low} low`
- KPI card shows type distribution: `{ip} ip | {domain} domain | {url} url | {hash} hash`

**Files changed:** `ThreatCommandConsole.tsx`

---

## Analyst Utility Report

### IOC Ingestion Verdict: SOLID

The IOC create/upsert pipeline:
1. Validates type via `normalizeIocType` (exactly ip/domain/url/hash, throws on invalid)
2. Sanitizes value (max 1024 chars), source (max 128 chars), tags (max 20 × 64 chars)
3. Clamps confidence to 0-100 with default 50
4. Performs intelligent upsert: confidence only increases (`GREATEST`), source prefers new non-null, last_seen_at updates
5. Generates audit log with actor context
6. Derives severity from confidence automatically

### Deduplication Verdict: REAL

Not decorative. The `ON CONFLICT (tenant_slug, ioc_type, value)` clause:
- Prevents duplicate IOC entries per tenant
- Intelligently merges attributes on conflict (confidence up, source update, timestamp update)
- Preserves original `first_seen_at` and `tags` (not overwritten on conflict)
- `incident_iocs` uses `ON CONFLICT DO NOTHING` for idempotent linking

### Source Traceability Verdict: PARTIAL BUT HONEST

- Source is captured (max 128 chars) on every IOC creation
- Source is stored in DB and displayed in IOC table
- Connector adapters include source identification (Wazuh, MISP, OpenCTI, TheHive)
- Audit trail records actor context (user ID, email, IP, user agent, trace ID)
- **Gap**: No source trust scoring or source reputation management. Sources are strings, not managed entities.

### Confidence Discipline Verdict: GOOD

- Confidence is a constrained integer (DB CHECK 0-100)
- Default is 50 (neutral, not inflated)
- On upsert, confidence only increases (GREATEST) — accumulation model
- Severity is derived from confidence with documented thresholds
- No AI-generated confidence — all values are analyst-set or system-default

### Search Capability Verdict: FUNCTIONAL

- Text search via ILIKE on IOC value with LIKE metacharacter escaping
- Type filter via normalizeIocType validation
- Confidence filter via minConfidence WHERE clause
- Pagination with total count, hasMore flag
- Ordering by most recent sighting (COALESCE(last_seen_at, first_seen_at) DESC)

---

## AI Safety Assessment

| Dimension | Finding |
|-----------|---------|
| IOC confidence | Not AI-generated. All confidence values are analyst-set or default 50. |
| Severity derivation | Rule-based from confidence thresholds, not LLM-driven |
| CVE summarization | AI-generated but grounding-verified via `checkOutputGrounding()` |
| Triage suggestions | Rule-based, labeled `automated: true`, explicit disclaimer |
| Connector normalization | Deterministic adapter code, no AI in ingestion pipeline |
| Severity inflation | `normalizeIocType` throws on invalid; severity normalization returns `'unknown'` for unrecognized |

**Verdict:** No AI hallucination risk in IOC management. The only AI-adjacent feature (CVE summarization) has grounding verification, disclaimer, and explicit model attribution. IOC confidence and severity are fully deterministic.

---

## Test Coverage

**New tests:** 100
**Total suite:** 631/631 passing

| Test Category | Count |
|---------------|-------|
| IOC type validation (normalizeIocType) | 3 |
| T1 — Route type allowlist consistency | 3 |
| IOC deduplication (ON CONFLICT) | 5 |
| IOC confidence and input validation | 4 |
| T7 — Severity derivation from confidence | 6 |
| T5 — minConfidence filter | 3 |
| IOC listing and pagination | 6 |
| IOC audit trail | 4 |
| IOC tenant isolation | 5 |
| IOC schema migration verification | 7 |
| IOC route wiring | 6 |
| Frontend types (IocRecord/IocSeverity) | 9 |
| T8 — Dashboard KPI breakdown | 4 |
| T2/T3/T4 — IOC table, search, detail display | 10 |
| T6 — IOC creation form tags | 4 |
| Threat connectors source attribution | 4 |
| Correlation engine | 6 |
| SIEM alert IOC-adjacent fields | 4 |
| CVE schema verification | 3 |
| asIoc row mapper | 4 |

---

## Completion Score

**Post-hardening: 8.6 / 10**

### What Moved the Score

| Before | After | Delta | Reason |
|--------|-------|-------|--------|
| Route accepts phantom IOC types | Type allowlist matches DB constraint exactly | +0.3 | No more silent filter failures or DB errors |
| IOCs shown as raw count only | Full searchable table with all attributes | +0.5 | Analysts can see and work with IOC data |
| No search/filter UI | Search by value, filter by type | +0.3 | IOC data is now actionable in the UI |
| No severity classification | Confidence-derived severity with documented thresholds | +0.3 | At-a-glance threat assessment |
| No minConfidence filter API | Filter supported at service, route, and frontend layers | +0.1 | Analysts can focus on high-confidence IOCs |
| Missing tags in creation form | Full tag input with add/remove | +0.1 | IOCs can be categorized during creation |
| Dashboard shows only count | Type and severity distribution breakdown | +0.2 | IOC posture awareness at a glance |

### What Prevents 10/10

| Remaining Gap | Impact | Priority |
|---------------|--------|----------|
| No IOC enrichment integration (VirusTotal, AbuseIPDB, WHOIS) | High | P2 |
| No IOC-to-alert auto-correlation (match IOC values against SIEM alert IPs/domains) | High | P2 |
| No IOC expiration/aging (old IOCs with no recent sightings should age out or flag) | Medium | P3 |
| No IOC type expansion (email, file hash subtypes like md5/sha256, CIDR ranges) | Medium | P3 |
| No IOC source trust scoring (some sources more reliable than others) | Medium | P3 |
| No IOC bulk import (CSV/STIX/OpenIOC ingestion) | Medium | P3 |
| No IOC export (CSV/STIX format export for sharing) | Medium | P3 |
| No IOC-specific dashboard with trend charts | Low | P4 |
| No IOC delete/archive capability | Low | P4 |
| No SIEM alert → IOC auto-extraction (extract sourceIp/destIp as IOCs automatically) | Medium | P3 |

---

## Files Changed Summary

| File | Action | Description |
|------|--------|-------------|
| `src/module-service.js` | Modified | T7: iocConfidenceToSeverity function, asIoc includes severity; T5: minConfidence WHERE clause in listIocs |
| `src/routes/crud.js` | Modified | T1: VALID_IOC_TYPES reduced to match DB; T5: minConfidence query param |
| `frontend/src/lib/backend.ts` | Modified | T7: IocSeverity type, severity in IocRecord; T5: minConfidence in fetchIocs |
| `frontend/.../ThreatCommandConsole.tsx` | Modified | T2: IOC table view; T3: search/filter UI; T4: detail display; T6: tag input; T8: KPI breakdown |
| `tests/ioc-threat-intel-hardening.test.js` | Created | 100 tests covering all hardening changes |
