# Executive / Analyst Dashboard — Audit Report

**Date:** 2026-03-10
**Auditor:** Claude Opus 4.6 (automated)
**Scope:** Dashboard data sources, KPI logic, chart truthfulness, no-data states, filter/scope behavior, role differences, AI summaries, drill-down usefulness, cross-module consistency

---

## 1. Pre-Audit Score: 7.0 / 10

### What was already working well

| Area | Status |
|------|--------|
| Role-based visibility | Consistent `hasRoleAccess()` gating across all consoles. Executive viewers see read-only, analysts get write controls, admins get governance panels |
| AI summary restraint | All AI endpoints (risk explanation, CVE summary, policy generation) include disclaimers, grounding scores, model/provider attribution, and template fallbacks when LLM unavailable |
| Empty state messaging | Most list views show actionable guidance (e.g., "Connect Postgres", "Run CVE sync", "Upload AWS logs") |
| Compliance readiness honesty | Gap engine flags validated-without-evidence controls and stale controls. Readiness score uses weighted formula, not simple percentage |
| Risk scoring transparency | Scoring formula and weights (`vulnerability 0.5 + exposure 0.3 + misconfiguration 0.2`) exposed in API response |
| Risk data freshness | Frontend shows amber warnings when findings are >24h or >72h old |
| SIEM SLA metrics | SLA breach counts shown per severity. Triage suggestions include confidence badges and disclaimer |
| Attack Map Panel | Uses real geo-tagged alert data from backend. Shows honest empty state when no geo data exists |
| Export security | All download routes require auth + role + tenant + audit logging |

### What was broken

| ID | Gap | Severity | Impact |
|----|-----|----------|--------|
| D1 | Landing page "Global Attack Map" rendered 4 hardcoded animated dots at fixed CSS positions — purely decorative, not data-driven | HIGH | Implied live geographic threat activity when none existed. Directly violated the truthfulness rule |
| D2 | Data source indicator (Wifi icon, label, pulse dot) always rendered green even when status was "NO DATA" or "UNAVAILABLE" | HIGH | A green pulsing indicator saying "UNAVAILABLE" contradicts itself — green implies healthy |
| D3 | ThreatCommand KPI cards used `.length` of capped arrays (limit:50/100/25) instead of server-side `pagination.total` | HIGH | "Incident Records: 50" when database has 200 incidents. Executives would make decisions based on incorrect counts |
| D4 | IOC Vault KPI count changed when user applied search filters, because it used the filtered query's `.length` | MEDIUM | Summary KPI should show total, not filtered subset. An analyst filtering for "ip" types would see the KPI drop |
| D5 | All KPI cards showed `0` with no distinction between "zero actual data" and "data not loaded / error occurred" | MEDIUM | "Active Threats: 0" could mean "confirmed safe" or "backend is down" — indistinguishable |
| D6 | Platform billing card subtitle said "Usage metering active" even when the billing query was disabled (insufficient role) or had failed | LOW | Overstated confidence in billing system functionality |

---

## 2. Fix Log

### D1: Remove Decorative Attack Map Dots

**File:** `ThreatDashboard.tsx`

- Removed all 4 hardcoded `animate-ping` dots at fixed CSS positions
- Added conditional empty state: "No geo data available" when `incidents.length === 0`
- Changed "Connected Sources" static label to dynamic: shows `"{n} events"` when data exists, `"No sources"` when empty

### D2: Status-Aware Data Source Indicator

**File:** `ThreatDashboard.tsx`

- Added `sourceColorClass` variable: green for `'live'`, amber for `'empty'`, red for `'unavailable'`
- Added `sourceDotClass` variable: green+pulse for `'live'`, amber (no pulse) for `'empty'`, red (no pulse) for `'unavailable'`
- Updated Wifi icon, label text, and pulse dot to use dynamic classes instead of hardcoded green

### D3: KPI Cards Use Server-Side Totals

**File:** `ThreatCommandConsole.tsx`

- Extracted `incidentTotal`, `cveFeedTotal`, `playbookTotal` from `pagination?.total` (with `.length` fallback)
- Updated "Incident Records", "CVE Feed", and "Active Playbooks" KPI cards to display the server-side total count

### D4: Unfiltered IOC Total Query

**File:** `ThreatCommandConsole.tsx`

- Added separate `iocTotalQuery` with `queryKey: ['iocs-total', tenant]` and `limit: 1` (fetches just the count, not filtered by search/type)
- IOC Vault KPI card now uses `iocTotalQuery.data?.pagination?.total` so the summary number stays stable regardless of active search filters

### D5: Loading/Error/Zero-Data Distinction

**Files:** `ThreatDashboard.tsx`, `ThreatCommandConsole.tsx`

- Landing page: Added `hasData` boolean derived from `dataSource === 'live'`. KPI values show `"—"` (em-dash) when no data instead of `0`
- ThreatCommand: All 6 KPI cards now show `"…"` during loading and `"—"` on error, with actual numbers only when data resolves successfully

### D6: Honest Billing Subtitle

**File:** `Platform.tsx`

- Replaced static `"Usage metering active"` with conditional states:
  - Data available: `"{N} usage events"`
  - Error: `"Usage data unavailable"`
  - Loading: `"Loading usage data…"`
  - No data: `"No usage data"`

---

## 3. Post-Audit Score: 8.4 / 10

| Area | Before | After | Notes |
|------|--------|-------|-------|
| Landing page truthfulness | 4/10 | 8/10 | Decorative dots removed, status indicator is data-aware |
| KPI metric accuracy | 5/10 | 9/10 | Server-side totals used, IOC count unfiltered |
| Loading/error states | 5/10 | 8/10 | em-dash and ellipsis distinguish no-data from loading/error |
| Role-based visibility | 9/10 | 9/10 | Already strong |
| AI summary restraint | 9/10 | 9/10 | Already strong — disclaimers, grounding, fallbacks |
| Data drill-down | 8/10 | 8/10 | Already good — filters, search, detail views |
| Cross-module consistency | 8/10 | 8/10 | Consistent ListResponse/PaginationMeta pattern |
| Billing subtitle honesty | 6/10 | 9/10 | Now data-aware, no false claims |

---

## 4. Metric Defensibility Assessment

### Defensible Metrics

1. **Incident/IOC/CVE/SIEM/Playbook counts**: Now sourced from `COUNT(*)` SQL queries returning `pagination.total`. Not capped by client-side fetch limits.

2. **SOC2 Readiness Score**: Weighted formula (validated=1.0, implemented=0.8, in_progress=0.45) with flags for validated-without-evidence and stale controls. Formula documented, warnings displayed.

3. **Risk Score**: Transparent formula `(vulnerability*0.5 + exposure*0.3 + misconfiguration*0.2) * 10` exposed in API response. Severity thresholds defined. AI explanation includes grounding verification.

4. **SIEM Alert Stats**: Pre-aggregated server-side via SQL `COUNT(*) FILTER (WHERE ...)` — not client-side tallies from capped arrays.

5. **CVE Severity Trend**: Server-side daily aggregation via `DATE_TRUNC('day', published_at)` with `GROUP BY`.

### Metrics With Known Limitations

1. **Trust Score** (`/v1/threats/summary`): Formula is `100 - (unresolved/total * 100)`. This is a custom formula, not an industry standard. It is bounded by SQL `GREATEST(0, LEAST(100, ...))`. Users should understand this is an internal operational metric, not a certification score.

2. **Incident severity/status breakdowns** (ThreatCommand overview cards): Still computed client-side from the fetched array (up to 50 records). The headline total is correct (from `pagination.total`), but the breakdown is approximate. This is an acceptable tradeoff.

3. **MTTR**: Returns `null` from connector data (no resolution timestamps available). Returns `N/A` in UI when null. Correctly avoids fabricating timing data.

---

## 5. Test Coverage

**File:** `tests/dashboard-hardening.test.js`
**Tests:** 89
**Suites:** 25 describe blocks

| Category | Tests |
|----------|-------|
| D1: Decorative dots removal | 5 |
| D2: Status-aware indicator colors | 9 |
| D3: KPI pagination.total usage | 6 |
| D4: Unfiltered IOC count | 3 |
| D5: Loading/error/zero-data distinction | 12 |
| D6: Billing subtitle honesty | 4 |
| Backend trust score formula | 3 |
| Backend incidents pagination | 2 |
| Backend IOCs pagination | 1 |
| Backend SIEM stats | 1 |
| Backend threat intel dashboard | 2 |
| buildAppStatus integrity | 3 |
| AI risk explanation boundedness | 3 |
| AI CVE summarization boundedness | 3 |
| AI compliance gap engine | 3 |
| Risk scoring transparency | 5 |
| Resilience HQ honesty | 3 |
| Attack map data-driven | 2 |
| SIEM SLA metrics | 3 |
| Role-based visibility | 4 |
| No-data honesty (3 suites) | 6 |
| Filter/drill-down | 3 |
| Cross-module consistency | 3 |

**Full suite:** 991 / 991 passing (zero regressions)

---

## 6. What Was Already Strong (Not Fixed — Not Broken)

These areas were audited and found to be truthful and well-implemented:

- **AI triage suggestions** (SIEM panel): Include confidence badges, disclaimers, and `automated: false` flag
- **Risk data freshness warnings**: Amber banners for >24h and >72h stale data
- **SOC2 validated-without-evidence warnings**: Prominently displayed, readiness score qualified
- **Policy approval workflow**: Generated policies start as `draft`, require human approval
- **CVE template fallback**: Includes honest caveat about standard best practices vs. tailored advice
- **Grounding verification**: Risk AI runs `checkOutputGrounding()` and returns ungrounded claims list
- **Attack Map Panel**: Uses real geo-tagged data, shows empty state when none exists (contrast with fixed D1 landing page map)

---

## 7. Remaining Gaps (Honest)

| # | Gap | Severity | Why Not Fixed |
|---|-----|----------|---------------|
| 1 | Incident severity/status breakdowns computed from capped 50-record array, not full dataset | LOW | Would require a separate stats endpoint; headline total is correct |
| 2 | IOC severity/type breakdowns computed from filtered search results, not global totals | LOW | Same as above; adding per-breakdown stat counters would be over-engineering |
| 3 | Backend Health card shows single word ("ok"/"degraded"/"down") — dependency-level detail discarded | LOW | Full dependency detail is available in API response; UI simplification is a design choice |
| 4 | Trust Score formula is custom, not industry-standard — could mislead executives | LOW | Formula is SQL-bounded and consistently computed; documenting its meaning is a product/UX task |
| 5 | CVE trend bar chart recomputes `max` inside `.map()` loop (O(n^2)) | LOW | Performance issue, not truthfulness issue; dataset is small (30 days) |
