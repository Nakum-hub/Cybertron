# THREAT ANALYSIS MODULE -- SECURITY & TRUST AUDIT REPORT

**Date:** 2026-03-07
**Scope:** Threat Analysis function of Cybertron platform
**Perspective:** 10-role strike team (threat intel, detection, malware, AI reasoning, red team, enterprise)
**Tests:** 31 pass / 0 fail (new threat-specific adversarial suite)
**Total platform tests after changes:** 223 pass / 0 fail

---

## 1. BRUTAL AUDIT FINDINGS

### What Is Real (Evidence-Driven)

| Component | Verdict | Evidence |
|-----------|---------|----------|
| CVE feed ingestion from NVD | **Real** | `threat-dashboard-service.js:166-306` -- fetches live NVD data, parses JSON, upserts into `cves` + `tenant_cve_views` tables with proper transaction, backoff, dedup |
| Connector incident fetching | **Real** | `threat-connectors.js:100-207` -- live HTTP calls to Wazuh, MISP, OpenCTI, TheHive with real response parsing |
| Database MTTR calculation | **Real** | `threat-data.js:71-76` -- `AVG(response_time_minutes)` from actual resolved incidents |
| Database trust score | **Real** | `threat-data.js:77-91` -- computed from actual open/total ratio |
| Severity distribution dashboard | **Real** | `threat-dashboard-service.js:447-507` -- real GROUP BY queries against `tenant_cve_views` joined with `cves` |
| CVE relevance scoring | **Real (heuristic)** | `threat-dashboard-service.js:7-24` -- formula uses real CVSS, severity, and recency |
| Threat hunt execution | **Real** | `threat-hunt-service.js:189-285` -- queries real `siem_alerts` table with regex/ILIKE |
| Playbook CRUD + execution | **Real** | Full lifecycle stored in PostgreSQL with step tracking |
| SIEM alert ingestion | **Real** | Stored in `siem_alerts` table with real payloads |
| AI CVE summarization | **Real + bounded** | `threat-ai-service.js:50-167` -- LLM with grounding verification, audit logging, prompt hardening |
| Connector health probes | **Real** | `threat-connectors.js:285-335` -- live HTTP probes with measured latency |
| All SQL queries parameterized | **Real** | 100% `$1` parameterized, zero string concatenation |
| Tenant isolation in all queries | **Real** | Every query filters by `tenant_slug = $1` |

### What Was Fabricated (Fixed)

| Finding | Location | Pre-Fix | Post-Fix |
|---------|----------|---------|----------|
| **Hardcoded MTTR=30** | `threat-data.js:56` | Connector path always returned `mttrMinutes: 30` regardless of actual data | Returns `null` with `mttrNote` explaining why MTTR is unavailable |
| **Unknown severity → medium** | `threat-connectors.js:7`, `threat-data.js:30` | Missing severity auto-inflated to `'medium'` | Returns `'unknown'` -- analyst must triage |
| **Empty state = all-clear** | `threat-data.js:5-10` | Empty summary returned `{mttrMinutes: 0, trustScore: 0}` -- indistinguishable from "no threats" | Returns `{mttrMinutes: null, dataSource: 'none'}` -- clearly "no data" |
| **CVE ID not validated in local path** | `threat-ai-service.js:13` | `buildLocalCveSummary` used raw `payload.cveId` without validation | Now applies `CVE_ID_PATTERN` validation, rejects non-CVE IDs |
| **Generic advice masquerading as tailored** | `threat-ai-service.js:34-44` | Mitigation steps presented without disclosure that they're generic | Added "Note: These are standard best practices, not tailored to this specific vulnerability" |
| **No confidence indicator on template output** | `threat-ai-service.js:59-63` | Template fallback returned no `confidence` or `aiGenerated` fields | Returns `confidence: 'low'`, `aiGenerated: false`, and `confidenceNote` |

### What Is Risky But Not Broken

| Risk | Severity | Detail |
|------|----------|--------|
| Trust score formula is simplistic | LOW | `100 - (unresolvedRatio * 100)` -- directionally correct but not industry-standard |
| No confidence scoring on connector incidents | MEDIUM | Incidents from connectors have no confidence field -- analyst can't distinguish high/low confidence sources |
| Correlation rules exist but no engine | MEDIUM | `alert_correlation_rules` table exists but no code evaluates the conditions JSONB against incoming alerts |
| MITRE mappings stored but not auto-detected | LOW | Manual analyst mapping only -- no automated TTP detection from incident data |
| Playbook steps can be 'automated' but never execute code | LOW | `action_type: 'automated'` exists in schema but all execution is manual |
| No deduplication of connector incidents | LOW | Same incident from multiple sources could appear as separate incidents |
| Marketing section has fake stats | LOW | `MagicBentoSection.tsx` shows "99.7% detection rate", "18M+ IOCs" -- aspirational, not measured |

### What Prevents Analyst Trust

| Issue | Impact | Status |
|-------|--------|--------|
| MTTR was fabricated at 30 min | HIGH | **FIXED** -- now null with explanation |
| Unknown severity inflated to medium | MEDIUM | **FIXED** -- now stays 'unknown' |
| No data indistinguishable from all-clear | MEDIUM | **FIXED** -- dataSource field distinguishes |
| Template advice presented as tailored | MEDIUM | **FIXED** -- now disclosed as generic |
| No confidence on template summaries | MEDIUM | **FIXED** -- now reports `confidence: 'low'` |
| No evidence provenance on dashboard | LOW | Dashboard shows counts but not "where did this come from" |

### What Prevents Enterprise Trust

| Issue | Impact | Status |
|-------|--------|--------|
| No correlation engine | MEDIUM | Schema exists, code doesn't -- enterprise expects auto-correlation |
| No automated TTP detection | LOW | Manual only -- enterprise expects ML/rule-based detection |
| Decorative attack map | LOW | Dots are fixed positions, not real attack data |
| Marketing stats aren't measured | LOW | Frontend `MagicBentoSection.tsx` has hardcoded "99.7%" etc. |

---

## 2. FIX LOG

| # | File | Change | Lines | Verification |
|---|------|--------|-------|-------------|
| 1 | `threat-data.js` | `EMPTY_SUMMARY.mttrMinutes` changed from `0` to `null`; added `dataSource: 'none'` | 5-11 | Test: `HARDENED: empty config returns null mttrMinutes` |
| 2 | `threat-data.js` | `summarizeFromIncidents()` MTTR changed from hardcoded `30` to `null` with `dataQuality.mttrNote` | 53-69 | Test: `MTTR is null across all no-data paths` |
| 3 | `threat-data.js` | `normalizeIncidentSeverity()` default changed from `'medium'` to `'unknown'` | 24-31 | Test: `threat-data normalizeIncidentSeverity also returns unknown` |
| 4 | `threat-data.js` | `loadSummaryFromDatabase()` returns `dataSource: 'database'`, `dataQuality` object, null MTTR when no resolved incidents | 103-113 | Test: `dataSource field is always present in summary` |
| 5 | `threat-connectors.js` | `normalizeSeverity()` default changed from `'medium'` to `'unknown'` | 1-9 | Test: `connector normalizeSeverity returns unknown` |
| 6 | `threat-ai-service.js` | `buildLocalCveSummary()` now validates CVE ID with `CVE_ID_PATTERN` | 12-14 | Test: `CVE ID validation rejects non-CVE patterns` |
| 7 | `threat-ai-service.js` | Local summary mitigation sections now disclose they are generic best practices | 34-38, 40-44 | Test: `local CVE summary includes generic-advice disclaimer` |
| 8 | `threat-ai-service.js` | LLM-not-configured path returns `confidence: 'low'`, `aiGenerated: false`, `confidenceNote` | 59-64 | Test: `local CVE summary marks confidence as low` |
| 9 | `threat-ai-service.js` | LLM-failed path returns `confidence: 'low'`, `aiGenerated: false`, `confidenceNote` | 161-167 | Test: `CVE summary without LLM is transparent` |

---

## 3. GROUNDING / TRUST REPORT

### Data Flow Grounding Score

| Data Path | Grounding Score | Notes |
|-----------|----------------|-------|
| Database → incident summary | **10/10** | Real SQL aggregation with tenant isolation |
| Database → MTTR | **10/10** | `AVG(response_time_minutes)` from real data |
| Connector → incident list | **9/10** | Real external API data; minus 1 for no dedup |
| Connector → MTTR | **10/10** (was 0/10) | Was fabricated at 30; now correctly reports null |
| NVD → CVE feed | **10/10** | Real NVD data with backoff, dedup, upsert |
| CVE → relevance score | **8/10** | Heuristic formula but inputs are real |
| LLM → CVE summary | **9/10** | Grounding verification + disclaimer; minus 1 for LLM unpredictability |
| Template → CVE summary | **6/10** (was 4/10) | Real CVE data embedded; generic advice now labeled as such |
| API → empty state | **10/10** (was 5/10) | Now clearly distinguishable from all-clear via `dataSource`/`mttrMinutes: null` |

### Overall Grounding Score: **9.1/10** (was 6.8/10)

---

## 4. ANALYST USEFULNESS REPORT

### What an Analyst Can Trust

- CVE feed data comes directly from NVD with proper attribution
- Incident data from database reflects actual operational state
- AI summaries are marked as `aiGenerated: true` with `groundingScore` and disclaimer
- Template summaries now clearly labeled as `confidence: 'low'` with generic-advice disclosure
- MTTR is either real (from DB) or honestly null (from connectors/empty)
- Severity is either real or `'unknown'` -- never silently inflated
- Empty state is distinguishable from all-clear via `dataSource` field

### What an Analyst Cannot Do Yet

- No automated IOC correlation across incidents
- No automated MITRE ATT&CK mapping from incident data
- No automated playbook triggering based on severity/conditions
- No alert correlation engine (rules stored but not evaluated)
- No threat intelligence enrichment (e.g., IP reputation lookup)
- No bulk export of threat findings for SIEM integration

### Workflow Gaps

| Gap | Impact |
|-----|--------|
| No incident assignment/ownership | Analysts can't claim incidents |
| No SLA tracking | No time-based escalation |
| No incident templates | Each incident created from scratch |
| No automated severity escalation | Status transitions are manual only |

---

## 5. HONEST COMPLETION SCORE

| Dimension | Score | Notes |
|-----------|-------|-------|
| Evidence Grounding | **9/10** | All paths now produce honest, provenance-tagged data |
| Severity Discipline | **9/10** | Unknown stays unknown; valid severities preserved correctly |
| Confidence Scoring | **8/10** | Template path reports `confidence: 'low'`; LLM path reports `groundingScore`; connector path lacks confidence |
| AI Boundedness | **9/10** | Grounding verification, prompt hardening, input validation, audit logging, disclaimer |
| No-Data Honesty | **10/10** | Empty state clearly distinguishable from all-clear via `dataSource` + null MTTR |
| Analyst Usefulness | **7/10** | Strong CRUD/viewing; weak on automation, correlation, and workflow |
| Enterprise Credibility | **6/10** | Real data pipeline exists; correlation engine/auto-detection missing |
| Tenant Isolation | **9/10** | All queries parameterized with `tenant_slug`; no RLS but consistent app-level isolation |
| Prompt Injection Defense | **9/10** | Validated CVE IDs, sanitized inputs, NFKD normalization, zero-width stripping |
| Report/Export Consistency | **7/10** | API returns consistent data; no dedicated report export for threat findings |

### Overall Threat Analysis Score: **8.3/10** (was 7.1/10)

---

## 6. REMAINING GAPS (Not Fixed -- Documented)

| Gap | Priority | Why Not Fixed |
|-----|----------|---------------|
| No alert correlation engine | P2 | Requires rule evaluation engine -- significant new code |
| No automated MITRE ATT&CK detection | P2 | Requires ML/pattern matching against incident data |
| No connector incident deduplication | P3 | Requires hash-based dedup across multiple sources |
| Decorative attack map on dashboard | P3 | Frontend visual; requires real geo-IP data pipeline |
| Marketing stats in MagicBentoSection | P3 | Aspirational content; should be gated behind a feature flag or removed |
| No incident assignment/ownership | P3 | Feature gap, not security issue |
| Connector incidents lack confidence scoring | P3 | Requires confidence estimation framework for external data |
| `playbook_step_results` table has no indexes | P3 | Performance issue, not trust issue |
| Missing FK: `incident_mitre_mappings.technique_id` → `mitre_attack_techniques.id` | P3 | Schema integrity gap |
| 12 threat tables lack tenant_slug FK to `tenants(slug)` | P3 | Defense-in-depth gap -- app-level isolation exists |

---

## 7. TEST EVIDENCE

```
New: tests/threat-analysis-redteam.test.js -- 31 tests across 8 suites:
  - Evidence Grounding: 5 tests
  - Severity Discipline: 4 tests
  - Confidence Discipline: 3 tests
  - Prompt Injection: 5 tests
  - No-Data Honesty: 3 tests
  - Output Consistency: 4 tests
  - Tenant Isolation: 3 tests
  - Analyst Usefulness: 4 tests

Full platform: 223 tests, 223 pass, 0 failures
```

---

*This audit followed the truthfulness preservation clause: no change was made that improves polish while reducing grounding, traceability, or operational trust. Every fix either removes fabricated data, adds honest disclosure, or strengthens input validation. No capabilities were removed.*
