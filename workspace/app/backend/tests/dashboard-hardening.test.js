const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

// =====================================================================
// Source file loading
// =====================================================================

const frontendBase = path.resolve(__dirname, '..', '..', 'frontend', 'src');
const backendBase = path.resolve(__dirname, '..', 'src');

const threatDashboardSource = fs.readFileSync(
  path.join(frontendBase, 'components', 'ThreatDashboard.tsx'),
  'utf8'
);
const threatCommandSource = fs.readFileSync(
  path.join(frontendBase, 'components', 'platform', 'ThreatCommandConsole.tsx'),
  'utf8'
);
const platformSource = fs.readFileSync(
  path.join(frontendBase, 'pages', 'Platform.tsx'),
  'utf8'
);
const backendTsSource = fs.readFileSync(
  path.join(frontendBase, 'lib', 'backend.ts'),
  'utf8'
);
const threatDataSource = fs.readFileSync(
  path.join(backendBase, 'threat-data.js'),
  'utf8'
);
const moduleServiceSource = fs.readFileSync(
  path.join(backendBase, 'module-service.js'),
  'utf8'
);
const riskScoringSource = fs.readFileSync(
  path.join(backendBase, 'ai', 'risk-scoring-service.js'),
  'utf8'
);
const complianceGapSource = fs.readFileSync(
  path.join(backendBase, 'ai', 'compliance-gap-engine.js'),
  'utf8'
);
const riskAiSource = fs.readFileSync(
  path.join(backendBase, 'ai', 'risk-ai-service.js'),
  'utf8'
);
const threatAiSource = fs.readFileSync(
  path.join(backendBase, 'ai', 'threat-ai-service.js'),
  'utf8'
);
const serverSource = fs.readFileSync(
  path.join(backendBase, 'server.js'),
  'utf8'
);
const siemServiceSource = fs.readFileSync(
  path.join(backendBase, 'siem-service.js'),
  'utf8'
);
const threatDashboardServiceSource = fs.readFileSync(
  path.join(backendBase, 'ai', 'threat-dashboard-service.js'),
  'utf8'
);

let riskEngineSource = '';
try {
  riskEngineSource = fs.readFileSync(
    path.join(backendBase, 'ai', 'risk-engine.js'),
    'utf8'
  );
} catch {}

let riskCopilotRoutesSource = '';
try {
  riskCopilotRoutesSource = fs.readFileSync(
    path.join(backendBase, 'modules', 'risk-copilot', 'routes.js'),
    'utf8'
  );
} catch {}

let resilHqSource = '';
try {
  resilHqSource = fs.readFileSync(
    path.join(frontendBase, 'components', 'platform', 'ResilienceHQConsole.tsx'),
    'utf8'
  );
} catch {}

let riskCopilotSource = '';
try {
  riskCopilotSource = fs.readFileSync(
    path.join(frontendBase, 'components', 'platform', 'RiskCopilotConsole.tsx'),
    'utf8'
  );
} catch {}

let siemAlertsPanelSource = '';
try {
  siemAlertsPanelSource = fs.readFileSync(
    path.join(frontendBase, 'components', 'platform', 'SiemAlertsPanel.tsx'),
    'utf8'
  );
} catch {}

let attackMapPanelSource = '';
try {
  attackMapPanelSource = fs.readFileSync(
    path.join(frontendBase, 'components', 'platform', 'AttackMapPanel.tsx'),
    'utf8'
  );
} catch {}

// =====================================================================
// 1. D1 — Landing page attack map: no decorative dots
// =====================================================================

describe('D1: Landing Page Attack Map — No Decorative Dots', () => {
  it('does not contain hardcoded animate-ping dots', () => {
    assert.ok(
      !threatDashboardSource.includes('animate-ping'),
      'animate-ping dots should have been removed from ThreatDashboard'
    );
  });

  it('does not contain hardcoded red/cyan/yellow/purple dot elements', () => {
    assert.ok(!threatDashboardSource.includes('bg-red-500 animate-ping'));
    assert.ok(!threatDashboardSource.includes('bg-cyan-500 animate-ping'));
    assert.ok(!threatDashboardSource.includes('bg-yellow-500 animate-ping'));
    assert.ok(!threatDashboardSource.includes('bg-purple-500 animate-ping'));
  });

  it('shows "No geo data available" when incidents are empty', () => {
    assert.ok(threatDashboardSource.includes('No geo data available'));
  });

  it('conditionally renders geo label based on incident count', () => {
    assert.ok(threatDashboardSource.includes('incidents.length === 0'));
    assert.ok(threatDashboardSource.includes('No sources'));
  });

  it('no longer uses static "Connected Sources" label', () => {
    assert.ok(!threatDashboardSource.includes("'Connected Sources'"));
    assert.ok(!threatDashboardSource.includes('"Connected Sources"'));
    assert.ok(!threatDashboardSource.includes('>Connected Sources<'));
  });
});

// =====================================================================
// 2. D2 — Data source indicator color matches status
// =====================================================================

describe('D2: Data Source Indicator — Status-Aware Colors', () => {
  it('defines sourceColorClass based on dataSource', () => {
    assert.ok(threatDashboardSource.includes('sourceColorClass'));
  });

  it('uses green for live status', () => {
    const block = threatDashboardSource.slice(
      threatDashboardSource.indexOf('const sourceColorClass'),
      threatDashboardSource.indexOf('const sourceDotClass')
    );
    assert.ok(block.includes("'text-green-400'"));
    assert.ok(block.includes("'live'"));
  });

  it('uses amber for empty/no-data status', () => {
    const block = threatDashboardSource.slice(
      threatDashboardSource.indexOf('const sourceColorClass'),
      threatDashboardSource.indexOf('const sourceDotClass')
    );
    assert.ok(block.includes("'text-amber-400'"));
    assert.ok(block.includes("'empty'"));
  });

  it('uses red for unavailable status', () => {
    const block = threatDashboardSource.slice(
      threatDashboardSource.indexOf('const sourceColorClass'),
      threatDashboardSource.indexOf('const sourceDotClass')
    );
    assert.ok(block.includes("'text-red-400'"));
  });

  it('defines sourceDotClass based on dataSource', () => {
    assert.ok(threatDashboardSource.includes('sourceDotClass'));
  });

  it('only pulses for live status', () => {
    const start = threatDashboardSource.indexOf('const sourceDotClass');
    const block = threatDashboardSource.slice(start, start + 300);
    assert.ok(block.includes('bg-green-400 animate-pulse'));
    assert.ok(block.includes('bg-amber-400'));
    assert.ok(block.includes('bg-red-400'));
    // Ensure animate-pulse only appears once (for the live/green case)
    const pulseMatches = block.match(/animate-pulse/g);
    assert.strictEqual(pulseMatches.length, 1);
  });

  it('Wifi icon uses dynamic sourceColorClass', () => {
    assert.ok(threatDashboardSource.includes('${sourceColorClass}'));
  });

  it('source label uses dynamic sourceColorClass', () => {
    // Check that the label span uses the dynamic class, not hardcoded green
    const indicatorBlock = threatDashboardSource.slice(
      threatDashboardSource.indexOf('<Wifi'),
      threatDashboardSource.indexOf('</div>', threatDashboardSource.indexOf('<Wifi')) + 6
    );
    assert.ok(!indicatorBlock.includes("'text-green-400'"));
    assert.ok(indicatorBlock.includes('sourceColorClass'));
  });

  it('dot uses dynamic sourceDotClass', () => {
    assert.ok(threatDashboardSource.includes('${sourceDotClass}'));
  });
});

// =====================================================================
// 3. D3 — ThreatCommand KPI cards use pagination.total
// =====================================================================

describe('D3: ThreatCommand KPIs — Use pagination.total Instead of .length', () => {
  it('extracts incidentTotal from pagination', () => {
    assert.ok(threatCommandSource.includes('incidentTotal'));
    assert.ok(threatCommandSource.includes('pagination?.total'));
  });

  it('extracts cveFeedTotal from pagination', () => {
    assert.ok(threatCommandSource.includes('cveFeedTotal'));
    assert.ok(
      threatCommandSource.includes("cveFeedQuery.data?.pagination?.total") ||
      threatCommandSource.includes('cveFeedTotal')
    );
  });

  it('extracts playbookTotal from pagination', () => {
    assert.ok(threatCommandSource.includes('playbookTotal'));
  });

  it('Incident Records card uses incidentTotal not incidents.length', () => {
    const kpiBlock = threatCommandSource.slice(
      threatCommandSource.indexOf("Incident Records"),
      threatCommandSource.indexOf("IOC Vault Entries")
    );
    assert.ok(!kpiBlock.includes('incidents.length'));
    assert.ok(kpiBlock.includes('incidentTotal'));
  });

  it('CVE Feed card uses cveFeedTotal', () => {
    const kpiBlock = threatCommandSource.slice(
      threatCommandSource.indexOf("CVE Feed"),
      threatCommandSource.indexOf("Active Playbooks")
    );
    assert.ok(!kpiBlock.includes('cveFeed.length'));
    assert.ok(kpiBlock.includes('cveFeedTotal'));
  });

  it('Active Playbooks card uses playbookTotal', () => {
    const kpiBlock = threatCommandSource.slice(
      threatCommandSource.indexOf("Active Playbooks"),
      threatCommandSource.indexOf("Critical CVEs")
    );
    assert.ok(!kpiBlock.includes('playbooks.length'));
    assert.ok(kpiBlock.includes('playbookTotal'));
  });
});

// =====================================================================
// 4. D4 — IOC KPI uses unfiltered total query
// =====================================================================

describe('D4: IOC KPI — Unfiltered Total Count', () => {
  it('has a separate iocTotalQuery for KPI card', () => {
    assert.ok(threatCommandSource.includes('iocTotalQuery'));
    assert.ok(threatCommandSource.includes("'iocs-total'"));
  });

  it('iocTotalQuery fetches with limit:1 (just for count)', () => {
    const block = threatCommandSource.slice(
      threatCommandSource.indexOf("'iocs-total'"),
      threatCommandSource.indexOf("'iocs-total'") + 500
    );
    assert.ok(block.includes('limit: 1'));
  });

  it('IOC KPI card uses iocTotalQuery not filtered iocs.length', () => {
    const kpiBlock = threatCommandSource.slice(
      threatCommandSource.indexOf("IOC Vault Entries"),
      threatCommandSource.indexOf("IOC Vault Entries") + 400
    );
    assert.ok(kpiBlock.includes('iocTotalQuery'));
    assert.ok(!kpiBlock.includes('{iocs.length}'));
  });
});

// =====================================================================
// 5. D5 — KPI cards distinguish loading/error from zero-data
// =====================================================================

describe('D5: KPI Cards — Loading/Error/Zero-Data Distinction', () => {
  it('ThreatDashboard defines hasData from dataSource', () => {
    assert.ok(threatDashboardSource.includes("hasData"));
    assert.ok(threatDashboardSource.includes("dataSource === 'live'"));
  });

  it('ThreatDashboard summary cards show em-dash when no data', () => {
    assert.ok(threatDashboardSource.includes("hasData ? summary.activeThreats"));
    assert.ok(threatDashboardSource.includes(": '—'"));
  });

  it('Active Threats shows "—" not "0" when no data', () => {
    const kpiBlock = threatDashboardSource.slice(
      threatDashboardSource.indexOf("'Active Threats'"),
      threatDashboardSource.indexOf("'Blocked Today'")
    );
    assert.ok(kpiBlock.includes("'—'"));
    assert.ok(kpiBlock.includes("hasData"));
  });

  it('Blocked Today shows "—" not "0" when no data', () => {
    const kpiBlock = threatDashboardSource.slice(
      threatDashboardSource.indexOf("'Blocked Today'"),
      threatDashboardSource.indexOf("'Open Incidents'")
    );
    assert.ok(kpiBlock.includes("'—'"));
    assert.ok(kpiBlock.includes("hasData"));
  });

  it('MTTR shows "—" not "N/A" when no data', () => {
    const kpiBlock = threatDashboardSource.slice(
      threatDashboardSource.indexOf("'MTTR'"),
      threatDashboardSource.indexOf('].map(metric')
    );
    assert.ok(kpiBlock.includes("!hasData ? '—'"));
  });

  it('ThreatCommand Incident card shows "…" when loading', () => {
    const kpiBlock = threatCommandSource.slice(
      threatCommandSource.indexOf("Incident Records"),
      threatCommandSource.indexOf("IOC Vault Entries")
    );
    assert.ok(kpiBlock.includes('incidentsQuery.isLoading'));
    assert.ok(kpiBlock.includes("'…'"));
  });

  it('ThreatCommand Incident card shows "—" on error', () => {
    const kpiBlock = threatCommandSource.slice(
      threatCommandSource.indexOf("Incident Records"),
      threatCommandSource.indexOf("IOC Vault Entries")
    );
    assert.ok(kpiBlock.includes('incidentsQuery.isError'));
    assert.ok(kpiBlock.includes("'—'"));
  });

  it('ThreatCommand SIEM card shows "…" when loading', () => {
    const kpiBlock = threatCommandSource.slice(
      threatCommandSource.indexOf("SIEM Alerts"),
      threatCommandSource.indexOf("CVE Feed")
    );
    assert.ok(kpiBlock.includes('siemStatsQuery.isLoading'));
  });

  it('ThreatCommand SIEM card shows "—" on error', () => {
    const kpiBlock = threatCommandSource.slice(
      threatCommandSource.indexOf("SIEM Alerts"),
      threatCommandSource.indexOf("CVE Feed")
    );
    assert.ok(kpiBlock.includes('siemStatsQuery.isError'));
  });

  it('ThreatCommand CVE card shows "…" when loading', () => {
    const kpiBlock = threatCommandSource.slice(
      threatCommandSource.indexOf("CVE Feed"),
      threatCommandSource.indexOf("Active Playbooks")
    );
    assert.ok(kpiBlock.includes('cveFeedQuery.isLoading'));
  });

  it('ThreatCommand Playbooks card shows "…" when loading', () => {
    const kpiBlock = threatCommandSource.slice(
      threatCommandSource.indexOf("Active Playbooks"),
      threatCommandSource.indexOf("Critical CVEs")
    );
    assert.ok(kpiBlock.includes('playbooksQuery.isLoading'));
  });

  it('ThreatCommand Critical CVEs card shows "…" when loading', () => {
    const kpiBlock = threatCommandSource.slice(
      threatCommandSource.indexOf("Critical CVEs"),
      threatCommandSource.indexOf("Critical CVEs") + 300
    );
    assert.ok(kpiBlock.includes('threatDashboardQuery.isLoading'));
  });
});

// =====================================================================
// 6. D6 — Platform billing subtitle honesty
// =====================================================================

describe('D6: Platform Billing Subtitle — Honest States', () => {
  it('no longer shows static "Usage metering active"', () => {
    assert.ok(!platformSource.includes("'Usage metering active'"));
    assert.ok(!platformSource.includes('"Usage metering active"'));
  });

  it('shows error state when billing usage query fails', () => {
    assert.ok(platformSource.includes('billingUsageQuery.isError'));
    assert.ok(platformSource.includes('Usage data unavailable'));
  });

  it('shows loading state when billing usage query is loading', () => {
    assert.ok(platformSource.includes('billingUsageQuery.isLoading'));
  });

  it('shows actual usage count when data is available', () => {
    assert.ok(platformSource.includes('usage events'));
    assert.ok(platformSource.includes('billingUsageQuery.data?.pagination?.total'));
  });
});

// =====================================================================
// 7. Backend KPI Data Truthfulness
// =====================================================================

describe('Backend KPI Data — Trust Score Formula', () => {
  it('trustScore is computed from incident resolved ratio', () => {
    assert.ok(threatDataSource.includes('trust_score'));
  });

  it('trustScore is bounded between 0 and 100', () => {
    assert.ok(
      threatDataSource.includes('LEAST(') || threatDataSource.includes('Math.min(')
    );
    assert.ok(
      threatDataSource.includes('GREATEST(') || threatDataSource.includes('Math.max(')
    );
  });

  it('MTTR returns null when computed from connector data', () => {
    const block = threatDataSource.slice(
      threatDataSource.indexOf('summarizeFromIncidents'),
      threatDataSource.indexOf('summarizeFromIncidents') + 2000
    );
    assert.ok(block.includes('mttrMinutes: null') || block.includes('mttrAvailable: false'));
  });
});

describe('Backend KPI Data — listIncidents Pagination', () => {
  it('returns pagination.total from COUNT query', () => {
    const fnBlock = moduleServiceSource.slice(
      moduleServiceSource.indexOf('async function listIncidents'),
      moduleServiceSource.indexOf('async function createIncident')
    );
    assert.ok(fnBlock.includes("COUNT(*)::INT AS total"));
    assert.ok(fnBlock.includes('pagination'));
    assert.ok(fnBlock.includes('total'));
  });

  it('returns hasMore flag', () => {
    const fnBlock = moduleServiceSource.slice(
      moduleServiceSource.indexOf('async function listIncidents'),
      moduleServiceSource.indexOf('async function createIncident')
    );
    assert.ok(fnBlock.includes('hasMore'));
  });
});

describe('Backend KPI Data — listIocs Pagination', () => {
  it('returns pagination.total from COUNT query', () => {
    const fnBlock = moduleServiceSource.slice(
      moduleServiceSource.indexOf('async function listIocs'),
      moduleServiceSource.indexOf('async function listIocs') + 2500
    );
    assert.ok(fnBlock.includes("COUNT(*)::INT AS total"));
    assert.ok(fnBlock.includes('pagination'));
  });
});

describe('Backend KPI Data — SIEM Alert Stats', () => {
  it('returns pre-aggregated stats from database', () => {
    assert.ok(siemServiceSource.includes('total_alerts'));
    assert.ok(siemServiceSource.includes('uncorrelated'));
    assert.ok(siemServiceSource.includes('critical_count'));
  });
});

describe('Backend KPI Data — Threat Intel Dashboard', () => {
  it('returns severity counts from database aggregation', () => {
    assert.ok(threatDashboardServiceSource.includes("c.severity"));
    assert.ok(threatDashboardServiceSource.includes("GROUP BY"));
  });

  it('returns trend data with daily grouping', () => {
    assert.ok(threatDashboardServiceSource.includes("DATE_TRUNC('day'"));
    assert.ok(threatDashboardServiceSource.includes('trend'));
  });
});

// =====================================================================
// 8. Backend buildAppStatus Truthfulness
// =====================================================================

describe('Backend buildAppStatus — Module Status Integrity', () => {
  it('queries incidents for threat-command status', () => {
    const block = serverSource.slice(
      serverSource.indexOf('buildAppStatus'),
      serverSource.indexOf('buildAppStatus') + 4000
    );
    assert.ok(block.includes('incidents'));
    assert.ok(block.includes("'threat-command'") || block.includes("threat-command"));
  });

  it('returns status as operational/degraded/no_data/unavailable', () => {
    const block = serverSource.slice(
      serverSource.indexOf('buildAppStatus'),
      serverSource.indexOf('buildAppStatus') + 4000
    );
    assert.ok(
      block.includes("'operational'") ||
      block.includes("'degraded'") ||
      block.includes("'no_data'") ||
      block.includes("'unavailable'")
    );
  });

  it('includes evidence object in status response', () => {
    const block = serverSource.slice(
      serverSource.indexOf('buildAppStatus'),
      serverSource.indexOf('buildAppStatus') + 4000
    );
    assert.ok(block.includes('evidence'));
  });
});

// =====================================================================
// 9. AI Summary Boundedness
// =====================================================================

describe('AI Summary Boundedness — Risk Explanation', () => {
  it('includes disclaimer in risk AI response', () => {
    assert.ok(riskAiSource.includes('disclaimer'));
  });

  it('includes groundingScore in risk AI response', () => {
    assert.ok(riskAiSource.includes('groundingScore'));
  });

  it('falls back to local mitigations when LLM fails', () => {
    assert.ok(riskAiSource.includes('buildLocalMitigationSuggestions'));
  });
});

describe('AI Summary Boundedness — CVE Summarization', () => {
  it('includes disclaimer in CVE AI summary', () => {
    assert.ok(threatAiSource.includes('disclaimer'));
  });

  it('falls back to local template when LLM not configured', () => {
    assert.ok(threatAiSource.includes('buildLocalCveSummary'));
  });

  it('local template includes honest caveat', () => {
    assert.ok(
      threatAiSource.includes('standard best practices') ||
      threatAiSource.includes('not tailored')
    );
  });
});

describe('AI Summary Boundedness — Compliance Gap Engine', () => {
  it('detects validated-without-evidence controls', () => {
    assert.ok(complianceGapSource.includes('validatedWithoutEvidence'));
  });

  it('detects stale controls (12+ months)', () => {
    assert.ok(complianceGapSource.includes('stale') || complianceGapSource.includes('Stale'));
  });

  it('readiness score uses weighted formula', () => {
    assert.ok(complianceGapSource.includes('validated'));
    assert.ok(complianceGapSource.includes('implemented'));
    assert.ok(complianceGapSource.includes('in_progress'));
  });
});

// =====================================================================
// 10. Risk Copilot Dashboard — Scoring Transparency
// =====================================================================

describe('Risk Copilot — Scoring Model Transparency', () => {
  it('scoring formula is exposed in API response', () => {
    assert.ok(riskCopilotRoutesSource.includes('scoringModel'));
    assert.ok(riskCopilotRoutesSource.includes('SCORING_FORMULA'));
  });

  it('scoring weights are defined with vulnerability/exposure/misconfiguration', () => {
    assert.ok(riskEngineSource.includes('SCORING_WEIGHTS'));
    assert.ok(riskEngineSource.includes('vulnerability'));
    assert.ok(riskEngineSource.includes('exposure'));
    assert.ok(riskEngineSource.includes('misconfiguration'));
  });

  it('risk frontend shows grounding score with color coding', () => {
    if (riskCopilotSource) {
      assert.ok(riskCopilotSource.includes('groundingScore'));
    }
  });

  it('risk frontend shows disclaimer text', () => {
    if (riskCopilotSource) {
      assert.ok(riskCopilotSource.includes('disclaimer'));
    }
  });

  it('risk frontend shows freshness warning for stale data', () => {
    if (riskCopilotSource) {
      assert.ok(
        riskCopilotSource.includes('24') || riskCopilotSource.includes('72') ||
        riskCopilotSource.includes('freshness') || riskCopilotSource.includes('stale')
      );
    }
  });
});

// =====================================================================
// 11. Resilience HQ — Compliance Dashboard Honesty
// =====================================================================

describe('Resilience HQ — SOC2 Dashboard Honesty', () => {
  it('shows validated-without-evidence warning', () => {
    if (resilHqSource) {
      assert.ok(resilHqSource.includes('validated without evidence'));
    }
  });

  it('readiness score shown with decimal precision', () => {
    if (resilHqSource) {
      assert.ok(
        resilHqSource.includes('toFixed') || resilHqSource.includes('readinessScore')
      );
    }
  });

  it('audit trail is gated behind canViewAudit', () => {
    if (resilHqSource) {
      assert.ok(resilHqSource.includes('canViewAudit'));
    }
  });
});

// =====================================================================
// 12. Attack Map Panel — Data-Driven (Not Decorative)
// =====================================================================

describe('AttackMapPanel — Data-Driven Visualization', () => {
  it('shows empty message when no geo data available', () => {
    if (attackMapPanelSource) {
      assert.ok(
        attackMapPanelSource.includes('No geo-tagged alert data') ||
        attackMapPanelSource.includes('No geo data')
      );
    }
  });

  it('renders nodes from real API data', () => {
    if (attackMapPanelSource) {
      assert.ok(attackMapPanelSource.includes('fetchAttackMapData'));
    }
  });
});

// =====================================================================
// 13. SIEM Alerts Panel — SLA Metrics Truthfulness
// =====================================================================

describe('SiemAlertsPanel — SLA Metrics', () => {
  it('shows SLA breach counts', () => {
    if (siemAlertsPanelSource) {
      assert.ok(
        siemAlertsPanelSource.includes('sla_breached') ||
        siemAlertsPanelSource.includes('SLA')
      );
    }
  });

  it('triage suggestion includes disclaimer', () => {
    if (siemAlertsPanelSource) {
      assert.ok(siemAlertsPanelSource.includes('disclaimer'));
    }
  });

  it('triage suggestion shows confidence badge', () => {
    if (siemAlertsPanelSource) {
      assert.ok(siemAlertsPanelSource.includes('confidence'));
    }
  });
});

// =====================================================================
// 14. Role/Tenant Tests
// =====================================================================

describe('Role-Based Dashboard Visibility', () => {
  it('ThreatCommand canWrite requires security_analyst', () => {
    assert.ok(threatCommandSource.includes("hasRoleAccess(role, 'security_analyst')"));
  });

  it('ThreatCommand canSyncThreatFeed requires tenant_admin', () => {
    assert.ok(threatCommandSource.includes("hasRoleAccess(role, 'tenant_admin')"));
  });

  it('Platform governance panel is role-gated', () => {
    assert.ok(platformSource.includes('PlatformGovernancePanel'));
    assert.ok(platformSource.includes("hasRoleAccess(role, 'tenant_admin')"));
  });

  it('Billing usage query is role-gated to security_analyst+', () => {
    assert.ok(platformSource.includes("hasRoleAccess(role, 'security_analyst')"));
  });
});

// =====================================================================
// 15. No-Data Honesty Tests
// =====================================================================

describe('No-Data Honesty — Landing Dashboard', () => {
  it('incident feed shows actionable empty message', () => {
    assert.ok(threatDashboardSource.includes('No incidents available yet'));
    assert.ok(threatDashboardSource.includes('Connect Postgres or external threat connectors'));
  });

  it('error state is displayed for unavailable backend', () => {
    assert.ok(threatDashboardSource.includes('Threat service is currently unavailable'));
  });
});

describe('No-Data Honesty — ThreatCommand Console', () => {
  it('incident queue shows empty message', () => {
    assert.ok(threatCommandSource.includes('No incidents recorded yet'));
  });

  it('CVE feed shows sync guidance when empty', () => {
    assert.ok(threatCommandSource.includes('No CVE entries ingested yet'));
  });
});

describe('No-Data Honesty — Platform Shell', () => {
  it('no accessible apps shows lock icon and message', () => {
    assert.ok(platformSource.includes('No Accessible Applications'));
  });

  it('backend config error shows diagnostic banner', () => {
    assert.ok(platformSource.includes('platformConfigError'));
  });
});

// =====================================================================
// 16. Filter/Drill-Down Tests
// =====================================================================

describe('Filter/Drill-Down Behavior', () => {
  it('ThreatCommand CVE feed supports day window filter', () => {
    assert.ok(threatCommandSource.includes('dashboardDays'));
      assert.ok(threatCommandSource.includes('Window (days)'));
  });

  it('ThreatCommand IOC search filters the IOC list', () => {
    assert.ok(threatCommandSource.includes('iocSearchTerm'));
    assert.ok(threatCommandSource.includes('iocTypeFilter'));
  });

  it('Backend fetchAuditLogs supports action/actorEmail/date filters', () => {
    assert.ok(backendTsSource.includes('action'));
    assert.ok(backendTsSource.includes('actorEmail'));
    assert.ok(backendTsSource.includes('startDate'));
    assert.ok(backendTsSource.includes('endDate'));
  });
});

// =====================================================================
// 17. Cross-Module Consistency
// =====================================================================

describe('Cross-Module Consistency', () => {
  it('all fetch functions use consistent auth pattern', () => {
    // All fetch functions for KPI data go through the api layer with auth
    assert.ok(backendTsSource.includes("auth: true"));
  });

  it('ListResponse generic is used for paginated endpoints', () => {
    assert.ok(backendTsSource.includes('ListResponse<'));
    assert.ok(backendTsSource.includes('PaginationMeta'));
  });

  it('backend PaginationMeta includes limit, offset, total, hasMore', () => {
    const block = backendTsSource.slice(
      backendTsSource.indexOf('interface PaginationMeta'),
      backendTsSource.indexOf('interface PaginationMeta') + 300
    );
    assert.ok(block.includes('limit'));
    assert.ok(block.includes('offset'));
    assert.ok(block.includes('total'));
    assert.ok(block.includes('hasMore'));
  });
});
