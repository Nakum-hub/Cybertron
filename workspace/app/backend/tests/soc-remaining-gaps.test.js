const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

// =====================================================================
// SOC Remaining Gaps -- Adversarial + Operational Tests
// =====================================================================

// ── Bulk Alert Operations ──

const {
  bulkUpdateAlertStatus,
  getAlertSlaMetrics,
  generateTriageSuggestion,
  getAlertTriageSuggestion,
  getAttackMapData,
  updateAlertNotes,
  DEFAULT_SLA_THRESHOLDS,
} = require('../src/siem-service');
const { parseSiemLogJsonBuffer } = require('../src/siem-log-parser');

describe('SOC Bulk Alert Operations', () => {

  it('bulkUpdateAlertStatus function exists', () => {
    assert.equal(typeof bulkUpdateAlertStatus, 'function');
  });

  it('returns empty result when database not configured', async () => {
    const result = await bulkUpdateAlertStatus({ databaseUrl: '' }, 'test', { alertIds: [1, 2], status: 'acknowledged' });
    assert.deepEqual(result, { updated: 0, failed: 0, results: [] });
  });

  it('rejects empty alertIds', async () => {
    const result = await bulkUpdateAlertStatus({ databaseUrl: '' }, 'test', { alertIds: [], status: 'acknowledged' });
    assert.equal(result.updated, 0);
  });

  it('rejects invalid status', async () => {
    const result = await bulkUpdateAlertStatus({ databaseUrl: '' }, 'test', { alertIds: [1], status: 'fake_status' });
    assert.equal(result.updated, 0);
  });

  it('caps alertIds to 100 max', () => {
    const fs = require('node:fs');
    const content = fs.readFileSync(require.resolve('../src/siem-service'), 'utf8');
    assert.ok(content.includes('.slice(0, 100)'),
      'Bulk operations must cap alertIds array to 100');
  });
});

describe('SOC File Upload Analysis', () => {

  it('parseSiemLogJsonBuffer function exists', () => {
    assert.equal(typeof parseSiemLogJsonBuffer, 'function');
  });

  it('parses JSON array uploads into normalized SIEM records', () => {
    const result = parseSiemLogJsonBuffer(Buffer.from(JSON.stringify([
      {
        id: 'evt-1',
        title: 'Impossible travel',
        severity: 'high',
        category: 'authentication',
        sourceIp: '198.51.100.5',
        destIp: '10.0.0.7',
        hostname: 'vpn-gateway',
        timestamp: '2026-03-10T08:00:00.000Z',
      },
    ])));

    assert.equal(result.count, 1);
    assert.equal(result.records[0].ruleName, 'Impossible travel');
    assert.equal(result.records[0].severity, 'high');
    assert.equal(result.records[0].sourceIp, '198.51.100.5');
  });

  it('parses NDJSON uploads into normalized SIEM records', () => {
    const payload = [
      JSON.stringify({ alert_id: 'ndjson-1', rule_name: 'Port scan', severity: 'medium' }),
      JSON.stringify({ alert_id: 'ndjson-2', rule_name: 'Malware hit', severity: 'critical' }),
    ].join('\n');
    const result = parseSiemLogJsonBuffer(Buffer.from(payload), { defaultSource: 'uploaded-ndjson' });

    assert.equal(result.count, 2);
    assert.equal(result.records[0].source, 'uploaded-ndjson');
    assert.equal(result.records[1].severity, 'critical');
  });

  it('threat-intel routes register SIEM upload endpoint', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', 'src', 'modules', 'threat-intel', 'routes.js'),
      'utf8'
    );
    assert.ok(content.includes("'/v1/threat-intel/siem/upload'") || content.includes("path: '/v1/threat-intel/siem/upload'"));
    assert.ok(content.includes('parseSiemLogJsonBuffer'), 'SIEM upload route must parse uploaded files');
    assert.ok(content.includes('threat_intel.siem.uploaded'), 'SIEM upload route must audit uploads');
  });
});

// ── SLA Tracking ──

describe('SOC SLA Metrics', () => {

  it('getAlertSlaMetrics function exists', () => {
    assert.equal(typeof getAlertSlaMetrics, 'function');
  });

  it('returns null when database not configured', async () => {
    const result = await getAlertSlaMetrics({ databaseUrl: '' }, 'test');
    assert.equal(result, null);
  });

  it('DEFAULT_SLA_THRESHOLDS defines thresholds for all severities', () => {
    assert.ok(DEFAULT_SLA_THRESHOLDS.critical);
    assert.ok(DEFAULT_SLA_THRESHOLDS.high);
    assert.ok(DEFAULT_SLA_THRESHOLDS.medium);
    assert.ok(DEFAULT_SLA_THRESHOLDS.low);
    assert.ok(DEFAULT_SLA_THRESHOLDS.info);
    // Each severity must have acknowledgeMinutes and resolveMinutes
    for (const [sev, thresholds] of Object.entries(DEFAULT_SLA_THRESHOLDS)) {
      assert.ok(typeof thresholds.acknowledgeMinutes === 'number',
        `${sev} must have acknowledgeMinutes`);
      assert.ok(typeof thresholds.resolveMinutes === 'number',
        `${sev} must have resolveMinutes`);
      assert.ok(thresholds.resolveMinutes > thresholds.acknowledgeMinutes,
        `${sev} resolveMinutes must be greater than acknowledgeMinutes`);
    }
  });

  it('critical SLA thresholds are strictest', () => {
    assert.ok(DEFAULT_SLA_THRESHOLDS.critical.acknowledgeMinutes <= DEFAULT_SLA_THRESHOLDS.high.acknowledgeMinutes);
    assert.ok(DEFAULT_SLA_THRESHOLDS.high.acknowledgeMinutes <= DEFAULT_SLA_THRESHOLDS.medium.acknowledgeMinutes);
  });

  it('SLA query includes breach counts', () => {
    const fs = require('node:fs');
    const content = fs.readFileSync(require.resolve('../src/siem-service'), 'utf8');
    assert.ok(content.includes('critical_sla_breached'), 'Must calculate critical SLA breaches');
    assert.ok(content.includes('high_sla_breached'), 'Must calculate high SLA breaches');
    assert.ok(content.includes('medium_sla_breached'), 'Must calculate medium SLA breaches');
    assert.ok(content.includes('low_sla_breached'), 'Must calculate low SLA breaches');
    assert.ok(content.includes('total_sla_breached'), 'Must calculate total SLA breaches');
  });
});

// ── AI Triage Suggestions ──

describe('SOC AI Triage Suggestions', () => {

  it('generateTriageSuggestion function exists', () => {
    assert.equal(typeof generateTriageSuggestion, 'function');
  });

  it('returns null for null input', () => {
    assert.equal(generateTriageSuggestion(null), null);
  });

  it('generates suggestion for critical alert', () => {
    const result = generateTriageSuggestion({
      id: 1, severity: 'critical', rule_name: 'test', category: 'test',
      source_ip: '10.0.0.1', dest_ip: '10.0.0.2',
    });
    assert.ok(result);
    assert.equal(result.suggestedPriority, 'critical');
    assert.ok(result.suggestions.some(s => s.action === 'escalate_immediately'));
    assert.ok(result.disclaimer, 'Must include disclaimer');
    assert.equal(result.automated, true, 'Must be labeled as automated');
  });

  it('detects brute force pattern', () => {
    const result = generateTriageSuggestion({
      id: 2, severity: 'high', rule_name: 'Brute Force Login', category: 'authentication',
      source_ip: '192.168.1.100', dest_ip: '10.0.0.5',
    });
    assert.ok(result.suggestions.some(s => s.action === 'check_auth_logs'));
  });

  it('detects malware pattern', () => {
    const result = generateTriageSuggestion({
      id: 3, severity: 'high', rule_name: 'Malware Detected', category: 'malware',
      source_ip: null, dest_ip: null,
    });
    assert.ok(result.suggestions.some(s => s.action === 'isolate_host'));
  });

  it('detects exfiltration pattern', () => {
    const result = generateTriageSuggestion({
      id: 4, severity: 'high', rule_name: 'Data Exfiltration Alert', category: 'exfiltration',
      source_ip: '10.0.0.1', dest_ip: '198.51.100.1',
    });
    assert.ok(result.suggestions.some(s => s.action === 'escalate_immediately'));
  });

  it('provides default suggestion for generic alerts', () => {
    const result = generateTriageSuggestion({
      id: 5, severity: 'low', rule_name: 'Generic Alert', category: 'generic',
      source_ip: null, dest_ip: null,
    });
    assert.ok(result.suggestions.some(s => s.action === 'review_and_classify'));
  });

  it('always includes disclaimer in suggestions', () => {
    const result = generateTriageSuggestion({
      id: 6, severity: 'info', rule_name: 'test', category: 'test',
    });
    assert.ok(result.disclaimer.includes('rule-based'),
      'Disclaimer must clarify these are rule-based, not AI predictions');
  });

  it('getAlertTriageSuggestion returns null when database not configured', async () => {
    const result = await getAlertTriageSuggestion({ databaseUrl: '' }, 'test', 1);
    assert.equal(result, null);
  });

  it('getAlertTriageSuggestion validates alertId', async () => {
    const result = await getAlertTriageSuggestion({ databaseUrl: '' }, 'test', NaN);
    assert.equal(result, null);
  });
});

// ── Attack Map Data ──

describe('SOC Attack Map: Geo-IP Data', () => {

  it('getAttackMapData function exists', () => {
    assert.equal(typeof getAttackMapData, 'function');
  });

  it('returns null when database not configured', async () => {
    const result = await getAttackMapData({ databaseUrl: '' }, 'test');
    assert.equal(result, null);
  });

  it('queries geo-IP data from raw_payload JSONB', () => {
    const fs = require('node:fs');
    const content = fs.readFileSync(require.resolve('../src/siem-service'), 'utf8');
    assert.ok(content.includes("raw_payload->>'source_geo_lat'"), 'Must extract source latitude');
    assert.ok(content.includes("raw_payload->>'source_geo_lon'"), 'Must extract source longitude');
    assert.ok(content.includes("raw_payload->>'source_country'"), 'Must extract source country');
    assert.ok(content.includes("raw_payload->>'dest_geo_lat'"), 'Must extract dest latitude');
    assert.ok(content.includes("raw_payload->>'dest_geo_lon'"), 'Must extract dest longitude');
  });

  it('returns structured data with nodes, edges, countrySummary', () => {
    const fs = require('node:fs');
    const content = fs.readFileSync(require.resolve('../src/siem-service'), 'utf8');
    const funcContent = content.substring(content.indexOf('async function getAttackMapData'));
    assert.ok(funcContent.includes('nodes:'), 'Must return nodes array');
    assert.ok(funcContent.includes('edges:'), 'Must return edges array');
    assert.ok(funcContent.includes('countrySummary:'), 'Must return country summary');
    assert.ok(funcContent.includes('timeRange:'), 'Must return time range');
    assert.ok(funcContent.includes('generatedAt:'), 'Must return generation timestamp');
  });

  it('limits edges to 500 max', () => {
    const fs = require('node:fs');
    const content = fs.readFileSync(require.resolve('../src/siem-service'), 'utf8');
    assert.ok(content.includes('edges.slice(0, 500)'),
      'Must limit edges to prevent oversized responses');
  });
});

// ── Alert Notes Update ──

describe('SOC Alert Notes Update', () => {

  it('updateAlertNotes function exists', () => {
    assert.equal(typeof updateAlertNotes, 'function');
  });

  it('returns null when database not configured', async () => {
    const result = await updateAlertNotes({ databaseUrl: '' }, 'test', 1, { notes: 'test' });
    assert.equal(result, null);
  });

  it('validates alertId', async () => {
    const result = await updateAlertNotes({ databaseUrl: '' }, 'test', NaN, { notes: 'test' });
    assert.equal(result, null);
  });

  it('truncates notes to 2000 chars', () => {
    const fs = require('node:fs');
    const content = fs.readFileSync(require.resolve('../src/siem-service'), 'utf8');
    const funcContent = content.substring(content.indexOf('async function updateAlertNotes'));
    assert.ok(funcContent.includes('.slice(0, 2000)'),
      'Notes must be truncated to 2000 chars');
  });

  it('uses parameterized query', () => {
    const fs = require('node:fs');
    const content = fs.readFileSync(require.resolve('../src/siem-service'), 'utf8');
    const funcContent = content.substring(
      content.indexOf('async function updateAlertNotes'),
      content.indexOf('module.exports')
    );
    assert.ok(funcContent.includes('$1') && funcContent.includes('$2') && funcContent.includes('$3'),
      'Must use parameterized queries');
  });
});

// ── SOAR Playbook Auto-Trigger ──

describe('SOC SOAR Playbook Auto-Trigger', () => {

  it('correlation engine queries auto_trigger playbooks', () => {
    const fs = require('node:fs');
    const content = fs.readFileSync(require.resolve('../src/correlation-engine'), 'utf8');
    assert.ok(content.includes('auto_trigger = TRUE'),
      'Must query playbooks with auto_trigger enabled');
  });

  it('correlation engine checks severity_trigger', () => {
    const fs = require('node:fs');
    const content = fs.readFileSync(require.resolve('../src/correlation-engine'), 'utf8');
    assert.ok(content.includes('severity_trigger'),
      'Must check severity_trigger for matching');
  });

  it('correlation engine checks category_trigger', () => {
    const fs = require('node:fs');
    const content = fs.readFileSync(require.resolve('../src/correlation-engine'), 'utf8');
    assert.ok(content.includes('category_trigger'),
      'Must check category_trigger for matching');
  });

  it('auto-triggered playbooks create execution records', () => {
    const fs = require('node:fs');
    const content = fs.readFileSync(require.resolve('../src/correlation-engine'), 'utf8');
    assert.ok(content.includes("typeof executePlaybook === 'function'"),
      'Auto-triggered playbooks must use executePlaybook service function');
  });

  it('logs SOAR auto-trigger events', () => {
    const fs = require('node:fs');
    const content = fs.readFileSync(require.resolve('../src/correlation-engine'), 'utf8');
    assert.ok(content.includes('soar_playbook_auto_triggered'),
      'Must log when a playbook is auto-triggered');
  });
});

// ── Migration 019 ──

describe('SOC Migration 019: SOAR Auto-Trigger Schema', () => {

  it('migration file exists', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const migrationPath = path.resolve(__dirname, '..', 'migrations', '019_soc_remaining_gaps.sql');
    assert.ok(fs.existsSync(migrationPath), 'Migration 019 must exist');
  });

  it('adds auto_trigger column to playbooks', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(path.resolve(__dirname, '..', 'migrations', '019_soc_remaining_gaps.sql'), 'utf8');
    assert.ok(content.includes('auto_trigger BOOLEAN'),
      'Must add auto_trigger column to playbooks');
  });

  it('adds severity_trigger and category_trigger columns', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(path.resolve(__dirname, '..', 'migrations', '019_soc_remaining_gaps.sql'), 'utf8');
    assert.ok(content.includes('severity_trigger TEXT'),
      'Must add severity_trigger column');
    assert.ok(content.includes('category_trigger TEXT'),
      'Must add category_trigger column');
  });

  it('creates index for active auto-trigger playbooks', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(path.resolve(__dirname, '..', 'migrations', '019_soc_remaining_gaps.sql'), 'utf8');
    assert.ok(content.includes('playbooks_auto_trigger_idx'),
      'Must create index for auto-trigger queries');
  });
});

// ── Analyst List ──

describe('SOC Analyst List for Assignment', () => {

  it('listTenantAnalysts function exists', () => {
    const { listTenantAnalysts } = require('../src/module-service');
    assert.equal(typeof listTenantAnalysts, 'function');
  });

  it('returns empty data when database not configured', async () => {
    const { listTenantAnalysts } = require('../src/module-service');
    const result = await listTenantAnalysts({ databaseUrl: '' }, 'test');
    assert.deepEqual(result, { data: [] });
  });

  it('queries users with analyst+ roles', () => {
    const fs = require('node:fs');
    const content = fs.readFileSync(require.resolve('../src/module-service'), 'utf8');
    assert.ok(content.includes("'security_analyst', 'tenant_admin', 'super_admin'"),
      'Must query users with security_analyst, tenant_admin, or super_admin roles');
  });
});

// ── Route Registration ──

describe('SOC Routes: New Endpoints', () => {

  it('registers POST /v1/threat-intel/siem/alerts/bulk-status', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', 'src', 'modules', 'threat-intel', 'routes.js'), 'utf8');
    assert.ok(content.includes("'/v1/threat-intel/siem/alerts/bulk-status'"),
      'Must register bulk-status endpoint');
    assert.ok(content.includes('bulkUpdateAlertStatus'),
      'Must call bulkUpdateAlertStatus');
  });

  it('registers GET /v1/threat-intel/siem/alerts/sla-metrics', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', 'src', 'modules', 'threat-intel', 'routes.js'), 'utf8');
    assert.ok(content.includes("'/v1/threat-intel/siem/alerts/sla-metrics'"),
      'Must register sla-metrics endpoint');
    assert.ok(content.includes('getAlertSlaMetrics'),
      'Must call getAlertSlaMetrics');
  });

  it('registers GET /v1/threat-intel/siem/attack-map', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', 'src', 'modules', 'threat-intel', 'routes.js'), 'utf8');
    assert.ok(content.includes("'/v1/threat-intel/siem/attack-map'"),
      'Must register attack-map endpoint');
    assert.ok(content.includes('getAttackMapData'),
      'Must call getAttackMapData');
  });

  it('registers GET /v1/threat-intel/analysts', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', 'src', 'modules', 'threat-intel', 'routes.js'), 'utf8');
    assert.ok(content.includes("'/v1/threat-intel/analysts'"),
      'Must register analysts endpoint');
    assert.ok(content.includes('listTenantAnalysts'),
      'Must call listTenantAnalysts');
  });

  it('registers triage-suggestion endpoint', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', 'src', 'modules', 'threat-intel', 'routes.js'), 'utf8');
    assert.ok(content.includes('triage-suggestion'),
      'Must register triage-suggestion endpoint');
    assert.ok(content.includes('getAlertTriageSuggestion'),
      'Must call getAlertTriageSuggestion');
  });

  it('registers notes endpoint', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', 'src', 'modules', 'threat-intel', 'routes.js'), 'utf8');
    assert.ok(content.includes('/notes'),
      'Must register notes endpoint');
    assert.ok(content.includes('updateAlertNotes'),
      'Must call updateAlertNotes');
  });

  it('bulk-status requires security_analyst role', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', 'src', 'modules', 'threat-intel', 'routes.js'), 'utf8');
    // Find the handler, not the route declaration -- use second occurrence
    const firstIdx = content.indexOf("'/v1/threat-intel/siem/alerts/bulk-status'");
    const handlerIdx = content.indexOf("'/v1/threat-intel/siem/alerts/bulk-status'", firstIdx + 1);
    const bulkSection = content.substring(handlerIdx, handlerIdx + 600);
    assert.ok(bulkSection.includes('security_analyst'),
      'Bulk operations must require security_analyst role');
  });

  it('bulk-status is audit logged', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', 'src', 'modules', 'threat-intel', 'routes.js'), 'utf8');
    assert.ok(content.includes('siem_alert.bulk_status_changed'),
      'Bulk status change must be audit logged');
  });

  it('notes endpoint is audit logged', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', 'src', 'modules', 'threat-intel', 'routes.js'), 'utf8');
    assert.ok(content.includes('siem_alert.notes_updated'),
      'Notes update must be audit logged');
  });
});

// ── Frontend: New SOC UI Features ──

describe('SOC Frontend: Remaining Gap UX', () => {

  it('SiemAlertsPanel has sort controls', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', '..', 'frontend', 'src', 'components', 'platform', 'SiemAlertsPanel.tsx'), 'utf8');
    assert.ok(content.includes('sortField'), 'Must have sort field state');
    assert.ok(content.includes('sortDir'), 'Must have sort direction state');
    assert.ok(content.includes('SortButton'), 'Must have sort button component');
    assert.ok(content.includes('event_time'), 'Must support sorting by event time');
    assert.ok(content.includes("'severity'"), 'Must support sorting by severity');
  });

  it('SiemAlertsPanel has bulk operation controls', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', '..', 'frontend', 'src', 'components', 'platform', 'SiemAlertsPanel.tsx'), 'utf8');
    assert.ok(content.includes('bulkMode'), 'Must have bulk mode state');
    assert.ok(content.includes('selectedAlertIds'), 'Must track selected alert IDs');
    assert.ok(content.includes('Bulk ACK'), 'Must have Bulk ACK button');
    assert.ok(content.includes('Bulk Dismiss'), 'Must have Bulk Dismiss button');
    assert.ok(content.includes('selectAll'), 'Must have Select All function');
  });

  it('SiemAlertsPanel has assignment dropdown', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', '..', 'frontend', 'src', 'components', 'platform', 'SiemAlertsPanel.tsx'), 'utf8');
    assert.ok(content.includes('analystsQuery'), 'Must fetch analysts for dropdown');
    assert.ok(content.includes('assignMutation'), 'Must have assign mutation');
    assert.ok(content.includes('Unassigned'), 'Must have Unassigned option');
    assert.ok(content.includes('assignAlertToUser'), 'Must use assignAlertToUser API');
  });

  it('SiemAlertsPanel has SLA metrics display', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', '..', 'frontend', 'src', 'components', 'platform', 'SiemAlertsPanel.tsx'), 'utf8');
    assert.ok(content.includes('SLA Metrics'), 'Must have SLA metrics toggle');
    assert.ok(content.includes('slaQuery'), 'Must fetch SLA data');
    assert.ok(content.includes('SLA Breached'), 'Must show SLA breach count');
    assert.ok(content.includes('Avg ACK Time'), 'Must show average acknowledge time');
  });

  it('SiemAlertsPanel has notes editing', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', '..', 'frontend', 'src', 'components', 'platform', 'SiemAlertsPanel.tsx'), 'utf8');
    assert.ok(content.includes('editingNotesId'), 'Must have notes editing state');
    assert.ok(content.includes('notesMutation'), 'Must have notes mutation');
    assert.ok(content.includes('Save Notes'), 'Must have Save Notes button');
    assert.ok(content.includes('updateAlertNotes'), 'Must use updateAlertNotes API');
  });

  it('SiemAlertsPanel has triage suggestion', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', '..', 'frontend', 'src', 'components', 'platform', 'SiemAlertsPanel.tsx'), 'utf8');
    assert.ok(content.includes('triageMutation'), 'Must have triage suggestion mutation');
    assert.ok(content.includes('Triage Suggestion'), 'Must have Triage Suggestion button');
    assert.ok(content.includes('triageSuggestion'), 'Must display triage suggestions');
    assert.ok(content.includes('disclaimer'), 'Must show AI/rule disclaimer');
  });

  it('SiemAlertsPanel has SOC file upload workflow', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', '..', 'frontend', 'src', 'components', 'platform', 'SiemAlertsPanel.tsx'), 'utf8');
    assert.ok(content.includes('Upload SOC Logs'), 'Must expose SOC upload action');
    assert.ok(content.includes('uploadMutation'), 'Must have upload mutation');
    assert.ok(content.includes('uploadSiemLogs'), 'Must call uploadSiemLogs API');
    assert.ok(content.includes('Run correlation after upload'), 'Must support post-upload correlation');
  });

  it('AttackMapPanel component exists', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    assert.ok(
      fs.existsSync(path.resolve(__dirname, '..', '..', 'frontend', 'src', 'components', 'platform', 'AttackMapPanel.tsx')),
      'AttackMapPanel.tsx must exist'
    );
  });

  it('AttackMapPanel renders SVG-based map', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', '..', 'frontend', 'src', 'components', 'platform', 'AttackMapPanel.tsx'), 'utf8');
    assert.ok(content.includes('viewBox'), 'Must render SVG viewBox');
    assert.ok(content.includes('project'), 'Must have coordinate projection function');
    assert.ok(content.includes('fetchAttackMapData'), 'Must fetch attack map data from API');
    assert.ok(content.includes('countrySummary'), 'Must display country summary');
    assert.ok(content.includes('Source IPs'), 'Must show source IPs in legend');
    assert.ok(content.includes('Destination IPs'), 'Must show destination IPs in legend');
  });

  it('ThreatCommandConsole includes attackmap tab', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', '..', 'frontend', 'src', 'components', 'platform', 'ThreatCommandConsole.tsx'), 'utf8');
    assert.ok(content.includes("'attackmap'"), 'Must have attackmap tab key');
    assert.ok(content.includes('AttackMapPanel'), 'Must render AttackMapPanel');
    assert.ok(content.includes('Attack Map'), 'Must have Attack Map label');
  });

  it('AttackMapPanel handles empty state honestly', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', '..', 'frontend', 'src', 'components', 'platform', 'AttackMapPanel.tsx'), 'utf8');
    assert.ok(content.includes('No geo-tagged alert data available'),
      'Must show honest empty state when no geo data exists');
    assert.ok(content.includes('source_geo_lat'),
      'Must explain what data is needed');
  });
});

// ── Backend Types ──

describe('SOC Backend Types: New API Functions', () => {

  it('backend.ts exports fetchTenantAnalysts', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', '..', 'frontend', 'src', 'lib', 'backend.ts'), 'utf8');
    assert.ok(content.includes('fetchTenantAnalysts'), 'Must export fetchTenantAnalysts');
    assert.ok(content.includes('AnalystRecord'), 'Must define AnalystRecord interface');
  });

  it('backend.ts exports bulkUpdateAlertStatus', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', '..', 'frontend', 'src', 'lib', 'backend.ts'), 'utf8');
    assert.ok(content.includes('bulkUpdateAlertStatus'), 'Must export bulkUpdateAlertStatus');
  });

  it('backend.ts exports fetchAlertSlaMetrics', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', '..', 'frontend', 'src', 'lib', 'backend.ts'), 'utf8');
    assert.ok(content.includes('fetchAlertSlaMetrics'), 'Must export fetchAlertSlaMetrics');
    assert.ok(content.includes('SlaMetrics'), 'Must define SlaMetrics interface');
  });

  it('backend.ts exports fetchAlertTriageSuggestion', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', '..', 'frontend', 'src', 'lib', 'backend.ts'), 'utf8');
    assert.ok(content.includes('fetchAlertTriageSuggestion'), 'Must export fetchAlertTriageSuggestion');
    assert.ok(content.includes('TriageSuggestion'), 'Must define TriageSuggestion interface');
  });

  it('backend.ts exports updateAlertNotes', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', '..', 'frontend', 'src', 'lib', 'backend.ts'), 'utf8');
    assert.ok(content.includes('export async function updateAlertNotes'), 'Must export updateAlertNotes');
  });

  it('backend.ts exports fetchAttackMapData', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', '..', 'frontend', 'src', 'lib', 'backend.ts'), 'utf8');
    assert.ok(content.includes('fetchAttackMapData'), 'Must export fetchAttackMapData');
    assert.ok(content.includes('AttackMapData'), 'Must define AttackMapData interface');
  });

  it('backend.ts exports uploadSiemLogs', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', '..', 'frontend', 'src', 'lib', 'backend.ts'), 'utf8');
    assert.ok(content.includes('export interface SiemFileUploadResult'), 'Must define SiemFileUploadResult interface');
    assert.ok(content.includes('export function uploadSiemLogs'), 'Must export uploadSiemLogs');
    assert.ok(content.includes("'/v1/threat-intel/siem/upload'"), 'Must target the SIEM upload endpoint');
  });
});
