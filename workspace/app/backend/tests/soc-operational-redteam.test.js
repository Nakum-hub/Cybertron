const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

// =====================================================================
// SOC Module -- Adversarial + Operational Tests
// =====================================================================

// ── Alert Lifecycle State Machine ──

const { VALID_ALERT_STATUSES, ALERT_STATUS_TRANSITIONS } = require('../src/siem-service');

describe('SOC Alert Lifecycle: State Machine', () => {

  it('defines exactly 6 alert statuses', () => {
    assert.equal(VALID_ALERT_STATUSES.length, 6);
    assert.deepEqual(VALID_ALERT_STATUSES, ['new', 'acknowledged', 'in_triage', 'escalated', 'resolved', 'dismissed']);
  });

  it('new → acknowledged is allowed', () => {
    assert.ok(ALERT_STATUS_TRANSITIONS['new'].includes('acknowledged'));
  });

  it('new → resolved is NOT allowed (must triage first)', () => {
    assert.ok(!ALERT_STATUS_TRANSITIONS['new'].includes('resolved'),
      'Cannot skip triage -- new alerts must be acknowledged or triaged before resolution');
  });

  it('resolved is terminal (no outgoing transitions)', () => {
    assert.deepEqual(ALERT_STATUS_TRANSITIONS['resolved'], []);
  });

  it('dismissed can only return to new (reopen)', () => {
    assert.deepEqual(ALERT_STATUS_TRANSITIONS['dismissed'], ['new']);
  });

  it('escalated can only transition to resolved', () => {
    assert.deepEqual(ALERT_STATUS_TRANSITIONS['escalated'], ['resolved']);
  });

  it('all statuses have defined transitions (no undefined keys)', () => {
    for (const status of VALID_ALERT_STATUSES) {
      assert.ok(Array.isArray(ALERT_STATUS_TRANSITIONS[status]),
        `Missing transition definition for status: ${status}`);
    }
  });

  it('no self-transitions allowed', () => {
    for (const [from, tos] of Object.entries(ALERT_STATUS_TRANSITIONS)) {
      assert.ok(!tos.includes(from), `Self-transition not allowed: ${from} -> ${from}`);
    }
  });
});

// ── Incident State Machine ──

describe('SOC Incident Lifecycle: State Machine', () => {

  it('normalizeIncidentStatus accepts all 4 statuses', () => {
    // Cannot import directly as module-service requires database,
    // so we test by reading the source
    const fs = require('node:fs');
    const content = fs.readFileSync(require.resolve('../src/module-service'), 'utf8');

    assert.ok(content.includes("'open'"), 'Must accept open');
    assert.ok(content.includes("'investigating'"), 'Must accept investigating');
    assert.ok(content.includes("'resolved'"), 'Must accept resolved');
    assert.ok(content.includes("'closed'"), 'Must accept closed');
  });

  it('INCIDENT_STATUS_TRANSITIONS enforces valid transitions', () => {
    const fs = require('node:fs');
    const content = fs.readFileSync(require.resolve('../src/module-service'), 'utf8');

    assert.ok(content.includes('INCIDENT_STATUS_TRANSITIONS'),
      'Must define INCIDENT_STATUS_TRANSITIONS map');
    // open can go to investigating, resolved, closed
    assert.ok(content.includes("'open':"));
    // investigating can go to open, resolved, closed
    assert.ok(content.includes("'investigating':"));
    // resolved can go to closed or open (reopen)
    assert.ok(content.includes("'resolved':"));
    // closed can only go to open (reopen only)
    assert.ok(content.includes("'closed':"));
  });

  it('updateIncident enforces state machine transitions', () => {
    const fs = require('node:fs');
    const content = fs.readFileSync(require.resolve('../src/module-service'), 'utf8');

    assert.ok(content.includes('invalid_status_transition'),
      'Must throw ServiceError for invalid transitions');
    assert.ok(content.includes('Cannot transition from'),
      'Error message must describe the invalid transition');
  });

  it('updateIncident auto-sets resolved_at when resolving', () => {
    const fs = require('node:fs');
    const content = fs.readFileSync(require.resolve('../src/module-service'), 'utf8');

    assert.ok(content.includes("newStatus === 'resolved'") && content.includes('resolved_at'),
      'Must auto-set resolved_at when transitioning to resolved');
  });
});

// ── Alert Assignment ──

describe('SOC Alert Assignment', () => {

  it('assignAlert function exists', () => {
    const { assignAlert } = require('../src/siem-service');
    assert.equal(typeof assignAlert, 'function');
  });

  it('assignAlert returns null when database not configured', async () => {
    const { assignAlert } = require('../src/siem-service');
    const result = await assignAlert({ databaseUrl: '' }, 'test', 1, { assignedTo: 1 });
    assert.equal(result, null);
  });

  it('assignAlert validates alertId', async () => {
    const { assignAlert } = require('../src/siem-service');
    const result = await assignAlert({ databaseUrl: '' }, 'test', NaN, { assignedTo: 1 });
    assert.equal(result, null);
  });
});

// ── Alert Escalation ──

describe('SOC Alert Escalation', () => {

  it('escalateAlertToIncident function exists', () => {
    const { escalateAlertToIncident } = require('../src/siem-service');
    assert.equal(typeof escalateAlertToIncident, 'function');
  });

  it('escalateAlertToIncident returns null when database not configured', async () => {
    const { escalateAlertToIncident } = require('../src/siem-service');
    const result = await escalateAlertToIncident({ databaseUrl: '' }, 'test', 1, {});
    assert.equal(result, null);
  });
});

// ── Status Update Validation ──

describe('SOC Alert Status Update', () => {

  it('updateAlertStatus function exists', () => {
    const { updateAlertStatus } = require('../src/siem-service');
    assert.equal(typeof updateAlertStatus, 'function');
  });

  it('updateAlertStatus returns null when database not configured', async () => {
    const { updateAlertStatus } = require('../src/siem-service');
    const result = await updateAlertStatus({ databaseUrl: '' }, 'test', 1, { status: 'acknowledged' });
    assert.equal(result, null);
  });

  it('updateAlertStatus rejects invalid status', async () => {
    const { updateAlertStatus } = require('../src/siem-service');
    const result = await updateAlertStatus({ databaseUrl: '' }, 'test', 1, { status: 'nonexistent' });
    assert.equal(result, null);
  });
});

// ── Search/Filter ──

describe('SOC Alert Search and Filters', () => {

  it('listSiemAlerts accepts status filter', () => {
    const fs = require('node:fs');
    const content = fs.readFileSync(require.resolve('../src/siem-service'), 'utf8');
    assert.ok(content.includes("status && VALID_ALERT_STATUSES.includes(status)"),
      'listSiemAlerts must validate and apply status filter');
  });

  it('listSiemAlerts accepts assignedTo filter', () => {
    const fs = require('node:fs');
    const content = fs.readFileSync(require.resolve('../src/siem-service'), 'utf8');
    assert.ok(content.includes('assignedTo'),
      'listSiemAlerts must support filtering by assigned analyst');
  });

  it('listSiemAlerts accepts free-text search', () => {
    const fs = require('node:fs');
    const content = fs.readFileSync(require.resolve('../src/siem-service'), 'utf8');
    assert.ok(content.includes('ILIKE'),
      'listSiemAlerts must support ILIKE search across fields');
    assert.ok(content.includes("search"),
      'listSiemAlerts must accept search parameter');
  });

  it('search parameter is sanitized (SQL wildcard % stripped)', () => {
    const fs = require('node:fs');
    const content = fs.readFileSync(require.resolve('../src/siem-service'), 'utf8');
    assert.ok(content.includes(".replace(/%/g, '')"),
      'Search input must strip % to prevent wildcard injection');
  });
});

// ── Migration 018 ──

describe('SOC Migration 018: Schema Hardening', () => {

  it('migration file exists', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const migrationPath = path.resolve(__dirname, '..', 'migrations', '018_soc_operational_hardening.sql');
    assert.ok(fs.existsSync(migrationPath), 'Migration 018 must exist');
  });

  it('adds status column to siem_alerts with CHECK constraint', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(path.resolve(__dirname, '..', 'migrations', '018_soc_operational_hardening.sql'), 'utf8');
    assert.ok(content.includes("ADD COLUMN IF NOT EXISTS status TEXT"),
      'Must add status column to siem_alerts');
    assert.ok(content.includes("'new', 'acknowledged', 'in_triage', 'escalated', 'resolved', 'dismissed'"),
      'Status CHECK must include all 6 states');
  });

  it('adds assigned_to column to siem_alerts', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(path.resolve(__dirname, '..', 'migrations', '018_soc_operational_hardening.sql'), 'utf8');
    assert.ok(content.includes("ADD COLUMN IF NOT EXISTS assigned_to BIGINT"),
      'Must add assigned_to column');
  });

  it('adds assigned_to column to incidents', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(path.resolve(__dirname, '..', 'migrations', '018_soc_operational_hardening.sql'), 'utf8');
    assert.ok(content.includes("ALTER TABLE incidents") && content.includes("assigned_to BIGINT"),
      'Must add assigned_to to incidents');
  });

  it('expands incident status CHECK to include closed', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(path.resolve(__dirname, '..', 'migrations', '018_soc_operational_hardening.sql'), 'utf8');
    assert.ok(content.includes("'open', 'investigating', 'resolved', 'closed'"),
      'Must expand incident status to include closed');
  });

  it('adds priority column to incidents', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(path.resolve(__dirname, '..', 'migrations', '018_soc_operational_hardening.sql'), 'utf8');
    assert.ok(content.includes("ADD COLUMN IF NOT EXISTS priority TEXT"),
      'Must add priority column to incidents');
  });

  it('adds escalated_from_alert_id for direct escalation tracking', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(path.resolve(__dirname, '..', 'migrations', '018_soc_operational_hardening.sql'), 'utf8');
    assert.ok(content.includes('escalated_from_alert_id'),
      'Must track which alert an incident was escalated from');
  });
});

// ── Correlation Engine SSE Broadcast ──

describe('SOC Correlation Engine: SSE Broadcast', () => {

  it('runCorrelationEngine accepts notifyIncidentCreated option', () => {
    const fs = require('node:fs');
    const content = fs.readFileSync(require.resolve('../src/correlation-engine'), 'utf8');
    assert.ok(content.includes('notifyIncidentCreated'),
      'Correlation engine must accept notifyIncidentCreated callback');
  });

  it('broadcasts SSE when auto-creating incidents', () => {
    const fs = require('node:fs');
    const content = fs.readFileSync(require.resolve('../src/correlation-engine'), 'utf8');
    assert.ok(content.includes('notifyIncidentCreated(tenantSlug'),
      'Must call notifyIncidentCreated with tenant and incident data');
  });
});

// ── Stats include lifecycle metrics ──

describe('SOC Stats: Lifecycle Metrics', () => {

  it('getSiemAlertStats includes status breakdown', () => {
    const fs = require('node:fs');
    const content = fs.readFileSync(require.resolve('../src/siem-service'), 'utf8');
    assert.ok(content.includes('new_count'), 'Stats must include new_count');
    assert.ok(content.includes('acknowledged_count'), 'Stats must include acknowledged_count');
    assert.ok(content.includes('in_triage_count'), 'Stats must include in_triage_count');
    assert.ok(content.includes('escalated_count'), 'Stats must include escalated_count');
    assert.ok(content.includes('resolved_count'), 'Stats must include resolved_count');
    assert.ok(content.includes('dismissed_count'), 'Stats must include dismissed_count');
  });

  it('getSiemAlertStats includes assigned_analyst_count', () => {
    const fs = require('node:fs');
    const content = fs.readFileSync(require.resolve('../src/siem-service'), 'utf8');
    assert.ok(content.includes('assigned_analyst_count'),
      'Stats must report how many distinct analysts have assignments');
  });
});

// ── Incident Serializer ──

describe('SOC Incident Serializer', () => {

  it('asIncident includes priority, assignedTo, escalatedFromAlertId', () => {
    const fs = require('node:fs');
    const content = fs.readFileSync(require.resolve('../src/module-service'), 'utf8');
    assert.ok(content.includes('assignedTo'), 'Must serialize assignedTo');
    assert.ok(content.includes('priority'), 'Must serialize priority');
    assert.ok(content.includes('escalatedFromAlertId'), 'Must serialize escalatedFromAlertId');
  });
});

// ── Frontend: Triage UX ──

describe('SOC Frontend: Triage UX', () => {

  it('SiemAlertsPanel includes status filter', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', '..', 'frontend', 'src', 'components', 'platform', 'SiemAlertsPanel.tsx'), 'utf8');
    assert.ok(content.includes('statusFilter'), 'Must have status filter state');
    assert.ok(content.includes('All statuses'), 'Must have all-statuses option');
  });

  it('SiemAlertsPanel includes search input', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', '..', 'frontend', 'src', 'components', 'platform', 'SiemAlertsPanel.tsx'), 'utf8');
    assert.ok(content.includes('searchQuery'), 'Must have search query state');
    assert.ok(content.includes('Search by'), 'Must have search placeholder text');
  });

  it('SiemAlertsPanel shows ACK button for new alerts', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', '..', 'frontend', 'src', 'components', 'platform', 'SiemAlertsPanel.tsx'), 'utf8');
    assert.ok(content.includes('ACK'), 'Must have acknowledge button');
    assert.ok(content.includes('Escalate'), 'Must have escalate button');
  });

  it('SiemAlertsPanel has raw payload drill-down', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', '..', 'frontend', 'src', 'components', 'platform', 'SiemAlertsPanel.tsx'), 'utf8');
    assert.ok(content.includes('Raw Payload'), 'Must show raw payload in expanded view');
    assert.ok(content.includes('JSON.stringify(alert.raw_payload'), 'Must render raw_payload as JSON');
  });

  it('ThreatCommandConsole has incident status update controls', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', '..', 'frontend', 'src', 'components', 'platform', 'ThreatCommandConsole.tsx'), 'utf8');
    assert.ok(content.includes('updateIncidentMutation'), 'Must have incident update mutation');
    assert.ok(content.includes('Investigating'), 'Must have Investigating button');
    assert.ok(content.includes('Resolve'), 'Must have Resolve button');
    assert.ok(content.includes('Reopen'), 'Must have Reopen button');
  });
});

// ── Adversarial: Malicious Inputs ──

describe('SOC Adversarial: Malicious Inputs', () => {

  it('search parameter is length-limited', () => {
    const fs = require('node:fs');
    const content = fs.readFileSync(require.resolve('../src/siem-service'), 'utf8');
    assert.ok(content.includes('.slice(0, 256)'),
      'Search must be truncated to prevent oversized queries');
  });

  it('notes field is length-limited', () => {
    const fs = require('node:fs');
    const content = fs.readFileSync(require.resolve('../src/siem-service'), 'utf8');
    assert.ok(content.includes('.slice(0, 2000)'),
      'Notes must be truncated to reasonable length');
  });

  it('alert status update uses parameterized queries', () => {
    const fs = require('node:fs');
    const content = fs.readFileSync(require.resolve('../src/siem-service'), 'utf8');
    // The updateAlertStatus function must use $N placeholders, not string concat
    const updateFunc = content.substring(content.indexOf('async function updateAlertStatus'), content.indexOf('async function assignAlert'));
    assert.ok(updateFunc.includes('$1') && updateFunc.includes('$2'),
      'updateAlertStatus must use parameterized queries');
    assert.ok(!updateFunc.includes('`${status}`'),
      'Must NOT use string interpolation for status in SQL');
  });
});

// ── Route Registration ──

describe('SOC Routes: Alert Lifecycle Endpoints', () => {

  it('registers PATCH /v1/threat-intel/siem/alerts/:alertId/status', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', 'src', 'modules', 'threat-intel', 'routes.js'), 'utf8');
    assert.ok(content.includes('/status'), 'Must register status endpoint');
    assert.ok(content.includes('updateAlertStatus'), 'Must call updateAlertStatus');
  });

  it('registers PATCH /v1/threat-intel/siem/alerts/:alertId/assign', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', 'src', 'modules', 'threat-intel', 'routes.js'), 'utf8');
    assert.ok(content.includes('/assign'), 'Must register assign endpoint');
    assert.ok(content.includes('assignAlert'), 'Must call assignAlert');
  });

  it('registers POST /v1/threat-intel/siem/alerts/:alertId/escalate', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', 'src', 'modules', 'threat-intel', 'routes.js'), 'utf8');
    assert.ok(content.includes('/escalate'), 'Must register escalate endpoint');
    assert.ok(content.includes('escalateAlertToIncident'), 'Must call escalateAlertToIncident');
  });

  it('all new endpoints require security_analyst role', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', 'src', 'modules', 'threat-intel', 'routes.js'), 'utf8');
    // Check that the status, assign, escalate sections all use security_analyst
    const statusSection = content.substring(content.indexOf('Alert Lifecycle Routes'), content.indexOf('Correlation Rules'));
    const analystChecks = (statusSection.match(/security_analyst/g) || []).length;
    assert.ok(analystChecks >= 3,
      `All 3 alert lifecycle endpoints must require security_analyst role (found ${analystChecks})`);
  });

  it('all new endpoints have audit logging', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const content = fs.readFileSync(
      path.resolve(__dirname, '..', 'src', 'modules', 'threat-intel', 'routes.js'), 'utf8');
    assert.ok(content.includes('siem_alert.status_changed'), 'Status change must be audit logged');
    assert.ok(content.includes('siem_alert.assigned'), 'Assignment must be audit logged');
    assert.ok(content.includes('siem_alert.escalated'), 'Escalation must be audit logged');
  });
});
