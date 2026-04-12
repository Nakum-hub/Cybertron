const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

// =====================================================================
// Incident Management Hardening Tests — Phase 3
// Covers: state machine, severity/priority normalization, audit trail,
//         timeline auto-generation, route wiring, frontend types,
//         alert-to-incident escalation, tenant isolation, ownership
// =====================================================================

const moduleServiceSource = fs.readFileSync(
  path.join(__dirname, '..', 'src', 'module-service.js'),
  'utf-8'
);

const siemServiceSource = fs.readFileSync(
  path.join(__dirname, '..', 'src', 'siem-service.js'),
  'utf-8'
);

const routeSource = fs.readFileSync(
  path.join(__dirname, '..', 'src', 'routes', 'crud.js'),
  'utf-8'
);

const notificationSource = fs.readFileSync(
  path.join(__dirname, '..', 'src', 'notification-service.js'),
  'utf-8'
);

const frontendTypesSource = fs.readFileSync(
  path.join(__dirname, '..', '..', 'frontend', 'src', 'lib', 'backend.ts'),
  'utf-8'
);

const dashboardSource = fs.readFileSync(
  path.join(__dirname, '..', '..', 'frontend', 'src', 'components', 'platform', 'ThreatCommandConsole.tsx'),
  'utf-8'
);

const threatDataSource = fs.readFileSync(
  path.join(__dirname, '..', 'src', 'threat-data.js'),
  'utf-8'
);

// =====================================================================
// Incident State Machine — INCIDENT_STATUS_TRANSITIONS
// =====================================================================

describe('Incident State Machine', () => {
  it('state machine is defined in module-service.js', () => {
    assert.ok(moduleServiceSource.includes('INCIDENT_STATUS_TRANSITIONS'));
  });

  it('open can transition to investigating, resolved, closed', () => {
    const idx = moduleServiceSource.indexOf("'open':");
    // Find the line containing 'open': and verify transitions
    const line = moduleServiceSource.slice(idx, moduleServiceSource.indexOf('\n', idx));
    assert.ok(line.includes('investigating'));
    assert.ok(line.includes('resolved'));
    assert.ok(line.includes('closed'));
  });

  it('investigating can transition to open, resolved, closed', () => {
    const idx = moduleServiceSource.indexOf("'investigating':");
    const line = moduleServiceSource.slice(idx, moduleServiceSource.indexOf('\n', idx));
    assert.ok(line.includes('open'));
    assert.ok(line.includes('resolved'));
    assert.ok(line.includes('closed'));
  });

  it('resolved can transition to closed and open (reopen)', () => {
    const idx = moduleServiceSource.indexOf("'resolved':");
    const line = moduleServiceSource.slice(idx, moduleServiceSource.indexOf('\n', idx));
    assert.ok(line.includes('closed'));
    assert.ok(line.includes('open'));
  });

  it('closed can only transition to open (reopen)', () => {
    // Find the specific 'closed': line (not the one inside another transition)
    const lines = moduleServiceSource.split('\n');
    const closedLine = lines.find(l => l.trim().startsWith("'closed'") && l.includes(':'));
    assert.ok(closedLine, 'Should have a closed transition line');
    assert.ok(closedLine.includes('open'));
    // Should NOT allow direct transition to investigating or resolved
    assert.ok(!closedLine.includes('investigating'));
  });

  it('state machine enforces transitions by querying current status', () => {
    assert.ok(moduleServiceSource.includes("SELECT status FROM incidents WHERE id = $1 AND tenant_slug = $2"));
    assert.ok(moduleServiceSource.includes('invalid_status_transition'));
  });

  it('normalizeIncidentStatus accepts open/investigating/resolved/closed', () => {
    assert.ok(moduleServiceSource.includes("if (normalized === 'open') return 'open'"));
    assert.ok(moduleServiceSource.includes("if (normalized === 'investigating') return 'investigating'"));
    assert.ok(moduleServiceSource.includes("if (normalized === 'resolved') return 'resolved'"));
    assert.ok(moduleServiceSource.includes("if (normalized === 'closed') return 'closed'"));
  });

  it('normalizeIncidentStatus rejects invalid values with ServiceError', () => {
    assert.ok(moduleServiceSource.includes('invalid_status'));
    assert.ok(moduleServiceSource.includes("Status must be one of"));
  });
});

// =====================================================================
// Severity and Priority Normalization
// =====================================================================

describe('Severity and Priority Normalization', () => {
  it('normalizeSeverity accepts only critical/high/medium/low', () => {
    assert.ok(moduleServiceSource.includes("if (normalized === 'critical') return 'critical'"));
    assert.ok(moduleServiceSource.includes("if (normalized === 'high') return 'high'"));
    assert.ok(moduleServiceSource.includes("if (normalized === 'medium') return 'medium'"));
    assert.ok(moduleServiceSource.includes("if (normalized === 'low') return 'low'"));
  });

  it('normalizeSeverity throws on invalid value', () => {
    assert.ok(moduleServiceSource.includes('invalid_severity'));
    assert.ok(moduleServiceSource.includes("Severity must be one of critical/high/medium/low"));
  });

  it('normalizePriority defaults to medium for invalid values', () => {
    const fnStart = moduleServiceSource.indexOf('function normalizePriority');
    const fnEnd = moduleServiceSource.indexOf('}', fnStart + 50);
    const fnBody = moduleServiceSource.slice(fnStart, fnEnd + 1);
    assert.ok(fnBody.includes("return 'medium'"));
  });
});

// =====================================================================
// I4 — Audit Trail: previousStatus
// =====================================================================

describe('I4 — Audit Trail previousStatus', () => {
  it('updateIncident tracks previousStatus variable', () => {
    assert.ok(moduleServiceSource.includes('let previousStatus = null'));
    assert.ok(moduleServiceSource.includes('previousStatus = currentStatus'));
  });

  it('audit log includes previousStatus in payload', () => {
    // Find the incident.updated audit log call
    const auditIdx = moduleServiceSource.indexOf("action: 'incident.updated'");
    assert.ok(auditIdx > 0);
    const auditBlock = moduleServiceSource.slice(auditIdx, auditIdx + 300);
    assert.ok(auditBlock.includes('previousStatus'), 'Audit log should contain previousStatus');
  });
});

// =====================================================================
// I5 — Auto Timeline Entry on Status Change
// =====================================================================

describe('I5 — Auto Timeline Entry on Status Change', () => {
  it('auto-generates timeline entry with event_type status_change', () => {
    assert.ok(moduleServiceSource.includes("'status_change'"));
  });

  it('auto-message describes the transition', () => {
    assert.ok(moduleServiceSource.includes('Status changed from'));
  });

  it('uses explicit timelineMessage when provided with status change', () => {
    const idx = moduleServiceSource.indexOf('Status changed from');
    assert.ok(idx > 0);
    // Preceding the auto message should be a check for payload.timelineMessage
    const block = moduleServiceSource.slice(idx - 200, idx);
    assert.ok(block.includes('payload.timelineMessage'));
  });

  it('falls back to updated event_type for non-status changes', () => {
    // After status_change block, there's an else if for general timelineMessage
    const statusChangeIdx = moduleServiceSource.indexOf("'status_change'");
    const afterBlock = moduleServiceSource.slice(statusChangeIdx, statusChangeIdx + 500);
    assert.ok(afterBlock.includes("'updated'"));
  });
});

// =====================================================================
// I2 — Route Body Validation for priority/assignedTo
// =====================================================================

describe('I2 — PATCH /v1/incidents/:id body validation', () => {
  it('optional fields include priority', () => {
    // The validateBodyShape for incident PATCH should include priority
    assert.ok(
      routeSource.includes("'priority'") && routeSource.includes("'assignedTo'"),
      'Body validation should include priority and assignedTo in optional fields'
    );
  });

  it('optional fields include assignedTo', () => {
    assert.ok(routeSource.includes("'assignedTo'"), 'Body validation should include assignedTo');
  });

  it('route requires security_analyst role', () => {
    // The incident PATCH handler uses requireRole with security_analyst
    assert.ok(routeSource.includes("requireRole(session, 'security_analyst'"));
  });
});

// =====================================================================
// Incident Assignment
// =====================================================================

describe('Incident Assignment', () => {
  it('updateIncident handles assignedTo field', () => {
    assert.ok(moduleServiceSource.includes("payload.assignedTo !== undefined"));
    assert.ok(moduleServiceSource.includes("pushUpdate('assigned_to'"));
  });

  it('auto-sets assigned_at timestamp when assigning', () => {
    assert.ok(moduleServiceSource.includes("pushUpdate('assigned_at'"));
  });

  it('clears assigned_to and assigned_at when assigning null', () => {
    const idx = moduleServiceSource.indexOf("payload.assignedTo !== undefined");
    const block = moduleServiceSource.slice(idx, idx + 200);
    assert.ok(block.includes('null'));
  });

  it('asIncident maps assigned_to and assigned_at', () => {
    assert.ok(moduleServiceSource.includes('assignedTo: row.assigned_to'));
    assert.ok(moduleServiceSource.includes('assignedAt: row.assigned_at'));
  });
});

// =====================================================================
// Incident Creation
// =====================================================================

describe('Incident Creation', () => {
  it('auto-creates initial timeline entry on creation', () => {
    // In createIncident, after INSERT, there's a timeline insert with 'created'
    const createIdx = moduleServiceSource.indexOf('async function createIncident');
    const createBlock = moduleServiceSource.slice(createIdx, createIdx + 2500);
    assert.ok(createBlock.includes("'created'"), 'createIncident should insert timeline entry with event_type created');
  });

  it('creates audit log with incident.created action', () => {
    assert.ok(moduleServiceSource.includes("action: 'incident.created'"));
  });

  it('validates incident title is required', () => {
    assert.ok(moduleServiceSource.includes('invalid_title'));
    assert.ok(moduleServiceSource.includes('Incident title is required'));
  });

  it('title is capped at 400 characters', () => {
    const createIdx = moduleServiceSource.indexOf('async function createIncident');
    const block = moduleServiceSource.slice(createIdx, createIdx + 500);
    assert.ok(block.includes('safeText(payload.title, 400)'));
  });

  it('auto-set resolved_at on status=resolved during update', () => {
    assert.ok(moduleServiceSource.includes("if (newStatus === 'resolved' && payload.resolvedAt === undefined)"));
  });
});

// =====================================================================
// IOC Linking
// =====================================================================

describe('IOC Linking', () => {
  it('linkIocToIncident creates audit log', () => {
    assert.ok(moduleServiceSource.includes("action: 'incident.ioc_linked'"));
  });

  it('uses ON CONFLICT DO NOTHING for idempotent linking', () => {
    assert.ok(moduleServiceSource.includes('ON CONFLICT (tenant_slug, incident_id, ioc_id) DO NOTHING'));
  });

  it('records iocId in audit payload', () => {
    const idx = moduleServiceSource.indexOf("'incident.ioc_linked'");
    const block = moduleServiceSource.slice(idx, idx + 400);
    assert.ok(block.includes('iocId'));
  });
});

// =====================================================================
// Alert-to-Incident Escalation
// =====================================================================

describe('Alert-to-Incident Escalation', () => {
  it('escalateAlertToIncident exists in siem-service', () => {
    assert.ok(siemServiceSource.includes('async function escalateAlertToIncident'));
  });

  it('creates incident with escalated_from_alert_id', () => {
    assert.ok(siemServiceSource.includes('escalated_from_alert_id'));
  });

  it('marks alert as escalated status and correlates', () => {
    const fnIdx = siemServiceSource.indexOf('async function escalateAlertToIncident');
    const block = siemServiceSource.slice(fnIdx, fnIdx + 2000);
    assert.ok(block.includes("status = 'escalated'"));
    assert.ok(block.includes('correlated = TRUE'));
    assert.ok(block.includes('incident_id = $3'));
  });

  it('creates timeline entry for escalation', () => {
    const fnIdx = siemServiceSource.indexOf('async function escalateAlertToIncident');
    const block = siemServiceSource.slice(fnIdx, fnIdx + 3000);
    assert.ok(block.includes("'escalated'"));
    assert.ok(block.includes('Escalated from SIEM alert'));
  });

  it('stores raw_event with escalation context', () => {
    const fnIdx = siemServiceSource.indexOf('async function escalateAlertToIncident');
    const block = siemServiceSource.slice(fnIdx, fnIdx + 2000);
    assert.ok(block.includes('escalatedFromAlert'));
    assert.ok(block.includes('alertRuleName'));
    assert.ok(block.includes('sourceIp'));
  });

  it('audits escalation event', () => {
    assert.ok(siemServiceSource.includes("'siem_alert.escalated'"));
  });
});

// =====================================================================
// SSE Notifications
// =====================================================================

describe('SSE Notifications', () => {
  it('notifyIncidentCreated broadcasts incident.created', () => {
    assert.ok(notificationSource.includes("'incident.created'"));
    assert.ok(notificationSource.includes('notifyIncidentCreated'));
  });

  it('notifyIncidentUpdated broadcasts incident.updated', () => {
    assert.ok(notificationSource.includes("'incident.updated'"));
    assert.ok(notificationSource.includes('notifyIncidentUpdated'));
  });

  it('route calls notifyIncidentCreated after creation', () => {
    assert.ok(routeSource.includes('notifyIncidentCreated(tenant, incident)'));
  });

  it('route calls notifyIncidentUpdated after update', () => {
    assert.ok(routeSource.includes('notifyIncidentUpdated(tenant, incident)'));
  });

  it('broadcast payload includes severity and status', () => {
    const createdIdx = notificationSource.indexOf('notifyIncidentCreated');
    const createdBlock = notificationSource.slice(createdIdx, createdIdx + 200);
    assert.ok(createdBlock.includes('severity'));

    const updatedIdx = notificationSource.indexOf('notifyIncidentUpdated');
    const updatedBlock = notificationSource.slice(updatedIdx, updatedIdx + 200);
    assert.ok(updatedBlock.includes('status'));
    assert.ok(updatedBlock.includes('severity'));
  });
});

// =====================================================================
// Threat Data — Truthfulness
// =====================================================================

describe('Threat Data — Truthfulness', () => {
  it('MTTR from connectors returns null, not fabricated', () => {
    assert.ok(threatDataSource.includes('mttrMinutes: null'));
    assert.ok(threatDataSource.includes('MTTR cannot be computed from connector data'));
  });

  it('connector data quality note explains limitation', () => {
    assert.ok(threatDataSource.includes('mttrAvailable: false'));
    assert.ok(threatDataSource.includes('MTTR requires database persistence'));
  });

  it('normalizeIncidentSeverity does not auto-inflate unknown to medium', () => {
    assert.ok(threatDataSource.includes("return 'unknown'"));
    assert.ok(threatDataSource.includes('do not auto-inflate'));
  });
});

// =====================================================================
// I1 — Frontend IncidentStatus includes closed
// =====================================================================

describe('I1 — Frontend IncidentStatus', () => {
  it('IncidentStatus type includes open', () => {
    const line = frontendTypesSource.split('\n').find(l => l.includes('IncidentStatus') && l.includes('='));
    assert.ok(line);
    assert.ok(line.includes("'open'"));
  });

  it('IncidentStatus type includes investigating', () => {
    const line = frontendTypesSource.split('\n').find(l => l.includes('IncidentStatus') && l.includes('='));
    assert.ok(line.includes("'investigating'"));
  });

  it('IncidentStatus type includes resolved', () => {
    const line = frontendTypesSource.split('\n').find(l => l.includes('IncidentStatus') && l.includes('='));
    assert.ok(line.includes("'resolved'"));
  });

  it('IncidentStatus type includes closed', () => {
    const line = frontendTypesSource.split('\n').find(l => l.includes('IncidentStatus') && l.includes('='));
    assert.ok(line.includes("'closed'"), 'IncidentStatus should include closed');
  });
});

// =====================================================================
// I3 — Frontend IncidentRecord fields
// =====================================================================

describe('I3 — Frontend IncidentRecord fields', () => {
  const recordStart = frontendTypesSource.indexOf('export interface IncidentRecord');
  const recordEnd = frontendTypesSource.indexOf('}', recordStart);
  const recordBlock = frontendTypesSource.slice(recordStart, recordEnd + 1);

  it('IncidentRecord includes priority', () => {
    assert.ok(recordBlock.includes('priority'), 'IncidentRecord should have priority field');
  });

  it('IncidentRecord includes assignedTo', () => {
    assert.ok(recordBlock.includes('assignedTo'), 'IncidentRecord should have assignedTo field');
  });

  it('IncidentRecord includes assignedAt', () => {
    assert.ok(recordBlock.includes('assignedAt'), 'IncidentRecord should have assignedAt field');
  });

  it('IncidentRecord includes escalatedFromAlertId', () => {
    assert.ok(recordBlock.includes('escalatedFromAlertId'), 'IncidentRecord should have escalatedFromAlertId field');
  });

  it('UpdateIncidentPayload includes priority', () => {
    const idx = frontendTypesSource.indexOf('UpdateIncidentPayload');
    const block = frontendTypesSource.slice(idx, idx + 200);
    assert.ok(block.includes('priority'));
  });

  it('UpdateIncidentPayload includes assignedTo', () => {
    const idx = frontendTypesSource.indexOf('UpdateIncidentPayload');
    const block = frontendTypesSource.slice(idx, idx + 200);
    assert.ok(block.includes('assignedTo'));
  });
});

// =====================================================================
// I6 — Dashboard severity/status breakdown
// =====================================================================

describe('I6 — Dashboard severity/status breakdown', () => {
  it('ThreatCommandConsole shows severity distribution', () => {
    assert.ok(dashboardSource.includes('incidentSeverityCounts.critical'));
    assert.ok(dashboardSource.includes('incidentSeverityCounts.high'));
    assert.ok(dashboardSource.includes('incidentSeverityCounts.medium'));
    assert.ok(dashboardSource.includes('incidentSeverityCounts.low'));
  });

  it('ThreatCommandConsole shows status distribution', () => {
    assert.ok(dashboardSource.includes('incidentStatusCounts.open'));
    assert.ok(dashboardSource.includes('incidentStatusCounts.investigating'));
    assert.ok(dashboardSource.includes('incidentStatusCounts.resolved'));
    assert.ok(dashboardSource.includes('incidentStatusCounts.closed'));
  });

  it('INCIDENT_STATUSES array includes closed', () => {
    assert.ok(dashboardSource.includes("'closed'"));
  });

  it('shows priority in incident list cards', () => {
    assert.ok(dashboardSource.includes('incident.priority'));
  });

  it('shows assignment info in incident list cards', () => {
    assert.ok(dashboardSource.includes('incident.assignedTo'));
  });
});

// =====================================================================
// Alert Module — State Machine
// =====================================================================

describe('Alert State Machine (SIEM)', () => {
  it('ALERT_STATUS_TRANSITIONS is defined', () => {
    assert.ok(siemServiceSource.includes('ALERT_STATUS_TRANSITIONS'));
  });

  it('resolved is terminal (no transitions)', () => {
    const lines = siemServiceSource.split('\n');
    const resolvedLine = lines.find(l => l.trim().startsWith("'resolved'") && l.includes(':'));
    assert.ok(resolvedLine);
    assert.ok(resolvedLine.includes('[]'), 'Resolved alerts should have no outgoing transitions');
  });

  it('alert status validation uses ALERT_STATUS_TRANSITIONS', () => {
    const fnIdx = siemServiceSource.indexOf('async function updateAlertStatus');
    const block = siemServiceSource.slice(fnIdx, fnIdx + 1000);
    assert.ok(block.includes('ALERT_STATUS_TRANSITIONS'));
    assert.ok(block.includes('invalid_status_transition'));
  });

  it('SLA thresholds are defined for all severities', () => {
    assert.ok(siemServiceSource.includes('DEFAULT_SLA_THRESHOLDS'));
    assert.ok(siemServiceSource.includes('critical'));
    assert.ok(siemServiceSource.includes('acknowledgeMinutes'));
    assert.ok(siemServiceSource.includes('resolveMinutes'));
  });
});

// =====================================================================
// Triage Suggestions — Bounded and Labeled
// =====================================================================

describe('Triage Suggestions — AI Safety', () => {
  it('generateTriageSuggestion includes disclaimer', () => {
    assert.ok(siemServiceSource.includes('disclaimer'));
    assert.ok(siemServiceSource.includes('rule-based suggestions'));
    assert.ok(siemServiceSource.includes('not AI predictions'));
  });

  it('suggestions include confidence level', () => {
    assert.ok(siemServiceSource.includes("confidence: 'high'"));
    assert.ok(siemServiceSource.includes("confidence: 'medium'"));
    assert.ok(siemServiceSource.includes("confidence: 'low'"));
  });

  it('marks output as automated: true', () => {
    assert.ok(siemServiceSource.includes('automated: true'));
  });

  it('default suggestion exists for unknown patterns', () => {
    assert.ok(siemServiceSource.includes('review_and_classify'));
    assert.ok(siemServiceSource.includes('Standard alert'));
  });
});

// =====================================================================
// Tenant Isolation
// =====================================================================

describe('Tenant Isolation — Incidents', () => {
  it('listIncidents filters by tenant_slug', () => {
    assert.ok(moduleServiceSource.includes("tenant_slug = $1"));
  });

  it('createIncident uses sanitizeTenant', () => {
    const fnIdx = moduleServiceSource.indexOf('async function createIncident');
    const block = moduleServiceSource.slice(fnIdx, fnIdx + 200);
    assert.ok(block.includes('sanitizeTenant(tenant)'));
  });

  it('updateIncident scopes to tenant', () => {
    assert.ok(moduleServiceSource.includes("WHERE tenant_slug = $1 AND id = $2"));
  });

  it('timeline queries scope to tenant_slug', () => {
    const fnIdx = moduleServiceSource.indexOf('async function listIncidentTimeline');
    const block = moduleServiceSource.slice(fnIdx, fnIdx + 600);
    assert.ok(block.includes('tenant_slug = $1'));
  });

  it('IOC linking scopes to tenant', () => {
    const fnIdx = moduleServiceSource.indexOf('async function linkIocToIncident');
    const block = moduleServiceSource.slice(fnIdx, fnIdx + 300);
    assert.ok(block.includes('tenant_slug'));
  });
});

// =====================================================================
// asIncident Row Mapping
// =====================================================================

describe('asIncident Row Mapping', () => {
  it('maps escalatedFromAlertId', () => {
    assert.ok(moduleServiceSource.includes('escalatedFromAlertId: row.escalated_from_alert_id'));
  });

  it('maps priority with fallback to severity', () => {
    const fnIdx = moduleServiceSource.indexOf('function asIncident');
    const block = moduleServiceSource.slice(fnIdx, fnIdx + 500);
    assert.ok(block.includes("row.priority || row.severity || 'medium'"));
  });

  it('maps assignedTo', () => {
    assert.ok(moduleServiceSource.includes('assignedTo: row.assigned_to'));
  });

  it('maps blocked as boolean', () => {
    assert.ok(moduleServiceSource.includes('blocked: Boolean(row.blocked)'));
  });
});

// =====================================================================
// Listing and Pagination
// =====================================================================

describe('Listing and Pagination', () => {
  it('listIncidents supports severity filter', () => {
    const fnIdx = moduleServiceSource.indexOf('async function listIncidents');
    const block = moduleServiceSource.slice(fnIdx, fnIdx + 800);
    assert.ok(block.includes('options.severity'));
    assert.ok(block.includes('normalizeSeverity(options.severity)'));
  });

  it('listIncidents supports status filter', () => {
    const fnIdx = moduleServiceSource.indexOf('async function listIncidents');
    const block = moduleServiceSource.slice(fnIdx, fnIdx + 800);
    assert.ok(block.includes('options.status'));
  });

  it('listIncidents supports search by title', () => {
    const fnIdx = moduleServiceSource.indexOf('async function listIncidents');
    const block = moduleServiceSource.slice(fnIdx, fnIdx + 800);
    assert.ok(block.includes('options.search'));
    assert.ok(block.includes('ILIKE'));
  });

  it('listIncidents caps limit between 1-100', () => {
    const fnIdx = moduleServiceSource.indexOf('async function listIncidents');
    const block = moduleServiceSource.slice(fnIdx, fnIdx + 300);
    assert.ok(block.includes('toSafeInteger(options.limit, 25, 1, 100)'));
  });

  it('empty results include message hint', () => {
    const fnIdx = moduleServiceSource.indexOf('async function listIncidents');
    const block = moduleServiceSource.slice(fnIdx, fnIdx + 2000);
    assert.ok(block.includes('No incidents ingested'));
  });
});
