const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

// =====================================================================
// Playbook / Response Automation Hardening Tests — Phase 3
// Covers: playbook lifecycle, step state machine, execution model,
//         tenant isolation, audit trail, auto-completion, result_summary,
//         SOAR auto-trigger, route validation, frontend types,
//         execution detail view, step result update controls
// =====================================================================

const playbookServiceSource = fs.readFileSync(
  path.join(__dirname, '..', 'src', 'playbook-service.js'),
  'utf-8'
);

const routeSource = fs.readFileSync(
  path.join(__dirname, '..', 'src', 'modules', 'threat-intel', 'routes.js'),
  'utf-8'
);

const correlationSource = fs.readFileSync(
  path.join(__dirname, '..', 'src', 'correlation-engine.js'),
  'utf-8'
);

const frontendTypesSource = fs.readFileSync(
  path.join(__dirname, '..', '..', 'frontend', 'src', 'lib', 'backend.ts'),
  'utf-8'
);

const playbookPanelSource = fs.readFileSync(
  path.join(__dirname, '..', '..', 'frontend', 'src', 'components', 'platform', 'PlaybookPanel.tsx'),
  'utf-8'
);

const migration013Source = fs.readFileSync(
  path.join(__dirname, '..', 'migrations', '013_mitre_attack_and_playbooks.sql'),
  'utf-8'
);

const migration017Source = fs.readFileSync(
  path.join(__dirname, '..', 'migrations', '017_rls_fk_indexes_dedup.sql'),
  'utf-8'
);

const migration019Source = fs.readFileSync(
  path.join(__dirname, '..', 'migrations', '019_soc_remaining_gaps.sql'),
  'utf-8'
);

// =====================================================================
// 1. Playbook Service — Constants and Validation
// =====================================================================

describe('Playbook Service — Constants', () => {
  it('VALID_SEVERITIES includes exactly critical/high/medium/low', () => {
    assert.ok(playbookServiceSource.includes("const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low']"));
  });

  it('VALID_ACTION_TYPES includes manual/automated/notification/approval', () => {
    assert.ok(playbookServiceSource.includes("const VALID_ACTION_TYPES = ['manual', 'automated', 'notification', 'approval']"));
  });

  it('VALID_EXEC_STATUSES includes running/completed/failed/cancelled', () => {
    assert.ok(playbookServiceSource.includes("const VALID_EXEC_STATUSES = ['running', 'completed', 'failed', 'cancelled']"));
  });

  it('VALID_STEP_STATUSES includes pending/in_progress/completed/skipped/failed', () => {
    assert.ok(playbookServiceSource.includes("const VALID_STEP_STATUSES = ['pending', 'in_progress', 'completed', 'skipped', 'failed']"));
  });

  it('MAX_LIST_LIMIT is capped at 200', () => {
    assert.ok(playbookServiceSource.includes('const MAX_LIST_LIMIT = 200'));
  });
});

// =====================================================================
// 2. Playbook CRUD — Input Validation
// =====================================================================

describe('Playbook CRUD — Input Validation', () => {
  it('createPlaybook sanitizes tenant via sanitizeTenant', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function createPlaybook'),
      playbookServiceSource.indexOf('async function updatePlaybook')
    );
    assert.ok(fnBody.includes('sanitizeTenant(tenant)'));
  });

  it('createPlaybook caps name at 255 chars', () => {
    assert.ok(playbookServiceSource.includes("String(name).slice(0, 255)"));
  });

  it('createPlaybook caps description at 2000 chars', () => {
    assert.ok(playbookServiceSource.includes("String(description).slice(0, 2000)"));
  });

  it('createPlaybook validates severityFilter against VALID_SEVERITIES', () => {
    assert.ok(playbookServiceSource.includes('VALID_SEVERITIES.includes(severityFilter)'));
  });

  it('createPlaybook defaults category to general and caps at 64 chars', () => {
    assert.ok(playbookServiceSource.includes("String(category || 'general').slice(0, 64)"));
  });

  it('updatePlaybook uses parameterized query with dynamic SET clauses', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function updatePlaybook'),
      playbookServiceSource.indexOf('async function addPlaybookStep')
    );
    assert.ok(fnBody.includes('WHERE id = $1 AND tenant_slug = $2'));
    assert.ok(fnBody.includes('updated_at = NOW()'));
  });

  it('updatePlaybook validates isActive as Boolean', () => {
    assert.ok(playbookServiceSource.includes('Boolean(updates.isActive)'));
  });
});

// =====================================================================
// 3. Step Creation — Tenant Isolation (P1 fix)
// =====================================================================

describe('Step Creation — Tenant Isolation', () => {
  it('addPlaybookStep accepts tenantSlug parameter', () => {
    assert.ok(playbookServiceSource.includes(
      'async function addPlaybookStep(config, playbookId, { title, description, actionType, assignedRole, timeoutMinutes, stepOrder }, tenantSlug)'
    ));
  });

  it('addPlaybookStep verifies playbook belongs to tenant when tenantSlug provided', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function addPlaybookStep'),
      playbookServiceSource.indexOf('async function executePlaybook')
    );
    assert.ok(fnBody.includes('SELECT id FROM playbooks WHERE id = $1 AND tenant_slug = $2'));
    assert.ok(fnBody.includes('playbook_not_found'));
  });

  it('route passes auth.tenant to addPlaybookStep', () => {
    // The route must pass the tenant as the last argument
    assert.ok(routeSource.includes('}, auth.tenant)'));
  });

  it('addPlaybookStep validates actionType against VALID_ACTION_TYPES', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function addPlaybookStep'),
      playbookServiceSource.indexOf('async function executePlaybook')
    );
    assert.ok(fnBody.includes('VALID_ACTION_TYPES.includes(actionType)'));
  });

  it('addPlaybookStep defaults actionType to manual if invalid', () => {
    assert.ok(playbookServiceSource.includes("VALID_ACTION_TYPES.includes(actionType) ? actionType : 'manual'"));
  });

  it('addPlaybookStep caps title at 255 chars', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function addPlaybookStep'),
      playbookServiceSource.indexOf('async function executePlaybook')
    );
    assert.ok(fnBody.includes("String(title).slice(0, 255)"));
  });

  it('addPlaybookStep caps assigned_role at 64 chars with default', () => {
    assert.ok(playbookServiceSource.includes("String(assignedRole || 'security_analyst').slice(0, 64)"));
  });

  it('addPlaybookStep clamps timeout between 1 and 1440 minutes', () => {
    assert.ok(playbookServiceSource.includes('Math.max(1, Math.min(1440, Number(timeoutMinutes) || 60))'));
  });

  it('addPlaybookStep auto-increments step_order when not provided', () => {
    assert.ok(playbookServiceSource.includes('COALESCE(MAX(step_order), 0)::INT AS max_order'));
  });
});

// =====================================================================
// 4. Execution Model — Transaction Safety
// =====================================================================

describe('Execution Model — Transaction Safety', () => {
  it('executePlaybook uses withClient for transactional execution', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function executePlaybook'),
      playbookServiceSource.indexOf('async function listPlaybookExecutions')
    );
    assert.ok(fnBody.includes('withClient(config'));
  });

  it('executePlaybook wraps in BEGIN/COMMIT with ROLLBACK on error', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function executePlaybook'),
      playbookServiceSource.indexOf('async function listPlaybookExecutions')
    );
    assert.ok(fnBody.includes("client.query('BEGIN')"));
    assert.ok(fnBody.includes("client.query('COMMIT')"));
    assert.ok(fnBody.includes("client.query('ROLLBACK')"));
  });

  it('executePlaybook creates step_results for each playbook step', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function executePlaybook'),
      playbookServiceSource.indexOf('async function listPlaybookExecutions')
    );
    assert.ok(fnBody.includes("INSERT INTO playbook_step_results (execution_id, step_id, status)"));
    assert.ok(fnBody.includes("'pending'"));
  });

  it('executePlaybook inserts initial status as running', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function executePlaybook'),
      playbookServiceSource.indexOf('async function listPlaybookExecutions')
    );
    assert.ok(fnBody.includes("'running'"));
    assert.ok(fnBody.includes("INSERT INTO playbook_executions"));
  });

  it('executePlaybook adds incident timeline entry when linked to incident', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function executePlaybook'),
      playbookServiceSource.indexOf('async function listPlaybookExecutions')
    );
    assert.ok(fnBody.includes("INSERT INTO incident_timeline"));
    assert.ok(fnBody.includes("playbook_executed"));
  });

  it('executePlaybook sanitizes tenant with sanitizeTenant', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function executePlaybook'),
      playbookServiceSource.indexOf('async function listPlaybookExecutions')
    );
    assert.ok(fnBody.includes('sanitizeTenant(tenant)'));
  });
});

// =====================================================================
// 5. Step Result Update — State Machine and Audit Trail (P3 fix)
// =====================================================================

describe('Step Result Update — State Machine', () => {
  it('updatePlaybookStepResult validates status against VALID_STEP_STATUSES', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function updatePlaybookStepResult'),
      playbookServiceSource.indexOf('async function getExecutionStepResults')
    );
    assert.ok(fnBody.includes('VALID_STEP_STATUSES.includes(status)'));
  });

  it('updatePlaybookStepResult defaults to pending for invalid status', () => {
    assert.ok(playbookServiceSource.includes("VALID_STEP_STATUSES.includes(status) ? status : 'pending'"));
  });

  it('started_at is set on transition to in_progress', () => {
    assert.ok(playbookServiceSource.includes("CASE WHEN psr.started_at IS NULL AND $1 = 'in_progress' THEN NOW()"));
  });

  it('completed_at is set on transition to terminal states', () => {
    assert.ok(playbookServiceSource.includes("CASE WHEN $1 IN ('completed', 'skipped', 'failed') THEN NOW()"));
  });

  it('notes are capped at 2000 chars', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function updatePlaybookStepResult'),
      playbookServiceSource.indexOf('async function getExecutionStepResults')
    );
    assert.ok(fnBody.includes("String(notes).slice(0, 2000)"));
  });

  it('tenant isolation via JOIN on playbook_executions.tenant_slug', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function updatePlaybookStepResult'),
      playbookServiceSource.indexOf('async function getExecutionStepResults')
    );
    assert.ok(fnBody.includes('pe.tenant_slug = $6'));
  });
});

describe('Step Result Update — Audit Trail (P3)', () => {
  it('fetches previous status before updating step result', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function updatePlaybookStepResult'),
      playbookServiceSource.indexOf('async function getExecutionStepResults')
    );
    assert.ok(fnBody.includes('previous_status'));
    assert.ok(fnBody.includes('SELECT psr.status AS previous_status'));
  });

  it('attaches previousStatus to returned result object', () => {
    assert.ok(playbookServiceSource.includes('updated.previousStatus = previousStatus'));
  });

  it('route includes previousStatus in audit log payload', () => {
    assert.ok(routeSource.includes('previousStatus: result.previousStatus'));
  });

  it('route logs threat_intel.playbook_step.updated action', () => {
    assert.ok(routeSource.includes('threat_intel.playbook_step.updated'));
  });
});

// =====================================================================
// 6. Execution Auto-Completion and Result Summary (P6 fix)
// =====================================================================

describe('Execution Auto-Completion', () => {
  it('checks for remaining non-terminal steps after step update', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function updatePlaybookStepResult'),
      playbookServiceSource.indexOf('async function getExecutionStepResults')
    );
    assert.ok(fnBody.includes("status NOT IN ('completed', 'skipped', 'failed')"));
    assert.ok(fnBody.includes('remaining'));
  });

  it('determines final status based on failed step count', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function updatePlaybookStepResult'),
      playbookServiceSource.indexOf('async function getExecutionStepResults')
    );
    assert.ok(fnBody.includes("status = 'failed'"));
    assert.ok(fnBody.includes('failed_count'));
    assert.ok(fnBody.includes("hasFailed ? 'failed' : 'completed'"));
  });

  it('builds result_summary with step outcome counts', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function updatePlaybookStepResult'),
      playbookServiceSource.indexOf('async function getExecutionStepResults')
    );
    assert.ok(fnBody.includes('totalSteps'));
    assert.ok(fnBody.includes("FILTER (WHERE status = 'completed')"));
    assert.ok(fnBody.includes("FILTER (WHERE status = 'failed')"));
    assert.ok(fnBody.includes("FILTER (WHERE status = 'skipped')"));
  });

  it('saves result_summary as JSON to playbook_executions', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function updatePlaybookStepResult'),
      playbookServiceSource.indexOf('async function getExecutionStepResults')
    );
    assert.ok(fnBody.includes('result_summary = $3'));
    assert.ok(fnBody.includes('JSON.stringify(resultSummary)'));
  });

  it('result_summary includes outcome and completedAt timestamp', () => {
    assert.ok(playbookServiceSource.includes('outcome: finalStatus'));
    assert.ok(playbookServiceSource.includes('completedAt:'));
  });
});

// =====================================================================
// 7. Execution Step Results Query (P7/P8)
// =====================================================================

describe('Execution Step Results Query', () => {
  it('getExecutionStepResults function exists and is exported', () => {
    assert.ok(playbookServiceSource.includes('async function getExecutionStepResults'));
    assert.ok(playbookServiceSource.includes('getExecutionStepResults,'));
  });

  it('JOINs step_results with step definitions for enriched output', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function getExecutionStepResults'),
      playbookServiceSource.indexOf('module.exports')
    );
    assert.ok(fnBody.includes('JOIN playbook_steps ps ON ps.id = psr.step_id'));
    assert.ok(fnBody.includes('JOIN playbook_executions pe ON pe.id = psr.execution_id'));
  });

  it('returns step metadata: title, order, action_type, assigned_role, timeout', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function getExecutionStepResults'),
      playbookServiceSource.indexOf('module.exports')
    );
    assert.ok(fnBody.includes('ps.title AS step_title'));
    assert.ok(fnBody.includes('ps.step_order'));
    assert.ok(fnBody.includes('ps.action_type'));
    assert.ok(fnBody.includes('ps.assigned_role'));
    assert.ok(fnBody.includes('ps.timeout_minutes'));
  });

  it('tenant-isolates via pe.tenant_slug', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function getExecutionStepResults'),
      playbookServiceSource.indexOf('module.exports')
    );
    assert.ok(fnBody.includes('pe.tenant_slug = $2'));
  });

  it('orders by step_order ASC', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function getExecutionStepResults'),
      playbookServiceSource.indexOf('module.exports')
    );
    assert.ok(fnBody.includes('ORDER BY ps.step_order ASC'));
  });

  it('returns empty array when database not configured', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function getExecutionStepResults'),
      playbookServiceSource.indexOf('module.exports')
    );
    assert.ok(fnBody.includes('return []'));
  });
});

// =====================================================================
// 8. Route Wiring and Validation
// =====================================================================

describe('Route Wiring — Playbook Routes', () => {
  it('GET /v1/threat-intel/playbooks route exists', () => {
    assert.ok(routeSource.includes("/v1/threat-intel/playbooks'") || routeSource.includes('/v1/threat-intel/playbooks'));
  });

  it('POST /v1/threat-intel/playbooks route exists', () => {
    const idx = routeSource.indexOf("context.path === '/v1/threat-intel/playbooks'");
    assert.ok(idx > -1);
    const block = routeSource.slice(idx, idx + 2000);
    assert.ok(block.includes("context.method === 'POST'"));
  });

  it('GET /v1/threat-intel/playbooks/:id route exists', () => {
    assert.ok(routeSource.includes('/v1/threat-intel/playbooks/'));
    assert.ok(routeSource.includes('getPlaybookWithSteps'));
  });

  it('PUT /v1/threat-intel/playbooks/:id route exists', () => {
    assert.ok(routeSource.includes('updatePlaybook'));
  });

  it('POST /v1/threat-intel/playbooks/:id/steps route exists', () => {
    assert.ok(routeSource.includes('addPlaybookStep'));
  });

  it('POST /v1/threat-intel/playbooks/:id/execute route exists', () => {
    assert.ok(routeSource.includes('executePlaybook'));
  });

  it('GET /v1/threat-intel/playbooks/executions route exists', () => {
    assert.ok(routeSource.includes('listPlaybookExecutions'));
  });

  it('PUT /v1/threat-intel/playbooks/executions/:execId/steps/:stepId route exists', () => {
    assert.ok(routeSource.includes('updatePlaybookStepResult'));
  });

  it('GET /v1/threat-intel/playbooks/executions/:execId/steps route exists', () => {
    assert.ok(routeSource.includes('getExecutionStepResults'));
  });
});

describe('Route Validation — Body Shape (P2)', () => {
  it('PUT /playbooks/:id validates body shape with validateBodyShape', () => {
    // There should be a validateBodyShape call for the update route
    const updateSection = routeSource.slice(
      routeSource.indexOf("'PUT'") > -1 ? routeSource.indexOf('updatePlaybook') - 500 : 0,
      routeSource.indexOf('updatePlaybook') + 200
    );
    assert.ok(routeSource.includes("optional: ['name', 'description', 'severityFilter', 'category', 'isActive']"));
  });

  it('PUT /playbooks/:id only accepts known fields', () => {
    assert.ok(routeSource.includes("'name', 'description', 'severityFilter', 'category', 'isActive'"));
  });
});

describe('Route Wiring — Auth and RBAC', () => {
  it('playbook routes use threatAuthChain', () => {
    assert.ok(routeSource.includes('threatAuthChain'));
  });

  it('playbook creation requires security_analyst role', () => {
    // Search for the POST playbooks handler and verify role requirement
    const createBlock = routeSource.slice(
      routeSource.indexOf("context.path === '/v1/threat-intel/playbooks'"),
      routeSource.indexOf("context.path === '/v1/threat-intel/playbooks'") + 3000
    );
    assert.ok(createBlock.includes('security_analyst'));
  });

  it('all playbook routes require authenticated session', () => {
    assert.ok(routeSource.includes('requireSession'));
  });
});

describe('Route Wiring — Audit Logging', () => {
  it('playbook creation generates audit log', () => {
    assert.ok(routeSource.includes('threat_intel.playbook.created'));
  });

  it('playbook update generates audit log', () => {
    assert.ok(routeSource.includes('threat_intel.playbook.updated'));
  });

  it('playbook step creation generates audit log', () => {
    assert.ok(routeSource.includes('threat_intel.playbook_step.created'));
  });

  it('playbook execution generates audit log', () => {
    assert.ok(routeSource.includes('threat_intel.playbook.executed'));
  });

  it('step result update generates audit log', () => {
    assert.ok(routeSource.includes('threat_intel.playbook_step.updated'));
  });
});

// =====================================================================
// 9. SOAR Auto-Trigger (P4 fix)
// =====================================================================

describe('SOAR Auto-Trigger — Correlation Engine', () => {
  it('runCorrelationEngine accepts executePlaybook callback', () => {
    assert.ok(correlationSource.includes('{ notifyIncidentCreated, executePlaybook }'));
  });

  it('loads active auto-trigger playbooks for tenant', () => {
    assert.ok(correlationSource.includes('auto_trigger = TRUE'));
    assert.ok(correlationSource.includes('is_active = TRUE'));
  });

  it('uses executePlaybook service function when available', () => {
    assert.ok(correlationSource.includes("typeof executePlaybook === 'function'"));
    assert.ok(correlationSource.includes('await executePlaybook(config'));
  });

  it('fallback INSERT uses valid schema columns (no triggered_by)', () => {
    // Make sure there's no triggered_by column reference
    const soarBlock = correlationSource.slice(
      correlationSource.indexOf('SOAR Playbook Auto-Trigger'),
      correlationSource.indexOf('module.exports')
    );
    assert.ok(!soarBlock.includes('triggered_by'));
    // Fallback uses started_by = NULL
    assert.ok(soarBlock.includes('started_by'));
  });

  it('logs soar_playbook_auto_triggered on successful trigger', () => {
    assert.ok(correlationSource.includes('soar_playbook_auto_triggered'));
  });

  it('catches and logs trigger failures gracefully', () => {
    assert.ok(correlationSource.includes('soar_trigger_failed'));
  });

  it('route passes executePlaybook to runCorrelationEngine', () => {
    assert.ok(routeSource.includes('runCorrelationEngine(config, auth.tenant, log, { notifyIncidentCreated, executePlaybook }'));
  });

  it('tracks autoTriggeredPlaybooks in correlation results', () => {
    assert.ok(correlationSource.includes('autoTriggeredPlaybooks'));
  });
});

// =====================================================================
// 10. DB Schema — Migrations
// =====================================================================

describe('DB Schema — Playbook Tables', () => {
  it('playbooks table exists in migration', () => {
    assert.ok(migration013Source.includes('CREATE TABLE IF NOT EXISTS playbooks'));
  });

  it('playbook_steps table exists in migration', () => {
    assert.ok(migration013Source.includes('CREATE TABLE IF NOT EXISTS playbook_steps'));
  });

  it('playbook_executions table exists in migration', () => {
    assert.ok(migration013Source.includes('CREATE TABLE IF NOT EXISTS playbook_executions'));
  });

  it('playbook_step_results table exists in migration', () => {
    assert.ok(migration013Source.includes('CREATE TABLE IF NOT EXISTS playbook_step_results'));
  });

  it('severity_filter has CHECK constraint for valid values', () => {
    assert.ok(migration013Source.includes("severity_filter TEXT CHECK (severity_filter IN ('critical', 'high', 'medium', 'low'))"));
  });

  it('action_type has CHECK constraint with default manual', () => {
    assert.ok(migration013Source.includes("action_type     TEXT DEFAULT 'manual' CHECK (action_type IN ('manual', 'automated', 'notification', 'approval'))"));
  });

  it('execution status has CHECK constraint', () => {
    assert.ok(migration013Source.includes("CHECK (status IN ('running', 'completed', 'failed', 'cancelled'))"));
  });

  it('step result status has CHECK constraint', () => {
    assert.ok(migration013Source.includes("CHECK (status IN ('pending', 'in_progress', 'completed', 'skipped', 'failed'))"));
  });
});

describe('DB Schema — RLS Policies', () => {
  it('playbooks table has RLS policy', () => {
    assert.ok(migration017Source.includes('tenant_isolation_playbooks ON playbooks'));
  });

  it('playbook_executions table has RLS policy', () => {
    assert.ok(migration017Source.includes('tenant_isolation_playbook_executions ON playbook_executions'));
  });
});

describe('DB Schema — Auto-Trigger Columns', () => {
  it('auto_trigger column added to playbooks', () => {
    assert.ok(migration019Source.includes('auto_trigger BOOLEAN NOT NULL DEFAULT FALSE'));
  });

  it('auto_trigger index exists for active playbooks', () => {
    assert.ok(migration019Source.includes('playbooks_auto_trigger_idx'));
  });
});

// =====================================================================
// 11. Frontend Types — PlaybookRecord, Execution, StepResult (P5)
// =====================================================================

describe('Frontend Types — PlaybookRecord', () => {
  it('PlaybookRecord interface exists', () => {
    assert.ok(frontendTypesSource.includes('export interface PlaybookRecord'));
  });

  it('PlaybookRecord includes auto_trigger field', () => {
    assert.ok(frontendTypesSource.includes('auto_trigger: boolean'));
  });

  it('PlaybookRecord includes severity_trigger field', () => {
    assert.ok(frontendTypesSource.includes('severity_trigger: string | null'));
  });

  it('PlaybookRecord includes category_trigger field', () => {
    assert.ok(frontendTypesSource.includes('category_trigger: string | null'));
  });

  it('PlaybookRecord includes standard fields', () => {
    const block = frontendTypesSource.slice(
      frontendTypesSource.indexOf('export interface PlaybookRecord'),
      frontendTypesSource.indexOf('}', frontendTypesSource.indexOf('export interface PlaybookRecord')) + 1
    );
    assert.ok(block.includes('id: number'));
    assert.ok(block.includes('tenant_slug: string'));
    assert.ok(block.includes('name: string'));
    assert.ok(block.includes('is_active: boolean'));
    assert.ok(block.includes('category: string'));
  });
});

describe('Frontend Types — PlaybookStep', () => {
  it('PlaybookStep interface exists', () => {
    assert.ok(frontendTypesSource.includes('export interface PlaybookStep'));
  });

  it('PlaybookStep includes action_type union', () => {
    assert.ok(frontendTypesSource.includes("'manual' | 'automated' | 'notification' | 'approval'"));
  });

  it('PlaybookStep includes timeout_minutes', () => {
    assert.ok(frontendTypesSource.includes('timeout_minutes: number'));
  });
});

describe('Frontend Types — PlaybookExecution', () => {
  it('PlaybookExecution interface exists', () => {
    assert.ok(frontendTypesSource.includes('export interface PlaybookExecution'));
  });

  it('PlaybookExecution status union includes all 4 states', () => {
    assert.ok(frontendTypesSource.includes("'running' | 'completed' | 'failed' | 'cancelled'"));
  });

  it('PlaybookExecution includes result_summary', () => {
    assert.ok(frontendTypesSource.includes('result_summary: Record<string, unknown>'));
  });

  it('PlaybookExecution includes optional stepResults', () => {
    assert.ok(frontendTypesSource.includes('stepResults?: PlaybookStepResult[]'));
  });
});

describe('Frontend Types — PlaybookStepResult', () => {
  it('PlaybookStepResult interface exists', () => {
    assert.ok(frontendTypesSource.includes('export interface PlaybookStepResult'));
  });

  it('PlaybookStepResult status union includes all 5 states', () => {
    assert.ok(frontendTypesSource.includes("'pending' | 'in_progress' | 'completed' | 'skipped' | 'failed'"));
  });

  it('PlaybookStepResult includes enriched step metadata fields', () => {
    assert.ok(frontendTypesSource.includes('step_title?: string'));
    assert.ok(frontendTypesSource.includes('step_order?: number'));
    assert.ok(frontendTypesSource.includes('action_type?: string'));
    assert.ok(frontendTypesSource.includes('assigned_role?: string'));
    assert.ok(frontendTypesSource.includes('timeout_minutes?: number'));
  });
});

describe('Frontend API Functions', () => {
  it('fetchPlaybooks function exists', () => {
    assert.ok(frontendTypesSource.includes('export async function fetchPlaybooks'));
  });

  it('fetchPlaybookDetail function exists', () => {
    assert.ok(frontendTypesSource.includes('export async function fetchPlaybookDetail'));
  });

  it('createPlaybook function exists', () => {
    assert.ok(frontendTypesSource.includes('export async function createPlaybook'));
  });

  it('updatePlaybook function exists', () => {
    assert.ok(frontendTypesSource.includes('export async function updatePlaybook'));
  });

  it('addPlaybookStep function exists', () => {
    assert.ok(frontendTypesSource.includes('export async function addPlaybookStep'));
  });

  it('executePlaybook function exists', () => {
    assert.ok(frontendTypesSource.includes('export async function executePlaybook'));
  });

  it('fetchPlaybookExecutions function exists', () => {
    assert.ok(frontendTypesSource.includes('export async function fetchPlaybookExecutions'));
  });

  it('updatePlaybookStepResult function exists', () => {
    assert.ok(frontendTypesSource.includes('export async function updatePlaybookStepResult'));
  });

  it('fetchExecutionStepResults function exists', () => {
    assert.ok(frontendTypesSource.includes('export async function fetchExecutionStepResults'));
  });

  it('fetchExecutionStepResults calls correct API endpoint', () => {
    assert.ok(frontendTypesSource.includes('/v1/threat-intel/playbooks/executions/${executionId}/steps'));
  });
});

// =====================================================================
// 12. PlaybookPanel UI — Execution Detail (P7/P8)
// =====================================================================

describe('PlaybookPanel — Execution Detail View', () => {
  it('imports fetchExecutionStepResults', () => {
    assert.ok(playbookPanelSource.includes('fetchExecutionStepResults'));
  });

  it('imports PlaybookStepResult type', () => {
    assert.ok(playbookPanelSource.includes('type PlaybookStepResult'));
  });

  it('has selectedExecId state for execution drill-down', () => {
    assert.ok(playbookPanelSource.includes('selectedExecId'));
    assert.ok(playbookPanelSource.includes('setSelectedExecId'));
  });

  it('queries step results for selected execution', () => {
    assert.ok(playbookPanelSource.includes("queryKey: ['execution-steps'"));
    assert.ok(playbookPanelSource.includes('fetchExecutionStepResults(tenant, selectedExecId!)'));
  });

  it('execution list items are clickable buttons for drill-down', () => {
    // Each execution row should toggle selectedExecId
    assert.ok(playbookPanelSource.includes('setSelectedExecId(selectedExecId === exec.id ? null : exec.id)'));
  });
});

describe('PlaybookPanel — Step Result Controls', () => {
  it('stepResultMutation is defined and functional', () => {
    assert.ok(playbookPanelSource.includes('stepResultMutation'));
    assert.ok(playbookPanelSource.includes('updatePlaybookStepResult'));
  });

  it('stepResultMutation supports notes parameter', () => {
    assert.ok(playbookPanelSource.includes('notes?: string'));
  });

  it('stepResultMutation invalidates step results query on success', () => {
    assert.ok(playbookPanelSource.includes("queryKey: ['execution-steps', tenant, selectedExecId]"));
  });

  it('renders Start button for pending steps', () => {
    assert.ok(playbookPanelSource.includes("status: 'in_progress'"));
    assert.ok(playbookPanelSource.includes('>Start<') || playbookPanelSource.includes('Start'));
  });

  it('renders Complete/Fail/Skip buttons for in_progress steps', () => {
    assert.ok(playbookPanelSource.includes("status: 'completed'"));
    assert.ok(playbookPanelSource.includes("status: 'failed'"));
    assert.ok(playbookPanelSource.includes("status: 'skipped'"));
  });

  it('disables controls when mutation is pending', () => {
    assert.ok(playbookPanelSource.includes('stepResultMutation.isPending'));
  });

  it('hides controls for terminal step states', () => {
    assert.ok(playbookPanelSource.includes("!['completed', 'skipped', 'failed'].includes(sr.status)"));
  });

  it('step progress displays step title, order, action type, and role', () => {
    assert.ok(playbookPanelSource.includes('sr.step_title'));
    assert.ok(playbookPanelSource.includes('sr.step_order'));
    assert.ok(playbookPanelSource.includes('sr.action_type'));
    assert.ok(playbookPanelSource.includes('sr.assigned_role'));
  });

  it('displays notes when present', () => {
    assert.ok(playbookPanelSource.includes('sr.notes'));
  });

  it('shows started_at and completed_at timestamps', () => {
    assert.ok(playbookPanelSource.includes('sr.started_at'));
    assert.ok(playbookPanelSource.includes('sr.completed_at'));
  });

  it('shows mutation error message', () => {
    assert.ok(playbookPanelSource.includes('stepResultMutation.isError'));
  });
});

describe('PlaybookPanel — Step Status Styling', () => {
  it('STEP_STATUS_COLORS includes all 5 step states', () => {
    assert.ok(playbookPanelSource.includes("pending: '"));
    assert.ok(playbookPanelSource.includes("in_progress: '"));
    assert.ok(playbookPanelSource.includes("completed: '"));
    assert.ok(playbookPanelSource.includes("skipped: '"));
    assert.ok(playbookPanelSource.includes("failed: '"));
  });
});

// =====================================================================
// 13. Playbook Listing — Pagination and Filtering
// =====================================================================

describe('Playbook Listing — Pagination', () => {
  it('listPlaybooks caps limit to MAX_LIST_LIMIT', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function listPlaybooks'),
      playbookServiceSource.indexOf('async function getPlaybookWithSteps')
    );
    assert.ok(fnBody.includes('Math.min(Math.max(1,'));
    assert.ok(fnBody.includes('MAX_LIST_LIMIT'));
  });

  it('listPlaybooks defaults activeOnly to true', () => {
    assert.ok(playbookServiceSource.includes('activeOnly = true'));
  });

  it('listPlaybooks supports category filter', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function listPlaybooks'),
      playbookServiceSource.indexOf('async function getPlaybookWithSteps')
    );
    assert.ok(fnBody.includes("category = $"));
  });

  it('listPlaybooks returns paginated result shape', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function listPlaybooks'),
      playbookServiceSource.indexOf('async function getPlaybookWithSteps')
    );
    assert.ok(fnBody.includes('data:'));
    assert.ok(fnBody.includes('total:'));
    assert.ok(fnBody.includes('limit: cappedLimit'));
    assert.ok(fnBody.includes('offset: cappedOffset'));
  });
});

describe('Execution Listing — Filters', () => {
  it('listPlaybookExecutions supports playbookId filter', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function listPlaybookExecutions'),
      playbookServiceSource.indexOf('async function updatePlaybookStepResult')
    );
    assert.ok(fnBody.includes('pe.playbook_id'));
  });

  it('listPlaybookExecutions supports incidentId filter', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function listPlaybookExecutions'),
      playbookServiceSource.indexOf('async function updatePlaybookStepResult')
    );
    assert.ok(fnBody.includes('pe.incident_id'));
  });

  it('listPlaybookExecutions validates status against VALID_EXEC_STATUSES', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function listPlaybookExecutions'),
      playbookServiceSource.indexOf('async function updatePlaybookStepResult')
    );
    assert.ok(fnBody.includes('VALID_EXEC_STATUSES.includes(status)'));
  });

  it('listPlaybookExecutions JOINs playbook name', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function listPlaybookExecutions'),
      playbookServiceSource.indexOf('async function updatePlaybookStepResult')
    );
    assert.ok(fnBody.includes('p.name AS playbook_name'));
    assert.ok(fnBody.includes('JOIN playbooks p ON p.id = pe.playbook_id'));
  });
});

// =====================================================================
// 14. Service Exports Completeness
// =====================================================================

describe('Service Module Exports', () => {
  it('playbook-service exports listPlaybooks', () => {
    assert.ok(playbookServiceSource.includes('listPlaybooks,'));
  });

  it('playbook-service exports getPlaybookWithSteps', () => {
    assert.ok(playbookServiceSource.includes('getPlaybookWithSteps,'));
  });

  it('playbook-service exports createPlaybook', () => {
    assert.ok(playbookServiceSource.includes('createPlaybook,'));
  });

  it('playbook-service exports updatePlaybook', () => {
    assert.ok(playbookServiceSource.includes('updatePlaybook,'));
  });

  it('playbook-service exports addPlaybookStep', () => {
    assert.ok(playbookServiceSource.includes('addPlaybookStep,'));
  });

  it('playbook-service exports executePlaybook', () => {
    assert.ok(playbookServiceSource.includes('executePlaybook,'));
  });

  it('playbook-service exports listPlaybookExecutions', () => {
    assert.ok(playbookServiceSource.includes('listPlaybookExecutions,'));
  });

  it('playbook-service exports updatePlaybookStepResult', () => {
    assert.ok(playbookServiceSource.includes('updatePlaybookStepResult,'));
  });

  it('playbook-service exports getExecutionStepResults', () => {
    assert.ok(playbookServiceSource.includes('getExecutionStepResults,'));
  });
});

// =====================================================================
// 15. Route deps destructuring includes all playbook functions
// =====================================================================

describe('Route Dependencies', () => {
  it('routes destructure getExecutionStepResults from deps', () => {
    assert.ok(routeSource.includes('getExecutionStepResults'));
  });

  it('routes destructure listPlaybooks from deps', () => {
    assert.ok(routeSource.includes('listPlaybooks,'));
  });

  it('routes destructure executePlaybook from deps', () => {
    assert.ok(routeSource.includes('executePlaybook,'));
  });

  it('routes destructure updatePlaybookStepResult from deps', () => {
    assert.ok(routeSource.includes('updatePlaybookStepResult,'));
  });
});

// =====================================================================
// 16. Playbook SELECT clauses include auto_trigger fields (P5)
// =====================================================================

describe('Playbook SELECT Clauses — Auto-Trigger Fields', () => {
  it('listPlaybooks SELECT includes auto_trigger, severity_trigger, category_trigger', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function listPlaybooks'),
      playbookServiceSource.indexOf('async function getPlaybookWithSteps')
    );
    assert.ok(fnBody.includes('auto_trigger'));
    assert.ok(fnBody.includes('severity_trigger'));
    assert.ok(fnBody.includes('category_trigger'));
  });

  it('getPlaybookWithSteps SELECT includes auto_trigger fields', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function getPlaybookWithSteps'),
      playbookServiceSource.indexOf('async function createPlaybook')
    );
    assert.ok(fnBody.includes('auto_trigger'));
    assert.ok(fnBody.includes('severity_trigger'));
    assert.ok(fnBody.includes('category_trigger'));
  });

  it('createPlaybook RETURNING includes auto_trigger fields', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function createPlaybook'),
      playbookServiceSource.indexOf('async function updatePlaybook')
    );
    assert.ok(fnBody.includes('auto_trigger'));
    assert.ok(fnBody.includes('severity_trigger'));
    assert.ok(fnBody.includes('category_trigger'));
  });

  it('updatePlaybook RETURNING includes auto_trigger fields', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function updatePlaybook'),
      playbookServiceSource.indexOf('async function addPlaybookStep')
    );
    assert.ok(fnBody.includes('auto_trigger'));
    assert.ok(fnBody.includes('severity_trigger'));
    assert.ok(fnBody.includes('category_trigger'));
  });
});

// =====================================================================
// 17. No-DB Safety — All functions gracefully handle missing DB
// =====================================================================

describe('No-DB Safety', () => {
  it('listPlaybooks returns empty on no databaseUrl', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function listPlaybooks'),
      playbookServiceSource.indexOf('async function getPlaybookWithSteps')
    );
    assert.ok(fnBody.includes("return { data: [], total: 0 }"));
  });

  it('getPlaybookWithSteps returns null on no databaseUrl', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function getPlaybookWithSteps'),
      playbookServiceSource.indexOf('async function createPlaybook')
    );
    assert.ok(fnBody.includes('return null'));
  });

  it('createPlaybook returns null on no databaseUrl', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function createPlaybook'),
      playbookServiceSource.indexOf('async function updatePlaybook')
    );
    assert.ok(fnBody.includes('return null'));
  });

  it('executePlaybook returns null on no databaseUrl', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function executePlaybook'),
      playbookServiceSource.indexOf('async function listPlaybookExecutions')
    );
    assert.ok(fnBody.includes('return null'));
  });

  it('updatePlaybookStepResult returns null on no databaseUrl', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function updatePlaybookStepResult'),
      playbookServiceSource.indexOf('async function getExecutionStepResults')
    );
    assert.ok(fnBody.includes('return null'));
  });

  it('getExecutionStepResults returns empty array on no databaseUrl', () => {
    const fnBody = playbookServiceSource.slice(
      playbookServiceSource.indexOf('async function getExecutionStepResults'),
      playbookServiceSource.indexOf('module.exports')
    );
    assert.ok(fnBody.includes('return []'));
  });

  it('runCorrelationEngine returns empty on no databaseUrl', () => {
    assert.ok(correlationSource.includes("return { evaluated: 0, correlations: [] }"));
  });
});

// =====================================================================
// 18. KPI Cards in PlaybookPanel
// =====================================================================

describe('PlaybookPanel — KPI Cards', () => {
  it('shows Active Playbooks count', () => {
    assert.ok(playbookPanelSource.includes('Active Playbooks'));
    assert.ok(playbookPanelSource.includes('playbooks.length'));
  });

  it('shows Recent Executions count', () => {
    assert.ok(playbookPanelSource.includes('Recent Executions'));
    assert.ok(playbookPanelSource.includes('executions.length'));
  });

  it('shows Running Now count', () => {
    assert.ok(playbookPanelSource.includes('Running Now'));
    assert.ok(playbookPanelSource.includes("e.status === 'running'"));
  });
});
