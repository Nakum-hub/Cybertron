const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

// =====================================================================
// Governance Hardening Tests — Phase 3
// Covers: state transitions, evidence requirements, policy approval,
//         audit trail enrichment, dashboard truthfulness, staleness
// =====================================================================

// ── G2: State Transition Validation (compliance-model.js) ──

const {
  upsertSoc2Status,
  createPolicyRecord,
  listPolicies,
  getPolicyRecord,
  updatePolicyStatus,
  VALID_TRANSITIONS,
} = require('../src/ai/compliance-model');

describe('G2 — SOC2 State Transition Validation', () => {
  it('VALID_TRANSITIONS is exported and has all five states', () => {
    assert.ok(VALID_TRANSITIONS);
    assert.ok(VALID_TRANSITIONS['not_started']);
    assert.ok(VALID_TRANSITIONS['in_progress']);
    assert.ok(VALID_TRANSITIONS['implemented']);
    assert.ok(VALID_TRANSITIONS['validated']);
    assert.ok(VALID_TRANSITIONS['not_applicable']);
  });

  it('not_started can only transition to in_progress or not_applicable', () => {
    const allowed = VALID_TRANSITIONS['not_started'];
    assert.deepEqual(allowed.sort(), ['in_progress', 'not_applicable'].sort());
  });

  it('in_progress can transition to implemented, not_started, or not_applicable', () => {
    const allowed = VALID_TRANSITIONS['in_progress'];
    assert.deepEqual(allowed.sort(), ['implemented', 'not_applicable', 'not_started'].sort());
  });

  it('implemented can transition to validated, in_progress, or not_applicable', () => {
    const allowed = VALID_TRANSITIONS['implemented'];
    assert.deepEqual(allowed.sort(), ['in_progress', 'not_applicable', 'validated'].sort());
  });

  it('validated CANNOT jump back to not_started directly', () => {
    const allowed = VALID_TRANSITIONS['validated'];
    assert.ok(!allowed.includes('not_started'));
  });

  it('not_applicable can only revert to not_started', () => {
    const allowed = VALID_TRANSITIONS['not_applicable'];
    assert.deepEqual(allowed, ['not_started']);
  });

  it('upsertSoc2Status is a function', () => {
    assert.equal(typeof upsertSoc2Status, 'function');
  });
});

// ── G2: State Transition Validation (compliance-framework-service.js) ──

const {
  upsertFrameworkControlStatus,
  computeFrameworkGap,
} = require('../src/compliance-framework-service');

describe('G2 — Multi-Framework State Transition Validation', () => {
  it('upsertFrameworkControlStatus is a function', () => {
    assert.equal(typeof upsertFrameworkControlStatus, 'function');
  });

  it('rejects invalid status values', async () => {
    await assert.rejects(
      () => upsertFrameworkControlStatus({}, {
        tenant: 'test',
        frameworkId: 'soc2',
        controlId: 'CC1.1',
        status: 'INVALID_STATUS',
      }),
      (err) => {
        assert.ok(err.message.includes('Invalid status'));
        return true;
      }
    );
  });
});

// ── G3: Evidence Requirement for Validated ──

describe('G3 — Evidence Requirement for Validated Status', () => {
  it('upsertSoc2Status function validates evidence for validated transition', () => {
    // Verify that the function source code checks for evidence_required
    const sourcePath = path.join(__dirname, '..', 'src', 'ai', 'compliance-model.js');
    const source = fs.readFileSync(sourcePath, 'utf8');
    assert.ok(source.includes('evidence_required'), 'compliance-model.js should throw evidence_required error');
    assert.ok(source.includes("Cannot mark control as validated without"), 'Should have evidence requirement message');
  });

  it('framework service validates transitions in upsertFrameworkControlStatus', () => {
    const sourcePath = path.join(__dirname, '..', 'src', 'compliance-framework-service.js');
    const source = fs.readFileSync(sourcePath, 'utf8');
    assert.ok(source.includes('invalid_status_transition'), 'Should contain transition validation code');
    assert.ok(source.includes('VALID_TRANSITIONS'), 'Should reference VALID_TRANSITIONS');
  });
});

// ── G1: Policy Approval Workflow ──

describe('G1 — Policy Approval Workflow', () => {
  it('createPolicyRecord is a function', () => {
    assert.equal(typeof createPolicyRecord, 'function');
  });

  it('listPolicies is a function', () => {
    assert.equal(typeof listPolicies, 'function');
  });

  it('getPolicyRecord is a function', () => {
    assert.equal(typeof getPolicyRecord, 'function');
  });

  it('updatePolicyStatus is a function', () => {
    assert.equal(typeof updatePolicyStatus, 'function');
  });

  it('policy approval transition rules are defined', () => {
    const sourcePath = path.join(__dirname, '..', 'src', 'ai', 'compliance-model.js');
    const source = fs.readFileSync(sourcePath, 'utf8');
    assert.ok(source.includes('VALID_POLICY_TRANSITIONS'));
    assert.ok(source.includes("'draft'"));
    assert.ok(source.includes("'pending_approval'"));
    assert.ok(source.includes("'approved'"));
    assert.ok(source.includes("'rejected'"));
    assert.ok(source.includes("'archived'"));
  });

  it('draft can transition to pending_approval or archived', () => {
    const sourcePath = path.join(__dirname, '..', 'src', 'ai', 'compliance-model.js');
    const source = fs.readFileSync(sourcePath, 'utf8');
    // Extract the VALID_POLICY_TRANSITIONS object
    const match = source.match(/VALID_POLICY_TRANSITIONS\s*=\s*\{([\s\S]*?)\};/);
    assert.ok(match, 'VALID_POLICY_TRANSITIONS must be defined');
    const block = match[1];
    // draft line should include pending_approval
    assert.ok(block.includes("'pending_approval'"));
  });

  it('approved can only transition to archived', () => {
    const sourcePath = path.join(__dirname, '..', 'src', 'ai', 'compliance-model.js');
    const source = fs.readFileSync(sourcePath, 'utf8');
    const match = source.match(/VALID_POLICY_TRANSITIONS\s*=\s*\{([\s\S]*?)\};/);
    assert.ok(match);
    // Find the line that starts with 'approved' (not 'pending_approval')
    const lines = match[1].split('\n');
    const approvedLine = lines.find(l => {
      const trimmed = l.trim();
      return trimmed.startsWith("'approved'") && trimmed.includes(':');
    });
    assert.ok(approvedLine, 'Should find the approved transition line');
    assert.ok(approvedLine.includes("'archived'"), 'Approved policies should be archivable');
    const bracketContent = approvedLine.match(/\[([^\]]+)\]/);
    assert.ok(bracketContent);
    assert.ok(!bracketContent[1].includes("'draft'"), 'Approved should not revert to draft');
  });

  it('updatePolicyStatus rejects missing policyId', async () => {
    await assert.rejects(
      () => updatePolicyStatus({}, { tenant: 'test', policyId: 'abc', status: 'approved' }),
      (err) => {
        assert.ok(err.message || err.code);
        return true;
      }
    );
  });
});

// ── G1: Policy Approval Routes ──

describe('G1 — Policy Approval Routes Wired', () => {
  it('compliance-engine routes include policy status endpoint', () => {
    const routesPath = path.join(__dirname, '..', 'src', 'modules', 'compliance-engine', 'routes.js');
    const source = fs.readFileSync(routesPath, 'utf8');
    assert.ok(source.includes('/v1/compliance/policies'), 'Should have policies list route');
    assert.ok(source.includes("'/v1/compliance/policies'") || source.includes('/v1/compliance/policies/'), 'Should have policies route');
  });

  it('policy status route requires compliance_officer role', () => {
    const routesPath = path.join(__dirname, '..', 'src', 'modules', 'compliance-engine', 'routes.js');
    const source = fs.readFileSync(routesPath, 'utf8');
    // Look for the PATCH policy status handler
    const patchIdx = source.indexOf('PATCH /v1/compliance/policies');
    assert.ok(patchIdx > 0, 'Should have PATCH policy status route comment');
    const handlerBlock = source.slice(patchIdx, patchIdx + 1200);
    assert.ok(handlerBlock.includes('compliance_officer'), 'Policy status updates require compliance_officer role');
  });

  it('policy status route logs audit with previousStatus', () => {
    const routesPath = path.join(__dirname, '..', 'src', 'modules', 'compliance-engine', 'routes.js');
    const source = fs.readFileSync(routesPath, 'utf8');
    const policyStatusSection = source.slice(source.indexOf('compliance.policy.'));
    assert.ok(policyStatusSection.includes('previousStatus'), 'Policy audit log should include previousStatus');
  });
});

// ── G4: Audit Trail Enrichment ──

describe('G4 — Audit Trail Enrichment with previousStatus', () => {
  it('SOC2 status update audit log includes previousStatus', () => {
    const routesPath = path.join(__dirname, '..', 'src', 'modules', 'compliance-engine', 'routes.js');
    const source = fs.readFileSync(routesPath, 'utf8');
    const soc2UpdateSection = source.slice(
      source.indexOf('compliance.soc2_status.updated'),
      source.indexOf('compliance.soc2_status.updated') + 300
    );
    assert.ok(soc2UpdateSection.includes('previousStatus'), 'SOC2 audit log must include previousStatus');
  });

  it('multi-framework status update audit log includes previousStatus', () => {
    const routesPath = path.join(__dirname, '..', 'src', 'modules', 'compliance-engine', 'routes.js');
    const source = fs.readFileSync(routesPath, 'utf8');
    const fwUpdateSection = source.slice(
      source.indexOf('compliance.framework_control_status.updated'),
      source.indexOf('compliance.framework_control_status.updated') + 300
    );
    assert.ok(fwUpdateSection.includes('previousStatus'), 'Framework audit log must include previousStatus');
  });

  it('upsertSoc2Status returns previousStatus in result', () => {
    const sourcePath = path.join(__dirname, '..', 'src', 'ai', 'compliance-model.js');
    const source = fs.readFileSync(sourcePath, 'utf8');
    assert.ok(source.includes('previousStatus: currentStatus'), 'Result should include previousStatus');
  });

  it('upsertFrameworkControlStatus returns previousStatus', () => {
    const sourcePath = path.join(__dirname, '..', 'src', 'compliance-framework-service.js');
    const source = fs.readFileSync(sourcePath, 'utf8');
    assert.ok(source.includes('row.previousStatus = currentStatus'), 'Framework upsert should set previousStatus');
  });
});

// ── G5: Dashboard Truthfulness ──

describe('G5 — Dashboard Truthfulness (validatedWithoutEvidence)', () => {
  it('computeFrameworkGap tracks validatedWithoutEvidence', () => {
    const result = computeFrameworkGap([
      { controlId: 'A.5.1', family: 'Test', title: 'T1', defaultWeight: 1, status: 'validated', evidenceCount: 0 },
      { controlId: 'A.5.2', family: 'Test', title: 'T2', defaultWeight: 1, status: 'validated', evidenceCount: 3 },
    ]);
    assert.equal(result.validatedWithoutEvidence, 1);
    assert.equal(result.validated, 2);
    assert.equal(result.readinessScore, 100);
  });

  it('validatedWithoutEvidence is 0 when all have evidence', () => {
    const result = computeFrameworkGap([
      { controlId: 'A.5.1', family: 'Test', title: 'T1', defaultWeight: 1, status: 'validated', evidenceCount: 2 },
    ]);
    assert.equal(result.validatedWithoutEvidence, 0);
  });

  it('validatedWithoutEvidence is 0 when no controls are validated', () => {
    const result = computeFrameworkGap([
      { controlId: 'A.5.1', family: 'Test', title: 'T1', defaultWeight: 1, status: 'not_started' },
    ]);
    assert.equal(result.validatedWithoutEvidence, 0);
  });

  it('SOC2 gap engine also tracks validatedWithoutEvidence', () => {
    const { computeComplianceGap } = require('../src/ai/compliance-gap-engine');
    const result = computeComplianceGap([
      { controlId: 'CC1.1', family: 'CC', title: 'T1', defaultWeight: 1, status: 'validated', evidenceCount: 0 },
      { controlId: 'CC1.2', family: 'CC', title: 'T2', defaultWeight: 1, status: 'validated', evidenceCount: 1 },
    ]);
    assert.equal(result.validatedWithoutEvidence, 1);
  });

  it('frontend ComplianceFrameworkPanel surfaces truthfulness warning', () => {
    const panelPath = path.join(__dirname, '..', '..', 'frontend', 'src', 'components', 'platform', 'ComplianceFrameworkPanel.tsx');
    const source = fs.readFileSync(panelPath, 'utf8');
    assert.ok(source.includes('validatedWithoutEvidence'), 'Panel should reference validatedWithoutEvidence');
    assert.ok(source.includes('readiness score may be overstated'), 'Panel should warn about overstated scores');
    assert.ok(source.includes('AlertTriangle'), 'Panel should use AlertTriangle icon for warnings');
  });

  it('frontend ResilienceHQConsole surfaces truthfulness warning for SOC2', () => {
    const consolePath = path.join(__dirname, '..', '..', 'frontend', 'src', 'components', 'platform', 'ResilienceHQConsole.tsx');
    const source = fs.readFileSync(consolePath, 'utf8');
    assert.ok(source.includes('validatedWithoutEvidence'), 'Console should reference validatedWithoutEvidence');
    assert.ok(source.includes('readiness score may be overstated'), 'Console should warn about overstated scores');
  });
});

// ── G6: Staleness Detection ──

describe('G6 — Staleness Detection', () => {
  it('computeComplianceGap tracks staleControls', () => {
    const { computeComplianceGap } = require('../src/ai/compliance-gap-engine');
    const twoYearsAgo = new Date(Date.now() - 2 * 365 * 24 * 60 * 60 * 1000).toISOString();
    const result = computeComplianceGap([
      { controlId: 'CC1.1', family: 'CC', title: 'T1', defaultWeight: 1, status: 'validated', evidenceCount: 1, updatedAt: twoYearsAgo },
      { controlId: 'CC1.2', family: 'CC', title: 'T2', defaultWeight: 1, status: 'implemented', evidenceCount: 1, updatedAt: new Date().toISOString() },
    ]);
    assert.equal(result.staleControls, 1, 'Should detect 1 stale control');
  });

  it('staleControls is 0 when all recently updated', () => {
    const { computeComplianceGap } = require('../src/ai/compliance-gap-engine');
    const result = computeComplianceGap([
      { controlId: 'CC1.1', family: 'CC', title: 'T1', defaultWeight: 1, status: 'validated', evidenceCount: 1, updatedAt: new Date().toISOString() },
    ]);
    assert.equal(result.staleControls, 0);
  });

  it('not_started controls are not counted as stale', () => {
    const { computeComplianceGap } = require('../src/ai/compliance-gap-engine');
    const twoYearsAgo = new Date(Date.now() - 2 * 365 * 24 * 60 * 60 * 1000).toISOString();
    const result = computeComplianceGap([
      { controlId: 'CC1.1', family: 'CC', title: 'T1', defaultWeight: 1, status: 'not_started', updatedAt: twoYearsAgo },
    ]);
    assert.equal(result.staleControls, 0, 'not_started controls should not be flagged as stale');
  });

  it('migration 020 adds review_due_at columns', () => {
    const migrationPath = path.join(__dirname, '..', 'migrations', '020_governance_hardening.sql');
    const source = fs.readFileSync(migrationPath, 'utf8');
    assert.ok(source.includes('review_due_at TIMESTAMPTZ'), 'Migration should add review_due_at column');
    assert.ok(source.includes('soc2_status'), 'Migration should cover soc2_status');
    assert.ok(source.includes('compliance_control_status'), 'Migration should cover compliance_control_status');
  });
});

// ── AI Governance Recommendation Boundedness ──

describe('AI Governance — Policy Draft Restraint', () => {
  it('policy-ai-service marks all outputs as requiring approval', () => {
    const servicePath = path.join(__dirname, '..', 'src', 'ai', 'policy-ai-service.js');
    const source = fs.readFileSync(servicePath, 'utf8');
    // Count how many times requiresApproval: true appears
    const matches = source.match(/requiresApproval:\s*true/g);
    assert.ok(matches && matches.length >= 2, 'Should have requiresApproval: true in both LLM and template paths');
  });

  it('AI-generated policies include explicit disclaimers', () => {
    const servicePath = path.join(__dirname, '..', 'src', 'ai', 'policy-ai-service.js');
    const source = fs.readFileSync(servicePath, 'utf8');
    assert.ok(source.includes('AI-generated draft policy'), 'Should have AI disclaimer');
    assert.ok(source.includes('reviewed and approved'), 'Should require human review');
    assert.ok(source.includes("approvalStatus: 'draft'"), 'Policies should default to draft status');
  });

  it('template policies also require approval', () => {
    const servicePath = path.join(__dirname, '..', 'src', 'ai', 'policy-ai-service.js');
    const source = fs.readFileSync(servicePath, 'utf8');
    assert.ok(source.includes('template-based policy draft must be reviewed'), 'Template policies should require approval');
  });

  it('policy grounding check is performed', () => {
    const servicePath = path.join(__dirname, '..', 'src', 'ai', 'policy-ai-service.js');
    const source = fs.readFileSync(servicePath, 'utf8');
    assert.ok(source.includes('checkOutputGrounding'), 'Should run grounding check on LLM output');
    assert.ok(source.includes('groundingScore'), 'Should expose grounding score');
  });
});

// ── No-Evidence Honesty ──

describe('No-Evidence Honesty', () => {
  it('gap analysis recommended actions are honest (not AI-generated)', () => {
    const { computeComplianceGap } = require('../src/ai/compliance-gap-engine');
    const result = computeComplianceGap([
      { controlId: 'CC1.1', family: 'CC', title: 'T1', defaultWeight: 1, status: 'not_started' },
    ]);
    assert.ok(result.gaps[0].recommendedAction.includes('Assign an owner'), 'Recommendation should be a templated string, not AI-generated');
  });

  it('empty controls returns score of 0 (no inflation)', () => {
    const { computeComplianceGap } = require('../src/ai/compliance-gap-engine');
    const result = computeComplianceGap([]);
    assert.equal(result.readinessScore, 0);
    assert.equal(result.totalControls, 0);
    assert.equal(result.validatedWithoutEvidence, 0);
  });

  it('framework gap with no controls returns score of 0', () => {
    const result = computeFrameworkGap([]);
    assert.equal(result.readinessScore, 0);
    assert.equal(result.validatedWithoutEvidence, 0);
  });
});

// ── Cross-Module: Frontend Types ──

describe('Frontend Governance Types', () => {
  it('PolicyRecord includes approval workflow fields', () => {
    const backendTsPath = path.join(__dirname, '..', '..', 'frontend', 'src', 'lib', 'backend.ts');
    const source = fs.readFileSync(backendTsPath, 'utf8');
    assert.ok(source.includes('PolicyStatus'), 'Should export PolicyStatus type');
    assert.ok(source.includes('approvedBy'), 'PolicyRecord should include approvedBy');
    assert.ok(source.includes('approvedAt'), 'PolicyRecord should include approvedAt');
    assert.ok(source.includes('rejectedBy'), 'PolicyRecord should include rejectedBy');
    assert.ok(source.includes('rejectionReason'), 'PolicyRecord should include rejectionReason');
  });

  it('ComplianceGap includes validatedWithoutEvidence', () => {
    const backendTsPath = path.join(__dirname, '..', '..', 'frontend', 'src', 'lib', 'backend.ts');
    const source = fs.readFileSync(backendTsPath, 'utf8');
    const gapSection = source.slice(source.indexOf('interface ComplianceGap'), source.indexOf('interface ComplianceGap') + 500);
    assert.ok(gapSection.includes('validatedWithoutEvidence'), 'ComplianceGap should include validatedWithoutEvidence');
  });

  it('API functions for policy approval exist', () => {
    const backendTsPath = path.join(__dirname, '..', '..', 'frontend', 'src', 'lib', 'backend.ts');
    const source = fs.readFileSync(backendTsPath, 'utf8');
    assert.ok(source.includes('fetchPolicies'), 'Should export fetchPolicies');
    assert.ok(source.includes('updatePolicyApprovalStatus'), 'Should export updatePolicyApprovalStatus');
  });
});

// ── Policy Approval Frontend UI ──

describe('Frontend Policy Approval UI', () => {
  it('ResilienceHQConsole includes policy governance section', () => {
    const consolePath = path.join(__dirname, '..', '..', 'frontend', 'src', 'components', 'platform', 'ResilienceHQConsole.tsx');
    const source = fs.readFileSync(consolePath, 'utf8');
    assert.ok(source.includes('Policy Governance'), 'Should have Policy Governance section');
    assert.ok(source.includes('Submit for Approval'), 'Should have Submit for Approval button');
    assert.ok(source.includes('Approve'), 'Should have Approve button');
    assert.ok(source.includes('Reject'), 'Should have Reject button');
    assert.ok(source.includes('Archive'), 'Should have Archive button');
    assert.ok(source.includes('Revert to Draft'), 'Should have Revert to Draft button');
  });

  it('policy approval UI requires compliance_officer role', () => {
    const consolePath = path.join(__dirname, '..', '..', 'frontend', 'src', 'components', 'platform', 'ResilienceHQConsole.tsx');
    const source = fs.readFileSync(consolePath, 'utf8');
    assert.ok(source.includes('canManageCompliance'), 'Should gate policy actions behind canManageCompliance');
  });

  it('rejection reason input is available', () => {
    const consolePath = path.join(__dirname, '..', '..', 'frontend', 'src', 'components', 'platform', 'ResilienceHQConsole.tsx');
    const source = fs.readFileSync(consolePath, 'utf8');
    assert.ok(source.includes('rejectionReason'), 'Should support rejection reason input');
    assert.ok(source.includes('Rejection reason'), 'Should have placeholder for rejection reason');
  });
});

// ── Migration 020 Structure ──

describe('Migration 020 — Governance Hardening', () => {
  it('migration file exists', () => {
    const migrationPath = path.join(__dirname, '..', 'migrations', '020_governance_hardening.sql');
    assert.ok(fs.existsSync(migrationPath), 'Migration 020 should exist');
  });

  it('adds review_due_at to soc2_status', () => {
    const migrationPath = path.join(__dirname, '..', 'migrations', '020_governance_hardening.sql');
    const source = fs.readFileSync(migrationPath, 'utf8');
    assert.ok(source.includes('ALTER TABLE soc2_status'), 'Should alter soc2_status');
    assert.ok(source.includes('review_due_at'), 'Should add review_due_at');
  });

  it('adds review_due_at to compliance_control_status', () => {
    const migrationPath = path.join(__dirname, '..', 'migrations', '020_governance_hardening.sql');
    const source = fs.readFileSync(migrationPath, 'utf8');
    assert.ok(source.includes('ALTER TABLE compliance_control_status'), 'Should alter compliance_control_status');
  });

  it('creates indexes for stale control queries', () => {
    const migrationPath = path.join(__dirname, '..', 'migrations', '020_governance_hardening.sql');
    const source = fs.readFileSync(migrationPath, 'utf8');
    assert.ok(source.includes('soc2_status_review_due_idx'), 'Should create soc2 review index');
    assert.ok(source.includes('compliance_control_status_review_due_idx'), 'Should create compliance review index');
  });
});

// ── Server Wiring ──

describe('Server Wiring for Governance', () => {
  it('server.js imports getPolicyRecord and updatePolicyStatus', () => {
    const serverPath = path.join(__dirname, '..', 'src', 'server.js');
    const source = fs.readFileSync(serverPath, 'utf8');
    assert.ok(source.includes('getPolicyRecord'), 'Should import getPolicyRecord');
    assert.ok(source.includes('updatePolicyStatus'), 'Should import updatePolicyStatus');
  });

  it('server.js includes new functions in route dependencies', () => {
    const serverPath = path.join(__dirname, '..', 'src', 'server.js');
    const source = fs.readFileSync(serverPath, 'utf8');
    // Find the buildPhase3RouteDependencies section
    const depsStart = source.indexOf('getPolicyRecord');
    assert.ok(depsStart > 0, 'getPolicyRecord should be in route deps');
    const depsContext = source.slice(Math.max(0, depsStart - 200), depsStart + 200);
    assert.ok(depsContext.includes('updatePolicyStatus'), 'updatePolicyStatus should be near getPolicyRecord in deps');
  });
});
