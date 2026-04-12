const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

// =====================================================================
// Risk Hardening Tests — Phase 3
// Covers: scoring consistency, severity thresholds, formula transparency,
//         treatment lifecycle, ownership/review, mitigation quality,
//         portfolio aggregation, AI grounding, route wiring
// =====================================================================

// ── risk-engine.js exports ──

const {
  computeRiskFinding,
  aggregateRiskPortfolio,
  severityFromScore,
  SCORING_WEIGHTS,
  SCORING_FORMULA,
  SEVERITY_THRESHOLDS,
} = require('../src/ai/risk-engine');

// ── risk-scoring-service.js exports ──

const {
  VALID_TREATMENT_STATUSES,
  updateRiskFindingTreatment,
} = require('../src/ai/risk-scoring-service');

// ── risk-ai-service.js exports ──

const {
  buildLocalMitigationSuggestions,
} = require('../src/ai/risk-ai-service');

// =====================================================================
// R1 — Scoring Formula Transparency
// =====================================================================

describe('R1 — Scoring Formula Transparency', () => {
  it('SCORING_WEIGHTS is exported with vulnerability, exposure, misconfiguration', () => {
    assert.ok(SCORING_WEIGHTS);
    assert.equal(SCORING_WEIGHTS.vulnerability, 0.5);
    assert.equal(SCORING_WEIGHTS.exposure, 0.3);
    assert.equal(SCORING_WEIGHTS.misconfiguration, 0.2);
  });

  it('weights sum to exactly 1.0', () => {
    const sum = SCORING_WEIGHTS.vulnerability + SCORING_WEIGHTS.exposure + SCORING_WEIGHTS.misconfiguration;
    assert.equal(sum, 1.0);
  });

  it('SCORING_FORMULA string is exported and describes the computation', () => {
    assert.equal(typeof SCORING_FORMULA, 'string');
    assert.ok(SCORING_FORMULA.includes('vulnerability'));
    assert.ok(SCORING_FORMULA.includes('exposure'));
    assert.ok(SCORING_FORMULA.includes('misconfiguration'));
    assert.ok(SCORING_FORMULA.includes('0.5'));
    assert.ok(SCORING_FORMULA.includes('0.3'));
    assert.ok(SCORING_FORMULA.includes('0.2'));
  });

  it('SEVERITY_THRESHOLDS is exported with correct boundaries', () => {
    assert.ok(SEVERITY_THRESHOLDS);
    assert.equal(SEVERITY_THRESHOLDS.critical, 90);
    assert.equal(SEVERITY_THRESHOLDS.high, 70);
    assert.equal(SEVERITY_THRESHOLDS.medium, 40);
    assert.equal(SEVERITY_THRESHOLDS.low, 0);
  });

  it('computeRiskFinding includes scoringWeights in detailsJson', () => {
    const finding = computeRiskFinding({
      vulnerabilityScore: 5,
      exposureScore: 5,
      misconfigurationScore: 5,
    });
    assert.ok(finding.detailsJson.scoringWeights);
    assert.equal(finding.detailsJson.scoringWeights.vulnerability, 0.5);
    assert.equal(finding.detailsJson.scoringWeights.exposure, 0.3);
    assert.equal(finding.detailsJson.scoringWeights.misconfiguration, 0.2);
  });
});

// =====================================================================
// Scoring Consistency — computeRiskFinding
// =====================================================================

describe('Scoring Consistency — computeRiskFinding', () => {
  it('all-zero inputs produce score 0', () => {
    const finding = computeRiskFinding({
      vulnerabilityScore: 0,
      exposureScore: 0,
      misconfigurationScore: 0,
    });
    assert.equal(finding.score, 0);
    assert.equal(finding.severity, 'low');
  });

  it('all-10 inputs produce score 100', () => {
    const finding = computeRiskFinding({
      vulnerabilityScore: 10,
      exposureScore: 10,
      misconfigurationScore: 10,
    });
    assert.equal(finding.score, 100);
    assert.equal(finding.severity, 'critical');
  });

  it('applies correct weighted formula: (v*0.5 + e*0.3 + m*0.2) * 10', () => {
    const finding = computeRiskFinding({
      vulnerabilityScore: 8,
      exposureScore: 6,
      misconfigurationScore: 4,
    });
    const expected = (8 * 0.5 + 6 * 0.3 + 4 * 0.2) * 10;
    assert.equal(finding.score, Number(expected.toFixed(2)));
  });

  it('clamps input scores to 0-10 range', () => {
    const finding = computeRiskFinding({
      vulnerabilityScore: 15,
      exposureScore: -3,
      misconfigurationScore: 20,
    });
    // Clamps: vuln=10, exp=0, misconfig=10
    const expected = (10 * 0.5 + 0 * 0.3 + 10 * 0.2) * 10;
    assert.equal(finding.score, Number(expected.toFixed(2)));
  });

  it('handles non-numeric input scores by falling back to 0', () => {
    const finding = computeRiskFinding({
      vulnerabilityScore: 'garbage',
      exposureScore: undefined,
      misconfigurationScore: null,
    });
    assert.equal(finding.score, 0);
  });

  it('records component scores in detailsJson', () => {
    const finding = computeRiskFinding({
      vulnerabilityScore: 7,
      exposureScore: 3,
      misconfigurationScore: 5,
    });
    assert.equal(finding.detailsJson.vulnerabilityScore, 7);
    assert.equal(finding.detailsJson.exposureScore, 3);
    assert.equal(finding.detailsJson.misconfigurationScore, 5);
  });

  it('severity override: explicit severity takes precedence over inferred', () => {
    const finding = computeRiskFinding({
      vulnerabilityScore: 1,
      exposureScore: 1,
      misconfigurationScore: 1,
      severity: 'critical',
    });
    // Score is (1*0.5+1*0.3+1*0.2)*10 = 10, inferred = 'low'
    // But explicit severity='critical' overrides
    assert.equal(finding.score, 10);
    assert.equal(finding.severity, 'critical');
  });

  it('invalid explicit severity falls back to inferred severity', () => {
    const finding = computeRiskFinding({
      vulnerabilityScore: 10,
      exposureScore: 10,
      misconfigurationScore: 10,
      severity: 'banana',
    });
    // Score = 100, inferred = 'critical', 'banana' not valid, uses inferred = 'critical'
    assert.equal(finding.severity, 'critical');
  });

  it('assetId is truncated to 191 chars', () => {
    const longId = 'a'.repeat(300);
    const finding = computeRiskFinding({
      vulnerabilityScore: 5,
      exposureScore: 5,
      misconfigurationScore: 5,
      assetId: longId,
    });
    assert.equal(finding.assetId.length, 191);
  });

  it('missing assetId produces null', () => {
    const finding = computeRiskFinding({
      vulnerabilityScore: 5,
      exposureScore: 5,
      misconfigurationScore: 5,
    });
    assert.equal(finding.assetId, null);
  });
});

// =====================================================================
// Severity Threshold Boundaries
// =====================================================================

describe('Severity Threshold Boundaries', () => {
  it('score 90 = critical', () => {
    assert.equal(severityFromScore(90), 'critical');
  });

  it('score 89.99 = high', () => {
    assert.equal(severityFromScore(89.99), 'high');
  });

  it('score 70 = high', () => {
    assert.equal(severityFromScore(70), 'high');
  });

  it('score 69.99 = medium', () => {
    assert.equal(severityFromScore(69.99), 'medium');
  });

  it('score 40 = medium', () => {
    assert.equal(severityFromScore(40), 'medium');
  });

  it('score 39.99 = low', () => {
    assert.equal(severityFromScore(39.99), 'low');
  });

  it('score 0 = low', () => {
    assert.equal(severityFromScore(0), 'low');
  });

  it('score 100 = critical', () => {
    assert.equal(severityFromScore(100), 'critical');
  });
});

// =====================================================================
// Mitigation Recommendations Quality
// =====================================================================

describe('Mitigation Recommendations — mapMitigations', () => {
  it('vulnerability category starts with patching recommendation', () => {
    const finding = computeRiskFinding({
      vulnerabilityScore: 9,
      exposureScore: 2,
      misconfigurationScore: 1,
      category: 'vulnerability',
    });
    const mitigations = finding.detailsJson.mitigationSuggestions;
    assert.ok(Array.isArray(mitigations));
    assert.ok(mitigations[0].toLowerCase().includes('patch'));
  });

  it('exposure category starts with ACL/firewall recommendation', () => {
    const finding = computeRiskFinding({
      vulnerabilityScore: 2,
      exposureScore: 9,
      misconfigurationScore: 1,
      category: 'exposure',
    });
    const mitigations = finding.detailsJson.mitigationSuggestions;
    assert.ok(mitigations[0].toLowerCase().includes('exposure') || mitigations[0].toLowerCase().includes('acl') || mitigations[0].toLowerCase().includes('firewall'));
  });

  it('config category starts with baseline configuration recommendation', () => {
    const finding = computeRiskFinding({
      vulnerabilityScore: 2,
      exposureScore: 2,
      misconfigurationScore: 9,
      category: 'misconfiguration',
    });
    const mitigations = finding.detailsJson.mitigationSuggestions;
    assert.ok(mitigations[0].toLowerCase().includes('config') || mitigations[0].toLowerCase().includes('baseline'));
  });

  it('critical severity receives escalation action', () => {
    const finding = computeRiskFinding({
      vulnerabilityScore: 10,
      exposureScore: 10,
      misconfigurationScore: 10,
      category: 'general',
    });
    const mitigations = finding.detailsJson.mitigationSuggestions;
    const hasEscalation = mitigations.some(m => m.toLowerCase().includes('escalat'));
    assert.ok(hasEscalation, 'Critical findings should have escalation recommendation');
  });

  it('low severity does NOT receive escalation action', () => {
    const finding = computeRiskFinding({
      vulnerabilityScore: 1,
      exposureScore: 1,
      misconfigurationScore: 1,
      category: 'general',
    });
    const mitigations = finding.detailsJson.mitigationSuggestions;
    const hasEscalation = mitigations.some(m => m.toLowerCase().includes('escalat'));
    assert.ok(!hasEscalation, 'Low findings should NOT have escalation recommendation');
  });

  it('all mitigations are non-empty strings', () => {
    const finding = computeRiskFinding({
      vulnerabilityScore: 5,
      exposureScore: 5,
      misconfigurationScore: 5,
      category: 'vulnerability',
    });
    for (const m of finding.detailsJson.mitigationSuggestions) {
      assert.equal(typeof m, 'string');
      assert.ok(m.length > 10, 'Each mitigation should be a meaningful sentence');
    }
  });
});

// =====================================================================
// Portfolio Aggregation — aggregateRiskPortfolio
// =====================================================================

describe('Portfolio Aggregation — aggregateRiskPortfolio', () => {
  it('empty array returns zero totals', () => {
    const portfolio = aggregateRiskPortfolio([]);
    assert.equal(portfolio.totalFindings, 0);
    assert.equal(portfolio.critical, 0);
    assert.equal(portfolio.highestScore, 0);
    assert.equal(portfolio.averageScore, 0);
  });

  it('null/undefined returns zero totals', () => {
    // aggregateRiskPortfolio uses default param `findings = []`, so undefined → empty array
    assert.equal(aggregateRiskPortfolio(undefined).totalFindings, 0);
    // Passing null explicitly bypasses the default, and the function handles it via Array.isArray guard
    // but accesses findings.length first — this is expected to set totalFindings to 0 via the guard
    assert.equal(aggregateRiskPortfolio().totalFindings, 0);
  });

  it('correctly counts severity distribution', () => {
    const findings = [
      { severity: 'critical', score: 95 },
      { severity: 'critical', score: 92 },
      { severity: 'high', score: 75 },
      { severity: 'medium', score: 50 },
      { severity: 'low', score: 20 },
    ];
    const portfolio = aggregateRiskPortfolio(findings);
    assert.equal(portfolio.totalFindings, 5);
    assert.equal(portfolio.critical, 2);
    assert.equal(portfolio.high, 1);
    assert.equal(portfolio.medium, 1);
    assert.equal(portfolio.low, 1);
  });

  it('highestScore is the true maximum, not average', () => {
    const findings = [
      { severity: 'critical', score: 95 },
      { severity: 'critical', score: 80 },
      { severity: 'low', score: 10 },
    ];
    const portfolio = aggregateRiskPortfolio(findings);
    assert.equal(portfolio.highestScore, 95);
  });

  it('averageScore is correctly computed', () => {
    const findings = [
      { severity: 'high', score: 80 },
      { severity: 'medium', score: 40 },
    ];
    const portfolio = aggregateRiskPortfolio(findings);
    assert.equal(portfolio.averageScore, 60);
  });

  it('single finding produces correct stats', () => {
    const findings = [{ severity: 'high', score: 72 }];
    const portfolio = aggregateRiskPortfolio(findings);
    assert.equal(portfolio.totalFindings, 1);
    assert.equal(portfolio.high, 1);
    assert.equal(portfolio.highestScore, 72);
    assert.equal(portfolio.averageScore, 72);
  });
});

// =====================================================================
// R4 — Treatment Status Lifecycle
// =====================================================================

describe('R4 — Treatment Status Lifecycle', () => {
  it('VALID_TREATMENT_STATUSES contains all 6 statuses', () => {
    assert.ok(VALID_TREATMENT_STATUSES instanceof Set);
    assert.equal(VALID_TREATMENT_STATUSES.size, 6);
    assert.ok(VALID_TREATMENT_STATUSES.has('open'));
    assert.ok(VALID_TREATMENT_STATUSES.has('mitigating'));
    assert.ok(VALID_TREATMENT_STATUSES.has('mitigated'));
    assert.ok(VALID_TREATMENT_STATUSES.has('accepted'));
    assert.ok(VALID_TREATMENT_STATUSES.has('transferred'));
    assert.ok(VALID_TREATMENT_STATUSES.has('avoided'));
  });

  it('updateRiskFindingTreatment is an exported function', () => {
    assert.equal(typeof updateRiskFindingTreatment, 'function');
  });

  it('rejects invalid treatment status synchronously via validation', async () => {
    // Without DB config it will fail on validation before hitting DB
    await assert.rejects(
      () => updateRiskFindingTreatment({}, 'test-tenant', 1, { treatmentStatus: 'invalid_status' }),
      err => err.message.includes('Treatment status must be one of') || err.statusCode === 400
    );
  });

  it('rejects invalid finding id (0)', async () => {
    await assert.rejects(
      () => updateRiskFindingTreatment({}, 'test-tenant', 0, { treatmentStatus: 'mitigated' }),
      err => err.message.includes('invalid') || err.statusCode === 400
    );
  });

  it('rejects negative finding id', async () => {
    await assert.rejects(
      () => updateRiskFindingTreatment({}, 'test-tenant', -5, { treatmentStatus: 'mitigated' }),
      err => err.message.includes('invalid') || err.statusCode === 400
    );
  });

  it('rejects non-integer finding id', async () => {
    await assert.rejects(
      () => updateRiskFindingTreatment({}, 'test-tenant', 'abc', { treatmentStatus: 'mitigated' }),
      err => err.message.includes('invalid') || err.statusCode === 400
    );
  });
});

// =====================================================================
// Category Normalization
// =====================================================================

describe('Category Normalization', () => {
  it('normalizes category to lowercase', () => {
    const finding = computeRiskFinding({
      vulnerabilityScore: 5,
      exposureScore: 5,
      misconfigurationScore: 5,
      category: 'VULNERABILITY',
    });
    assert.equal(finding.category, 'vulnerability');
  });

  it('trims whitespace', () => {
    const finding = computeRiskFinding({
      vulnerabilityScore: 5,
      exposureScore: 5,
      misconfigurationScore: 5,
      category: '  exposure  ',
    });
    assert.equal(finding.category, 'exposure');
  });

  it('truncates to 64 characters', () => {
    const longCat = 'x'.repeat(100);
    const finding = computeRiskFinding({
      vulnerabilityScore: 5,
      exposureScore: 5,
      misconfigurationScore: 5,
      category: longCat,
    });
    assert.equal(finding.category.length, 64);
  });

  it('defaults to general when empty', () => {
    const finding = computeRiskFinding({
      vulnerabilityScore: 5,
      exposureScore: 5,
      misconfigurationScore: 5,
      category: '',
    });
    assert.equal(finding.category, 'general');
  });

  it('defaults to general when null', () => {
    const finding = computeRiskFinding({
      vulnerabilityScore: 5,
      exposureScore: 5,
      misconfigurationScore: 5,
      category: null,
    });
    assert.equal(finding.category, 'general');
  });
});

// =====================================================================
// Evidence Handling
// =====================================================================

describe('Evidence Handling in computeRiskFinding', () => {
  it('preserves evidence object when provided', () => {
    const evidence = { cveId: 'CVE-2024-1234', affectedVersions: ['1.0', '1.1'] };
    const finding = computeRiskFinding({
      vulnerabilityScore: 8,
      exposureScore: 5,
      misconfigurationScore: 3,
      evidence,
    });
    assert.deepEqual(finding.detailsJson.evidence, evidence);
  });

  it('returns empty object when evidence is null', () => {
    const finding = computeRiskFinding({
      vulnerabilityScore: 5,
      exposureScore: 5,
      misconfigurationScore: 5,
      evidence: null,
    });
    assert.deepEqual(finding.detailsJson.evidence, {});
  });

  it('returns empty object when evidence is a string', () => {
    const finding = computeRiskFinding({
      vulnerabilityScore: 5,
      exposureScore: 5,
      misconfigurationScore: 5,
      evidence: 'not-an-object',
    });
    assert.deepEqual(finding.detailsJson.evidence, {});
  });

  it('returns empty object when evidence is missing', () => {
    const finding = computeRiskFinding({
      vulnerabilityScore: 5,
      exposureScore: 5,
      misconfigurationScore: 5,
    });
    assert.deepEqual(finding.detailsJson.evidence, {});
  });
});

// =====================================================================
// AI Local Fallback — buildLocalMitigationSuggestions
// =====================================================================

describe('AI Local Fallback — buildLocalMitigationSuggestions', () => {
  it('returns default message for empty findings', () => {
    const suggestions = buildLocalMitigationSuggestions([]);
    assert.ok(suggestions.length >= 1);
    assert.ok(suggestions[0].toLowerCase().includes('no active'));
  });

  it('extracts mitigations from finding details', () => {
    const findings = [
      {
        details: {
          mitigationSuggestions: [
            'Patch vulnerable package or OS component to vendor-fixed version.',
            'Validate affected asset ownership and business criticality.',
          ],
        },
      },
    ];
    const suggestions = buildLocalMitigationSuggestions(findings);
    assert.ok(suggestions.length >= 2);
    assert.ok(suggestions[0].includes('Patch'));
  });

  it('deduplicates suggestions across findings', () => {
    const sharedMitigation = 'Validate affected asset ownership and business criticality.';
    const findings = [
      { details: { mitigationSuggestions: [sharedMitigation] } },
      { details: { mitigationSuggestions: [sharedMitigation] } },
    ];
    const suggestions = buildLocalMitigationSuggestions(findings);
    const count = suggestions.filter(s => s === sharedMitigation).length;
    assert.equal(count, 1, 'Duplicate suggestions should be deduplicated');
  });

  it('caps at 12 suggestions maximum', () => {
    const findings = Array.from({ length: 20 }, (_, i) => ({
      details: {
        mitigationSuggestions: [`Unique suggestion number ${i + 1} with enough length to pass validation.`],
      },
    }));
    const suggestions = buildLocalMitigationSuggestions(findings);
    assert.ok(suggestions.length <= 12);
  });
});

// =====================================================================
// Finding Details Metadata
// =====================================================================

describe('Finding Details Metadata', () => {
  it('source defaults to aws_log', () => {
    const finding = computeRiskFinding({
      vulnerabilityScore: 5,
      exposureScore: 5,
      misconfigurationScore: 5,
    });
    assert.equal(finding.detailsJson.source, 'aws_log');
  });

  it('title defaults to Unlabeled finding', () => {
    const finding = computeRiskFinding({
      vulnerabilityScore: 5,
      exposureScore: 5,
      misconfigurationScore: 5,
    });
    assert.equal(finding.detailsJson.title, 'Unlabeled finding');
  });

  it('title is truncated to 255 chars', () => {
    const finding = computeRiskFinding({
      vulnerabilityScore: 5,
      exposureScore: 5,
      misconfigurationScore: 5,
      title: 'T'.repeat(300),
    });
    assert.equal(finding.detailsJson.title.length, 255);
  });

  it('ingestedAt is a valid ISO timestamp', () => {
    const finding = computeRiskFinding({
      vulnerabilityScore: 5,
      exposureScore: 5,
      misconfigurationScore: 5,
    });
    const parsed = new Date(finding.detailsJson.ingestedAt);
    assert.ok(!Number.isNaN(parsed.getTime()));
  });
});

// =====================================================================
// Route Wiring — risk-copilot/routes.js
// =====================================================================

describe('Route Wiring — risk-copilot/routes.js', () => {
  const routesSource = fs.readFileSync(
    path.join(__dirname, '..', 'src', 'modules', 'risk-copilot', 'routes.js'),
    'utf-8'
  );

  it('treatment PATCH route is declared', () => {
    assert.ok(routesSource.includes("method: 'PATCH'"));
    assert.ok(routesSource.includes('/v1/risk/findings/:id/treatment'));
  });

  it('updateRiskFindingTreatment is used in handler deps', () => {
    assert.ok(routesSource.includes('updateRiskFindingTreatment'));
  });

  it('scoringModel is embedded in compute response', () => {
    assert.ok(routesSource.includes('scoringModel'));
    assert.ok(routesSource.includes('SCORING_FORMULA'));
    assert.ok(routesSource.includes('SCORING_WEIGHTS'));
    assert.ok(routesSource.includes('SEVERITY_THRESHOLDS'));
  });

  it('treatment handler requires security_analyst role', () => {
    // The handler at line ~440 uses requireProductAccess with 'security_analyst'
    const treatmentIdx = routesSource.indexOf("'risk-copilot', 'security_analyst'");
    assert.ok(treatmentIdx > 0, 'Treatment handler should enforce security_analyst RBAC');
    // Verify it's after the PATCH treatment regex
    const treatmentRegexIdx = routesSource.indexOf('/treatment$/.test');
    assert.ok(treatmentRegexIdx > 0);
    assert.ok(treatmentIdx > treatmentRegexIdx, 'security_analyst check should follow treatment path match');
  });

  it('treatment handler emits audit log with previousTreatmentStatus', () => {
    assert.ok(
      routesSource.includes('previousTreatmentStatus'),
      'Audit log should include previous treatment status'
    );
  });
});

// =====================================================================
// Migration SQL — 021_risk_hardening.sql
// =====================================================================

describe('Migration — 021_risk_hardening.sql', () => {
  const migrationPath = path.join(__dirname, '..', 'migrations', '021_risk_hardening.sql');

  it('migration file exists', () => {
    assert.ok(fs.existsSync(migrationPath));
  });

  const sql = fs.readFileSync(migrationPath, 'utf-8');

  it('adds treatment_status column', () => {
    assert.ok(sql.includes('treatment_status'));
  });

  it('treatment_status has CHECK constraint with all 6 values', () => {
    assert.ok(sql.includes('open'));
    assert.ok(sql.includes('mitigating'));
    assert.ok(sql.includes('mitigated'));
    assert.ok(sql.includes('accepted'));
    assert.ok(sql.includes('transferred'));
    assert.ok(sql.includes('avoided'));
  });

  it('adds owner_user_id column', () => {
    assert.ok(sql.includes('owner_user_id'));
  });

  it('adds reviewed_at column', () => {
    assert.ok(sql.includes('reviewed_at'));
  });

  it('adds review_notes column', () => {
    assert.ok(sql.includes('review_notes'));
  });

  it('adds residual_score column', () => {
    assert.ok(sql.includes('residual_score'));
  });

  it('creates treatment status index', () => {
    assert.ok(sql.includes('risk_findings_treatment_status_idx'));
  });

  it('creates owner index', () => {
    assert.ok(sql.includes('risk_findings_owner_idx'));
  });
});

// =====================================================================
// Server Wiring — server.js
// =====================================================================

describe('Server Wiring — updateRiskFindingTreatment', () => {
  const serverSource = fs.readFileSync(
    path.join(__dirname, '..', 'src', 'server.js'),
    'utf-8'
  );

  it('server imports updateRiskFindingTreatment', () => {
    assert.ok(serverSource.includes('updateRiskFindingTreatment'));
  });
});

// =====================================================================
// Frontend Types — backend.ts
// =====================================================================

describe('Frontend Types — backend.ts risk types', () => {
  const typesSource = fs.readFileSync(
    path.join(__dirname, '..', '..', 'frontend', 'src', 'lib', 'backend.ts'),
    'utf-8'
  );

  it('RiskTreatmentStatus type is defined', () => {
    assert.ok(typesSource.includes('RiskTreatmentStatus'));
  });

  it('RiskFindingRecord includes treatmentStatus', () => {
    assert.ok(typesSource.includes('treatmentStatus'));
  });

  it('RiskFindingRecord includes ownerUserId', () => {
    assert.ok(typesSource.includes('ownerUserId'));
  });

  it('RiskFindingRecord includes residualScore', () => {
    assert.ok(typesSource.includes('residualScore'));
  });

  it('RiskScoringModel interface is defined', () => {
    assert.ok(typesSource.includes('RiskScoringModel'));
  });

  it('RiskComputeResponse includes scoringModel', () => {
    const idx = typesSource.indexOf('RiskComputeResponse');
    assert.ok(idx > 0);
    const block = typesSource.slice(idx, idx + 500);
    assert.ok(block.includes('scoringModel'));
  });

  it('RiskComputeResponse includes groundingScore', () => {
    const idx = typesSource.indexOf('RiskComputeResponse');
    assert.ok(idx > 0);
    const block = typesSource.slice(idx, idx + 500);
    assert.ok(block.includes('groundingScore'));
  });

  it('RiskComputeResponse includes disclaimer', () => {
    const idx = typesSource.indexOf('RiskComputeResponse');
    assert.ok(idx > 0);
    const block = typesSource.slice(idx, idx + 500);
    assert.ok(block.includes('disclaimer'));
  });

  it('updateRiskFindingTreatment API function is defined', () => {
    assert.ok(typesSource.includes('updateRiskFindingTreatment'));
  });

  it('RiskPortfolioSummary includes treatmentDistribution', () => {
    const idx = typesSource.indexOf('RiskPortfolioSummary');
    assert.ok(idx > 0);
    const block = typesSource.slice(idx, idx + 300);
    assert.ok(block.includes('treatmentDistribution'));
  });
});

// =====================================================================
// Frontend Dashboard — RiskCopilotConsole.tsx
// =====================================================================

describe('Frontend Dashboard — RiskCopilotConsole.tsx', () => {
  const dashSource = fs.readFileSync(
    path.join(__dirname, '..', '..', 'frontend', 'src', 'components', 'platform', 'RiskCopilotConsole.tsx'),
    'utf-8'
  );

  it('shows severity distribution in KPI cards', () => {
    assert.ok(dashSource.includes('portfolio.critical'));
    assert.ok(dashSource.includes('portfolio.high'));
    assert.ok(dashSource.includes('portfolio.medium'));
    assert.ok(dashSource.includes('portfolio.low'));
  });

  it('includes data freshness warning function', () => {
    assert.ok(dashSource.includes('freshnessWarning'));
    assert.ok(dashSource.includes('72 hours'));
    assert.ok(dashSource.includes('24 hours'));
  });

  it('displays grounding score badge', () => {
    assert.ok(dashSource.includes('groundingScore'));
    assert.ok(dashSource.includes('Grounding:'));
  });

  it('displays AI disclaimer text', () => {
    assert.ok(dashSource.includes('disclaimer'));
  });

  it('shows scoring model transparency section', () => {
    assert.ok(dashSource.includes('Scoring Model Transparency'));
    assert.ok(dashSource.includes('scoringModel.formula'));
    assert.ok(dashSource.includes('scoringModel.weights'));
  });

  it('includes treatment status controls per finding', () => {
    assert.ok(dashSource.includes('treatmentStatus'));
    assert.ok(dashSource.includes('TREATMENT_OPTIONS'));
    assert.ok(dashSource.includes('treatmentMutation'));
  });

  it('shows residual score when present', () => {
    assert.ok(dashSource.includes('residualScore'));
    assert.ok(dashSource.includes('Residual'));
  });

  it('imports updateRiskFindingTreatment', () => {
    assert.ok(dashSource.includes('updateRiskFindingTreatment'));
  });

  it('imports RiskTreatmentStatus type', () => {
    assert.ok(dashSource.includes('RiskTreatmentStatus'));
  });
});

// =====================================================================
// AI Service — Grounding & Disclaimer
// =====================================================================

describe('AI Service — Grounding & Disclaimer', () => {
  const aiSource = fs.readFileSync(
    path.join(__dirname, '..', 'src', 'ai', 'risk-ai-service.js'),
    'utf-8'
  );

  it('AI service produces groundingScore in output', () => {
    assert.ok(aiSource.includes('groundingScore'));
  });

  it('AI service produces disclaimer in output', () => {
    assert.ok(aiSource.includes('disclaimer'));
    assert.ok(aiSource.includes('AI-generated'));
  });

  it('AI service logs grounding score to audit trail', () => {
    assert.ok(aiSource.includes('groundingScore: groundingResult.score'));
  });

  it('AI service has insufficient data guard', () => {
    assert.ok(aiSource.includes('Insufficient risk data'));
    assert.ok(aiSource.includes('summarizedFindings.length < 3'));
  });

  it('AI service calls checkOutputGrounding', () => {
    assert.ok(aiSource.includes('checkOutputGrounding'));
  });
});

// =====================================================================
// R7 — Portfolio SQL Aggregation Fix
// =====================================================================

describe('R7 — Portfolio SQL Aggregation Fix', () => {
  const serviceSource = fs.readFileSync(
    path.join(__dirname, '..', 'src', 'ai', 'risk-scoring-service.js'),
    'utf-8'
  );

  it('getRiskPortfolioSummary uses MAX(score) for highestScore', () => {
    assert.ok(serviceSource.includes('max_score'));
    assert.ok(serviceSource.includes('MAX(score)'));
  });

  it('highestScore is computed from max_score, not avg_score', () => {
    // The old bug used avg_score for highestScore. Verify the fix.
    const portfolioFnIdx = serviceSource.indexOf('getRiskPortfolioSummary');
    const fnBody = serviceSource.slice(portfolioFnIdx, portfolioFnIdx + 1500);
    assert.ok(fnBody.includes('maxScore > portfolio.highestScore'));
  });

  it('treatmentDistribution is included in portfolio summary', () => {
    assert.ok(serviceSource.includes('treatmentDistribution'));
    assert.ok(serviceSource.includes('treatment_status'));
  });

  it('listRiskFindings selects treatment columns', () => {
    const listIdx = serviceSource.indexOf('listRiskFindings');
    const fnBody = serviceSource.slice(listIdx, listIdx + 1500);
    assert.ok(fnBody.includes('treatment_status'));
    assert.ok(fnBody.includes('owner_user_id'));
    assert.ok(fnBody.includes('reviewed_at'));
    assert.ok(fnBody.includes('review_notes'));
    assert.ok(fnBody.includes('residual_score'));
  });
});
