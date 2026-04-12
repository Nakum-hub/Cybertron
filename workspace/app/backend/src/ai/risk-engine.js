function toNumber(value, fallback = 0) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return parsed;
}

function clamp(value, minimum, maximum) {
  return Math.max(minimum, Math.min(maximum, value));
}

function normalizeCategory(value) {
  const normalized = String(value || 'general').trim().toLowerCase();
  if (!normalized) {
    return 'general';
  }
  return normalized.slice(0, 64);
}

function normalizeSeverity(value, fallback = 'medium') {
  const normalized = String(value || fallback).trim().toLowerCase();
  if (normalized === 'critical') return 'critical';
  if (normalized === 'high') return 'high';
  if (normalized === 'medium') return 'medium';
  if (normalized === 'low') return 'low';
  return fallback;
}

function severityFromScore(score) {
  if (score >= 90) return 'critical';
  if (score >= 70) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

function mapMitigations(category, severity) {
  const base = [
    'Validate affected asset ownership and business criticality.',
    'Open tracked remediation ticket with owner and due date.',
  ];

  if (category.includes('vuln')) {
    base.unshift('Patch vulnerable package or OS component to vendor-fixed version.');
  } else if (category.includes('exposure')) {
    base.unshift('Restrict external exposure using network ACL, WAF, or firewall policy.');
  } else if (category.includes('config')) {
    base.unshift('Apply secure baseline configuration and enforce drift detection.');
  } else {
    base.unshift('Investigate event context and confirm detection accuracy.');
  }

  if (severity === 'critical' || severity === 'high') {
    base.push('Escalate to incident commander and verify containment in under 4 hours.');
  }

  return base;
}

// Scoring formula constants — exposed for transparency
const SCORING_WEIGHTS = {
  vulnerability: 0.5,
  exposure: 0.3,
  misconfiguration: 0.2,
};
const SCORING_FORMULA = 'score = (vulnerability * 0.5 + exposure * 0.3 + misconfiguration * 0.2) * 10';
const SEVERITY_THRESHOLDS = { critical: 90, high: 70, medium: 40, low: 0 };

function computeRiskFinding(record) {
  const vulnerabilityScore = clamp(toNumber(record.vulnerabilityScore, 0), 0, 10);
  const exposureScore = clamp(toNumber(record.exposureScore, 0), 0, 10);
  const misconfigurationScore = clamp(toNumber(record.misconfigurationScore, 0), 0, 10);

  const weighted = (
    vulnerabilityScore * SCORING_WEIGHTS.vulnerability +
    exposureScore * SCORING_WEIGHTS.exposure +
    misconfigurationScore * SCORING_WEIGHTS.misconfiguration
  ) * 10;
  const score = Number(weighted.toFixed(2));
  const inferredSeverity = severityFromScore(score);
  const severity = normalizeSeverity(record.severity, inferredSeverity);
  const category = normalizeCategory(record.category);

  return {
    assetId: String(record.assetId || '').trim().slice(0, 191) || null,
    category,
    severity,
    score,
    detailsJson: {
      source: String(record.source || 'aws_log').trim().slice(0, 64) || 'aws_log',
      title: String(record.title || 'Unlabeled finding').trim().slice(0, 255),
      evidence: record.evidence && typeof record.evidence === 'object' ? record.evidence : {},
      vulnerabilityScore,
      exposureScore,
      misconfigurationScore,
      scoringWeights: SCORING_WEIGHTS,
      mitigationSuggestions: mapMitigations(category, severity),
      ingestedAt: new Date().toISOString(),
    },
  };
}

function aggregateRiskPortfolio(findings = []) {
  const totals = {
    totalFindings: findings.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    averageScore: 0,
    highestScore: 0,
  };

  if (!Array.isArray(findings) || findings.length === 0) {
    return totals;
  }

  let scoreSum = 0;
  for (const finding of findings) {
    const severity = normalizeSeverity(finding.severity);
    totals[severity] += 1;
    const score = toNumber(finding.score, 0);
    scoreSum += score;
    totals.highestScore = Math.max(totals.highestScore, score);
  }

  totals.averageScore = Number((scoreSum / findings.length).toFixed(2));
  return totals;
}

module.exports = {
  computeRiskFinding,
  aggregateRiskPortfolio,
  severityFromScore,
  SCORING_WEIGHTS,
  SCORING_FORMULA,
  SEVERITY_THRESHOLDS,
};
