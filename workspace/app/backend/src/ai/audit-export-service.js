const { generateAuditPackagePdf } = require('./report-generator');
const { computeComplianceGap } = require('./compliance-gap-engine');

function buildAuditManifest(payload = {}) {
  const controls = Array.isArray(payload.controls) ? payload.controls : [];
  const evidence = Array.isArray(payload.evidence) ? payload.evidence : [];
  const policies = Array.isArray(payload.policies) ? payload.policies : [];
  const gap = computeComplianceGap(controls);

  return {
    tenant: payload.tenant || 'global',
    generatedAt: payload.generatedAt || new Date().toISOString(),
    controlsCount: controls.length,
    evidenceCount: evidence.length,
    policiesCount: policies.length,
    readinessScore: gap.readinessScore,
    gapSummary: {
      notStarted: gap.notStarted,
      inProgress: gap.inProgress,
      implemented: gap.implemented,
      validated: gap.validated,
      notApplicable: gap.notApplicable,
    },
  };
}

function buildAuditPackage(payload = {}) {
  const manifest = buildAuditManifest(payload);
  const pdfBuffer = generateAuditPackagePdf({
    tenant: payload.tenant,
    generatedAt: manifest.generatedAt,
    controls: payload.controls,
    evidence: payload.evidence,
    policies: payload.policies,
  });

  return {
    pdfBuffer,
    manifest,
  };
}

module.exports = {
  buildAuditManifest,
  buildAuditPackage,
};
