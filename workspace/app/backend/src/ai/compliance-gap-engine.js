function weightForStatus(status) {
  const normalized = String(status || '').trim().toLowerCase();
  if (normalized === 'validated') return 1.0;
  if (normalized === 'implemented') return 0.8;
  if (normalized === 'in_progress') return 0.45;
  if (normalized === 'not_applicable') return 1.0;
  return 0.0;
}

function computeComplianceGap(controls = []) {
  const summary = {
    totalControls: 0,
    validated: 0,
    implemented: 0,
    inProgress: 0,
    notStarted: 0,
    notApplicable: 0,
    readinessScore: 0,
    gaps: [],
    validatedWithoutEvidence: 0,
    staleControls: 0,
  };

  if (!Array.isArray(controls) || controls.length === 0) {
    return summary;
  }

  const now = Date.now();
  const STALE_THRESHOLD_MS = 365 * 24 * 60 * 60 * 1000; // 12 months
  let weightedScore = 0;
  let totalWeight = 0;
  for (const control of controls) {
    const status = String(control.status || 'not_started').trim().toLowerCase();
    const weight = Number(control.defaultWeight || 1);
    const normalizedWeight = Number.isFinite(weight) && weight > 0 ? weight : 1;
    summary.totalControls += 1;
    totalWeight += normalizedWeight;
    weightedScore += normalizedWeight * weightForStatus(status);

    if (status === 'validated') {
      summary.validated += 1;
      if (Number(control.evidenceCount || 0) === 0) {
        summary.validatedWithoutEvidence += 1;
      }
    }
    else if (status === 'implemented') summary.implemented += 1;
    else if (status === 'in_progress') summary.inProgress += 1;
    else if (status === 'not_applicable') summary.notApplicable += 1;
    else summary.notStarted += 1;

    // G6: Staleness — controls validated/implemented but not updated in 12+ months
    if ((status === 'validated' || status === 'implemented') && control.updatedAt) {
      const updatedMs = new Date(control.updatedAt).getTime();
      if (Number.isFinite(updatedMs) && (now - updatedMs) > STALE_THRESHOLD_MS) {
        summary.staleControls += 1;
      }
    }

    if (status !== 'validated' && status !== 'not_applicable') {
      summary.gaps.push({
        controlId: control.controlId,
        family: control.family,
        title: control.title,
        status,
        evidenceCount: Number(control.evidenceCount || 0),
        recommendedAction:
          status === 'not_started'
            ? 'Assign an owner and publish implementation timeline.'
            : status === 'in_progress'
              ? 'Complete implementation and collect objective evidence.'
              : 'Run validation review and attach auditor-ready evidence.',
      });
    }
  }

  summary.readinessScore = totalWeight > 0 ? Number(((weightedScore / totalWeight) * 100).toFixed(2)) : 0;
  summary.gaps.sort((a, b) => {
    if (a.status === b.status) {
      return a.controlId.localeCompare(b.controlId);
    }
    if (a.status === 'not_started') return -1;
    if (b.status === 'not_started') return 1;
    if (a.status === 'in_progress') return -1;
    if (b.status === 'in_progress') return 1;
    return 0;
  });

  return summary;
}

module.exports = {
  computeComplianceGap,
};
