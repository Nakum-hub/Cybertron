const { ServiceError } = require('../auth-service');

function safeText(value, maxLength) {
  const text = String(value || '').trim();
  if (!text) {
    return '';
  }
  return text.slice(0, maxLength);
}

function normalizeScore(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return 0;
  }
  if (parsed < 0) {
    return 0;
  }
  if (parsed > 10) {
    return 10;
  }
  return Number(parsed.toFixed(2));
}

function getCandidateRecords(payload) {
  if (Array.isArray(payload)) {
    return payload;
  }

  if (payload && typeof payload === 'object') {
    if (Array.isArray(payload.records)) return payload.records;
    if (Array.isArray(payload.findings)) return payload.findings;
    if (Array.isArray(payload.events)) return payload.events;
    if (Array.isArray(payload.Records)) return payload.Records;
  }

  return [];
}

function parseAwsLogJsonBuffer(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    throw new ServiceError(400, 'invalid_aws_log_upload', 'Uploaded AWS log file is empty.');
  }

  let payload;
  try {
    payload = JSON.parse(buffer.toString('utf8'));
  } catch {
    throw new ServiceError(400, 'invalid_aws_log_json', 'AWS log upload must be valid JSON.');
  }

  const records = getCandidateRecords(payload);
  if (!records.length) {
    throw new ServiceError(
      400,
      'invalid_aws_log_records',
      'AWS log JSON must include a non-empty records/findings/events array.'
    );
  }

  if (records.length > 5_000) {
    throw new ServiceError(
      413,
      'aws_log_too_many_records',
      'AWS log upload exceeds maximum record count (5000).'
    );
  }

  const normalized = records.map((record, idx) => {
    if (!record || typeof record !== 'object') {
      throw new ServiceError(
        400,
        'invalid_aws_log_record',
        `Record at index ${idx} must be an object.`
      );
    }

    const severity = safeText(record.severity || record.level, 16).toLowerCase() || 'medium';
    const category =
      safeText(record.category || record.findingType || record.controlType, 64).toLowerCase() || 'general';
    const assetId =
      safeText(record.assetId || record.resourceId || record.instanceId || record.arn, 191) || null;
    const vulnerabilityScore = normalizeScore(
      record.vulnerabilityScore ?? record.vulnScore ?? record.cvssScore
    );
    const exposureScore = normalizeScore(record.exposureScore ?? record.exposedScore ?? record.internetExposure);
    const misconfigurationScore = normalizeScore(
      record.misconfigurationScore ?? record.configScore ?? record.configurationRisk
    );

    return {
      source: 'aws_ingest',
      title: safeText(record.title || record.finding || record.description, 255) || `AWS finding ${idx + 1}`,
      severity,
      category,
      assetId,
      vulnerabilityScore,
      exposureScore,
      misconfigurationScore,
      evidence: {
        accountId: safeText(record.accountId, 64) || null,
        region: safeText(record.region, 32) || null,
        eventName: safeText(record.eventName, 128) || null,
        rawSeverity: safeText(record.severity || record.level, 64) || null,
      },
    };
  });

  return {
    records: normalized,
    count: normalized.length,
  };
}

module.exports = {
  parseAwsLogJsonBuffer,
};
