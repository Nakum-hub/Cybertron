const { ServiceError } = require('./auth-service');

function safeText(value, maxLength) {
  const text = String(value || '').trim();
  if (!text) {
    return '';
  }
  return text.slice(0, maxLength);
}

function getNestedValue(record, paths) {
  for (const path of paths) {
    const parts = String(path).split('.');
    let current = record;
    let matched = true;
    for (const part of parts) {
      if (!current || typeof current !== 'object' || !(part in current)) {
        matched = false;
        break;
      }
      current = current[part];
    }
    if (matched && current !== undefined && current !== null && String(current).trim() !== '') {
      return current;
    }
  }
  return null;
}

function normalizeSeverity(value) {
  const normalized = String(value || '').trim().toLowerCase();
  if (['critical', 'crit', 'sev1', 'p1'].includes(normalized)) return 'critical';
  if (['high', 'sev2', 'p2', 'major'].includes(normalized)) return 'high';
  if (['medium', 'med', 'moderate', 'sev3', 'p3'].includes(normalized)) return 'medium';
  if (['low', 'sev4', 'p4', 'minor'].includes(normalized)) return 'low';
  if (['info', 'informational', 'notice'].includes(normalized)) return 'info';

  const numeric = Number(value);
  if (Number.isFinite(numeric)) {
    if (numeric >= 9) return 'critical';
    if (numeric >= 7) return 'high';
    if (numeric >= 4) return 'medium';
    if (numeric > 0) return 'low';
    return 'info';
  }

  return 'medium';
}

function normalizeTimestamp(value) {
  if (!value) {
    return null;
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return null;
  }
  return parsed.toISOString();
}

function parseStructuredPayload(text) {
  try {
    return JSON.parse(text);
  } catch {
    const lines = text
      .split(/\r?\n/)
      .map(line => line.trim())
      .filter(Boolean);

    if (!lines.length) {
      throw new ServiceError(400, 'invalid_siem_log_upload', 'Uploaded SOC log file is empty.');
    }

    const records = lines.map((line, index) => {
      try {
        return JSON.parse(line);
      } catch {
        throw new ServiceError(
          400,
          'invalid_siem_log_jsonl',
          `Uploaded SOC log line ${index + 1} is not valid JSON.`
        );
      }
    });
    return { records };
  }
}

function getCandidateRecords(payload) {
  if (Array.isArray(payload)) {
    return payload;
  }

  if (payload && typeof payload === 'object') {
    if (Array.isArray(payload.records)) return payload.records;
    if (Array.isArray(payload.alerts)) return payload.alerts;
    if (Array.isArray(payload.events)) return payload.events;
    if (Array.isArray(payload.logs)) return payload.logs;
    if (Array.isArray(payload.findings)) return payload.findings;
  }

  return [];
}

function parseSiemLogJsonBuffer(buffer, { defaultSource } = {}) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    throw new ServiceError(400, 'invalid_siem_log_upload', 'Uploaded SOC log file is empty.');
  }

  const text = buffer.toString('utf8').trim();
  if (!text) {
    throw new ServiceError(400, 'invalid_siem_log_upload', 'Uploaded SOC log file is empty.');
  }

  let payload;
  try {
    payload = parseStructuredPayload(text);
  } catch (error) {
    if (error instanceof ServiceError) {
      throw error;
    }
    throw new ServiceError(400, 'invalid_siem_log_json', 'SOC log upload must be valid JSON or JSON Lines.');
  }

  const records = getCandidateRecords(payload);
  if (!records.length) {
    throw new ServiceError(
      400,
      'invalid_siem_log_records',
      'SOC log upload must include a non-empty records/alerts/events/logs array.'
    );
  }

  if (records.length > 5_000) {
    throw new ServiceError(
      413,
      'siem_log_too_many_records',
      'SOC log upload exceeds maximum record count (5000).'
    );
  }

  const fallbackSource = safeText(defaultSource, 128) || 'uploaded_log';
  const normalized = records.map((record, index) => {
    if (!record || typeof record !== 'object' || Array.isArray(record)) {
      throw new ServiceError(
        400,
        'invalid_siem_log_record',
        `SOC log record at index ${index} must be an object.`
      );
    }

    const source = safeText(
      getNestedValue(record, ['source', 'vendor', 'tool', 'product', 'provider']),
      128
    ) || fallbackSource;
    const alertId = safeText(
      getNestedValue(record, ['alertId', 'alert_id', 'id', 'eventId', 'event_id', 'findingId']),
      255
    ) || null;
    const ruleName = safeText(
      getNestedValue(record, ['ruleName', 'rule_name', 'title', 'name', 'signature', 'eventName', 'message']),
      255
    ) || `Uploaded event ${index + 1}`;
    const category = safeText(
      getNestedValue(record, ['category', 'eventType', 'event_type', 'type', 'findingType']),
      64
    ).toLowerCase() || 'generic';
    const sourceIp = safeText(
      getNestedValue(record, ['sourceIp', 'source_ip', 'srcIp', 'src_ip', 'clientIp', 'source.ip']),
      45
    ) || null;
    const destIp = safeText(
      getNestedValue(record, ['destIp', 'dest_ip', 'destinationIp', 'destination_ip', 'dstIp', 'dst_ip', 'destination.ip']),
      45
    ) || null;
    const hostname = safeText(
      getNestedValue(record, ['hostname', 'host', 'hostName', 'deviceName', 'assetId', 'resourceId']),
      255
    ) || null;
    const eventTime = normalizeTimestamp(
      getNestedValue(record, ['eventTime', 'event_time', 'timestamp', 'time', 'createdAt', 'observedAt'])
    );

    return {
      source,
      alertId,
      ruleName,
      severity: normalizeSeverity(getNestedValue(record, ['severity', 'level', 'priority', 'cvssScore'])),
      category,
      sourceIp,
      destIp,
      hostname,
      eventTime,
      rawPayload: record,
    };
  });

  return {
    records: normalized,
    count: normalized.length,
  };
}

module.exports = {
  parseSiemLogJsonBuffer,
};
