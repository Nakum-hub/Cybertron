const { query } = require('./database');
const { sanitizeTenant, toSafeInteger } = require('./validators');
const { appendAuditLog } = require('./audit-log');
const { ServiceError } = require('./auth-service');
const { getConnectorStatus } = require('./threat-connectors');

function normalizeSeverity(value) {
  const normalized = String(value || '').toLowerCase().trim();
  if (normalized === 'critical') return 'critical';
  if (normalized === 'high') return 'high';
  if (normalized === 'medium') return 'medium';
  if (normalized === 'low') return 'low';
  throw new ServiceError(400, 'invalid_severity', 'Severity must be one of critical/high/medium/low.');
}

function normalizeIncidentStatus(value) {
  const normalized = String(value || '').toLowerCase().trim();
  if (normalized === 'open') return 'open';
  if (normalized === 'investigating') return 'investigating';
  if (normalized === 'resolved') return 'resolved';
  if (normalized === 'closed') return 'closed';
  throw new ServiceError(400, 'invalid_status', 'Status must be one of open/investigating/resolved/closed.');
}

const INCIDENT_STATUS_TRANSITIONS = {
  'open':          ['investigating', 'resolved', 'closed'],
  'investigating': ['open', 'resolved', 'closed'],
  'resolved':      ['closed', 'open'],  // can reopen or close
  'closed':        ['open'],            // can reopen only
};

function normalizeIocType(value) {
  const normalized = String(value || '').toLowerCase().trim();
  if (normalized === 'ip') return 'ip';
  if (normalized === 'domain') return 'domain';
  if (normalized === 'url') return 'url';
  if (normalized === 'hash') return 'hash';
  throw new ServiceError(400, 'invalid_ioc_type', 'IOC type must be one of ip/domain/url/hash.');
}

function normalizePriority(value) {
  const normalized = String(value || '').toLowerCase().trim();
  if (normalized === 'critical') return 'critical';
  if (normalized === 'high') return 'high';
  if (normalized === 'medium') return 'medium';
  if (normalized === 'low') return 'low';
  return 'medium';
}

function normalizeRequestStatus(value) {
  const normalized = String(value || '').toLowerCase().trim();
  if (normalized === 'open') return 'open';
  if (normalized === 'triaged') return 'triaged';
  if (normalized === 'in_progress') return 'in_progress';
  if (normalized === 'resolved') return 'resolved';
  if (normalized === 'closed') return 'closed';
  throw new ServiceError(
    400,
    'invalid_request_status',
    'Service request status must be open/triaged/in_progress/resolved/closed.'
  );
}

function safeText(value, maxLength = 4096) {
  const text = String(value || '').trim();
  if (!text) {
    return '';
  }

  return text.slice(0, maxLength);
}

function escapeLikePattern(str) {
  return str.replace(/[%_\\]/g, '\\$&');
}

function normalizeActorUserId(value) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    return null;
  }

  return parsed;
}

function sanitizeMetadataObject(input, depth = 0) {
  if (depth > 8) {
    return {};
  }

  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return {};
  }

  const blockedKeys = new Set(['__proto__', 'constructor', 'prototype']);
  const output = {};
  for (const [key, value] of Object.entries(input)) {
    if (blockedKeys.has(key)) {
      continue;
    }

    if (value && typeof value === 'object' && !Array.isArray(value)) {
      output[key] = sanitizeMetadataObject(value, depth + 1);
      continue;
    }

    if (Array.isArray(value)) {
      output[key] = value
        .slice(0, 100)
        .map(item =>
          item && typeof item === 'object' && !Array.isArray(item)
            ? sanitizeMetadataObject(item, depth + 1)
            : item
        );
      continue;
    }

    output[key] = value;
  }

  return output;
}

function parseDateOrNow(value) {
  const date = value ? new Date(value) : new Date();
  if (Number.isNaN(date.getTime())) {
    throw new ServiceError(400, 'invalid_date', 'Invalid date value.');
  }

  return date.toISOString();
}

function asIncident(row) {
  return {
    id: String(row.id),
    tenant: row.tenant_slug,
    title: row.title,
    severity: row.severity,
    status: row.status,
    priority: row.priority || row.severity || 'medium',
    blocked: Boolean(row.blocked),
    source: row.source || null,
    assignedTo: row.assigned_to ? String(row.assigned_to) : null,
    assignedAt: row.assigned_at ? new Date(row.assigned_at).toISOString() : null,
    detectedAt: new Date(row.detected_at).toISOString(),
    resolvedAt: row.resolved_at ? new Date(row.resolved_at).toISOString() : null,
    responseTimeMinutes: row.response_time_minutes === null ? null : Number(row.response_time_minutes),
    escalatedFromAlertId: row.escalated_from_alert_id ? String(row.escalated_from_alert_id) : null,
    createdAt: row.created_at ? new Date(row.created_at).toISOString() : null,
  };
}

function iocConfidenceToSeverity(confidence) {
  const c = Number(confidence) || 0;
  if (c >= 90) return 'critical';
  if (c >= 70) return 'high';
  if (c >= 40) return 'medium';
  return 'low';
}

function asIoc(row) {
  const confidence = Number(row.confidence);
  return {
    id: String(row.id),
    tenant: row.tenant_slug,
    type: row.ioc_type,
    value: row.value,
    source: row.source || null,
    confidence,
    severity: iocConfidenceToSeverity(confidence),
    firstSeenAt: row.first_seen_at ? new Date(row.first_seen_at).toISOString() : null,
    lastSeenAt: row.last_seen_at ? new Date(row.last_seen_at).toISOString() : null,
    tags: row.tags || [],
    createdAt: row.created_at ? new Date(row.created_at).toISOString() : null,
  };
}

function asServiceRequest(row) {
  return {
    id: String(row.id),
    tenant: row.tenant_slug,
    requesterEmail: row.requester_email,
    category: row.category,
    priority: row.priority,
    status: row.status,
    subject: row.subject,
    description: row.description || null,
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString(),
  };
}

function asReport(row) {
  return {
    id: String(row.id),
    tenant: row.tenant_slug,
    reportType: row.report_type,
    reportDate: row.report_date,
    storagePath: row.storage_path || null,
    storageProvider: row.storage_provider || 'local',
    checksumSha256: row.checksum_sha256 || null,
    fileName: row.file_name || null,
    mimeType: row.mime_type || null,
    sizeBytes: row.size_bytes === null ? null : Number(row.size_bytes),
    idempotencyKey: row.idempotency_key || null,
    metadata: row.metadata || {},
    uploadedAt: row.uploaded_at ? new Date(row.uploaded_at).toISOString() : null,
    createdAt: new Date(row.created_at).toISOString(),
  };
}

async function listIncidents(config, tenant, options = {}) {
  const tenantSlug = sanitizeTenant(tenant);
  const limit = toSafeInteger(options.limit, 25, 1, 100);
  const offset = toSafeInteger(options.offset, 0, 0, 50_000);

  const where = ['tenant_slug = $1'];
  const values = [tenantSlug];

  if (options.severity) {
    values.push(normalizeSeverity(options.severity));
    where.push(`severity = $${values.length}`);
  }

  if (options.status) {
    values.push(normalizeIncidentStatus(options.status));
    where.push(`status = $${values.length}`);
  }

  if (options.search) {
    values.push(`%${escapeLikePattern(safeText(options.search, 128))}%`);
    where.push(`title ILIKE $${values.length}`);
  }

  const whereClause = where.join(' AND ');
  const countResult = await query(
    config,
    `SELECT COUNT(*)::INT AS total FROM incidents WHERE ${whereClause}`,
    values
  );
  const total = Number(countResult?.rows?.[0]?.total || 0);

  values.push(limit, offset);
  const rows = await query(
    config,
    `
      SELECT
        id, tenant_slug, title, severity, status, blocked, source, detected_at,
        resolved_at, response_time_minutes, created_at
      FROM incidents
      WHERE ${whereClause}
      ORDER BY detected_at DESC, id DESC
      LIMIT $${values.length - 1}
      OFFSET $${values.length}
    `,
    values
  );

  const data = (rows?.rows || []).map(asIncident);
  return {
    data,
    pagination: {
      limit,
      offset,
      total,
      hasMore: offset + data.length < total,
    },
    message: data.length
      ? undefined
      : 'No incidents ingested. Configure connectors or create incidents manually.',
  };
}

async function createIncident(config, tenant, payload, contextMeta = {}) {
  const tenantSlug = sanitizeTenant(tenant);
  const title = safeText(payload.title, 400);
  if (!title) {
    throw new ServiceError(400, 'invalid_title', 'Incident title is required.');
  }

  const severity = normalizeSeverity(payload.severity || 'medium');
  const status = normalizeIncidentStatus(payload.status || 'open');
  const source = safeText(payload.source, 128) || null;
  const blocked = Boolean(payload.blocked);
  const detectedAt = parseDateOrNow(payload.detectedAt);
  const responseTime = payload.responseTimeMinutes === undefined || payload.responseTimeMinutes === null
    ? null
    : toSafeInteger(payload.responseTimeMinutes, 0, 0, 100_000);
  const resolvedAt = payload.resolvedAt ? parseDateOrNow(payload.resolvedAt) : null;

  const inserted = await query(
    config,
    `
      INSERT INTO incidents (
        tenant_slug,
        title,
        severity,
        status,
        blocked,
        source,
        detected_at,
        resolved_at,
        response_time_minutes,
        raw_event
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)
      RETURNING
        id, tenant_slug, title, severity, status, priority, blocked, source, assigned_to, assigned_at,
        detected_at, resolved_at, response_time_minutes, escalated_from_alert_id, created_at
    `,
    [
      tenantSlug,
      title,
      severity,
      status,
      blocked,
      source,
      detectedAt,
      resolvedAt,
      responseTime,
      JSON.stringify(payload.rawEvent || {}),
    ]
  );

  const incident = asIncident(inserted.rows[0]);
  await query(
    config,
    `
      INSERT INTO incident_timeline (tenant_slug, incident_id, event_type, message, actor_user_id)
      VALUES ($1,$2,'created',$3,$4)
    `,
    [
      tenantSlug,
      Number(incident.id),
      safeText(payload.timelineMessage || 'Incident created', 512),
      normalizeActorUserId(contextMeta.actorUserId),
    ]
  );

  await appendAuditLog(config, {
    tenantSlug,
    actorId: contextMeta.actorUserId,
    actorEmail: contextMeta.actorEmail,
    action: 'incident.created',
    targetType: 'incident',
    targetId: incident.id,
    ipAddress: contextMeta.ipAddress,
    userAgent: contextMeta.userAgent,
    traceId: contextMeta.traceId,
    payload: {
      severity: incident.severity,
      status: incident.status,
    },
  });

  return incident;
}

async function updateIncident(config, tenant, incidentId, payload, contextMeta = {}) {
  const tenantSlug = sanitizeTenant(tenant);
  const id = Number(incidentId);
  if (!Number.isFinite(id) || id <= 0) {
    throw new ServiceError(400, 'invalid_incident_id', 'Incident id is invalid.');
  }

  const updates = [];
  const values = [tenantSlug, id];
  let previousStatus = null;

  const pushUpdate = (sqlFragment, value) => {
    values.push(value);
    updates.push(`${sqlFragment} = $${values.length}`);
  };

  if (payload.title !== undefined) {
    const title = safeText(payload.title, 400);
    if (!title) {
      throw new ServiceError(400, 'invalid_title', 'Incident title cannot be empty.');
    }
    pushUpdate('title', title);
  }
  if (payload.severity !== undefined) {
    pushUpdate('severity', normalizeSeverity(payload.severity));
  }
  if (payload.status !== undefined) {
    const newStatus = normalizeIncidentStatus(payload.status);

    // Enforce state machine: fetch current status
    const currentResult = await query(config,
      'SELECT status FROM incidents WHERE id = $1 AND tenant_slug = $2',
      [id, tenantSlug]
    );
    if (!currentResult?.rows?.length) {
      throw new ServiceError(404, 'incident_not_found', 'Incident was not found.');
    }
    const currentStatus = currentResult.rows[0].status;
    previousStatus = currentStatus;
    const allowed = INCIDENT_STATUS_TRANSITIONS[currentStatus] || [];
    if (currentStatus !== newStatus && !allowed.includes(newStatus)) {
      throw new ServiceError(400, 'invalid_status_transition',
        `Cannot transition from '${currentStatus}' to '${newStatus}'. Allowed transitions: ${allowed.join(', ') || 'none'}.`
      );
    }

    pushUpdate('status', newStatus);

    // Auto-set resolved_at when transitioning to resolved
    if (newStatus === 'resolved' && payload.resolvedAt === undefined) {
      pushUpdate('resolved_at', new Date().toISOString());
    }
  }
  if (payload.priority !== undefined) {
    pushUpdate('priority', normalizePriority(payload.priority));
  }
  if (payload.assignedTo !== undefined) {
    pushUpdate('assigned_to', payload.assignedTo ? Number(payload.assignedTo) : null);
    pushUpdate('assigned_at', payload.assignedTo ? new Date().toISOString() : null);
  }
  if (payload.blocked !== undefined) {
    pushUpdate('blocked', Boolean(payload.blocked));
  }
  if (payload.source !== undefined) {
    pushUpdate('source', safeText(payload.source, 128) || null);
  }
  if (payload.responseTimeMinutes !== undefined) {
    pushUpdate('response_time_minutes', toSafeInteger(payload.responseTimeMinutes, 0, 0, 100_000));
  }
  if (payload.resolvedAt !== undefined) {
    pushUpdate('resolved_at', payload.resolvedAt ? parseDateOrNow(payload.resolvedAt) : null);
  }

  if (!updates.length) {
    throw new ServiceError(400, 'no_updates', 'No fields were provided for update.');
  }

  const result = await query(
    config,
    `
      UPDATE incidents
      SET ${updates.join(', ')}
      WHERE tenant_slug = $1 AND id = $2
      RETURNING
        id, tenant_slug, title, severity, status, priority, blocked, source, assigned_to, assigned_at,
        detected_at, resolved_at, response_time_minutes, escalated_from_alert_id, created_at
    `,
    values
  );

  if (!result || !result.rows.length) {
    throw new ServiceError(404, 'incident_not_found', 'Incident was not found.');
  }

  const incident = asIncident(result.rows[0]);

  // Auto-generate timeline entry for status transitions
  if (previousStatus !== null && payload.status !== undefined && previousStatus !== payload.status) {
    const autoMessage = payload.timelineMessage
      || `Status changed from ${previousStatus} to ${incident.status}`;
    await query(
      config,
      `
        INSERT INTO incident_timeline (tenant_slug, incident_id, event_type, message, actor_user_id)
        VALUES ($1,$2,'status_change',$3,$4)
      `,
      [tenantSlug, id, safeText(autoMessage, 512), normalizeActorUserId(contextMeta.actorUserId)]
    );
  } else if (payload.timelineMessage) {
    await query(
      config,
      `
        INSERT INTO incident_timeline (tenant_slug, incident_id, event_type, message, actor_user_id)
        VALUES ($1,$2,'updated',$3,$4)
      `,
      [tenantSlug, id, safeText(payload.timelineMessage, 512), normalizeActorUserId(contextMeta.actorUserId)]
    );
  }

  await appendAuditLog(config, {
    tenantSlug,
    actorId: contextMeta.actorUserId,
    actorEmail: contextMeta.actorEmail,
    action: 'incident.updated',
    targetType: 'incident',
    targetId: incident.id,
    ipAddress: contextMeta.ipAddress,
    userAgent: contextMeta.userAgent,
    traceId: contextMeta.traceId,
    payload: {
      fields: Object.keys(payload || {}),
      previousStatus,
    },
  });

  return incident;
}

async function listIncidentTimeline(config, tenant, incidentId, limit = 100) {
  const tenantSlug = sanitizeTenant(tenant);
  const id = Number(incidentId);
  const cappedLimit = toSafeInteger(limit, 50, 1, 200);

  const result = await query(
    config,
    `
      SELECT
        id, tenant_slug, incident_id, event_type, message, actor_user_id, created_at
      FROM incident_timeline
      WHERE tenant_slug = $1 AND incident_id = $2
      ORDER BY created_at ASC
      LIMIT $3
    `,
    [tenantSlug, id, cappedLimit]
  );

  return (result?.rows || []).map(row => ({
    id: String(row.id),
    incidentId: String(row.incident_id),
    eventType: row.event_type,
    message: row.message,
    actorUserId: row.actor_user_id ? String(row.actor_user_id) : null,
    createdAt: new Date(row.created_at).toISOString(),
  }));
}

async function listIocs(config, tenant, options = {}) {
  const tenantSlug = sanitizeTenant(tenant);
  const limit = toSafeInteger(options.limit, 50, 1, 200);
  const offset = toSafeInteger(options.offset, 0, 0, 50_000);

  const where = ['tenant_slug = $1'];
  const values = [tenantSlug];

  if (options.iocType) {
    values.push(normalizeIocType(options.iocType));
    where.push(`ioc_type = $${values.length}`);
  }

  if (options.search) {
    values.push(`%${escapeLikePattern(safeText(options.search, 128))}%`);
    where.push(`value ILIKE $${values.length}`);
  }

  if (options.minConfidence !== undefined && options.minConfidence !== null) {
    const minConf = toSafeInteger(options.minConfidence, 0, 0, 100);
    values.push(minConf);
    where.push(`confidence >= $${values.length}`);
  }

  const whereClause = where.join(' AND ');
  const count = await query(
    config,
    `SELECT COUNT(*)::INT AS total FROM iocs WHERE ${whereClause}`,
    values
  );
  const total = Number(count?.rows?.[0]?.total || 0);

  values.push(limit, offset);
  const rows = await query(
    config,
    `
      SELECT
        id, tenant_slug, ioc_type, value, source, confidence, first_seen_at, last_seen_at, tags, created_at
      FROM iocs
      WHERE ${whereClause}
      ORDER BY COALESCE(last_seen_at, first_seen_at) DESC, id DESC
      LIMIT $${values.length - 1}
      OFFSET $${values.length}
    `,
    values
  );

  const data = (rows?.rows || []).map(asIoc);
  return {
    data,
    pagination: {
      limit,
      offset,
      total,
      hasMore: offset + data.length < total,
    },
    message: data.length ? undefined : 'No IOCs stored for this tenant yet.',
  };
}

async function createIoc(config, tenant, payload, contextMeta = {}) {
  const tenantSlug = sanitizeTenant(tenant);
  const iocType = normalizeIocType(payload.iocType);
  const value = safeText(payload.value, 1024);
  if (!value) {
    throw new ServiceError(400, 'invalid_ioc_value', 'IOC value is required.');
  }

  const confidence = toSafeInteger(payload.confidence, 50, 0, 100);
  const source = safeText(payload.source, 128) || null;
  const firstSeenAt = payload.firstSeenAt ? parseDateOrNow(payload.firstSeenAt) : new Date().toISOString();
  const lastSeenAt = payload.lastSeenAt ? parseDateOrNow(payload.lastSeenAt) : null;
  const tags = Array.isArray(payload.tags) ? payload.tags.slice(0, 20).map(item => safeText(item, 64)).filter(Boolean) : [];

  const result = await query(
    config,
    `
      INSERT INTO iocs (
        tenant_slug,
        ioc_type,
        value,
        source,
        confidence,
        first_seen_at,
        last_seen_at,
        tags,
        created_by_user_id
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9)
      ON CONFLICT (tenant_slug, ioc_type, value)
      DO UPDATE SET
        source = COALESCE(EXCLUDED.source, iocs.source),
        confidence = GREATEST(iocs.confidence, EXCLUDED.confidence),
        last_seen_at = COALESCE(EXCLUDED.last_seen_at, iocs.last_seen_at)
      RETURNING
        id, tenant_slug, ioc_type, value, source, confidence, first_seen_at, last_seen_at, tags, created_at
    `,
    [
      tenantSlug,
      iocType,
      value,
      source,
      confidence,
      firstSeenAt,
      lastSeenAt,
      JSON.stringify(tags),
      normalizeActorUserId(contextMeta.actorUserId),
    ]
  );

  const ioc = asIoc(result.rows[0]);
  await appendAuditLog(config, {
    tenantSlug,
    actorId: contextMeta.actorUserId,
    actorEmail: contextMeta.actorEmail,
    action: 'ioc.upserted',
    targetType: 'ioc',
    targetId: ioc.id,
    ipAddress: contextMeta.ipAddress,
    userAgent: contextMeta.userAgent,
    traceId: contextMeta.traceId,
    payload: {
      iocType: ioc.type,
      value: ioc.value,
    },
  });

  return ioc;
}

async function linkIocToIncident(config, tenant, incidentId, iocId, contextMeta = {}) {
  const tenantSlug = sanitizeTenant(tenant);
  const result = await query(
    config,
    `
      INSERT INTO incident_iocs (tenant_slug, incident_id, ioc_id)
      VALUES ($1,$2,$3)
      ON CONFLICT (tenant_slug, incident_id, ioc_id) DO NOTHING
      RETURNING id
    `,
    [tenantSlug, Number(incidentId), Number(iocId)]
  );

  await appendAuditLog(config, {
    tenantSlug,
    actorId: contextMeta.actorUserId,
    actorEmail: contextMeta.actorEmail,
    action: 'incident.ioc_linked',
    targetType: 'incident',
    targetId: String(incidentId),
    ipAddress: contextMeta.ipAddress,
    userAgent: contextMeta.userAgent,
    traceId: contextMeta.traceId,
    payload: {
      iocId: String(iocId),
      created: Boolean(result?.rows?.length),
    },
  });
}

async function createServiceRequest(config, tenant, payload, contextMeta = {}) {
  const tenantSlug = sanitizeTenant(tenant);
  const requesterEmail = safeText(payload.requesterEmail || contextMeta.actorEmail, 191).toLowerCase();
  if (!requesterEmail || !requesterEmail.includes('@')) {
    throw new ServiceError(400, 'invalid_requester_email', 'A valid requester email is required.');
  }

  const category = safeText(payload.category, 64);
  const subject = safeText(payload.subject, 255);
  const description = safeText(payload.description, 5000) || null;
  const priority = normalizePriority(payload.priority);

  if (!category) {
    throw new ServiceError(400, 'invalid_category', 'Service request category is required.');
  }
  if (!subject) {
    throw new ServiceError(400, 'invalid_subject', 'Service request subject is required.');
  }

  const inserted = await query(
    config,
    `
      INSERT INTO service_requests (
        tenant_slug,
        requester_email,
        category,
        priority,
        status,
        subject,
        description
      )
      VALUES ($1,$2,$3,$4,'open',$5,$6)
      RETURNING id, tenant_slug, requester_email, category, priority, status, subject, description, created_at, updated_at
    `,
    [tenantSlug, requesterEmail, category, priority, subject, description]
  );

  const requestRecord = asServiceRequest(inserted.rows[0]);

  if (payload.comment) {
    await addServiceRequestComment(config, tenantSlug, requestRecord.id, payload.comment, contextMeta);
  }

  await appendAuditLog(config, {
    tenantSlug,
    actorId: contextMeta.actorUserId,
    actorEmail: requesterEmail,
    action: 'service_request.created',
    targetType: 'service_request',
    targetId: requestRecord.id,
    ipAddress: contextMeta.ipAddress,
    userAgent: contextMeta.userAgent,
    traceId: contextMeta.traceId,
    payload: {
      category,
      priority,
    },
  });

  return requestRecord;
}

async function updateServiceRequest(config, tenant, requestId, payload, contextMeta = {}) {
  const tenantSlug = sanitizeTenant(tenant);
  const id = Number(requestId);
  if (!Number.isFinite(id) || id <= 0) {
    throw new ServiceError(400, 'invalid_request_id', 'Service request id is invalid.');
  }

  const updates = [];
  const values = [tenantSlug, id];
  const pushUpdate = (column, value) => {
    values.push(value);
    updates.push(`${column} = $${values.length}`);
  };

  if (payload.priority !== undefined) {
    pushUpdate('priority', normalizePriority(payload.priority));
  }
  if (payload.status !== undefined) {
    pushUpdate('status', normalizeRequestStatus(payload.status));
  }
  if (payload.category !== undefined) {
    const category = safeText(payload.category, 64);
    if (!category) {
      throw new ServiceError(400, 'invalid_category', 'Category cannot be empty.');
    }
    pushUpdate('category', category);
  }
  if (payload.subject !== undefined) {
    const subject = safeText(payload.subject, 255);
    if (!subject) {
      throw new ServiceError(400, 'invalid_subject', 'Subject cannot be empty.');
    }
    pushUpdate('subject', subject);
  }
  if (payload.description !== undefined) {
    pushUpdate('description', safeText(payload.description, 5000) || null);
  }

  if (!updates.length && !payload.comment) {
    throw new ServiceError(400, 'no_updates', 'No fields provided for service request update.');
  }

  let updated = null;
  if (updates.length) {
    updated = await query(
      config,
      `
        UPDATE service_requests
        SET ${updates.join(', ')}, updated_at = NOW()
        WHERE tenant_slug = $1 AND id = $2
        RETURNING id, tenant_slug, requester_email, category, priority, status, subject, description, created_at, updated_at
      `,
      values
    );
  } else {
    updated = await query(
      config,
      `
        SELECT id, tenant_slug, requester_email, category, priority, status, subject, description, created_at, updated_at
        FROM service_requests
        WHERE tenant_slug = $1 AND id = $2
        LIMIT 1
      `,
      [tenantSlug, id]
    );
  }

  if (!updated || !updated.rows.length) {
    throw new ServiceError(404, 'service_request_not_found', 'Service request was not found.');
  }

  if (payload.comment) {
    await addServiceRequestComment(config, tenantSlug, id, payload.comment, contextMeta);
  }

  const requestRecord = asServiceRequest(updated.rows[0]);
  await appendAuditLog(config, {
    tenantSlug,
    actorId: contextMeta.actorUserId,
    actorEmail: contextMeta.actorEmail,
    action: 'service_request.updated',
    targetType: 'service_request',
    targetId: requestRecord.id,
    ipAddress: contextMeta.ipAddress,
    userAgent: contextMeta.userAgent,
    traceId: contextMeta.traceId,
    payload: {
      fields: Object.keys(payload || {}),
    },
  });

  return requestRecord;
}

async function addServiceRequestComment(config, tenantSlug, requestId, comment, contextMeta = {}) {
  const body = safeText(comment, 4000);
  if (!body) {
    throw new ServiceError(400, 'invalid_comment', 'Comment cannot be empty.');
  }

  const result = await query(
    config,
    `
      INSERT INTO service_request_comments (
        request_id,
        tenant_slug,
        author_user_id,
        author_email,
        body
      )
      VALUES ($1,$2,$3,$4,$5)
      RETURNING id, request_id, author_user_id, author_email, body, created_at
    `,
    [
      Number(requestId),
      tenantSlug,
      normalizeActorUserId(contextMeta.actorUserId),
      contextMeta.actorEmail || null,
      body,
    ]
  );

  return {
    id: String(result.rows[0].id),
    requestId: String(result.rows[0].request_id),
    authorUserId: result.rows[0].author_user_id ? String(result.rows[0].author_user_id) : null,
    authorEmail: result.rows[0].author_email || null,
    body: result.rows[0].body,
    createdAt: new Date(result.rows[0].created_at).toISOString(),
  };
}

async function listServiceRequestComments(config, tenant, requestId, limit = 100) {
  const tenantSlug = sanitizeTenant(tenant);
  const cappedLimit = toSafeInteger(limit, 50, 1, 200);
  const id = Number(requestId);

  const result = await query(
    config,
    `
      SELECT id, request_id, author_user_id, author_email, body, created_at
      FROM service_request_comments
      WHERE tenant_slug = $1 AND request_id = $2
      ORDER BY created_at ASC
      LIMIT $3
    `,
    [tenantSlug, id, cappedLimit]
  );

  return (result?.rows || []).map(row => ({
    id: String(row.id),
    requestId: String(row.request_id),
    authorUserId: row.author_user_id ? String(row.author_user_id) : null,
    authorEmail: row.author_email || null,
    body: row.body,
    createdAt: new Date(row.created_at).toISOString(),
  }));
}

async function createReport(config, tenant, payload, contextMeta = {}) {
  const tenantSlug = sanitizeTenant(tenant);
  const reportType = safeText(payload.reportType, 64);
  const reportDate = safeText(payload.reportDate, 24);
  const storagePath = safeText(payload.storagePath, 2048) || null;
  const storageProvider = safeText(payload.storageProvider || 'local', 32) || 'local';
  const checksumSha256 = safeText(payload.checksumSha256, 128) || null;
  const fileName = safeText(payload.fileName, 255) || null;
  const mimeType = safeText(payload.mimeType, 128) || null;
  const idempotencyKey = safeText(payload.idempotencyKey, 128) || null;
  const sizeBytes = payload.sizeBytes === undefined || payload.sizeBytes === null
    ? null
    : toSafeInteger(payload.sizeBytes, 0, 0, 1_000_000_000);
  const metadata = sanitizeMetadataObject(payload.metadata);

  if (!reportType) {
    throw new ServiceError(400, 'invalid_report_type', 'Report type is required.');
  }
  if (!reportDate) {
    throw new ServiceError(400, 'invalid_report_date', 'Report date is required.');
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(reportDate) || Number.isNaN(new Date(`${reportDate}T00:00:00Z`).getTime())) {
    throw new ServiceError(400, 'invalid_report_date', 'Report date must be in YYYY-MM-DD format.');
  }

  const inserted = await query(
    config,
    `
      INSERT INTO reports (
        tenant_slug,
        report_type,
        report_date,
        storage_path,
        storage_provider,
        checksum_sha256,
        metadata,
        file_name,
        mime_type,
        size_bytes,
        idempotency_key
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11)
      RETURNING
        id, tenant_slug, report_type, report_date, storage_path, checksum_sha256,
        metadata, file_name, mime_type, size_bytes, idempotency_key, storage_provider,
        uploaded_at, created_at
    `,
    [
      tenantSlug,
      reportType,
      reportDate,
      storagePath,
      storageProvider,
      checksumSha256,
      JSON.stringify(metadata),
      fileName,
      mimeType,
      sizeBytes,
      idempotencyKey,
    ]
  );

  const report = asReport(inserted.rows[0]);
  await appendAuditLog(config, {
    tenantSlug,
    actorId: contextMeta.actorUserId,
    actorEmail: contextMeta.actorEmail,
    action: 'report.created',
    targetType: 'report',
    targetId: report.id,
    ipAddress: contextMeta.ipAddress,
    userAgent: contextMeta.userAgent,
    traceId: contextMeta.traceId,
    payload: {
      reportType: report.reportType,
      fileName: report.fileName,
    },
  });

  return report;
}

async function getReportById(config, tenant, reportId) {
  const tenantSlug = sanitizeTenant(tenant);
  const id = Number(reportId);

  const result = await query(
    config,
    `
      SELECT
        id, tenant_slug, report_type, report_date, storage_path, checksum_sha256,
        metadata, file_name, mime_type, size_bytes, idempotency_key, storage_provider,
        uploaded_at, created_at
      FROM reports
      WHERE tenant_slug = $1 AND id = $2
      LIMIT 1
    `,
    [tenantSlug, id]
  );

  if (!result || !result.rows.length) {
    throw new ServiceError(404, 'report_not_found', 'Report was not found.');
  }

  return asReport(result.rows[0]);
}

async function findReportByIdempotencyKey(config, tenant, idempotencyKey) {
  const tenantSlug = sanitizeTenant(tenant);
  const key = safeText(idempotencyKey, 128);
  if (!key) {
    return null;
  }

  const result = await query(
    config,
    `
      SELECT
        id, tenant_slug, report_type, report_date, storage_path, checksum_sha256,
        metadata, file_name, mime_type, size_bytes, idempotency_key, storage_provider,
        uploaded_at, created_at
      FROM reports
      WHERE tenant_slug = $1 AND idempotency_key = $2
      LIMIT 1
    `,
    [tenantSlug, key]
  );

  if (!result || !result.rows.length) {
    return null;
  }

  return asReport(result.rows[0]);
}

async function findReportByChecksum(config, tenant, payload = {}) {
  const tenantSlug = sanitizeTenant(tenant);
  const checksum = safeText(payload.checksumSha256, 128);
  const reportType = safeText(payload.reportType, 64);
  const reportDate = safeText(payload.reportDate, 24);
  const fileName = safeText(payload.fileName, 255);
  const sizeBytes = payload.sizeBytes === undefined || payload.sizeBytes === null
    ? null
    : toSafeInteger(payload.sizeBytes, 0, 0, 1_000_000_000);

  if (!checksum || !reportType || !reportDate) {
    return null;
  }

  const result = await query(
    config,
    `
      SELECT
        id, tenant_slug, report_type, report_date, storage_path, checksum_sha256,
        metadata, file_name, mime_type, size_bytes, idempotency_key, storage_provider,
        uploaded_at, created_at
      FROM reports
      WHERE tenant_slug = $1
        AND checksum_sha256 = $2
        AND report_type = $3
        AND report_date = $4
        AND ($5::BIGINT IS NULL OR size_bytes = $5)
        AND ($6::TEXT IS NULL OR file_name = $6)
      ORDER BY created_at DESC
      LIMIT 1
    `,
    [tenantSlug, checksum, reportType, reportDate, sizeBytes, fileName || null]
  );

  if (!result || !result.rows.length) {
    return null;
  }

  return asReport(result.rows[0]);
}

async function logReportDownload(config, tenant, reportId, contextMeta = {}) {
  const tenantSlug = sanitizeTenant(tenant);
  await query(
    config,
    `
      INSERT INTO report_download_logs (
        tenant_slug,
        report_id,
        actor_user_id,
        actor_email,
        ip_address,
        user_agent,
        trace_id
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7)
    `,
    [
      tenantSlug,
      Number(reportId),
      normalizeActorUserId(contextMeta.actorUserId),
      contextMeta.actorEmail || null,
      contextMeta.ipAddress || null,
      contextMeta.userAgent || null,
      contextMeta.traceId || null,
    ]
  );

  await appendAuditLog(config, {
    tenantSlug,
    actorId: contextMeta.actorUserId,
    actorEmail: contextMeta.actorEmail,
    action: 'report.downloaded',
    targetType: 'report',
    targetId: String(reportId),
    ipAddress: contextMeta.ipAddress,
    userAgent: contextMeta.userAgent,
    traceId: contextMeta.traceId,
    payload: {},
  });
}

async function getConnectorsStatus(config, log) {
  const status = await getConnectorStatus(config, log);
  return {
    checkedAt: new Date().toISOString(),
    connectors: status,
  };
}

// --- List tenant analysts for assignment dropdowns ---

async function listTenantAnalysts(config, tenant) {
  if (!config.databaseUrl) return { data: [] };

  const tenantSlug = sanitizeTenant(tenant);
  const result = await query(
    config,
    `
      SELECT u.id, u.email, u.display_name
      FROM users u
      WHERE u.tenant_slug = $1
        AND u.is_active = TRUE
        AND u.role IN ('security_analyst', 'tenant_admin', 'super_admin')
      ORDER BY u.display_name ASC, u.email ASC
      LIMIT 100
    `,
    [tenantSlug]
  );

  return {
    data: (result?.rows || []).map(row => ({
      id: row.id,
      email: row.email,
      displayName: row.display_name || row.email,
    })),
  };
}

module.exports = {
  listIncidents,
  createIncident,
  updateIncident,
  listIncidentTimeline,
  listIocs,
  createIoc,
  linkIocToIncident,
  createServiceRequest,
  updateServiceRequest,
  listServiceRequestComments,
  createReport,
  findReportByIdempotencyKey,
  findReportByChecksum,
  getReportById,
  logReportDownload,
  getConnectorsStatus,
  listTenantAnalysts,
};
