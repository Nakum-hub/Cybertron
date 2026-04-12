const { query } = require('../database');
const { sanitizeTenant, toSafeInteger } = require('../validators');
const { ServiceError } = require('../auth-service');

const ALLOWED_SOC2_STATUS = new Set([
  'not_started',
  'in_progress',
  'implemented',
  'validated',
  'not_applicable',
]);

// Valid governance state transitions — controls must progress through the lifecycle.
// not_applicable can be set from any state, and any state can revert to not_started.
const VALID_TRANSITIONS = {
  'not_started':     ['in_progress', 'not_applicable'],
  'in_progress':     ['implemented', 'not_started', 'not_applicable'],
  'implemented':     ['validated', 'in_progress', 'not_applicable'],
  'validated':       ['implemented', 'not_applicable'],
  'not_applicable':  ['not_started'],
};

function validateTransition(currentStatus, newStatus) {
  if (currentStatus === newStatus) return; // no-op is always safe
  const allowed = VALID_TRANSITIONS[currentStatus];
  if (!allowed || !allowed.includes(newStatus)) {
    throw new ServiceError(
      400,
      'invalid_status_transition',
      `Cannot transition from '${currentStatus}' to '${newStatus}'. Allowed: ${(allowed || []).join(', ')}.`
    );
  }
}

const ALLOWED_POLICY_STATUS = new Set([
  'draft',
  'pending_approval',
  'approved',
  'rejected',
  'archived',
]);

function normalizeControlId(value) {
  const normalized = String(value || '').trim().toUpperCase();
  if (!/^[A-Z0-9.-]{2,64}$/.test(normalized)) {
    throw new ServiceError(400, 'invalid_control_id', 'Control id is invalid.');
  }
  return normalized;
}

function normalizeStatus(value) {
  const normalized = String(value || '').trim().toLowerCase();
  if (!ALLOWED_SOC2_STATUS.has(normalized)) {
    throw new ServiceError(
      400,
      'invalid_soc2_status',
      'Status must be one of not_started/in_progress/implemented/validated/not_applicable.'
    );
  }
  return normalized;
}

function normalizeActorUserId(value) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    return null;
  }
  return parsed;
}

function safeText(value, maxLength = 1024) {
  const text = String(value || '').trim();
  if (!text) {
    return '';
  }
  return text.slice(0, maxLength);
}

async function listSoc2Controls(config) {
  const result = await query(
    config,
    `
      SELECT control_id, family, title, description, default_weight
      FROM soc2_controls
      ORDER BY control_id ASC
    `
  );

  return (result?.rows || []).map(row => ({
    controlId: row.control_id,
    family: row.family,
    title: row.title,
    description: row.description,
    defaultWeight: Number(row.default_weight || 1),
  }));
}

async function listSoc2Status(config, tenant) {
  const tenantSlug = sanitizeTenant(tenant || 'global');
  const result = await query(
    config,
    `
      SELECT
        c.control_id,
        c.family,
        c.title,
        c.description,
        c.default_weight,
        COALESCE(s.status, 'not_started') AS status,
        s.owner_user_id,
        COALESCE(s.evidence_count, 0) AS evidence_count,
        s.notes,
        s.updated_at
      FROM soc2_controls c
      LEFT JOIN soc2_status s
        ON s.control_id = c.control_id
       AND s.tenant_slug = $1
      ORDER BY c.control_id ASC
    `,
    [tenantSlug]
  );

  return (result?.rows || []).map(row => ({
    controlId: row.control_id,
    family: row.family,
    title: row.title,
    description: row.description,
    defaultWeight: Number(row.default_weight || 1),
    status: row.status,
    ownerUserId: row.owner_user_id ? String(row.owner_user_id) : null,
    evidenceCount: Number(row.evidence_count || 0),
    notes: row.notes || '',
    updatedAt: row.updated_at ? new Date(row.updated_at).toISOString() : null,
  }));
}

async function upsertSoc2Status(config, payload = {}) {
  const tenantSlug = sanitizeTenant(payload.tenant || 'global');
  const controlId = normalizeControlId(payload.controlId);
  const status = normalizeStatus(payload.status);
  const ownerUserId = normalizeActorUserId(payload.ownerUserId);
  const notes = safeText(payload.notes, 4_000) || null;

  const controlCheck = await query(
    config,
    `
      SELECT control_id
      FROM soc2_controls
      WHERE control_id = $1
      LIMIT 1
    `,
    [controlId]
  );
  if (!controlCheck?.rows?.length) {
    throw new ServiceError(404, 'soc2_control_not_found', 'SOC2 control was not found.');
  }

  // Fetch current status for transition validation + audit trail
  const currentRow = await query(
    config,
    `SELECT status, COALESCE(evidence_count, 0)::INT AS evidence_count
     FROM soc2_status WHERE tenant_slug = $1 AND control_id = $2 LIMIT 1`,
    [tenantSlug, controlId]
  );
  const currentStatus = currentRow?.rows?.[0]?.status || 'not_started';
  const currentEvidence = Number(currentRow?.rows?.[0]?.evidence_count || 0);

  // G2: Enforce valid state transitions
  validateTransition(currentStatus, status);

  // G3: Require evidence for validated status
  if (status === 'validated' && currentEvidence === 0) {
    throw new ServiceError(
      400,
      'evidence_required',
      'Cannot mark control as validated without at least one evidence document. Upload evidence first.'
    );
  }

  const result = await query(
    config,
    `
      INSERT INTO soc2_status (
        tenant_slug,
        control_id,
        status,
        owner_user_id,
        notes,
        updated_at
      )
      VALUES ($1,$2,$3,$4,$5,NOW())
      ON CONFLICT (tenant_slug, control_id)
      DO UPDATE SET
        status = EXCLUDED.status,
        owner_user_id = EXCLUDED.owner_user_id,
        notes = EXCLUDED.notes,
        updated_at = NOW()
      RETURNING tenant_slug, control_id, status, owner_user_id, evidence_count, notes, updated_at
    `,
    [tenantSlug, controlId, status, ownerUserId, notes]
  );

  const row = result.rows[0];
  return {
    tenant: row.tenant_slug,
    controlId: row.control_id,
    status: row.status,
    previousStatus: currentStatus,
    ownerUserId: row.owner_user_id ? String(row.owner_user_id) : null,
    evidenceCount: Number(row.evidence_count || 0),
    notes: row.notes || '',
    updatedAt: new Date(row.updated_at).toISOString(),
  };
}

async function incrementSoc2EvidenceCount(config, tenant, controlId) {
  const tenantSlug = sanitizeTenant(tenant || 'global');
  const normalizedControlId = normalizeControlId(controlId);

  await query(
    config,
    `
      INSERT INTO soc2_status (tenant_slug, control_id, status, evidence_count, updated_at)
      VALUES ($1,$2,'not_started',1,NOW())
      ON CONFLICT (tenant_slug, control_id)
      DO UPDATE SET
        evidence_count = soc2_status.evidence_count + 1,
        updated_at = NOW()
    `,
    [tenantSlug, normalizedControlId]
  );
}

async function createSoc2EvidenceRecord(config, payload = {}) {
  const tenantSlug = sanitizeTenant(payload.tenant || 'global');
  const controlId = normalizeControlId(payload.controlId);
  const fileName = safeText(payload.fileName, 255);
  const mimeType = safeText(payload.mimeType, 128);
  const storageKey = safeText(payload.storageKey, 2_048);
  const checksumSha256 = safeText(payload.checksumSha256, 128);
  const uploadedBy = normalizeActorUserId(payload.uploadedBy);
  const sizeBytes = toSafeInteger(payload.sizeBytes, 0, 0, 2_147_483_647);

  if (!fileName || !mimeType || !storageKey || !checksumSha256) {
    throw new ServiceError(400, 'invalid_soc2_evidence', 'Evidence metadata is incomplete.');
  }

  const result = await query(
    config,
    `
      INSERT INTO soc2_evidence (
        tenant_slug,
        control_id,
        filename,
        mime,
        size_bytes,
        storage_key,
        checksum_sha256,
        uploaded_by
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
      RETURNING id, tenant_slug, control_id, filename, mime, size_bytes, storage_key, checksum_sha256, uploaded_by, created_at
    `,
    [tenantSlug, controlId, fileName, mimeType, sizeBytes, storageKey, checksumSha256, uploadedBy]
  );

  await incrementSoc2EvidenceCount(config, tenantSlug, controlId);

  const row = result.rows[0];
  return {
    id: String(row.id),
    tenant: row.tenant_slug,
    controlId: row.control_id,
    fileName: row.filename,
    mimeType: row.mime,
    sizeBytes: Number(row.size_bytes || 0),
    storageKey: row.storage_key,
    checksumSha256: row.checksum_sha256,
    uploadedBy: row.uploaded_by ? String(row.uploaded_by) : null,
    createdAt: new Date(row.created_at).toISOString(),
  };
}

async function listSoc2Evidence(config, tenant, options = {}) {
  const tenantSlug = sanitizeTenant(tenant || 'global');
  const limit = toSafeInteger(options.limit, 50, 1, 500);
  const offset = toSafeInteger(options.offset, 0, 0, 50_000);
  const controlId = options.controlId ? normalizeControlId(options.controlId) : null;

  const values = [tenantSlug];
  const where = ['tenant_slug = $1'];
  if (controlId) {
    values.push(controlId);
    where.push(`control_id = $${values.length}`);
  }

  const whereSql = where.join(' AND ');
  const count = await query(
    config,
    `SELECT COUNT(*)::INT AS total FROM soc2_evidence WHERE ${whereSql}`,
    values
  );
  const total = Number(count?.rows?.[0]?.total || 0);

  values.push(limit, offset);
  const result = await query(
    config,
    `
      SELECT
        id,
        tenant_slug,
        control_id,
        filename,
        mime,
        size_bytes,
        storage_key,
        checksum_sha256,
        uploaded_by,
        created_at
      FROM soc2_evidence
      WHERE ${whereSql}
      ORDER BY created_at DESC, id DESC
      LIMIT $${values.length - 1}
      OFFSET $${values.length}
    `,
    values
  );

  const data = (result?.rows || []).map(row => ({
    id: String(row.id),
    tenant: row.tenant_slug,
    controlId: row.control_id,
    fileName: row.filename,
    mimeType: row.mime,
    sizeBytes: Number(row.size_bytes || 0),
    storageKey: row.storage_key,
    checksumSha256: row.checksum_sha256,
    uploadedBy: row.uploaded_by ? String(row.uploaded_by) : null,
    createdAt: new Date(row.created_at).toISOString(),
  }));

  return {
    data,
    pagination: {
      limit,
      offset,
      total,
      hasMore: offset + data.length < total,
    },
  };
}

async function createPolicyRecord(config, payload = {}) {
  const tenantSlug = sanitizeTenant(payload.tenant || 'global');
  const policyKey = safeText(payload.policyKey, 96).toLowerCase();
  const content = String(payload.content || '').trim();
  const createdBy = normalizeActorUserId(payload.createdBy);
  if (!policyKey || !content) {
    throw new ServiceError(400, 'invalid_policy_payload', 'Policy key and content are required.');
  }

  const result = await query(
    config,
    `
      INSERT INTO policies (tenant_slug, policy_key, content, created_by)
      VALUES ($1,$2,$3,$4)
      RETURNING id, tenant_slug, policy_key, content, created_by, created_at, status
    `,
    [tenantSlug, policyKey, content, createdBy]
  );

  const row = result.rows[0];
  return {
    id: String(row.id),
    tenant: row.tenant_slug,
    policyKey: row.policy_key,
    content: row.content,
    createdBy: row.created_by ? String(row.created_by) : null,
    createdAt: new Date(row.created_at).toISOString(),
    status: row.status || 'draft',
  };
}

async function listPolicies(config, tenant, limit = 20) {
  const tenantSlug = sanitizeTenant(tenant || 'global');
  const capped = toSafeInteger(limit, 20, 1, 200);
  const result = await query(
    config,
    `
      SELECT id, tenant_slug, policy_key, content, created_by, created_at,
             status, approved_by, approved_at, rejected_by, rejected_at, rejection_reason
      FROM policies
      WHERE tenant_slug = $1
      ORDER BY created_at DESC, id DESC
      LIMIT $2
    `,
    [tenantSlug, capped]
  );

  return (result?.rows || []).map(row => ({
    id: String(row.id),
    tenant: row.tenant_slug,
    policyKey: row.policy_key,
    content: row.content,
    createdBy: row.created_by ? String(row.created_by) : null,
    createdAt: new Date(row.created_at).toISOString(),
    status: row.status || 'draft',
    approvedBy: row.approved_by ? String(row.approved_by) : null,
    approvedAt: row.approved_at ? new Date(row.approved_at).toISOString() : null,
    rejectedBy: row.rejected_by ? String(row.rejected_by) : null,
    rejectedAt: row.rejected_at ? new Date(row.rejected_at).toISOString() : null,
    rejectionReason: row.rejection_reason || null,
  }));
}

async function getPolicyRecord(config, tenant, policyId) {
  const tenantSlug = sanitizeTenant(tenant || 'global');
  const id = Number(policyId);
  if (!Number.isInteger(id) || id <= 0) {
    throw new ServiceError(400, 'invalid_policy_id', 'Policy id is invalid.');
  }
  const result = await query(
    config,
    `SELECT id, tenant_slug, policy_key, content, created_by, created_at,
            status, approved_by, approved_at, rejected_by, rejected_at, rejection_reason
     FROM policies WHERE tenant_slug = $1 AND id = $2 LIMIT 1`,
    [tenantSlug, id]
  );
  if (!result?.rows?.length) {
    throw new ServiceError(404, 'policy_not_found', 'Policy was not found.');
  }
  const row = result.rows[0];
  return {
    id: String(row.id),
    tenant: row.tenant_slug,
    policyKey: row.policy_key,
    content: row.content,
    createdBy: row.created_by ? String(row.created_by) : null,
    createdAt: new Date(row.created_at).toISOString(),
    status: row.status || 'draft',
    approvedBy: row.approved_by ? String(row.approved_by) : null,
    approvedAt: row.approved_at ? new Date(row.approved_at).toISOString() : null,
    rejectedBy: row.rejected_by ? String(row.rejected_by) : null,
    rejectedAt: row.rejected_at ? new Date(row.rejected_at).toISOString() : null,
    rejectionReason: row.rejection_reason || null,
  };
}

const VALID_POLICY_TRANSITIONS = {
  'draft':              ['pending_approval', 'archived'],
  'pending_approval':   ['approved', 'rejected', 'draft'],
  'approved':           ['archived'],
  'rejected':           ['draft', 'archived'],
  'archived':           ['draft'],
};

async function updatePolicyStatus(config, payload = {}) {
  const tenantSlug = sanitizeTenant(payload.tenant || 'global');
  const id = Number(payload.policyId);
  if (!Number.isInteger(id) || id <= 0) {
    throw new ServiceError(400, 'invalid_policy_id', 'Policy id is invalid.');
  }

  const newStatus = String(payload.status || '').trim().toLowerCase();
  if (!ALLOWED_POLICY_STATUS.has(newStatus)) {
    throw new ServiceError(
      400,
      'invalid_policy_status',
      `Status must be one of: draft, pending_approval, approved, rejected, archived.`
    );
  }

  const actorId = normalizeActorUserId(payload.actorId);
  const rejectionReason = safeText(payload.rejectionReason, 2_000) || null;

  // Fetch current record
  const current = await query(
    config,
    `SELECT id, status FROM policies WHERE tenant_slug = $1 AND id = $2 LIMIT 1`,
    [tenantSlug, id]
  );
  if (!current?.rows?.length) {
    throw new ServiceError(404, 'policy_not_found', 'Policy was not found.');
  }
  const currentStatus = current.rows[0].status || 'draft';

  // Validate transition
  const allowed = VALID_POLICY_TRANSITIONS[currentStatus];
  if (!allowed || !allowed.includes(newStatus)) {
    throw new ServiceError(
      400,
      'invalid_policy_transition',
      `Cannot transition policy from '${currentStatus}' to '${newStatus}'. Allowed: ${(allowed || []).join(', ')}.`
    );
  }

  let updateSql = '';
  const params = [tenantSlug, id, newStatus];

  if (newStatus === 'approved') {
    params.push(actorId);
    updateSql = `status = $3, approved_by = $4, approved_at = NOW(), rejected_by = NULL, rejected_at = NULL, rejection_reason = NULL`;
  } else if (newStatus === 'rejected') {
    params.push(actorId, rejectionReason);
    updateSql = `status = $3, rejected_by = $4, rejected_at = NOW(), rejection_reason = $5, approved_by = NULL, approved_at = NULL`;
  } else {
    updateSql = `status = $3`;
  }

  const result = await query(
    config,
    `UPDATE policies SET ${updateSql}
     WHERE tenant_slug = $1 AND id = $2
     RETURNING id, tenant_slug, policy_key, content, created_by, created_at,
               status, approved_by, approved_at, rejected_by, rejected_at, rejection_reason`,
    params
  );

  const row = result.rows[0];
  return {
    id: String(row.id),
    tenant: row.tenant_slug,
    policyKey: row.policy_key,
    content: row.content,
    createdBy: row.created_by ? String(row.created_by) : null,
    createdAt: new Date(row.created_at).toISOString(),
    status: row.status,
    previousStatus: currentStatus,
    approvedBy: row.approved_by ? String(row.approved_by) : null,
    approvedAt: row.approved_at ? new Date(row.approved_at).toISOString() : null,
    rejectedBy: row.rejected_by ? String(row.rejected_by) : null,
    rejectedAt: row.rejected_at ? new Date(row.rejected_at).toISOString() : null,
    rejectionReason: row.rejection_reason || null,
  };
}

async function createAuditPackageRecord(config, payload = {}) {
  const tenantSlug = sanitizeTenant(payload.tenant || 'global');
  const pdfStoragePath = safeText(payload.pdfStoragePath, 2_048);
  if (!pdfStoragePath) {
    throw new ServiceError(500, 'audit_package_path_missing', 'Audit package path is required.');
  }

  const result = await query(
    config,
    `
      INSERT INTO audit_packages (tenant_slug, pdf_storage_path, manifest_json)
      VALUES ($1,$2,$3::jsonb)
      RETURNING id, tenant_slug, pdf_storage_path, manifest_json, created_at
    `,
    [tenantSlug, pdfStoragePath, JSON.stringify(payload.manifestJson || {})]
  );

  const row = result.rows[0];
  return {
    id: String(row.id),
    tenant: row.tenant_slug,
    pdfStoragePath: row.pdf_storage_path,
    manifest: row.manifest_json || {},
    createdAt: new Date(row.created_at).toISOString(),
  };
}

async function getAuditPackageRecord(config, tenant, packageId) {
  const tenantSlug = sanitizeTenant(tenant || 'global');
  const id = Number(packageId);
  if (!Number.isInteger(id) || id <= 0) {
    throw new ServiceError(400, 'invalid_audit_package_id', 'Audit package id is invalid.');
  }

  const result = await query(
    config,
    `
      SELECT id, tenant_slug, pdf_storage_path, manifest_json, created_at
      FROM audit_packages
      WHERE tenant_slug = $1 AND id = $2
      LIMIT 1
    `,
    [tenantSlug, id]
  );
  if (!result?.rows?.length) {
    throw new ServiceError(404, 'audit_package_not_found', 'Audit package was not found.');
  }

  const row = result.rows[0];
  return {
    id: String(row.id),
    tenant: row.tenant_slug,
    pdfStoragePath: row.pdf_storage_path,
    manifest: row.manifest_json || {},
    createdAt: new Date(row.created_at).toISOString(),
  };
}

module.exports = {
  listSoc2Controls,
  listSoc2Status,
  upsertSoc2Status,
  createSoc2EvidenceRecord,
  listSoc2Evidence,
  createPolicyRecord,
  listPolicies,
  getPolicyRecord,
  updatePolicyStatus,
  createAuditPackageRecord,
  getAuditPackageRecord,
  VALID_TRANSITIONS,
};
