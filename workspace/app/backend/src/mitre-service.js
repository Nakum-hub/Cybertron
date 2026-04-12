const { query } = require('./database');
const { sanitizeTenant } = require('./validators');

async function listMitreTechniques(config, { tactic } = {}) {
  if (!config.databaseUrl) {
    return { data: [], total: 0 };
  }

  let sql = `
    SELECT
      id AS technique_id,
      id,
      tactic,
      name,
      description,
      url
    FROM mitre_attack_techniques
  `;
  const params = [];

  if (tactic) {
    sql += ' WHERE tactic = $1';
    params.push(String(tactic).toLowerCase().trim());
  }

  sql += ' ORDER BY id ASC';

  const result = await query(config, sql, params);
  const rows = result?.rows || [];
  return { data: rows, total: rows.length };
}

async function listIncidentMitreMappings(config, tenant, incidentId) {
  if (!config.databaseUrl) {
    return { data: [] };
  }

  const tenantSlug = sanitizeTenant(tenant);
  const result = await query(
    config,
    `
      SELECT
        im.id,
        im.technique_id,
        im.confidence,
        im.notes,
        im.created_by,
        im.created_at,
        mt.tactic,
        mt.name AS technique_name,
        mt.description AS technique_description,
        mt.url AS technique_url
      FROM incident_mitre_mappings im
      JOIN mitre_attack_techniques mt ON mt.id = im.technique_id
      WHERE im.tenant_slug = $1 AND im.incident_id = $2
      ORDER BY mt.tactic, mt.id
    `,
    [tenantSlug, Number(incidentId)]
  );

  return { data: result?.rows || [] };
}

async function addIncidentMitreMapping(config, { tenant, incidentId, techniqueId, confidence, notes, createdBy }) {
  if (!config.databaseUrl) {
    return null;
  }

  const tenantSlug = sanitizeTenant(tenant);
  const normalizedTechniqueId = String(techniqueId || '').trim().toUpperCase();
  if (!normalizedTechniqueId) {
    const err = new Error('Technique id is required.');
    err.statusCode = 400;
    err.code = 'invalid_technique_id';
    throw err;
  }

  const techniqueResult = await query(
    config,
    'SELECT id FROM mitre_attack_techniques WHERE id = $1',
    [normalizedTechniqueId]
  );
  if (!techniqueResult?.rows?.length) {
    const err = new Error(`MITRE technique '${normalizedTechniqueId}' was not found.`);
    err.statusCode = 404;
    err.code = 'mitre_technique_not_found';
    throw err;
  }

  const result = await query(
    config,
    `
      INSERT INTO incident_mitre_mappings (tenant_slug, incident_id, technique_id, confidence, notes, created_by)
      VALUES ($1, $2, $3, $4, $5, $6)
      ON CONFLICT (tenant_slug, incident_id, technique_id) DO UPDATE
        SET confidence = EXCLUDED.confidence,
            notes = EXCLUDED.notes
      RETURNING id, tenant_slug, incident_id, technique_id, confidence, notes, created_by, created_at
    `,
    [
      tenantSlug,
      Number(incidentId),
      normalizedTechniqueId,
      Math.max(0, Math.min(100, Number(confidence) || 50)),
      notes ? String(notes).slice(0, 2000) : null,
      createdBy ? Number(createdBy) : null,
    ]
  );

  return result?.rows?.[0] || null;
}

async function removeIncidentMitreMapping(config, tenant, mappingId) {
  if (!config.databaseUrl) {
    return false;
  }

  const tenantSlug = sanitizeTenant(tenant);
  const result = await query(
    config,
    'DELETE FROM incident_mitre_mappings WHERE id = $1 AND tenant_slug = $2 RETURNING id',
    [Number(mappingId), tenantSlug]
  );

  return (result?.rowCount || 0) > 0;
}

async function getMitreHeatmap(config, tenant, { days } = {}) {
  if (!config.databaseUrl) {
    return { data: [] };
  }

  const tenantSlug = sanitizeTenant(tenant);
  const safeDays = days ? Math.max(1, Math.min(Number(days) || 90, 365)) : null;
  const timeFilter = safeDays
    ? 'AND im.created_at >= NOW() - INTERVAL \'1 day\' * $2'
    : '';
  const params = safeDays ? [tenantSlug, safeDays] : [tenantSlug];

  const result = await query(
    config,
    `
      SELECT
        mt.tactic,
        mt.id AS technique_id,
        mt.name AS technique_name,
        COUNT(im.id)::INT AS incident_count,
        AVG(im.confidence)::INT AS avg_confidence
      FROM mitre_attack_techniques mt
      LEFT JOIN incident_mitre_mappings im
        ON im.technique_id = mt.id AND im.tenant_slug = $1
        ${timeFilter}
      GROUP BY mt.tactic, mt.id, mt.name
      ORDER BY mt.tactic, incident_count DESC
    `,
    params
  );

  return {
    data: result?.rows || [],
    timeRange: safeDays ? `${safeDays}d` : 'all_time',
  };
}

module.exports = {
  listMitreTechniques,
  listIncidentMitreMappings,
  addIncidentMitreMapping,
  removeIncidentMitreMapping,
  getMitreHeatmap,
};
