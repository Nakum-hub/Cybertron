const { query, withClient } = require('./database');
const { sanitizeTenant } = require('./validators');

const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low'];
const VALID_ACTION_TYPES = ['manual', 'automated', 'notification', 'approval'];
const VALID_EXEC_STATUSES = ['running', 'completed', 'failed', 'cancelled'];
const VALID_STEP_STATUSES = ['pending', 'in_progress', 'completed', 'skipped', 'failed'];
const MAX_LIST_LIMIT = 200;

async function listPlaybooks(config, tenant, { limit = 50, offset = 0, category, activeOnly = true } = {}) {
  if (!config.databaseUrl) {
    return { data: [], total: 0 };
  }

  const cappedLimit = Math.min(Math.max(1, Number(limit) || 50), MAX_LIST_LIMIT);
  const cappedOffset = Math.max(0, Number(offset) || 0);
  const tenantSlug = sanitizeTenant(tenant);
  const conditions = ['tenant_slug = $1'];
  const params = [tenantSlug];
  let paramIdx = 2;

  if (activeOnly) {
    conditions.push('is_active = TRUE');
  }

  if (category) {
    conditions.push(`category = $${paramIdx}`);
    params.push(String(category).slice(0, 64));
    paramIdx++;
  }

  const where = conditions.join(' AND ');

  const countResult = await query(
    config,
    `SELECT COUNT(*)::INT AS total FROM playbooks WHERE ${where}`,
    params
  );

  const result = await query(
    config,
    `
      SELECT id, tenant_slug, name, description, severity_filter, category, is_active,
             auto_trigger, severity_trigger, category_trigger,
             created_by, created_at, updated_at
      FROM playbooks
      WHERE ${where}
      ORDER BY updated_at DESC
      LIMIT $${paramIdx} OFFSET $${paramIdx + 1}
    `,
    [...params, cappedLimit, cappedOffset]
  );

  return {
    data: result?.rows || [],
    total: countResult?.rows?.[0]?.total || 0,
    limit: cappedLimit,
    offset: cappedOffset,
  };
}

async function getPlaybookWithSteps(config, tenant, playbookId) {
  if (!config.databaseUrl) {
    return null;
  }

  const tenantSlug = sanitizeTenant(tenant);
  const pbResult = await query(
    config,
    `
      SELECT id, tenant_slug, name, description, severity_filter, category, is_active,
             auto_trigger, severity_trigger, category_trigger,
             created_by, created_at, updated_at
      FROM playbooks
      WHERE id = $1 AND tenant_slug = $2
    `,
    [Number(playbookId), tenantSlug]
  );

  const playbook = pbResult?.rows?.[0];
  if (!playbook) {
    return null;
  }

  const stepsResult = await query(
    config,
    `
      SELECT id, step_order, title, description, action_type, assigned_role, timeout_minutes, created_at
      FROM playbook_steps
      WHERE playbook_id = $1
      ORDER BY step_order ASC
    `,
    [playbook.id]
  );

  playbook.steps = stepsResult?.rows || [];
  return playbook;
}

async function createPlaybook(config, { tenant, name, description, severityFilter, category, createdBy }) {
  if (!config.databaseUrl) {
    return null;
  }

  const tenantSlug = sanitizeTenant(tenant);
  const safeSeverity = VALID_SEVERITIES.includes(severityFilter) ? severityFilter : null;

  const result = await query(
    config,
    `
      INSERT INTO playbooks (tenant_slug, name, description, severity_filter, category, created_by)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING id, tenant_slug, name, description, severity_filter, category, is_active, auto_trigger, severity_trigger, category_trigger, created_by, created_at, updated_at
    `,
    [
      tenantSlug,
      String(name).slice(0, 255),
      description ? String(description).slice(0, 2000) : null,
      safeSeverity,
      String(category || 'general').slice(0, 64),
      createdBy ? Number(createdBy) : null,
    ]
  );

  return result?.rows?.[0] || null;
}

async function updatePlaybook(config, tenant, playbookId, updates) {
  if (!config.databaseUrl) {
    return null;
  }

  const tenantSlug = sanitizeTenant(tenant);
  const sets = ['updated_at = NOW()'];
  const params = [Number(playbookId), tenantSlug];
  let paramIdx = 3;

  if (updates.name !== undefined) {
    sets.push(`name = $${paramIdx}`);
    params.push(String(updates.name).slice(0, 255));
    paramIdx++;
  }
  if (updates.description !== undefined) {
    sets.push(`description = $${paramIdx}`);
    params.push(updates.description ? String(updates.description).slice(0, 2000) : null);
    paramIdx++;
  }
  if (updates.severityFilter !== undefined) {
    const safeSeverity = VALID_SEVERITIES.includes(updates.severityFilter) ? updates.severityFilter : null;
    sets.push(`severity_filter = $${paramIdx}`);
    params.push(safeSeverity);
    paramIdx++;
  }
  if (updates.category !== undefined) {
    sets.push(`category = $${paramIdx}`);
    params.push(String(updates.category).slice(0, 64));
    paramIdx++;
  }
  if (updates.isActive !== undefined) {
    sets.push(`is_active = $${paramIdx}`);
    params.push(Boolean(updates.isActive));
    paramIdx++;
  }

  const result = await query(
    config,
    `
      UPDATE playbooks SET ${sets.join(', ')}
      WHERE id = $1 AND tenant_slug = $2
      RETURNING id, tenant_slug, name, description, severity_filter, category, is_active, auto_trigger, severity_trigger, category_trigger, created_by, created_at, updated_at
    `,
    params
  );

  return result?.rows?.[0] || null;
}

async function addPlaybookStep(config, playbookId, { title, description, actionType, assignedRole, timeoutMinutes, stepOrder }, tenantSlug) {
  if (!config.databaseUrl) {
    return null;
  }

  // Verify playbook belongs to the tenant if tenantSlug is provided
  if (tenantSlug) {
    const ownerCheck = await query(
      config,
      'SELECT id FROM playbooks WHERE id = $1 AND tenant_slug = $2',
      [Number(playbookId), sanitizeTenant(tenantSlug)]
    );
    if (!ownerCheck?.rows?.length) {
      const { ServiceError } = require('./auth-service');
      throw new ServiceError(404, 'playbook_not_found', 'Playbook not found.');
    }
  }

  const safeActionType = VALID_ACTION_TYPES.includes(actionType) ? actionType : 'manual';

  if (stepOrder === undefined || stepOrder === null) {
    const maxResult = await query(
      config,
      'SELECT COALESCE(MAX(step_order), 0)::INT AS max_order FROM playbook_steps WHERE playbook_id = $1',
      [Number(playbookId)]
    );
    stepOrder = (maxResult?.rows?.[0]?.max_order || 0) + 1;
  }

  const result = await query(
    config,
    `
      INSERT INTO playbook_steps (playbook_id, step_order, title, description, action_type, assigned_role, timeout_minutes)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING id, playbook_id, step_order, title, description, action_type, assigned_role, timeout_minutes, created_at
    `,
    [
      Number(playbookId),
      Number(stepOrder),
      String(title).slice(0, 255),
      description ? String(description).slice(0, 2000) : null,
      safeActionType,
      String(assignedRole || 'security_analyst').slice(0, 64),
      Math.max(1, Math.min(1440, Number(timeoutMinutes) || 60)),
    ]
  );

  return result?.rows?.[0] || null;
}

async function executePlaybook(config, { tenant, playbookId, incidentId, startedBy }) {
  if (!config.databaseUrl) {
    return null;
  }

  const tenantSlug = sanitizeTenant(tenant);

  return withClient(config, async (client) => {
    await client.query('BEGIN');
    try {
      const execResult = await client.query(
      `
        INSERT INTO playbook_executions (tenant_slug, playbook_id, incident_id, status, started_by)
        VALUES ($1, $2, $3, 'running', $4)
        RETURNING id, tenant_slug, playbook_id, incident_id, status, started_by, started_at
      `,
      [
        tenantSlug,
        Number(playbookId),
        incidentId ? Number(incidentId) : null,
        startedBy ? Number(startedBy) : null,
      ]
    );

    const execution = execResult.rows[0];

    const stepsResult = await client.query(
      'SELECT id, step_order FROM playbook_steps WHERE playbook_id = $1 ORDER BY step_order ASC',
      [Number(playbookId)]
    );

    const stepResults = [];
    for (const step of stepsResult.rows) {
      const srResult = await client.query(
        `
          INSERT INTO playbook_step_results (execution_id, step_id, status)
          VALUES ($1, $2, 'pending')
          RETURNING id, execution_id, step_id, status
        `,
        [execution.id, step.id]
      );
      stepResults.push(srResult.rows[0]);
    }

    execution.stepResults = stepResults;

    // Add incident timeline entry when playbook is linked to an incident
    if (incidentId) {
      const pbNameResult = await client.query(
        'SELECT name FROM playbooks WHERE id = $1',
        [Number(playbookId)]
      );
      const pbName = pbNameResult.rows[0]?.name || `Playbook #${playbookId}`;
      await client.query(
        `
          INSERT INTO incident_timeline (tenant_slug, incident_id, event_type, message, actor_user_id)
          VALUES ($1, $2, 'playbook_executed', $3, $4)
        `,
        [
          tenantSlug,
          Number(incidentId),
          `Playbook "${pbName}" execution started (execution #${execution.id})`,
          startedBy ? Number(startedBy) : null,
        ]
      );
    }

    await client.query('COMMIT');
    return execution;
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    }
  });
}

async function listPlaybookExecutions(config, tenant, { playbookId, incidentId, status, limit = 50, offset = 0 } = {}) {
  if (!config.databaseUrl) {
    return { data: [], total: 0 };
  }

  const cappedLimit = Math.min(Math.max(1, Number(limit) || 50), MAX_LIST_LIMIT);
  const cappedOffset = Math.max(0, Number(offset) || 0);
  const tenantSlug = sanitizeTenant(tenant);
  const conditions = ['pe.tenant_slug = $1'];
  const params = [tenantSlug];
  let paramIdx = 2;

  if (playbookId) {
    conditions.push(`pe.playbook_id = $${paramIdx}`);
    params.push(Number(playbookId));
    paramIdx++;
  }
  if (incidentId) {
    conditions.push(`pe.incident_id = $${paramIdx}`);
    params.push(Number(incidentId));
    paramIdx++;
  }
  if (status && VALID_EXEC_STATUSES.includes(status)) {
    conditions.push(`pe.status = $${paramIdx}`);
    params.push(status);
    paramIdx++;
  }

  const where = conditions.join(' AND ');

  const countResult = await query(
    config,
    `SELECT COUNT(*)::INT AS total FROM playbook_executions pe WHERE ${where}`,
    params
  );

  const result = await query(
    config,
    `
      SELECT pe.id, pe.tenant_slug, pe.playbook_id, pe.incident_id, pe.status,
             pe.started_by, pe.started_at, pe.completed_at, pe.result_summary,
             p.name AS playbook_name
      FROM playbook_executions pe
      JOIN playbooks p ON p.id = pe.playbook_id
      WHERE ${where}
      ORDER BY pe.started_at DESC
      LIMIT $${paramIdx} OFFSET $${paramIdx + 1}
    `,
    [...params, cappedLimit, cappedOffset]
  );

  return {
    data: result?.rows || [],
    total: countResult?.rows?.[0]?.total || 0,
    limit: cappedLimit,
    offset: cappedOffset,
  };
}

async function updatePlaybookStepResult(config, tenant, executionId, stepId, { status, notes, completedBy }) {
  if (!config.databaseUrl) {
    return null;
  }

  const tenantSlug = sanitizeTenant(tenant);
  const safeStatus = VALID_STEP_STATUSES.includes(status) ? status : 'pending';
  const now = ['completed', 'skipped', 'failed'].includes(safeStatus) ? 'NOW()' : 'NULL';

  // Fetch previous status for audit trail reconstruction
  const prevResult = await query(
    config,
    `
      SELECT psr.status AS previous_status
      FROM playbook_step_results psr
      JOIN playbook_executions pe ON pe.id = psr.execution_id
      WHERE psr.execution_id = $1 AND psr.step_id = $2 AND pe.tenant_slug = $3
    `,
    [Number(executionId), Number(stepId), tenantSlug]
  );
  const previousStatus = prevResult?.rows?.[0]?.previous_status || null;

  const result = await query(
    config,
    `
      UPDATE playbook_step_results psr
      SET status = $1,
          notes = $2,
          completed_by = $3,
          started_at = CASE WHEN psr.started_at IS NULL AND $1 = 'in_progress' THEN NOW() ELSE psr.started_at END,
          completed_at = CASE WHEN $1 IN ('completed', 'skipped', 'failed') THEN NOW() ELSE psr.completed_at END
      FROM playbook_executions pe
      WHERE psr.execution_id = $4
        AND psr.step_id = $5
        AND pe.id = psr.execution_id
        AND pe.tenant_slug = $6
      RETURNING psr.id, psr.execution_id, psr.step_id, psr.status, psr.started_at, psr.completed_at, psr.notes, psr.completed_by
    `,
    [
      safeStatus,
      notes ? String(notes).slice(0, 2000) : null,
      completedBy ? Number(completedBy) : null,
      Number(executionId),
      Number(stepId),
      tenantSlug,
    ]
  );

  const updated = result?.rows?.[0];
  if (updated) {
    updated.previousStatus = previousStatus;
  }

  if (updated && ['completed', 'skipped', 'failed'].includes(safeStatus)) {
    const pendingCheck = await query(
      config,
      `
        SELECT COUNT(*)::INT AS remaining
        FROM playbook_step_results
        WHERE execution_id = $1 AND status NOT IN ('completed', 'skipped', 'failed')
      `,
      [Number(executionId)]
    );

    const remaining = pendingCheck?.rows?.[0]?.remaining || 0;
    if (remaining === 0) {
      const failedCheck = await query(
        config,
        `
          SELECT COUNT(*)::INT AS failed_count
          FROM playbook_step_results
          WHERE execution_id = $1 AND status = 'failed'
        `,
        [Number(executionId)]
      );
      const hasFailed = (failedCheck?.rows?.[0]?.failed_count || 0) > 0;
      const finalStatus = hasFailed ? 'failed' : 'completed';

      // Build result_summary from step outcomes
      const summaryQuery = await query(
        config,
        `
          SELECT
            COUNT(*)::INT AS total_steps,
            COUNT(*) FILTER (WHERE status = 'completed')::INT AS completed,
            COUNT(*) FILTER (WHERE status = 'failed')::INT AS failed,
            COUNT(*) FILTER (WHERE status = 'skipped')::INT AS skipped
          FROM playbook_step_results
          WHERE execution_id = $1
        `,
        [Number(executionId)]
      );
      const summary = summaryQuery?.rows?.[0] || {};
      const resultSummary = {
        totalSteps: summary.total_steps || 0,
        completed: summary.completed || 0,
        failed: summary.failed || 0,
        skipped: summary.skipped || 0,
        outcome: finalStatus,
        completedAt: new Date().toISOString(),
      };

      await query(
        config,
        `
          UPDATE playbook_executions
          SET status = $1, completed_at = NOW(), result_summary = $3
          WHERE id = $2
        `,
        [finalStatus, Number(executionId), JSON.stringify(resultSummary)]
      );
    }
  }

  return updated;
}

async function getExecutionStepResults(config, tenant, executionId) {
  if (!config.databaseUrl) {
    return [];
  }

  const tenantSlug = sanitizeTenant(tenant);
  const result = await query(
    config,
    `
      SELECT psr.id, psr.execution_id, psr.step_id, psr.status, psr.started_at, psr.completed_at, psr.notes, psr.completed_by,
             ps.title AS step_title, ps.step_order, ps.action_type, ps.assigned_role, ps.timeout_minutes
      FROM playbook_step_results psr
      JOIN playbook_steps ps ON ps.id = psr.step_id
      JOIN playbook_executions pe ON pe.id = psr.execution_id
      WHERE psr.execution_id = $1 AND pe.tenant_slug = $2
      ORDER BY ps.step_order ASC
    `,
    [Number(executionId), tenantSlug]
  );

  return result?.rows || [];
}

// --- Stale Execution Cleanup (timeout enforcement) ---
// Marks playbook executions as 'failed' if they've been 'running' longer than the
// maximum step timeout across all their steps (or a default 24h ceiling).
async function cleanupStaleExecutions(config, tenant) {
  if (!config.databaseUrl) return { cleaned: 0 };

  const tenantSlug = sanitizeTenant(tenant);
  const result = await query(
    config,
    `
      UPDATE playbook_executions pe
      SET status = 'failed',
          completed_at = NOW(),
          result_summary = jsonb_build_object(
            'outcome', 'failed',
            'reason', 'execution_timeout',
            'completedAt', NOW()::TEXT
          )
      WHERE pe.tenant_slug = $1
        AND pe.status = 'running'
        AND pe.started_at < NOW() - INTERVAL '24 hours'
      RETURNING pe.id
    `,
    [tenantSlug]
  );

  return { cleaned: result?.rowCount || 0 };
}

// --- Analyst Workflow Metrics ---
// Returns per-analyst throughput, MTTA, MTTR, false positive rate
async function getAnalystWorkflowMetrics(config, tenant, { days = 30 } = {}) {
  if (!config.databaseUrl) return { data: [] };

  const tenantSlug = sanitizeTenant(tenant);
  const result = await query(
    config,
    `
      SELECT
        u.id AS analyst_id,
        u.email AS analyst_email,
        u.display_name AS analyst_name,
        COUNT(*) FILTER (WHERE sa.assigned_to = u.id)::INT AS total_assigned,
        COUNT(*) FILTER (WHERE sa.assigned_to = u.id AND sa.status = 'resolved')::INT AS resolved_count,
        COUNT(*) FILTER (WHERE sa.assigned_to = u.id AND sa.status = 'dismissed')::INT AS dismissed_count,
        COUNT(*) FILTER (WHERE sa.assigned_to = u.id AND sa.status = 'escalated')::INT AS escalated_count,
        ROUND(AVG(EXTRACT(EPOCH FROM (sa.acknowledged_at - sa.ingested_at)) / 60)
          FILTER (WHERE sa.assigned_to = u.id AND sa.acknowledged_at IS NOT NULL)::NUMERIC, 2)
          AS avg_time_to_ack_minutes,
        ROUND(AVG(EXTRACT(EPOCH FROM (sa.resolved_at - sa.ingested_at)) / 60)
          FILTER (WHERE sa.assigned_to = u.id AND sa.status = 'resolved' AND sa.resolved_at IS NOT NULL)::NUMERIC, 2)
          AS avg_time_to_resolve_minutes
      FROM users u
      LEFT JOIN siem_alerts sa
        ON sa.assigned_to = u.id
        AND sa.tenant_slug = $1
        AND sa.ingested_at >= NOW() - INTERVAL '1 day' * $2
      WHERE u.tenant_slug = $1
        AND u.is_active = TRUE
        AND u.role IN ('security_analyst', 'tenant_admin', 'super_admin')
      GROUP BY u.id, u.email, u.display_name
      ORDER BY resolved_count DESC
      LIMIT 50
    `,
    [tenantSlug, Math.min(Math.max(1, days), 365)]
  );

  return { data: result?.rows || [] };
}

module.exports = {
  listPlaybooks,
  getPlaybookWithSteps,
  createPlaybook,
  updatePlaybook,
  addPlaybookStep,
  executePlaybook,
  listPlaybookExecutions,
  updatePlaybookStepResult,
  getExecutionStepResults,
  cleanupStaleExecutions,
  getAnalystWorkflowMetrics,
};
