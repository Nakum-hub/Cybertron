const { query } = require('./database');
const { sanitizeTenant } = require('./validators');
const { log: structuredLog } = require('./logger');

// Correlation engine: evaluates stored alert_correlation_rules against uncorrelated siem_alerts.
// Supports rule types: threshold, sequence, aggregation, anomaly.
// Each rule's conditions JSONB defines what to match and thresholds.

const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

function logCorrelation(tenant, action, details = {}) {
  structuredLog('info', `correlation.${action}`, {
    service: 'correlation-engine',
    tenant,
    ...details,
  });
}

// Evaluate a threshold rule: fires when count of alerts matching criteria exceeds threshold
// within a time window.
// Expected conditions shape:
// {
//   field: "severity" | "source" | "category" | "rule_name" | "hostname" | "source_ip" | "dest_ip",
//   value: "critical",           -- value to match (or array of values)
//   threshold: 5,                -- minimum alert count to trigger
//   windowMinutes: 60            -- time window in minutes
// }
async function evaluateThresholdRule(config, tenant, rule) {
  const conditions = rule.conditions || {};
  const field = conditions.field;
  const value = conditions.value;
  const threshold = Number(conditions.threshold) || 5;
  const windowMinutes = Number(conditions.windowMinutes) || 60;

  const allowedFields = ['severity', 'source', 'category', 'rule_name', 'hostname', 'source_ip', 'dest_ip'];
  if (!allowedFields.includes(field)) {
    return [];
  }

  const values = Array.isArray(value) ? value : [value];
  const placeholders = values.map((_, i) => `$${i + 4}`).join(', ');

  const result = await query(
    config,
    `
      SELECT id, alert_id, rule_name, severity, source, category, source_ip, dest_ip, hostname, event_time
      FROM siem_alerts
      WHERE tenant_slug = $1
        AND correlated = FALSE
        AND ${field} IN (${placeholders})
        AND event_time >= NOW() - INTERVAL '1 minute' * $2
      ORDER BY event_time DESC
      LIMIT $3
    `,
    [tenant, windowMinutes, 500, ...values.map(v => String(v))]
  );

  const alerts = result?.rows || [];
  if (alerts.length >= threshold) {
    return alerts;
  }
  return [];
}

// Evaluate an aggregation rule: fires when a specific field has too many distinct values
// within a time window (e.g., port scan detection -- many dest_ips from one source_ip).
// Expected conditions shape:
// {
//   groupByField: "source_ip",
//   countField: "dest_ip",
//   threshold: 10,
//   windowMinutes: 15
// }
async function evaluateAggregationRule(config, tenant, rule) {
  const conditions = rule.conditions || {};
  const groupByField = conditions.groupByField;
  const countField = conditions.countField;
  const threshold = Number(conditions.threshold) || 10;
  const windowMinutes = Number(conditions.windowMinutes) || 15;

  const allowedFields = ['severity', 'source', 'category', 'rule_name', 'hostname', 'source_ip', 'dest_ip'];
  if (!allowedFields.includes(groupByField) || !allowedFields.includes(countField)) {
    return [];
  }

  const result = await query(
    config,
    `
      SELECT ${groupByField} AS group_key, COUNT(DISTINCT ${countField}) AS distinct_count,
             ARRAY_AGG(id ORDER BY event_time DESC) AS alert_ids
      FROM siem_alerts
      WHERE tenant_slug = $1
        AND correlated = FALSE
        AND event_time >= NOW() - INTERVAL '1 minute' * $2
      GROUP BY ${groupByField}
      HAVING COUNT(DISTINCT ${countField}) >= $3
      LIMIT 50
    `,
    [tenant, windowMinutes, threshold]
  );

  const rows = result?.rows || [];
  if (rows.length === 0) return [];

  // Fetch all matching alert IDs for the groups that exceeded threshold
  const allAlertIds = rows.flatMap(r => (r.alert_ids || []).slice(0, 100));
  if (allAlertIds.length === 0) return [];

  const alertResult = await query(
    config,
    `
      SELECT id, alert_id, rule_name, severity, source, category, source_ip, dest_ip, hostname, event_time
      FROM siem_alerts
      WHERE id = ANY($1::BIGINT[])
      ORDER BY event_time DESC
    `,
    [allAlertIds]
  );

  return alertResult?.rows || [];
}

// Evaluate a sequence rule: fires when specific events happen in a defined order
// within a time window.
// Expected conditions shape:
// {
//   steps: [
//     { field: "category", value: "authentication_failure" },
//     { field: "category", value: "privilege_escalation" }
//   ],
//   windowMinutes: 30,
//   groupByField: "source_ip"    -- events must share this field value
// }
async function evaluateSequenceRule(config, tenant, rule) {
  const conditions = rule.conditions || {};
  const steps = conditions.steps;
  const windowMinutes = Number(conditions.windowMinutes) || 30;
  const groupByField = conditions.groupByField || 'source_ip';

  if (!Array.isArray(steps) || steps.length < 2) return [];

  const allowedFields = ['severity', 'source', 'category', 'rule_name', 'hostname', 'source_ip', 'dest_ip'];
  if (!allowedFields.includes(groupByField)) return [];

  // Check first step to find candidate groups
  const firstStep = steps[0];
  if (!allowedFields.includes(firstStep.field)) return [];

  const firstResult = await query(
    config,
    `
      SELECT DISTINCT ${groupByField} AS group_key
      FROM siem_alerts
      WHERE tenant_slug = $1
        AND correlated = FALSE
        AND ${firstStep.field} = $2
        AND event_time >= NOW() - INTERVAL '1 minute' * $3
    `,
    [tenant, String(firstStep.value), windowMinutes]
  );

  const candidateGroups = (firstResult?.rows || []).map(r => r.group_key).filter(Boolean);
  if (candidateGroups.length === 0) return [];

  // For each candidate group, verify sequential presence of all steps IN TEMPORAL ORDER
  const matchedAlerts = [];
  for (const groupKey of candidateGroups.slice(0, 50)) {
    let allStepsFound = true;
    let previousStepMaxTime = null;

    for (const step of steps) {
      if (!allowedFields.includes(step.field)) { allStepsFound = false; break; }

      // Each step must have an event that occurred AFTER the previous step's earliest match
      const timeCondition = previousStepMaxTime
        ? `AND event_time > $5`
        : '';
      const timeParams = previousStepMaxTime
        ? [tenant, groupKey, String(step.value), windowMinutes, previousStepMaxTime]
        : [tenant, groupKey, String(step.value), windowMinutes];

      const stepResult = await query(
        config,
        `
          SELECT MIN(event_time) AS earliest_time FROM siem_alerts
          WHERE tenant_slug = $1
            AND correlated = FALSE
            AND ${groupByField} = $2
            AND ${step.field} = $3
            AND event_time >= NOW() - INTERVAL '1 minute' * $4
            ${timeCondition}
        `,
        timeParams
      );

      const earliestTime = stepResult?.rows?.[0]?.earliest_time;
      if (!earliestTime) {
        allStepsFound = false;
        break;
      }
      previousStepMaxTime = earliestTime;
    }

    if (allStepsFound) {
      // Fetch all alerts in this group within the window
      const groupAlerts = await query(
        config,
        `
          SELECT id, alert_id, rule_name, severity, source, category, source_ip, dest_ip, hostname, event_time
          FROM siem_alerts
          WHERE tenant_slug = $1
            AND correlated = FALSE
            AND ${groupByField} = $2
            AND event_time >= NOW() - INTERVAL '1 minute' * $3
          ORDER BY event_time ASC
          LIMIT 200
        `,
        [tenant, groupKey, windowMinutes]
      );
      matchedAlerts.push(...(groupAlerts?.rows || []));
    }
  }

  return matchedAlerts;
}

// Evaluate an anomaly rule: fires on statistical deviation from baseline.
// Expected conditions shape:
// {
//   field: "severity",
//   value: "critical",
//   baselineWindowHours: 24,
//   deviationMultiplier: 3,
//   currentWindowMinutes: 60
// }
async function evaluateAnomalyRule(config, tenant, rule) {
  const conditions = rule.conditions || {};
  const field = conditions.field;
  const value = conditions.value;
  const baselineHours = Number(conditions.baselineWindowHours) || 24;
  const deviationMultiplier = Number(conditions.deviationMultiplier) || 3;
  const currentMinutes = Number(conditions.currentWindowMinutes) || 60;

  const allowedFields = ['severity', 'source', 'category', 'rule_name', 'hostname', 'source_ip', 'dest_ip'];
  if (!allowedFields.includes(field)) return [];

  // Compute hourly baseline (average count per hour in baseline window)
  const baselineResult = await query(
    config,
    `
      SELECT COUNT(*)::FLOAT / GREATEST($2, 1) AS avg_per_hour
      FROM siem_alerts
      WHERE tenant_slug = $1
        AND ${field} = $3
        AND event_time >= NOW() - INTERVAL '1 hour' * $2
        AND event_time < NOW() - INTERVAL '1 minute' * $4
    `,
    [tenant, baselineHours, String(value), currentMinutes]
  );

  const avgPerHour = baselineResult?.rows?.[0]?.avg_per_hour || 0;
  const expectedInWindow = avgPerHour * (currentMinutes / 60);
  const anomalyThreshold = Math.max(1, expectedInWindow * deviationMultiplier);

  // Count current window
  const currentResult = await query(
    config,
    `
      SELECT id, alert_id, rule_name, severity, source, category, source_ip, dest_ip, hostname, event_time
      FROM siem_alerts
      WHERE tenant_slug = $1
        AND correlated = FALSE
        AND ${field} = $2
        AND event_time >= NOW() - INTERVAL '1 minute' * $3
      ORDER BY event_time DESC
      LIMIT 500
    `,
    [tenant, String(value), currentMinutes]
  );

  const alerts = currentResult?.rows || [];
  if (alerts.length >= anomalyThreshold) {
    return alerts;
  }
  return [];
}

const EVALUATORS = {
  threshold: evaluateThresholdRule,
  aggregation: evaluateAggregationRule,
  sequence: evaluateSequenceRule,
  anomaly: evaluateAnomalyRule,
};

// Run all active correlation rules for a tenant against uncorrelated SIEM alerts.
// Returns an array of { rule, matchedAlertCount, correlatedCount } objects.
async function runCorrelationEngine(config, tenant, log = () => {}, { notifyIncidentCreated, executePlaybook } = {}) {
  if (!config.databaseUrl) {
    return { evaluated: 0, correlations: [] };
  }

  const tenantSlug = sanitizeTenant(tenant);

  // Load all active rules for this tenant
  const rulesResult = await query(
    config,
    `
      SELECT id, name, rule_type, conditions, severity_output
      FROM alert_correlation_rules
      WHERE tenant_slug = $1 AND is_active = TRUE
      ORDER BY created_at ASC
    `,
    [tenantSlug]
  );

  const rules = rulesResult?.rows || [];
  if (rules.length === 0) {
    return { evaluated: 0, correlations: [] };
  }

  const correlations = [];

  for (const rule of rules) {
    const evaluator = EVALUATORS[rule.rule_type];
    if (!evaluator) {
      log('warn', 'correlation.unknown_rule_type', { ruleId: rule.id, ruleType: rule.rule_type });
      continue;
    }

    try {
      const matchedAlerts = await evaluator(config, tenantSlug, rule);

      if (matchedAlerts.length > 0) {
        // Create an incident from the correlated alerts
        const incidentResult = await query(
          config,
          `
            INSERT INTO incidents (tenant_slug, title, severity, status, source, detected_at, raw_event)
            VALUES ($1, $2, $3, 'open', 'correlation_engine', NOW(), $4)
            RETURNING id
          `,
          [
            tenantSlug,
            `[Auto-Correlated] ${rule.name} (${matchedAlerts.length} alerts)`,
            VALID_SEVERITIES.includes(rule.severity_output) ? rule.severity_output : 'high',
            JSON.stringify({
              ruleId: rule.id,
              ruleName: rule.name,
              ruleType: rule.rule_type,
              matchedAlertCount: matchedAlerts.length,
              sampleAlertIds: matchedAlerts.slice(0, 10).map(a => a.id),
            }),
          ]
        );

        const incidentId = incidentResult?.rows?.[0]?.id;
        if (incidentId) {
          // Mark matched alerts as correlated
          const alertIds = matchedAlerts.map(a => a.id);
          await query(
            config,
            `
              UPDATE siem_alerts
              SET correlated = TRUE, incident_id = $1
              WHERE id = ANY($2::BIGINT[])
                AND tenant_slug = $3
                AND correlated = FALSE
            `,
            [incidentId, alertIds, tenantSlug]
          );

          correlations.push({
            ruleId: rule.id,
            ruleName: rule.name,
            ruleType: rule.rule_type,
            ruleSeverity: VALID_SEVERITIES.includes(rule.severity_output) ? rule.severity_output : 'high',
            matchedAlertCount: matchedAlerts.length,
            incidentId,
          });

          logCorrelation(tenantSlug, 'rule_fired', {
            ruleId: rule.id,
            ruleName: rule.name,
            ruleType: rule.rule_type,
            matchedAlerts: matchedAlerts.length,
            incidentId,
          });

          // Broadcast real-time SSE notification for auto-created incidents
          if (typeof notifyIncidentCreated === 'function') {
            try {
              const incTitle = `[Auto-Correlated] ${rule.name} (${matchedAlerts.length} alerts)`;
              const incSeverity = VALID_SEVERITIES.includes(rule.severity_output) ? rule.severity_output : 'high';
              notifyIncidentCreated(tenantSlug, { id: incidentId, title: incTitle, severity: incSeverity });
            } catch (_) { /* best-effort notification */ }
          }
        }
      }
    } catch (error) {
      log('error', 'correlation.rule_evaluation_failed', {
        ruleId: rule.id,
        ruleName: rule.name,
        error: error instanceof Error ? error.message : 'unknown error',
      });
    }
  }

  // --- SOAR Playbook Auto-Trigger ---
  // After correlations, check if any playbooks should auto-fire based on rule severity/category
  if (correlations.length > 0) {
    try {
      const playbookResult = await query(
        config,
        `
          SELECT id, name, severity_trigger, category_trigger
          FROM playbooks
          WHERE tenant_slug = $1
            AND is_active = TRUE
            AND auto_trigger = TRUE
          ORDER BY created_at ASC
        `,
        [tenantSlug]
      );

      const autoPlaybooks = playbookResult?.rows || [];
      for (const correlation of correlations) {
        for (const playbook of autoPlaybooks) {
          // Match severity if specified
          const matchSeverity = !playbook.severity_trigger ||
            playbook.severity_trigger === correlation.ruleSeverity;
          // Match category if specified (from rule name pattern)
          const matchCategory = !playbook.category_trigger ||
            (correlation.ruleName || '').toLowerCase().includes((playbook.category_trigger || '').toLowerCase());

          if (matchSeverity && matchCategory) {
            // Create an execution record via executePlaybook service (creates step results, timeline, audit trail)
            try {
              let execution;
              if (typeof executePlaybook === 'function') {
                execution = await executePlaybook(config, {
                  tenant: tenantSlug,
                  playbookId: playbook.id,
                  incidentId: correlation.incidentId || null,
                  startedBy: null, // automated, no human actor
                });
              } else {
                // Fallback: direct insert using valid schema columns
                const execResult = await query(
                  config,
                  `
                    INSERT INTO playbook_executions (tenant_slug, playbook_id, incident_id, status, started_by)
                    VALUES ($1, $2, $3, 'running', NULL)
                    RETURNING id
                  `,
                  [tenantSlug, playbook.id, correlation.incidentId || null]
                );
                execution = execResult?.rows?.[0];
              }

              correlation.autoTriggeredPlaybooks = correlation.autoTriggeredPlaybooks || [];
              correlation.autoTriggeredPlaybooks.push({
                playbookId: playbook.id,
                playbookName: playbook.name,
                triggeredAt: new Date().toISOString(),
              });

              logCorrelation(tenantSlug, 'soar_playbook_auto_triggered', {
                playbookId: playbook.id,
                playbookName: playbook.name,
                incidentId: correlation.incidentId,
                ruleId: correlation.ruleId,
              });
            } catch (triggerErr) {
              log('warn', 'correlation.soar_trigger_failed', {
                playbookId: playbook.id,
                error: triggerErr instanceof Error ? triggerErr.message : 'unknown',
              });
            }
          }
        }
      }
    } catch (soarErr) {
      log('warn', 'correlation.soar_lookup_failed', {
        error: soarErr instanceof Error ? soarErr.message : 'unknown',
      });
    }
  }

  return {
    evaluated: rules.length,
    correlations,
  };
}

module.exports = {
  runCorrelationEngine,
};
