const { createLlmProvider } = require('./llm-provider');
const { sanitizePromptInput, safePromptValue, hardenSystemPrompt, extractJsonFromLlmResponse, assessLlmOutput } = require('./prompt-utils');
const { generateTextWithQualityGate } = require('./quality-gated-generation');
const { appendAuditLog } = require('../audit-log');

const PROMPT_VERSION = 'siem-triage-v1';
const SIEM_TRIAGE_MAX_TOKENS = 850;
const VALID_PRIORITIES = new Set(['critical', 'high', 'medium', 'low']);
const VALID_CONFIDENCE = new Set(['high', 'medium', 'low']);

function normalizePriority(value, fallback = 'medium') {
  const normalized = String(value || '').toLowerCase().trim();
  if (VALID_PRIORITIES.has(normalized)) {
    return normalized;
  }
  return fallback;
}

function normalizeConfidence(value, fallback = 'medium') {
  const normalized = String(value || '').toLowerCase().trim();
  if (VALID_CONFIDENCE.has(normalized)) {
    return normalized;
  }
  return fallback;
}

function summarizeRawPayload(rawPayload) {
  if (!rawPayload || typeof rawPayload !== 'object') {
    return '';
  }

  try {
    return sanitizePromptInput(JSON.stringify(rawPayload, null, 2), 1_500);
  } catch {
    return '';
  }
}

function buildFallbackSummary(alert, fallbackSuggestion) {
  const alertName = alert.ruleName || alert.rule_name || alert.alertId || alert.alert_id || `alert ${alert.id || 'unknown'}`;
  const severity = String(alert.severity || 'medium').toLowerCase();
  const target = alert.hostname || alert.destIp || alert.dest_ip || 'the affected asset';
  const leadReason = Array.isArray(fallbackSuggestion?.suggestions) && fallbackSuggestion.suggestions.length > 0
    ? fallbackSuggestion.suggestions[0].reason
    : 'Review the raw telemetry and classify the alert before taking containment actions.';

  return `${alertName} is a ${severity}-severity alert affecting ${target}. ${leadReason}`;
}

function buildFallbackTriageResponse({
  alert,
  fallbackSuggestion,
  reason,
  details,
  upstreamProvider,
  upstreamModel,
  attempts,
}) {
  return {
    ...fallbackSuggestion,
    summary: buildFallbackSummary(alert, fallbackSuggestion),
    evidence: [
      `db_alert_id:${alert.id}`,
      `severity:${alert.severity}`,
      `category:${alert.category}`,
    ].filter(entry => !String(entry).endsWith(':')),
    llm: {
      provider: 'local',
      model: reason ? 'quality-gated-fallback' : 'rule-based',
      aiGenerated: false,
      groundingScore: 0,
      promptVersion: PROMPT_VERSION,
      qualityGate: reason
        ? {
            accepted: false,
            attempts: attempts || 1,
            reasons: Array.isArray(details) ? details.slice(0, 10) : [String(reason)],
            upstreamProvider: upstreamProvider || null,
            upstreamModel: upstreamModel || null,
          }
        : undefined,
    },
  };
}

function validateSuggestions(items = []) {
  if (!Array.isArray(items)) {
    return null;
  }

  const normalized = items
    .slice(0, 5)
    .map(item => ({
      action: safePromptValue(item?.action || '', 64, 'review_and_classify').replace(/\s+/g, '_').toLowerCase(),
      confidence: normalizeConfidence(item?.confidence, 'medium'),
      reason: sanitizePromptInput(item?.reason || '', 280),
    }))
    .filter(item => item.action && item.reason);

  if (normalized.length < 2) {
    return null;
  }

  return normalized;
}

function validateEvidence(items = []) {
  if (!Array.isArray(items)) {
    return null;
  }

  const evidence = items
    .slice(0, 8)
    .map(item => sanitizePromptInput(item, 120))
    .filter(Boolean);

  if (evidence.length < 2) {
    return null;
  }

  return evidence;
}

async function generateAlertTriageSuggestionWithAi(config, log, payload = {}, context = {}, fallbackSuggestion) {
  const provider = createLlmProvider(config, log);

  if (!provider.isConfigured()) {
    return buildFallbackTriageResponse({
      alert: payload,
      fallbackSuggestion,
    });
  }

  const safeTenant = sanitizePromptInput(payload.tenant || context.tenantSlug || 'global', 64);
  const safeAlertId = String(payload.id || '').trim();
  const safeExternalAlertId = safePromptValue(payload.alertId || payload.alert_id || '', 64, '');
  const safeRuleName = safePromptValue(payload.ruleName || payload.rule_name || 'Unknown alert', 120, 'Unknown alert');
  const safeSeverity = normalizePriority(payload.severity, 'medium');
  const safeCategory = safePromptValue(payload.category || 'unknown', 64, 'unknown');
  const safeStatus = safePromptValue(payload.status || 'new', 32, 'new');
  const safeSourceIp = safePromptValue(payload.sourceIp || payload.source_ip || '', 64, '');
  const safeDestIp = safePromptValue(payload.destIp || payload.dest_ip || '', 64, '');
  const safeHostname = safePromptValue(payload.hostname || '', 128, '');
  const rawPayloadSummary = summarizeRawPayload(payload.rawPayload || payload.raw_payload);

  const fallbackPriority = normalizePriority(fallbackSuggestion?.suggestedPriority, safeSeverity);
  const evidenceIds = [
    safeAlertId,
    safeExternalAlertId,
    safeSourceIp,
    safeDestIp,
    safeHostname,
  ].filter(Boolean);
  const knownTerms = [
    safeSeverity,
    safeCategory,
    safeRuleName,
    safeStatus,
  ].filter(Boolean);

  const userPrompt = [
    `Tenant: ${safeTenant}`,
    `Database alert id: ${safeAlertId || 'unknown'}`,
    `External alert id: ${safeExternalAlertId || 'unknown'}`,
    `Rule name: ${safeRuleName}`,
    `Severity: ${safeSeverity}`,
    `Category: ${safeCategory}`,
    `Status: ${safeStatus}`,
    `Source IP: ${safeSourceIp || 'unknown'}`,
    `Destination IP: ${safeDestIp || 'unknown'}`,
    `Hostname: ${safeHostname || 'unknown'}`,
    `Raw payload: ${rawPayloadSummary || 'none'}`,
    '',
    'Return ONLY valid JSON using this exact schema:',
    '{',
    '  "summary": "<2-4 sentence triage summary>",',
    '  "suggestedPriority": "critical|high|medium|low",',
    '  "suggestions": [',
    '    { "action": "<snake_case_action>", "confidence": "high|medium|low", "reason": "<grounded justification>" }',
    '  ],',
    '  "evidence": ["<exact field:value from the input>", "<exact field:value from the input>"]',
    '}',
    '',
    'Rules:',
    '- Ground every statement in the provided alert fields only.',
    '- Reference the exact alert identifiers, severity, rule name, IPs, hostname, status, or category when present.',
    '- Provide 2 to 5 concrete triage actions in priority order.',
    '- Do not invent users, malware families, geolocation, tooling, incidents, or remediation beyond what the alert supports.',
    '- Keep the summary concise and analyst-friendly.',
  ].join('\n');

  try {
    const startedAt = Date.now();
    const gatedResult = await generateTextWithQualityGate({
      provider,
      log,
      promptPayload: {
        systemPrompt: hardenSystemPrompt(
          'You are Cybertron SIEM Triage Copilot. Produce concise, evidence-grounded triage guidance for SOC analysts.'
        ),
        userPrompt,
        temperature: 0.1,
        maxTokens: SIEM_TRIAGE_MAX_TOKENS,
      },
      context,
      maxAttempts: 2,
      qualityContext: {
        requiredIds: evidenceIds,
        knownTerms,
      },
      evaluate: text => {
        const parsed = extractJsonFromLlmResponse(text);
        const summary = parsed?.summary && typeof parsed.summary === 'string'
          ? parsed.summary.trim()
          : '';
        const suggestions = validateSuggestions(parsed?.suggestions);
        const evidence = validateEvidence(parsed?.evidence);
        const suggestedPriority = normalizePriority(parsed?.suggestedPriority, fallbackPriority);
        const groundingCandidate = [
          summary,
          ...(suggestions || []).map(item => `${item.action}\n${item.reason}\n${item.confidence}`),
          ...(evidence || []),
        ].join('\n');
        const evaluation = assessLlmOutput(
          groundingCandidate,
          {
            alertId: safeAlertId,
            externalAlertId: safeExternalAlertId,
            ruleName: safeRuleName,
            severity: safeSeverity,
            category: safeCategory,
            status: safeStatus,
            sourceIp: safeSourceIp,
            destIp: safeDestIp,
            hostname: safeHostname,
            rawPayload: rawPayloadSummary,
          },
          {
            requiredIds: evidenceIds,
            knownTerms,
            minGroundingScore: 65,
            minReferencedIds: evidenceIds.length > 0 ? 1 : 0,
            minReferencedTerms: Math.min(2, knownTerms.length),
            minimumLength: 120,
            maxLength: 8_000,
          }
        );

        const failureReasons = [...evaluation.failureReasons];
        if (!parsed) {
          failureReasons.unshift('invalid_json_schema');
        }
        if (summary.length < 80) {
          failureReasons.push(`summary_too_short:${summary.length}<80`);
        }
        if (!suggestions) {
          failureReasons.push('missing_or_invalid_suggestions');
        }
        if (!evidence) {
          failureReasons.push('missing_or_invalid_evidence');
        }

        return {
          ...evaluation,
          accepted: Boolean(parsed) && Boolean(suggestions) && Boolean(evidence) && summary.length >= 80 && evaluation.accepted,
          summary,
          suggestions,
          evidence,
          suggestedPriority,
          parsed,
          failureReasons,
        };
      },
    });

    const llmResult = gatedResult.llmResult;
    const evaluation = gatedResult.evaluation || {};
    if (!gatedResult.accepted) {
      return buildFallbackTriageResponse({
        alert: payload,
        fallbackSuggestion,
        reason: 'grounding_failed',
        details: evaluation.failureReasons,
        upstreamProvider: llmResult?.provider,
        upstreamModel: llmResult?.model,
        attempts: gatedResult.attempt,
      });
    }

    appendAuditLog(config, {
      tenantSlug: safeTenant,
      actorId: context.actorId || null,
      actorEmail: context.actorEmail || null,
      action: 'ai.siem.triage_generated',
      targetType: 'siem_alert',
      targetId: safeAlertId || safeExternalAlertId || null,
      ipAddress: context.ipAddress || null,
      userAgent: context.userAgent || null,
      traceId: context.requestId || null,
      payload: {
        provider: llmResult.provider,
        model: llmResult.model,
        severity: safeSeverity,
        groundingScore: evaluation.grounding?.score ?? null,
        qualityGateAccepted: true,
        qualityGateAttempts: gatedResult.attempt,
        promptVersion: PROMPT_VERSION,
        latencyMs: Date.now() - startedAt,
      },
    }).catch(() => {});

    return {
      ...fallbackSuggestion,
      suggestedPriority: evaluation.suggestedPriority,
      suggestions: evaluation.suggestions,
      summary: evaluation.summary,
      evidence: evaluation.evidence,
      automated: true,
      disclaimer: 'AI-assisted triage suggestion grounded in the alert evidence. Validate against raw telemetry before containment.',
      llm: {
        provider: llmResult.provider,
        model: llmResult.model,
        aiGenerated: true,
        groundingScore: evaluation.grounding?.score ?? 0,
        promptVersion: PROMPT_VERSION,
        qualityGate: {
          accepted: true,
          attempts: gatedResult.attempt,
        },
      },
    };
  } catch (error) {
    log('error', 'siem-ai.llm_request_failed', {
      message: error.message,
      requestId: context.requestId,
    });

    return buildFallbackTriageResponse({
      alert: payload,
      fallbackSuggestion,
      reason: 'llm_request_failed',
      details: [error.message],
    });
  }
}

module.exports = {
  generateAlertTriageSuggestionWithAi,
};
