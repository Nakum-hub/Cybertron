const { createLlmProvider } = require('./llm-provider');
const {
  sanitizePromptInput, safePromptValue, hardenSystemPrompt,
  extractJsonFromLlmResponse, assessLlmOutput,
} = require('./prompt-utils');
const { appendAuditLog } = require('../audit-log');
const { selectPromptVariant, buildExperimentLogEntry } = require('./prompt-registry');
const { generateTextWithQualityGate } = require('./quality-gated-generation');

// ── Local mitigation builder (fallback only when LLM parsing fails) ───────────

function buildLocalMitigationSuggestions(findings = []) {
  const suggestions = [];
  for (const finding of findings.slice(0, 10)) {
    const mitigation = Array.isArray(finding.details?.mitigationSuggestions)
      ? finding.details.mitigationSuggestions
      : [];
    for (const item of mitigation) {
      if (!item || suggestions.includes(item)) {
        continue;
      }
      suggestions.push(item);
      if (suggestions.length >= 12) {
        return suggestions;
      }
    }
  }

  if (suggestions.length === 0) {
    suggestions.push(
      'No active high-risk findings. Keep daily log ingestion and vulnerability patching cadence active.'
    );
  }

  return suggestions;
}

function buildLocalRiskExplanation(summarizedFindings, portfolio) {
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of summarizedFindings) {
    const sev = String(f.severity || '').toLowerCase();
    if (sev in severityCounts) severityCounts[sev]++;
  }
  const totalFindings = summarizedFindings.length;
  const topCategories = [...new Set(summarizedFindings.map(f => f.category).filter(Boolean))].slice(0, 5);
  const priorityFindings = [...summarizedFindings]
    .sort((left, right) => Number(right.score || 0) - Number(left.score || 0))
    .slice(0, 3);
  const lines = [
    `Rule-based risk analysis (LLM not configured):`,
    ``,
    `- ${totalFindings} risk finding(s) analyzed.`,
    `- Severity breakdown: ${severityCounts.critical} critical, ${severityCounts.high} high, ${severityCounts.medium} medium, ${severityCounts.low} low.`,
  ];
  if (topCategories.length > 0) {
    lines.push(`- Top risk categories: ${topCategories.join(', ')}.`);
  }
  if (portfolio.totalAssets) {
    lines.push(`- Portfolio scope: ${portfolio.totalAssets} asset(s) under management.`);
  }
  if (severityCounts.critical > 0) {
    lines.push(`- Immediate action required: ${severityCounts.critical} critical finding(s) demand priority remediation.`);
  }
  if (priorityFindings.length > 0) {
    lines.push('', 'Priority findings:');
    for (const finding of priorityFindings) {
      lines.push(
        `- ${finding.assetId}: ${String(finding.severity || 'unknown').toUpperCase()} ${finding.category || 'risk'} ` +
        `(${finding.title || 'Untitled finding'}, source: ${finding.source || 'unknown'}, score: ${finding.score ?? 'n/a'}).`
      );
    }
  }
  lines.push(``, `Note: Configure an LLM provider (LLM_PROVIDER) for tailored executive risk briefings with detailed mitigation plans.`);
  return lines.join('\n');
}

function validateMitigations(raw) {
  if (!Array.isArray(raw)) {
    return null;
  }
  const valid = raw
    .filter(item => typeof item === 'string' && item.trim().length > 10)
    .map(item => item.trim().slice(0, 500))
    .slice(0, 15);
  return valid.length >= 2 ? valid : null;
}

function validateEvidence(raw) {
  if (!Array.isArray(raw)) {
    return null;
  }
  const valid = raw
    .filter(item => typeof item === 'string' && item.trim().length > 2)
    .map(item => item.trim().slice(0, 128))
    .slice(0, 12);
  return valid.length >= 1 ? valid : null;
}

function buildRiskFallbackResponse({ summarizedFindings, findings, portfolio, reason, details, upstreamProvider, upstreamModel, attempts }) {
  return {
    explanation: buildLocalRiskExplanation(summarizedFindings, portfolio),
    provider: 'local',
    model: reason ? 'quality-gated-fallback' : 'rule-based',
    aiGenerated: false,
    mitigationSuggestions: buildLocalMitigationSuggestions(findings),
    qualityGate: reason
      ? {
          accepted: false,
          attempts: attempts || 1,
          reasons: Array.isArray(details) ? details.slice(0, 10) : [String(reason)],
          upstreamProvider: upstreamProvider || null,
          upstreamModel: upstreamModel || null,
        }
      : undefined,
    disclaimer: reason
      ? 'AI draft was withheld because it did not meet Cybertron grounding checks. Review the rule-based output and underlying findings.'
      : undefined,
  };
}

const PROMPT_VERSION = 'risk-v2';

// ── Core AI risk explanation + mitigation generator ───────────────────────────

async function generateRiskExplanation(config, log, payload = {}, context = {}) {
  const provider = createLlmProvider(config, log);
  const findings = Array.isArray(payload.findings) ? payload.findings : [];
  const portfolio = payload.portfolio || {};
  const tenant = sanitizePromptInput(payload.tenant || 'global', 64);

  const summarizedFindings = findings.slice(0, 12).map(item => ({
    id: item.id,
    category: sanitizePromptInput(item.category, 64),
    severity: sanitizePromptInput(item.severity, 16),
    score: item.score,
    assetId: safePromptValue(item.assetId, 128, 'unknown-asset'),
    title: safePromptValue(item.details?.title, 255, 'Untitled finding'),
    source: safePromptValue(item.details?.source, 128, 'unknown'),
  }));

  // Insufficient data guard: with fewer than 3 findings, the LLM would fill gaps with assumptions
  if (summarizedFindings.length < 3 && !provider.isConfigured()) {
    return {
      explanation: 'Insufficient risk data for AI analysis. Ingest more log data to enable comprehensive risk assessment.',
      provider: 'local',
      model: 'insufficient-data',
      aiGenerated: false,
      mitigationSuggestions: buildLocalMitigationSuggestions(findings),
    };
  }

  // LLM not configured guard: provide rule-based analysis instead of crashing with 503
  if (!provider.isConfigured()) {
    log('warn', 'risk-ai.llm_not_configured', {
      message: 'LLM provider not configured; returning rule-based risk analysis.',
      findingCount: summarizedFindings.length,
      requestId: context.requestId,
    });

    return {
      ...buildRiskFallbackResponse({
        summarizedFindings,
        findings,
        portfolio,
      }),
    };
  }

  const userPrompt = [
    `Tenant: ${tenant}`,
    '',
    'Analyze the cybersecurity risk portfolio and findings below.',
    'Respond ONLY with valid JSON using this exact schema (no markdown wrapping):',
    '',
    '{',
    '  "explanation": "<executive summary>",',
    '  "mitigations": ["<action 1>", "<action 2>", ...],',
    '  "evidence": ["<asset-id-or-finding-id>", "<severity-or-category>", ...]',
    '}',
    '',
    'Rules for "explanation":',
    '- Write for a non-technical executive audience.',
    '- Summarize overall risk posture with key patterns, business impact, and exposure.',
    '- Use concise bullet-point format (use \\n for line breaks).',
    '- Reference at least one exact asset ID from the findings when available.',
    '- End with 3-5 concrete next actions leadership should authorize immediately.',
    '',
    'Rules for "mitigations":',
    '- Provide 5-10 specific, actionable remediation steps ordered by urgency.',
    '- Reference actual asset IDs, categories, and severity levels from the findings.',
    '- Specify exact technologies, configurations, or procedures to apply.',
    '- Each item must be one concrete sentence an engineer can act on today.',
    '- Prioritize critical and high severity findings first.',
    '',
    'Rules for "evidence":',
    '- List the exact asset IDs, finding IDs, severities, or categories that support the explanation.',
    '- Do not invent evidence that is not present in the input data.',
    '',
    'Portfolio and findings data:',
    JSON.stringify(
      {
        portfolio,
        findings: summarizedFindings,
      },
      null,
      2
    ),
  ].join('\n');

  // Check for A/B prompt variant
  const variant = selectPromptVariant(PROMPT_VERSION);
  const systemPrompt = variant
    ? hardenSystemPrompt(variant.systemPrompt)
    : hardenSystemPrompt(
        'You are Cybertron Risk Copilot, an expert cybersecurity risk analyst. ' +
        'You produce structured JSON containing executive risk briefings and prioritized, ' +
        'finding-specific mitigation plans. Always respond with valid JSON only.'
      );

  const startedAt = Date.now();
  const assetIds = summarizedFindings.map(f => f.assetId).filter(id => id !== 'unknown-asset');
  const knownTerms = [
    ...new Set(
      summarizedFindings
        .flatMap(f => [f.severity, f.category])
        .filter(Boolean)
    ),
  ];

  const gatedResult = await generateTextWithQualityGate({
    provider,
    log,
    promptPayload: {
      systemPrompt,
      userPrompt,
      temperature: variant?.temperature ?? 0.05,
    },
    context,
    maxAttempts: 2,
    qualityContext: {
      requiredIds: assetIds,
      knownTerms,
    },
    evaluate: text => {
      const parsed = extractJsonFromLlmResponse(text);
      const explanation = parsed?.explanation && typeof parsed.explanation === 'string'
        ? parsed.explanation.trim()
        : '';
      const mitigations = validateMitigations(parsed?.mitigations);
      const evidence = validateEvidence(parsed?.evidence);
      const groundingCandidate = [
        explanation,
        ...(mitigations || []),
        ...(evidence || []),
      ].join('\n');
      const evaluation = assessLlmOutput(
        groundingCandidate,
        { portfolio, findings: summarizedFindings },
        {
          requiredIds: assetIds,
          knownTerms,
          minGroundingScore: 65,
          minReferencedIds: Math.min(1, assetIds.length),
          minReferencedTerms: knownTerms.length > 1 ? 2 : Math.min(1, knownTerms.length),
          minimumLength: 140,
        }
      );

      const failureReasons = [...evaluation.failureReasons];
      if (!parsed) {
        failureReasons.unshift('invalid_json_schema');
      }
      if (explanation.length < 120) {
        failureReasons.push(`executive_summary_too_short:${explanation.length}<120`);
      }
      if (!evidence) {
        failureReasons.push('missing_evidence_list');
      }

      return {
        ...evaluation,
        accepted: Boolean(parsed) && Boolean(evidence) && evaluation.accepted,
        parsed,
        explanation,
        mitigations,
        evidence,
        failureReasons,
      };
    },
  });

  const llmResult = gatedResult.llmResult;
  const gating = gatedResult.evaluation || {};
  if (!gatedResult.accepted) {
    return buildRiskFallbackResponse({
      summarizedFindings,
      findings,
      portfolio,
      reason: 'grounding_failed',
      details: gating.failureReasons,
      upstreamProvider: llmResult?.provider,
      upstreamModel: llmResult?.model,
      attempts: gatedResult.attempt,
    });
  }

  const explanation = gating.explanation;
  const mitigationSuggestions = gating.mitigations || buildLocalMitigationSuggestions(findings);
  const groundingResult = gating.grounding;

  // Log A/B experiment data if a variant was selected
  if (variant) {
    log('info', 'prompt_experiment', buildExperimentLogEntry({
      promptKey: PROMPT_VERSION,
      variantId: variant.variantId,
      requestId: context.requestId,
      tenantSlug: sanitizePromptInput(payload.tenant || 'global', 64),
      latencyMs: Date.now() - startedAt,
      groundingScore: groundingResult.score,
      parsedSuccessfully: true,
    }));
  }

  // Audit trail: record AI operation for compliance
  appendAuditLog(config, {
    tenantSlug: sanitizePromptInput(payload.tenant || 'global', 64),
    actorId: context.actorId || null,
    actorEmail: context.actorEmail || null,
    action: 'ai.risk.explanation_generated',
    targetType: 'risk_portfolio',
    targetId: context.requestId || null,
    ipAddress: context.ipAddress || null,
    userAgent: context.userAgent || null,
    traceId: context.requestId || null,
    payload: {
      provider: llmResult.provider,
      model: llmResult.model,
      findingsCount: summarizedFindings.length,
      groundingScore: groundingResult.score,
      qualityGateAccepted: true,
      qualityGateAttempts: gatedResult.attempt,
      promptVersion: PROMPT_VERSION,
    },
  }).catch(() => {}); // non-blocking, never fail the main request
  return {
    explanation,
    provider: llmResult.provider,
    model: llmResult.model,
    mitigationSuggestions,
    aiGenerated: true,
    groundedInFindings: summarizedFindings.length,
    groundingScore: groundingResult.score,
    groundingDetails: groundingResult.ungroundedClaims.length > 0 ? groundingResult.ungroundedClaims : undefined,
    disclaimer: 'AI-generated analysis based on ingested findings. Review before acting.',
    promptVersion: PROMPT_VERSION,
    qualityGate: {
      accepted: true,
      attempts: gatedResult.attempt,
      mitigationSource: gating.mitigations ? 'ai' : 'local-fallback',
    },
  };
}

module.exports = {
  extractJsonFromLlmResponse,
  generateRiskExplanation,
  buildLocalMitigationSuggestions,
};
