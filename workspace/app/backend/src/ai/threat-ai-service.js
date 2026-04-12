const { createLlmProvider } = require('./llm-provider');

const { sanitizePromptInput, hardenSystemPrompt, assessLlmOutput } = require('./prompt-utils');
const { appendAuditLog } = require('../audit-log');
const { selectPromptVariant, buildExperimentLogEntry } = require('./prompt-registry');
const { generateTextWithQualityGate } = require('./quality-gated-generation');

const PROMPT_VERSION = 'threat-v2';
const THREAT_SUMMARY_MAX_TOKENS = 900;

const CVE_ID_PATTERN = /^CVE-\d{4}-\d{4,}$/;
const VALID_CVE_SEVERITIES = ['critical', 'high', 'medium', 'low', 'unknown'];

function buildLocalCveSummary(payload) {
  const rawCveId = String(payload.cveId || 'unknown').trim().slice(0, 24);
  const cveId = CVE_ID_PATTERN.test(rawCveId) ? rawCveId : 'unknown';
  const severity = String(payload.severity || 'unknown').toUpperCase();
  const cvss = payload.cvssScore ?? 'n/a';
  const description = String(payload.description || 'No description available.').trim();
  const publishedAt = payload.publishedAt ? new Date(payload.publishedAt).toISOString().slice(0, 10) : null;
  const lastModifiedAt = payload.lastModifiedAt ? new Date(payload.lastModifiedAt).toISOString().slice(0, 10) : null;

  const severityImpact = {
    CRITICAL: 'immediate and severe risk to affected systems, potentially allowing full compromise',
    HIGH: 'significant risk that could result in unauthorized access or data exposure',
    MEDIUM: 'moderate risk that could be exploited under specific conditions',
    LOW: 'limited risk with minimal direct impact under normal configurations',
  };

  const impact = severityImpact[severity] || 'risk level requires further analysis';
  const evidenceLines = [
    `- CVE ID: ${cveId}`,
    `- Severity: ${severity}`,
    `- CVSS: ${cvss}`,
  ];
  if (publishedAt) {
    evidenceLines.push(`- Published: ${publishedAt}`);
  }
  if (lastModifiedAt) {
    evidenceLines.push(`- Last modified: ${lastModifiedAt}`);
  }

  const lines = [
    `## ${cveId} Summary`,
    '',
    '### What it means',
    description,
    '',
    '### Business impact',
    `This ${severity}-severity vulnerability (CVSS ${cvss}) presents ${impact}. Organizations using affected software should prioritize remediation based on verified exposure.`,
    '',
    '### Immediate mitigation steps',
    '> Note: These are standard best practices, not tailored to this specific vulnerability. Check vendor advisories for CVE-specific remediation.',
    '- Check if affected software versions are deployed in your environment',
    '- Apply vendor patches or vendor-approved workarounds if available',
    '- Restrict network exposure to affected services where possible',
    '- Enable enhanced logging on affected systems until remediation is verified',
    '',
    '### What to monitor after mitigation',
    '> Note: Generic monitoring guidance. Review CVE details for specific detection signatures.',
    '- Watch for exploitation attempts in IDS/IPS and authentication logs',
    '- Monitor affected service behavior for anomalies and restart failures',
    '- Track vendor advisories for follow-up patches or rollback notices',
    '- Verify patch deployment across all affected instances',
    '',
    '### Evidence basis',
    ...evidenceLines,
  ];

  return lines.join('\n');
}

function buildThreatFallbackResponse({ payload, reason, details, upstreamProvider, upstreamModel, attempts }) {
  return {
    summaryText: buildLocalCveSummary(payload),
    provider: 'local',
    model: reason ? 'quality-gated-fallback' : 'rule-based',
    aiGenerated: false,
    confidence: 'low',
    confidenceNote: reason
      ? 'AI draft was withheld because it did not meet grounding and structure checks. The fallback summary is template-based and should be validated against vendor guidance.'
      : 'Template-based summary with generic mitigation advice. LLM not configured for tailored analysis.',
    qualityGate: reason
      ? {
          accepted: false,
          attempts: attempts || 1,
          reasons: Array.isArray(details) ? details.slice(0, 10) : [String(reason)],
          upstreamProvider: upstreamProvider || null,
          upstreamModel: upstreamModel || null,
        }
      : undefined,
  };
}

async function summarizeCveWithAi(config, log, payload = {}, context = {}) {
  const provider = createLlmProvider(config, log);

  if (!provider.isConfigured()) {
    log('warn', 'threat-ai.llm_not_configured', {
      message: 'LLM provider not configured, using local CVE summary fallback.',
      requestId: context.requestId,
    });

    return buildThreatFallbackResponse({ payload });
  }

  const safeTenant = sanitizePromptInput(payload.tenant || 'global', 64);
  const rawCveId = String(payload.cveId || 'unknown').trim().slice(0, 24);
  const safeCveId = CVE_ID_PATTERN.test(rawCveId) ? rawCveId : 'unknown';
  const rawSeverity = String(payload.severity || 'unknown').toLowerCase().trim();
  const safeSeverity = VALID_CVE_SEVERITIES.includes(rawSeverity) ? rawSeverity : 'unknown';
  const safeDescription = sanitizePromptInput(payload.description || 'No description provided.', 8000);
  const safePublishedAt = payload.publishedAt ? sanitizePromptInput(payload.publishedAt, 64) : '';
  const safeLastModifiedAt = payload.lastModifiedAt ? sanitizePromptInput(payload.lastModifiedAt, 64) : '';
  const cvssScore = payload.cvssScore ?? 'n/a';

  const userPrompt = [
    `Tenant: ${safeTenant}`,
    `CVE: ${safeCveId}`,
    `Severity: ${safeSeverity}`,
    `CVSS: ${cvssScore}`,
    `Published: ${safePublishedAt || 'unknown'}`,
    `Last modified: ${safeLastModifiedAt || 'unknown'}`,
    'Summarize this vulnerability in plain English.',
    'Return plain text only using these exact headings:',
    'What it means',
    'Business impact',
    'Immediate mitigation steps',
    'What to monitor after mitigation',
    'Evidence basis',
    'Reference the exact CVE ID and real severity from the input data.',
    'Do not invent vendor names, affected products, indicators, or remediation that is not supported by the input.',
    '',
    safeDescription,
  ].join('\n');

  try {
    const variant = selectPromptVariant(PROMPT_VERSION);
    const systemPrompt = variant
      ? hardenSystemPrompt(variant.systemPrompt)
      : hardenSystemPrompt(
          'You are Cybertron Threat Intel Summarizer. Write concise executive and analyst-friendly vulnerability summaries.'
        );

    const startedAt = Date.now();
    const knownTerms = [safeSeverity].filter(severity => severity !== 'unknown');
    const gatedResult = await generateTextWithQualityGate({
      provider,
      log,
      promptPayload: {
        systemPrompt,
        userPrompt,
        temperature: variant?.temperature ?? 0.15,
        // Keep synchronous threat summaries concise enough to return before the live app times out.
        maxTokens: THREAT_SUMMARY_MAX_TOKENS,
      },
      context,
      maxAttempts: 2,
      qualityContext: {
        requiredIds: safeCveId !== 'unknown' ? [safeCveId] : [],
        knownTerms,
      },
      evaluate: text => {
        const evaluation = assessLlmOutput(
          text,
          {
            cveId: safeCveId,
            severity: safeSeverity,
            cvssScore,
            description: safeDescription,
            publishedAt: safePublishedAt,
            lastModifiedAt: safeLastModifiedAt,
          },
          {
            requiredIds: safeCveId !== 'unknown' ? [safeCveId] : [],
            knownTerms,
            requiredHeadings: [
              'What it means',
              'Business impact',
              'Immediate mitigation steps',
              'What to monitor after mitigation',
              'Evidence basis',
            ],
            minGroundingScore: 60,
            minReferencedIds: safeCveId !== 'unknown' ? 1 : 0,
            minReferencedTerms: knownTerms.length > 0 ? 1 : 0,
            minimumLength: 220,
            maxLength: 10_000,
          }
        );

        const failureReasons = [...evaluation.failureReasons];
        if (safeCveId !== 'unknown' && !text.includes(safeCveId)) {
          failureReasons.push('missing_explicit_cve_reference');
        }

        return {
          ...evaluation,
          accepted: evaluation.accepted && failureReasons.length === 0,
          failureReasons,
        };
      },
    });

    const llmResult = gatedResult.llmResult;
    const groundingResult = gatedResult.evaluation?.grounding;

    if (!gatedResult.accepted) {
      return buildThreatFallbackResponse({
        payload,
        reason: 'grounding_failed',
        details: gatedResult.evaluation?.failureReasons,
        upstreamProvider: llmResult?.provider,
        upstreamModel: llmResult?.model,
        attempts: gatedResult.attempt,
      });
    }

    if (variant) {
      log('info', 'prompt_experiment', buildExperimentLogEntry({
        promptKey: PROMPT_VERSION,
        variantId: variant.variantId,
        requestId: context.requestId,
        tenantSlug: safeTenant,
        latencyMs: Date.now() - startedAt,
        groundingScore: groundingResult.score,
        parsedSuccessfully: true,
      }));
    }

    appendAuditLog(config, {
      tenantSlug: safeTenant,
      actorId: context.actorId || null,
      actorEmail: context.actorEmail || null,
      action: 'ai.threat.cve_summarized',
      targetType: 'cve',
      targetId: safeCveId,
      ipAddress: context.ipAddress || null,
      userAgent: context.userAgent || null,
      traceId: context.requestId || null,
      payload: {
        provider: llmResult.provider,
        model: llmResult.model,
        severity: safeSeverity,
        groundingScore: groundingResult.score,
        qualityGateAccepted: true,
        qualityGateAttempts: gatedResult.attempt,
        promptVersion: PROMPT_VERSION,
      },
    }).catch(() => {});

    return {
      summaryText: gatedResult.evaluation.validation.text,
      provider: llmResult.provider,
      model: llmResult.model,
      aiGenerated: true,
      disclaimer: 'AI-generated summary. Verify against official vendor advisories before acting.',
      promptVersion: PROMPT_VERSION,
      groundingScore: groundingResult.score,
      groundingDetails: groundingResult.ungroundedClaims.length > 0 ? groundingResult.ungroundedClaims : undefined,
      qualityGate: {
        accepted: true,
        attempts: gatedResult.attempt,
      },
    };
  } catch (error) {
    log('error', 'threat-ai.llm_request_failed', {
      message: error.message,
      requestId: context.requestId,
    });

    return {
      ...buildThreatFallbackResponse({
        payload,
        reason: 'llm_request_failed',
        details: [error.message],
      }),
      model: 'rule-based-fallback',
      confidenceNote: 'LLM call failed; fell back to a template-based summary with generic advice.',
    };
  }
}

module.exports = {
  summarizeCveWithAi,
  buildLocalCveSummary,
};
