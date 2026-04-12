const { sanitizePromptInput } = require('./prompt-utils');

function buildRepairInstructions(evaluation = {}, qualityContext = {}) {
  const instructions = [];
  const failureReasons = Array.isArray(evaluation.failureReasons) ? evaluation.failureReasons : [];
  const missingHeadings = Array.isArray(evaluation.missingHeadings) ? evaluation.missingHeadings : [];
  const requiredIds = Array.isArray(qualityContext.requiredIds) ? qualityContext.requiredIds.filter(Boolean) : [];
  const knownTerms = Array.isArray(qualityContext.knownTerms) ? qualityContext.knownTerms.filter(Boolean) : [];

  if (failureReasons.length > 0) {
    instructions.push(`- The previous answer was rejected for: ${failureReasons.join('; ')}.`);
  }
  if (missingHeadings.length > 0) {
    instructions.push(`- Include these exact sections/headings: ${missingHeadings.join(', ')}.`);
  }
  if (requiredIds.length > 0) {
    instructions.push(`- Reference exact evidence IDs from the input data, including: ${requiredIds.slice(0, 8).join(', ')}.`);
  }
  if (knownTerms.length > 0) {
    instructions.push(`- Use the real severity/control/domain terms from the input data: ${knownTerms.slice(0, 8).join(', ')}.`);
  }

  instructions.push('- Rewrite the full answer from scratch.');
  instructions.push('- Do not mention this quality-gate repair step.');
  instructions.push('- Do not add facts, controls, CVEs, standards, asset IDs, or technologies that are not in the provided data.');

  return instructions.join('\n');
}

function buildRepairPrompt(baseUserPrompt, evaluation = {}, qualityContext = {}) {
  return [
    baseUserPrompt,
    '',
    'QUALITY GATE REPAIR INSTRUCTIONS:',
    buildRepairInstructions(evaluation, qualityContext),
  ].join('\n');
}

async function generateTextWithQualityGate(options = {}) {
  const provider = options.provider;
  const log = typeof options.log === 'function' ? options.log : () => {};
  const evaluate = options.evaluate;
  const basePromptPayload = options.promptPayload || {};
  const context = options.context || {};
  const qualityContext = options.qualityContext || {};
  const maxAttempts = Math.max(1, Number(options.maxAttempts) || 2);

  if (!provider || typeof provider.generateText !== 'function') {
    throw new Error('LLM provider is required for quality-gated generation.');
  }
  if (typeof evaluate !== 'function') {
    throw new Error('evaluate callback is required for quality-gated generation.');
  }

  let promptPayload = { ...basePromptPayload };
  let lastAttempt = null;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const llmResult = await provider.generateText(promptPayload, context);
    const evaluation = await evaluate(llmResult.text, { llmResult, attempt });

    lastAttempt = {
      accepted: Boolean(evaluation?.accepted),
      attempt,
      llmResult,
      evaluation: evaluation || { accepted: false, failureReasons: ['missing_evaluation'] },
    };

    if (lastAttempt.accepted) {
      return lastAttempt;
    }

    log('warn', 'ai.quality_gate.rejected', {
      requestId: context.requestId,
      attempt,
      provider: llmResult.provider,
      model: llmResult.model,
      failureReasons: Array.isArray(lastAttempt.evaluation.failureReasons)
        ? lastAttempt.evaluation.failureReasons.slice(0, 10)
        : ['quality_gate_rejected'],
      groundingScore: lastAttempt.evaluation.grounding?.score ?? null,
    });

    if (attempt >= maxAttempts) {
      break;
    }

    promptPayload = {
      ...basePromptPayload,
      userPrompt: buildRepairPrompt(basePromptPayload.userPrompt || '', lastAttempt.evaluation, {
        requiredIds: requiredIdsToSafeStrings(qualityContext.requiredIds),
        knownTerms: requiredTermsToSafeStrings(qualityContext.knownTerms),
      }),
      temperature: Math.min(
        Number.isFinite(basePromptPayload.temperature) ? basePromptPayload.temperature : 0.2,
        0.1
      ),
    };
  }

  return lastAttempt;
}

function requiredIdsToSafeStrings(values = []) {
  return values
    .map(value => sanitizePromptInput(value, 64))
    .filter(Boolean);
}

function requiredTermsToSafeStrings(values = []) {
  return values
    .map(value => sanitizePromptInput(value, 64))
    .filter(Boolean);
}

module.exports = {
  generateTextWithQualityGate,
};
