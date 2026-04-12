#!/usr/bin/env node

const fs = require('node:fs/promises');
const path = require('node:path');

const DEFAULT_INPUT = path.resolve(__dirname, 'data', 'cybertron_bootstrap_sft.jsonl');
const DEFAULT_OUTPUT = path.resolve(__dirname, 'data', 'cybertron_teacher_sft.jsonl');
const DEFAULT_ENDPOINT = 'https://models.github.ai/inference/chat/completions';
const DEFAULT_VARIANTS = 3;
const STYLE_VARIANTS = [
  {
    id: 'balanced',
    instruction:
      'Produce a balanced, production-grade answer grounded in the provided evidence. Optimize for accuracy, structure, and safe actionability.',
  },
  {
    id: 'executive',
    instruction:
      'Optimize for leadership readability while preserving concrete technical substance. Keep the tone decisive and operationally useful.',
  },
  {
    id: 'operator',
    instruction:
      'Optimize for operator usefulness. Be explicit, actionable, and concrete so an analyst or engineer can act immediately.',
  },
  {
    id: 'audit',
    instruction:
      'Optimize for auditability and control traceability. Preserve approval gates, confidence notes, and grounded caveats where relevant.',
  },
];

function parseArgs(argv) {
  const args = {
    input: DEFAULT_INPUT,
    output: DEFAULT_OUTPUT,
    endpoint: process.env.GITHUB_MODELS_ENDPOINT || DEFAULT_ENDPOINT,
    model: process.env.GITHUB_MODELS_MODEL || '',
    limit: 0,
    task: '',
    variants: DEFAULT_VARIANTS,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const current = argv[index];
    if (current === '--in' && argv[index + 1]) {
      args.input = path.resolve(argv[index + 1]);
      index += 1;
      continue;
    }
    if (current === '--out' && argv[index + 1]) {
      args.output = path.resolve(argv[index + 1]);
      index += 1;
      continue;
    }
    if (current === '--model' && argv[index + 1]) {
      args.model = argv[index + 1];
      index += 1;
      continue;
    }
    if (current === '--limit' && argv[index + 1]) {
      args.limit = Number.parseInt(argv[index + 1], 10) || 0;
      index += 1;
      continue;
    }
    if (current === '--task' && argv[index + 1]) {
      args.task = argv[index + 1];
      index += 1;
      continue;
    }
    if (current === '--variants' && argv[index + 1]) {
      args.variants = Math.max(1, Number.parseInt(argv[index + 1], 10) || DEFAULT_VARIANTS);
      index += 1;
    }
  }

  return args;
}

async function readJsonl(filePath) {
  const raw = await fs.readFile(filePath, 'utf8');
  return raw
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(Boolean)
    .map(line => JSON.parse(line));
}

function buildText(systemPrompt, userPrompt, assistantResponse) {
  return [
    '### System',
    systemPrompt,
    '',
    '### User',
    userPrompt,
    '',
    '### Assistant',
    assistantResponse,
    '',
  ].join('\n');
}

function buildTeacherPrompt(row, style) {
  const payload = JSON.stringify(row.payload, null, 2);
  const weakBaseline = JSON.stringify(row.response, null, 2);
  const sharedSystem = [
    'You are Cybertron Teacher Model.',
    'Create the strongest possible training target for Cybertron AI.',
    'Stay fully grounded in the provided context.',
    'Do not invent assets, controls, or vulnerabilities.',
    'Do not claim the output is rule-based or template-based, because this target is AI-generated.',
    'Do not wrap the response in markdown fences.',
    style.instruction,
  ].join(' ');

  if (row.taskType === 'risk_explanation') {
    return {
      systemPrompt: sharedSystem,
      userPrompt: [
        'Task: produce a superior risk-copilot output for training.',
        'Return valid JSON only with this exact shape:',
        '{',
        '  "explanation": "<executive risk briefing>",',
        '  "mitigationSuggestions": ["<action 1>", "<action 2>", "..."],',
        '  "disclaimer": "<brief AI-review note>"',
        '}',
        'Rules:',
        '- Explain business impact and technical urgency clearly.',
        '- Keep mitigationSuggestions concrete, direct, and grounded in the actual findings.',
        '- Include 5-10 mitigationSuggestions when the evidence supports it.',
        '- The disclaimer must say the output is AI-generated and should be reviewed before action.',
        '',
        'Context JSON:',
        payload,
        '',
        'Weak baseline to outperform:',
        weakBaseline,
      ].join('\n'),
    };
  }

  if (row.taskType === 'policy_draft') {
    return {
      systemPrompt: sharedSystem,
      userPrompt: [
        'Task: produce a superior compliance policy draft for training.',
        'Return valid JSON only with this exact shape:',
        '{',
        '  "policyKey": "<policy key>",',
        '  "content": "<full policy document in markdown>",',
        '  "approvalStatus": "draft",',
        '  "requiresApproval": true,',
        '  "approvalNote": "<review requirement>"',
        '}',
        'Rules:',
        '- Preserve approval gates.',
        '- Write content that is practical, startup-appropriate, and audit-aware.',
        '- Keep the policy grounded in the provided controls and organization context.',
        '- Do not claim the draft is already approved or active.',
        '',
        'Context JSON:',
        payload,
        '',
        'Weak baseline to outperform:',
        weakBaseline,
      ].join('\n'),
    };
  }

  return {
    systemPrompt: sharedSystem,
    userPrompt: [
      'Task: produce a superior threat-intel summary for training.',
      'Return valid JSON only with this exact shape:',
      '{',
      '  "summaryText": "<plain-language vulnerability summary>",',
      '  "confidence": "<low|medium|high>",',
      '  "confidenceNote": "<brief justification>",',
      '  "disclaimer": "<review note>"',
      '}',
      'Rules:',
      '- Keep the summary concrete and grounded in the provided CVE context.',
      '- Include business impact, immediate mitigation, and what to monitor.',
      '- The disclaimer must tell operators to validate against vendor or authoritative advisories before acting.',
      '',
      'Context JSON:',
      payload,
      '',
      'Weak baseline to outperform:',
      weakBaseline,
    ].join('\n'),
  };
}

async function generateTeacherResponse({ endpoint, token, model, messages }) {
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      model,
      messages,
      temperature: 0.2,
      top_p: 1,
    }),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`GitHub Models request failed (${response.status}): ${body}`);
  }

  const payload = await response.json();
  return payload?.choices?.[0]?.message?.content;
}

function normalizeTeacherContent(content) {
  const text = String(content || '').trim();
  const fencedMatch = text.match(/^```(?:json|markdown|text)?\s*([\s\S]*?)\s*```$/i);
  if (fencedMatch) {
    return fencedMatch[1].trim();
  }
  return text;
}

async function writeJsonl(filePath, rows) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  const content = rows.map(row => JSON.stringify(row)).join('\n') + '\n';
  await fs.writeFile(filePath, content, 'utf8');
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || '';

  if (!token) {
    throw new Error('Missing GITHUB_TOKEN or GH_TOKEN. Run gh auth login, then export a token before using GitHub Models.');
  }
  if (!args.model) {
    throw new Error('Missing model selection. Set GITHUB_MODELS_MODEL or pass --model <catalog-model-id>.');
  }

  const sourceRows = await readJsonl(args.input);
  const filtered = sourceRows.filter(row => !args.task || row.taskType === args.task);
  const limited = args.limit > 0 ? filtered.slice(0, args.limit) : filtered;
  const outputs = [];

  for (const row of limited) {
    const styles = STYLE_VARIANTS.slice(0, args.variants);
    for (let variantIndex = 0; variantIndex < styles.length; variantIndex += 1) {
      const style = styles[variantIndex];
      const prompt = buildTeacherPrompt(row, style);
      const promptMessages = [
        {
          role: 'system',
          content: prompt.systemPrompt,
        },
        {
          role: 'user',
          content: prompt.userPrompt,
        },
      ];

      const teacherContent = await generateTeacherResponse({
        endpoint: args.endpoint,
        token,
        model: args.model,
        messages: promptMessages,
      });

      if (!teacherContent || !String(teacherContent).trim()) {
        throw new Error(`Empty teacher response for ${row.id} (${style.id})`);
      }

      const systemPrompt = prompt.systemPrompt;
      const userPrompt = prompt.userPrompt;
      const assistantResponse = normalizeTeacherContent(teacherContent);

      outputs.push({
        id: `${row.id}-teacher-${style.id}`,
        parentId: row.id,
        taskType: row.taskType,
        source: 'github-models-teacher',
        teacherModel: args.model,
        variantStyle: style.id,
        aiGenerated: true,
        messages: [
          ...promptMessages,
          {
            role: 'assistant',
            content: assistantResponse,
          },
        ],
        text: buildText(systemPrompt, userPrompt, assistantResponse),
      });

      console.log(
        JSON.stringify({
          ok: true,
          id: row.id,
          taskType: row.taskType,
          model: args.model,
          variantStyle: style.id,
        })
      );
    }
  }

  await writeJsonl(args.output, outputs);

  console.log(
    JSON.stringify(
      {
        ok: true,
        records: outputs.length,
        output: args.output,
        model: args.model,
        endpoint: args.endpoint,
      },
      null,
      2
    )
  );
}

main().catch(error => {
  console.error(
    JSON.stringify(
      {
        ok: false,
        message: error.message,
      },
      null,
      2
    )
  );
  process.exitCode = 1;
});
