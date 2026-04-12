#!/usr/bin/env node

const fs = require('node:fs/promises');
const path = require('node:path');

const { generateRiskExplanation } = require('../app/backend/src/ai/risk-ai-service');
const { generatePolicyDraft } = require('../app/backend/src/ai/policy-ai-service');
const { summarizeCveWithAi } = require('../app/backend/src/ai/threat-ai-service');

const DEFAULT_OUTPUT = path.resolve(__dirname, 'data', 'cybertron_bootstrap_sft.jsonl');
const DEFAULT_MANIFEST = path.resolve(__dirname, 'data', 'cybertron_bootstrap_manifest.json');
const DATA_SOURCE = 'cybertron-bootstrap-rule-template';

const baseConfig = {
  llmProvider: 'none',
  databaseUrl: '',
};

function log() {
  // Keep dataset export quiet unless a hard failure happens.
}

function parseArgs(argv) {
  const args = {
    out: DEFAULT_OUTPUT,
    manifest: DEFAULT_MANIFEST,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const current = argv[index];
    if (current === '--out' && argv[index + 1]) {
      args.out = path.resolve(argv[index + 1]);
      index += 1;
      continue;
    }
    if (current === '--manifest' && argv[index + 1]) {
      args.manifest = path.resolve(argv[index + 1]);
      index += 1;
    }
  }

  return args;
}

function buildContext(taskType, recordId) {
  return {
    actorId: 'cybertron-bootstrap-export',
    actorEmail: 'bootstrap@cybertron.local',
    requestId: `${taskType}-${recordId}`,
    tenantSlug: 'bootstrap',
  };
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

function buildUserPrompt(taskLabel, payload) {
  return [
    `${taskLabel}`,
    '',
    'Use only the provided Cybertron context. Be explicit if the output is template-based or rule-based.',
    '',
    'Context JSON:',
    JSON.stringify(payload, null, 2),
  ].join('\n');
}

function buildRecord({ id, taskType, systemPrompt, userPrompt, response, payload }) {
  const assistantResponse = JSON.stringify(response, null, 2);
  return {
    id,
    taskType,
    source: DATA_SOURCE,
    aiGenerated: false,
    payload,
    response,
    messages: [
      {
        role: 'system',
        content: systemPrompt,
      },
      {
        role: 'user',
        content: userPrompt,
      },
      {
        role: 'assistant',
        content: assistantResponse,
      },
    ],
    text: buildText(systemPrompt, userPrompt, assistantResponse),
  };
}

const riskScenarios = [
  {
    id: 'risk-001',
    payload: {
      tenant: 'global',
      portfolio: {
        totalAssets: 84,
        criticalAssets: 12,
        internetFacingAssets: 18,
      },
      findings: [
        {
          id: 'rf-001',
          category: 'vulnerability',
          severity: 'critical',
          score: 96,
          assetId: 'prod-edge-gateway-01',
          details: {
            title: 'Internet-facing VPN appliance missing emergency patch',
            source: 'nessus',
            mitigationSuggestions: [
              'Apply the vendor emergency patch to prod-edge-gateway-01 within the next maintenance window.',
              'Restrict inbound administration to the corporate VPN management subnet only.',
            ],
          },
        },
        {
          id: 'rf-002',
          category: 'identity',
          severity: 'high',
          score: 83,
          assetId: 'okta-admin-group',
          details: {
            title: 'Dormant privileged accounts without MFA enrollment',
            source: 'identity-audit',
            mitigationSuggestions: [
              'Disable dormant privileged accounts in okta-admin-group until owners re-attest access and enroll in MFA.',
              'Run an emergency privileged-access review for all administrator groups this week.',
            ],
          },
        },
        {
          id: 'rf-003',
          category: 'data-protection',
          severity: 'high',
          score: 79,
          assetId: 'customer-data-warehouse',
          details: {
            title: 'Sensitive exports retained beyond approved retention window',
            source: 'dlp-monitor',
            mitigationSuggestions: [
              'Purge expired customer exports from customer-data-warehouse and re-apply lifecycle policies.',
              'Enable automated weekly validation for retention jobs on the data warehouse export bucket.',
            ],
          },
        },
      ],
    },
  },
  {
    id: 'risk-002',
    payload: {
      tenant: 'global',
      portfolio: {
        totalAssets: 36,
        criticalAssets: 5,
        internetFacingAssets: 7,
      },
      findings: [
        {
          id: 'rf-004',
          category: 'cloud',
          severity: 'high',
          score: 77,
          assetId: 'aws-prod-account',
          details: {
            title: 'CloudTrail disabled in one production region',
            source: 'aws-config',
            mitigationSuggestions: [
              'Re-enable CloudTrail organization trails in the affected production region immediately.',
              'Create a guardrail that blocks production account changes when audit logging is disabled.',
            ],
          },
        },
        {
          id: 'rf-005',
          category: 'endpoint',
          severity: 'medium',
          score: 58,
          assetId: 'finance-laptop-fleet',
          details: {
            title: 'Endpoint agent drift detected on finance laptops',
            source: 'edr',
            mitigationSuggestions: [
              'Reinstall the EDR sensor on finance-laptop-fleet devices missing the current policy version.',
              'Alert the SOC when endpoint agent health checks fail for more than 24 hours.',
            ],
          },
        },
        {
          id: 'rf-006',
          category: 'backup',
          severity: 'medium',
          score: 52,
          assetId: 'postgres-prod-primary',
          details: {
            title: 'Backup restore test overdue',
            source: 'backup-audit',
            mitigationSuggestions: [
              'Run and document a full restore test for postgres-prod-primary this week.',
              'Add quarterly restore verification tasks to the production operations calendar.',
            ],
          },
        },
        {
          id: 'rf-007',
          category: 'network',
          severity: 'low',
          score: 28,
          assetId: 'branch-office-fw-02',
          details: {
            title: 'Firewall rule comments missing on legacy rule set',
            source: 'firewall-review',
            mitigationSuggestions: [
              'Add business justification comments to legacy rules on branch-office-fw-02.',
            ],
          },
        },
      ],
    },
  },
  {
    id: 'risk-003',
    payload: {
      tenant: 'global',
      portfolio: {
        totalAssets: 12,
        criticalAssets: 2,
        internetFacingAssets: 3,
      },
      findings: [
        {
          id: 'rf-008',
          category: 'application-security',
          severity: 'critical',
          score: 93,
          assetId: 'customer-portal-api',
          details: {
            title: 'Authenticated path traversal in document export endpoint',
            source: 'pentest',
            mitigationSuggestions: [
              'Disable the vulnerable document export endpoint on customer-portal-api until the path traversal fix is deployed.',
              'Add regression tests for traversal sequences and enforce canonical path validation.',
            ],
          },
        },
        {
          id: 'rf-009',
          category: 'logging',
          severity: 'high',
          score: 72,
          assetId: 'siem-ingest-cluster',
          details: {
            title: 'Dropped log events during ingestion spikes',
            source: 'siem-health',
            mitigationSuggestions: [
              'Increase queue depth and ingestion worker count for siem-ingest-cluster before the next peak period.',
              'Alert on dropped-event thresholds above baseline in the SIEM health dashboard.',
            ],
          },
        },
        {
          id: 'rf-010',
          category: 'identity',
          severity: 'high',
          score: 74,
          assetId: 'break-glass-admin',
          details: {
            title: 'Break-glass account password age exceeds policy',
            source: 'iam-review',
            mitigationSuggestions: [
              'Rotate the break-glass-admin password and store the updated secret in the approved vault.',
              'Require a witnessed quarterly attestation for all emergency admin credentials.',
            ],
          },
        },
      ],
    },
  },
];

const policyScenarios = [
  {
    id: 'policy-001',
    payload: {
      tenant: 'global',
      organization: 'Cybertron Labs',
      policyKey: 'incident-response-policy',
      controls: [
        { controlId: 'CC7.2', status: 'implemented', notes: '24x7 escalation rotation in place' },
        { controlId: 'CC7.4', status: 'partially_implemented', notes: 'Post-incident reviews tracked manually' },
      ],
    },
  },
  {
    id: 'policy-002',
    payload: {
      tenant: 'global',
      organization: 'Cybertron Labs',
      policyKey: 'access-control-policy',
      controls: [
        { controlId: 'CC6.1', status: 'implemented', notes: 'RBAC defined for core SaaS roles' },
        { controlId: 'CC6.3', status: 'implemented', notes: 'MFA required for administrators' },
      ],
    },
  },
  {
    id: 'policy-003',
    payload: {
      tenant: 'global',
      organization: 'Cybertron Labs',
      policyKey: 'data-protection-policy',
      controls: [
        { controlId: 'CC6.6', status: 'implemented', notes: 'Encryption at rest enabled' },
        { controlId: 'CC8.1', status: 'partially_implemented', notes: 'Retention policy rollout in progress' },
      ],
    },
  },
  {
    id: 'policy-004',
    payload: {
      tenant: 'global',
      organization: 'Cybertron Labs',
      policyKey: 'third-party-risk-policy',
      controls: [
        { controlId: 'CC9.2', status: 'not_started', notes: 'Vendor review workflow not fully deployed' },
      ],
    },
  },
];

const threatScenarios = [
  {
    id: 'threat-001',
    payload: {
      tenant: 'global',
      cveId: 'CVE-2025-1111',
      severity: 'critical',
      cvssScore: 9.8,
      description: 'Remote code execution in a widely deployed edge gateway allows unauthenticated takeover when management services are exposed to the internet.',
    },
  },
  {
    id: 'threat-002',
    payload: {
      tenant: 'global',
      cveId: 'CVE-2025-2048',
      severity: 'high',
      cvssScore: 8.1,
      description: 'An access-control bypass in a CI/CD platform can expose build secrets to authenticated users with limited repository access.',
    },
  },
  {
    id: 'threat-003',
    payload: {
      tenant: 'global',
      cveId: 'CVE-2024-9988',
      severity: 'medium',
      cvssScore: 6.5,
      description: 'A malformed request can force excessive CPU consumption in a log processing service, degrading alerting throughput under load.',
    },
  },
  {
    id: 'threat-004',
    payload: {
      tenant: 'global',
      cveId: 'CVE-2024-7710',
      severity: 'low',
      cvssScore: 3.8,
      description: 'A low-severity information disclosure reveals software version details in a legacy status endpoint.',
    },
  },
];

async function buildRiskRecords() {
  const systemPrompt = [
    'You are Cybertron Risk Copilot.',
    'Generate grounded executive risk briefings and concrete mitigations.',
    'If the output is rule-based or template-based, say so explicitly and never imply live LLM generation.',
    'Return JSON only.',
  ].join(' ');

  const records = [];
  for (const scenario of riskScenarios) {
    const result = await generateRiskExplanation(
      baseConfig,
      log,
      scenario.payload,
      buildContext('risk', scenario.id)
    );

    records.push(
      buildRecord({
        id: scenario.id,
        taskType: 'risk_explanation',
        systemPrompt,
        userPrompt: buildUserPrompt(
          'Generate an executive risk explanation and prioritized mitigations for the portfolio below.',
          scenario.payload
        ),
        payload: scenario.payload,
        response: {
          explanation: result.explanation,
          mitigationSuggestions: result.mitigationSuggestions,
          provider: result.provider,
          model: result.model,
          aiGenerated: result.aiGenerated,
        },
      })
    );
  }

  return records;
}

async function buildPolicyRecords() {
  const systemPrompt = [
    'You are Cybertron Compliance Engine.',
    'Draft practical security policy content and preserve approval gates.',
    'When using template output, label it honestly as non-AI-generated.',
    'Return JSON only.',
  ].join(' ');

  const records = [];
  for (const scenario of policyScenarios) {
    const result = await generatePolicyDraft(
      baseConfig,
      log,
      scenario.payload,
      buildContext('policy', scenario.id)
    );

    records.push(
      buildRecord({
        id: scenario.id,
        taskType: 'policy_draft',
        systemPrompt,
        userPrompt: buildUserPrompt(
          'Draft a policy document using the provided organization context and mapped controls.',
          scenario.payload
        ),
        payload: scenario.payload,
        response: {
          policyKey: result.policyKey,
          content: result.content,
          provider: result.provider,
          model: result.model,
          aiGenerated: result.aiGenerated,
          approvalStatus: result.approvalStatus,
          requiresApproval: result.requiresApproval,
          approvalNote: result.approvalNote,
        },
      })
    );
  }

  return records;
}

async function buildThreatRecords() {
  const systemPrompt = [
    'You are Cybertron Threat Intel.',
    'Summarize vulnerability records for operators and executives without inventing evidence.',
    'If the output is generic or rule-based, label it honestly.',
    'Return JSON only.',
  ].join(' ');

  const records = [];
  for (const scenario of threatScenarios) {
    const result = await summarizeCveWithAi(
      baseConfig,
      log,
      scenario.payload,
      buildContext('threat', scenario.id)
    );

    records.push(
      buildRecord({
        id: scenario.id,
        taskType: 'threat_summary',
        systemPrompt,
        userPrompt: buildUserPrompt(
          'Summarize the vulnerability for a Cybertron customer and preserve confidence labeling.',
          scenario.payload
        ),
        payload: scenario.payload,
        response: {
          summaryText: result.summaryText,
          provider: result.provider,
          model: result.model,
          aiGenerated: result.aiGenerated,
          confidence: result.confidence || 'n/a',
          confidenceNote: result.confidenceNote || null,
        },
      })
    );
  }

  return records;
}

async function writeJsonl(filePath, records) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  const content = records.map(record => JSON.stringify(record)).join('\n') + '\n';
  await fs.writeFile(filePath, content, 'utf8');
}

async function writeManifest(filePath, outputPath, records, generatedAt) {
  const taskCounts = records.reduce((accumulator, record) => {
    accumulator[record.taskType] = (accumulator[record.taskType] || 0) + 1;
    return accumulator;
  }, {});

  const manifest = {
    generatedAt,
    output: outputPath,
    records: records.length,
    taskCounts,
    source: DATA_SOURCE,
    aiGenerated: false,
    disclaimer:
      'Bootstrap supervised data generated from Cybertron rule-based and template-based fallbacks. Useful for warm-start experiments and eval harnesses, not a substitute for human-reviewed production training data.',
  };

  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, JSON.stringify(manifest, null, 2) + '\n', 'utf8');
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const generatedAt = new Date().toISOString();
  const records = [
    ...(await buildRiskRecords()),
    ...(await buildPolicyRecords()),
    ...(await buildThreatRecords()),
  ];

  await writeJsonl(args.out, records);
  await writeManifest(args.manifest, args.out, records, generatedAt);

  console.log(
    JSON.stringify(
      {
        ok: true,
        records: records.length,
        output: args.out,
        manifest: args.manifest,
        source: DATA_SOURCE,
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
