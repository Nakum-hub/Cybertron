#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const frontendRoot = path.resolve(__dirname, '..');

async function ensureExists(relativePath) {
  const absolute = path.join(frontendRoot, relativePath);
  try {
    await fs.access(absolute);
  } catch {
    throw new Error(`Missing required file: ${relativePath}`);
  }
}

function assertCondition(condition, label) {
  if (!condition) {
    throw new Error(`Assertion failed: ${label}`);
  }
  process.stdout.write(`PASS: ${label}\n`);
}

async function run() {
  await ensureExists('src/pages/UiWiringPage.tsx');
  await ensureExists('src/fixtures/aws-logs.sample.json');
  await ensureExists('src/fixtures/evidence.sample.pdf');

  const appSource = await fs.readFile(path.join(frontendRoot, 'src/App.tsx'), 'utf8');
  const uiWiringSource = await fs.readFile(path.join(frontendRoot, 'src/pages/UiWiringPage.tsx'), 'utf8');
  const backendClientSource = await fs.readFile(path.join(frontendRoot, 'src/lib/backend.ts'), 'utf8');
  const awsFixture = await fs.readFile(path.join(frontendRoot, 'src/fixtures/aws-logs.sample.json'), 'utf8');
  const evidenceFixture = await fs.readFile(path.join(frontendRoot, 'src/fixtures/evidence.sample.pdf'), 'utf8');

  assertCondition(appSource.includes('path="/qa/ui-wiring"'), 'route /qa/ui-wiring registered in App.tsx');

  const requiredTransactionIds = [
    'txn-risk-copilot-e2e',
    'txn-compliance-e2e',
    'txn-threat-intel-e2e',
  ];
  for (const id of requiredTransactionIds) {
    assertCondition(uiWiringSource.includes(`id: '${id}'`), `transaction case exists (${id})`);
  }

  const requiredEndpointFragments = [
    '/v1/risk/ingest/aws-logs',
    '/v1/risk/report/generate',
    '/v1/compliance/soc2/evidence/upload',
    '/v1/compliance/audit-package/',
    '/v1/threat-intel/cve/sync',
    '/v1/threat-intel/dashboard',
  ];
  for (const fragment of requiredEndpointFragments) {
    assertCondition(uiWiringSource.includes(fragment), `transaction endpoint referenced (${fragment})`);
  }

  assertCondition(
    backendClientSource.includes('export async function fetchRiskReportPdfBinary'),
    'risk report binary verifier helper exists'
  );
  assertCondition(
    backendClientSource.includes('export async function fetchAuditPackagePdfBinary'),
    'audit package binary verifier helper exists'
  );

  assertCondition(awsFixture.includes('"records"'), 'aws log fixture contains records payload');
  assertCondition(evidenceFixture.startsWith('%PDF-'), 'evidence fixture starts with PDF signature');

  process.stdout.write('UI wiring transaction static checks passed.\n');
}

run().catch(error => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
