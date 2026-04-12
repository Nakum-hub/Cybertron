#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');
const sourceRoot = path.join(projectRoot, 'src');

async function readFile(relativePath) {
  return fs.readFile(path.join(projectRoot, relativePath), 'utf8');
}

async function collectFiles(rootPath) {
  const stack = [rootPath];
  const files = [];

  while (stack.length) {
    const current = stack.pop();
    const entries = await fs.readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      const resolved = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(resolved);
      } else if (entry.isFile() && /\.(ts|tsx|js|jsx)$/.test(entry.name)) {
        files.push(resolved);
      }
    }
  }

  return files;
}

function assertCondition(condition, label) {
  if (!condition) {
    throw new Error(`Assertion failed: ${label}`);
  }
  process.stdout.write(`PASS: ${label}\n`);
}

async function run() {
  const files = await collectFiles(sourceRoot);
  const tokenStoragePattern =
    /(localStorage|sessionStorage)\.(setItem|getItem|removeItem)\(\s*['"`](token|refresh_token|access_token|refreshToken|accessToken)['"`]/i;
  const contextStoragePattern =
    /(localStorage|sessionStorage)\.(setItem|getItem|removeItem)\(\s*['"`](cybertron_role|cybertron_tenant)['"`]/i;

  let tokenStorageViolations = 0;
  let contextStorageViolations = 0;
  for (const file of files) {
    const source = await fs.readFile(file, 'utf8');
    if (tokenStoragePattern.test(source)) {
      tokenStorageViolations += 1;
      process.stderr.write(`FAIL: token storage usage found in ${path.relative(projectRoot, file)}\n`);
    }

    if (contextStoragePattern.test(source)) {
      contextStorageViolations += 1;
      process.stderr.write(`FAIL: role/tenant localStorage usage found in ${path.relative(projectRoot, file)}\n`);
    }
  }

  assertCondition(tokenStorageViolations === 0, 'no token persistence in localStorage/sessionStorage source paths');
  assertCondition(contextStorageViolations === 0, 'no role/tenant persistence in localStorage');

  const apiSource = await readFile('src/lib/api.ts');
  assertCondition(apiSource.includes("credentials: 'include'"), 'api client uses credentials include');
  assertCondition(
    apiSource.includes('x-cybertron-public-fingerprint'),
    'api client sends public fingerprint header on auth writes'
  );

  const backendSource = await readFile('src/lib/backend.ts');
  assertCondition(backendSource.includes('xhr.withCredentials = true'), 'upload xhr uses withCredentials');
  assertCondition(
    backendSource.includes("return api.get<OpenApiSpec>('/v1/system/openapi', { auth: true });"),
    'openapi fetch requires authenticated requests'
  );

  const appSource = await readFile('src/App.tsx');
  assertCondition(appSource.includes('path="/diagnostics"'), 'diagnostics route is registered');
  assertCondition(
    appSource.includes('path="/diagnostics" element={<InternalRouteGate'),
    'diagnostics route is protected by internal route gate'
  );
  assertCondition(
    appSource.includes('path="/docs" element={<InternalRouteGate'),
    'docs route is protected by internal route gate'
  );
  assertCondition(
    appSource.includes('path="/qa/ui-wiring" element={<InternalRouteGate'),
    'ui wiring route is protected by internal route gate'
  );

  const diagnosticsSource = await readFile('src/pages/StatusPage.tsx');
  assertCondition(
    diagnosticsSource.includes('Fix Steps'),
    'status/diagnostics page provides actionable dependency remediation steps'
  );

  const authSource = await readFile('src/lib/auth.ts');
  assertCondition(!authSource.includes("TOKEN_KEY = 'token'"), 'legacy localStorage token key removed');
  assertCondition(!authSource.includes("REFRESH_TOKEN_KEY = 'refresh_token'"), 'legacy localStorage refresh key removed');
  assertCondition(
    authSource.includes("const PUBLIC_FINGERPRINT_KEY = 'cybertronPublicFingerprint'"),
    'public fingerprint helper is defined for auth abuse controls'
  );

  process.stdout.write('Frontend security regression checks passed.\n');
}

run().catch(error => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
