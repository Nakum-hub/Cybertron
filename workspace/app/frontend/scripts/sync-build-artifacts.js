#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function copyDistTo(targetDir, distDir) {
  await fs.rm(targetDir, { recursive: true, force: true });
  await fs.mkdir(targetDir, { recursive: true });
  await fs.cp(distDir, targetDir, { recursive: true });
}

async function run() {
  const frontendRoot = path.resolve(__dirname, '..');
  const workspaceRoot = path.resolve(frontendRoot, '..', '..', '..');
  const distDir = path.join(frontendRoot, 'dist');

  const latestDir = path.join(workspaceRoot, 'build', 'latest');
  const versionDir = path.join(workspaceRoot, 'build', 'v1');

  await copyDistTo(latestDir, distDir);
  await copyDistTo(versionDir, distDir);

  process.stdout.write(`Synced build artifacts to:\n- ${latestDir}\n- ${versionDir}\n`);
}

run().catch(error => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});