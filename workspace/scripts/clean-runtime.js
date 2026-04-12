#!/usr/bin/env node

const fs = require('node:fs/promises');
const path = require('node:path');

const workspaceRoot = path.resolve(__dirname, '..');
const repoRoot = path.resolve(workspaceRoot, '..');
const cliArgs = new Set(process.argv.slice(2));
const dryRun = cliArgs.has('--dry-run');

const targets = [
  path.join(workspaceRoot, '.runtime'),
  path.join(workspaceRoot, 'uploads'),
  path.join(repoRoot, '.cache'),
  path.join(repoRoot, 'cover'),
  path.join(repoRoot, 'coverage'),
];

async function pathExists(targetPath) {
  try {
    await fs.access(targetPath);
    return true;
  } catch {
    return false;
  }
}

async function main() {
  let touched = 0;

  for (const target of targets) {
    const exists = await pathExists(target);
    if (!exists) {
      process.stdout.write(`SKIP: ${path.relative(repoRoot, target).replace(/\\/g, '/') || '.'} (not present)\n`);
      continue;
    }

    touched += 1;
    if (dryRun) {
      process.stdout.write(`PLAN: remove ${path.relative(repoRoot, target).replace(/\\/g, '/')}\n`);
      continue;
    }

    await fs.rm(target, { recursive: true, force: true });
    process.stdout.write(`REMOVED: ${path.relative(repoRoot, target).replace(/\\/g, '/')}\n`);
  }

  if (dryRun) {
    process.stdout.write(
      touched > 0 ? 'Runtime cleanup dry-run completed.\n' : 'Runtime cleanup dry-run found nothing to remove.\n'
    );
    return;
  }

  process.stdout.write(touched > 0 ? 'Runtime cleanup completed.\n' : 'Runtime cleanup found nothing to remove.\n');
}

main().catch(error => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
