#!/usr/bin/env node

const { spawnSync } = require('node:child_process');
const { findComposeServiceContainer } = require('./docker-compose-runtime');

async function run() {
  const containerName = findComposeServiceContainer('backend');
  const args = [
    'exec',
    '-w',
    '/srv/cybertron/backend',
    containerName,
    'node',
    'scripts/bootstrap-admin.js',
    ...process.argv.slice(2),
  ];

  const result = spawnSync('docker', args, {
    stdio: 'inherit',
    encoding: 'utf8',
  });

  if (result.error) {
    throw result.error;
  }

  if (result.status !== 0) {
    process.exitCode = result.status || 1;
  }
}

run().catch(error => {
  process.stderr.write(`${error instanceof Error ? error.message : 'Admin bootstrap failed.'}\n`);
  process.exitCode = 1;
});
