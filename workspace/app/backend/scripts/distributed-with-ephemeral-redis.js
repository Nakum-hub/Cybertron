#!/usr/bin/env node

const path = require('node:path');
const { spawn } = require('node:child_process');
const { RedisMemoryServer } = require('redis-memory-server');

const backendRoot = path.resolve(__dirname, '..');

function getNpmCommand() {
  return process.platform === 'win32' ? 'npm.cmd' : 'npm';
}

function runScript(scriptName, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(`${getNpmCommand()} run ${scriptName}`, [], {
      cwd: backendRoot,
      env,
      stdio: 'inherit',
      shell: true,
    });

    child.on('error', reject);
    child.on('exit', code => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(new Error(`${scriptName} failed with exit code ${code ?? 1}`));
    });
  });
}

async function main() {
  const redisServer = new RedisMemoryServer();

  try {
    const host = await redisServer.getHost();
    const port = await redisServer.getPort();
    const redisUrl = `redis://${host}:${port}`;

    process.stdout.write(`[qa] Using ephemeral Redis at ${redisUrl}\n`);

    const env = {
      ...process.env,
      REDIS_URL: redisUrl,
    };

    await runScript('qa:distributed-auth', env);
    await runScript('qa:distributed-rate', env);

    process.stdout.write('[qa] Distributed auth/rate checks passed with ephemeral Redis.\n');
  } finally {
    await redisServer.stop();
  }
}

main().catch(error => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
