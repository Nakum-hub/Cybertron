#!/usr/bin/env node

const { spawn } = require('node:child_process');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');

const backendRoot = path.resolve(__dirname, '..');
const pgliteServerEntrypoint = path.resolve(
  backendRoot,
  'node_modules',
  '@electric-sql',
  'pglite-socket',
  'dist',
  'scripts',
  'server.cjs'
);
const cliArgs = new Set(process.argv.slice(2));

const parsedPort = Number(process.env.EMBEDDED_DB_PORT || 55432);
const embeddedDbPort = Number.isFinite(parsedPort) && parsedPort > 0 ? Math.floor(parsedPort) : 55432;
const embeddedDbTarget = process.env.EMBEDDED_DB_PATH || 'memory://';
const skipLoad =
  cliArgs.has('--skip-load') || String(process.env.EMBEDDED_DB_SKIP_LOAD || 'false').toLowerCase() === 'true';
const embeddedDbVerbose = String(process.env.EMBEDDED_DB_VERBOSE || 'false').toLowerCase() === 'true';

let activeDbProcess = null;

const sharedEnv = {
  ...process.env,
  DATABASE_URL: process.env.DATABASE_URL || `postgresql://postgres:postgres@127.0.0.1:${embeddedDbPort}/postgres`,
  DB_POOL_MAX: process.env.DB_POOL_MAX || '1',
  DB_SSL_MODE: process.env.DB_SSL_MODE || 'disable',
  AUTH_MODE: process.env.AUTH_MODE || 'jwt_hs256',
  JWT_SECRET: process.env.JWT_SECRET || 'embedded-qa-jwt-secret',
  ALLOW_PUBLIC_REGISTRATION: process.env.ALLOW_PUBLIC_REGISTRATION || 'true',
  ALLOW_INSECURE_DEMO_AUTH: process.env.ALLOW_INSECURE_DEMO_AUTH || 'false',
  AUTH_COOKIE_SECURE: process.env.AUTH_COOKIE_SECURE || 'false',
  AUTH_COOKIE_SAMESITE: process.env.AUTH_COOKIE_SAMESITE || 'lax',
  CSRF_ENABLED: process.env.CSRF_ENABLED || 'true',
  RED_TEAM_REQUIRE_DATABASE: 'true',
  LOAD_REQUIRE_DATABASE: 'true',
};

if (!sharedEnv.LOAD_ALLOW_SHORT && sharedEnv.LOAD_DURATION_MS) {
  const duration = Number(sharedEnv.LOAD_DURATION_MS);
  if (Number.isFinite(duration) && duration > 0 && duration < 300_000) {
    sharedEnv.LOAD_ALLOW_SHORT = 'true';
  }
}

function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function waitForPort(host, port, timeoutMs = 20_000) {
  return new Promise((resolve, reject) => {
    const startedAt = Date.now();

    const tryConnect = () => {
      const socket = net.createConnection({ host, port });

      socket.once('connect', () => {
        socket.destroy();
        resolve();
      });

      socket.once('error', () => {
        socket.destroy();
        if (Date.now() - startedAt >= timeoutMs) {
          reject(new Error(`Timed out waiting for embedded database on ${host}:${port}`));
          return;
        }
        setTimeout(tryConnect, 200);
      });
    };

    tryConnect();
  });
}

function runNodeScript(relativeScriptPath, env, label) {
  return new Promise((resolve, reject) => {
    const scriptPath = path.resolve(backendRoot, relativeScriptPath);
    process.stdout.write(`\n[qa-embedded-db] Running ${label}\n`);

    const child = spawn(process.execPath, [scriptPath], {
      cwd: backendRoot,
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    child.stdout.on('data', chunk => {
      process.stdout.write(chunk.toString());
    });

    child.stderr.on('data', chunk => {
      process.stderr.write(chunk.toString());
    });

    child.on('error', error => {
      reject(error);
    });

    child.on('exit', code => {
      if (code === 0) {
        resolve();
        return;
      }

      reject(new Error(`${label} failed with exit code ${String(code)}`));
    });
  });
}

async function stopProcessGracefully(child) {
  if (!child || child.killed || child.exitCode !== null) {
    return;
  }

  const exited = new Promise(resolve => {
    child.once('exit', () => resolve());
  });

  child.kill('SIGTERM');
  await Promise.race([exited, wait(3_000)]);

  if (child.exitCode === null && !child.killed) {
    child.kill('SIGKILL');
  }
}

function startEmbeddedDb() {
  process.stdout.write(
    `[qa-embedded-db] Starting embedded Postgres-compatible DB on 127.0.0.1:${embeddedDbPort} (${embeddedDbTarget})\n`
  );

  const child = spawn(
    process.execPath,
    [pgliteServerEntrypoint, `--db=${embeddedDbTarget}`, `--port=${String(embeddedDbPort)}`, '--host=127.0.0.1'],
    {
      cwd: backendRoot,
      env: process.env,
      stdio: embeddedDbVerbose ? ['ignore', 'pipe', 'pipe'] : ['ignore', 'ignore', 'ignore'],
    }
  );

  if (embeddedDbVerbose) {
    child.stdout.on('data', chunk => {
      process.stdout.write(`[embedded-db] ${chunk.toString()}`);
    });

    child.stderr.on('data', chunk => {
      process.stderr.write(`[embedded-db] ${chunk.toString()}`);
    });
  }

  return child;
}

async function runDbBackedPhase(label, scriptPath) {
  process.stdout.write(`\n[qa-embedded-db] Phase: ${label}\n`);
  const dbProcess = startEmbeddedDb();
  activeDbProcess = dbProcess;

  try {
    await waitForPort('127.0.0.1', embeddedDbPort);
    await runNodeScriptWithRetry('scripts/migrate.js', sharedEnv, `${label} migrations`, 5, 1_000);
    await runNodeScriptWithRetry(scriptPath, sharedEnv, label, 2, 500);
  } finally {
    await stopProcessGracefully(dbProcess);
    activeDbProcess = null;
  }
}

async function runNodeScriptWithRetry(relativeScriptPath, env, label, maxAttempts, delayMs) {
  let lastError = null;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      await runNodeScript(relativeScriptPath, env, label);
      return;
    } catch (error) {
      lastError = error;
      const message = error instanceof Error ? error.message : String(error || 'unknown failure');
      const timeoutLikeFailure =
        message.toLowerCase().includes('connection timeout') ||
        message.toLowerCase().includes('timed out') ||
        message.toLowerCase().includes('could not connect');

      if (attempt >= maxAttempts || !timeoutLikeFailure) {
        throw error;
      }

      process.stdout.write(
        `[qa-embedded-db] ${label} attempt ${attempt} failed with transient DB timeout. Retrying in ${delayMs}ms...\n`
      );
      await wait(delayMs);
    }
  }

  throw lastError instanceof Error ? lastError : new Error(`${label} failed`);
}

async function shutdownFromSignal(signal) {
  process.stdout.write(`[qa-embedded-db] Received ${signal}, shutting down...\n`);
  await stopProcessGracefully(activeDbProcess);
  process.exit(1);
}

async function main() {
  if (!fs.existsSync(pgliteServerEntrypoint)) {
    throw new Error(
      'Embedded DB launcher is missing. Run "npm install --prefix workspace/app/backend" to install dependencies.'
    );
  }

  process.once('SIGINT', () => {
    void shutdownFromSignal('SIGINT');
  });
  process.once('SIGTERM', () => {
    void shutdownFromSignal('SIGTERM');
  });

  await runNodeScript('scripts/report-upload-unit-check.js', sharedEnv, 'report upload unit checks');
  await runDbBackedPhase('smoke checks', 'scripts/smoke-check.js');
  await runDbBackedPhase('red-team checks', 'scripts/red-team-check.js');
  await runDbBackedPhase('oauth identity checks', 'scripts/oauth-identity-check.js');
  await runDbBackedPhase('phase3 AI checks', 'scripts/phase3-ai-check.js');
  if (!skipLoad) {
    await runDbBackedPhase('load checks', 'scripts/load-smoke.js');
  } else {
    process.stdout.write('[qa-embedded-db] Skipping load checks (--skip-load or EMBEDDED_DB_SKIP_LOAD=true).\n');
  }

  process.stdout.write('[qa-embedded-db] Strict DB-backed backend QA passed.\n');
}

main().catch(error => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
