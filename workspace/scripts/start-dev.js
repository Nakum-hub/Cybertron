const { spawn, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const net = require('node:net');
const { createRequire } = require('node:module');
const path = require('node:path');

const workspaceRoot = path.resolve(__dirname, '..');
const backendRoot = path.resolve(workspaceRoot, 'app', 'backend');
const backendPackageRequire = createRequire(path.resolve(backendRoot, 'package.json'));

const FRONTEND_PORT = 3000;
const BACKEND_PORT = 8001;
const EMBEDDED_DB_PORT = Number(process.env.START_DEV_EMBEDDED_DB_PORT || 55432);
const EMBEDDED_DB_PATH = process.env.START_DEV_EMBEDDED_DB_PATH || path.resolve(workspaceRoot, '.runtime', 'pglite-dev');
const EMBEDDED_DB_URL = `postgresql://postgres:postgres@127.0.0.1:${EMBEDDED_DB_PORT}/postgres`;
const EMBEDDED_REDIS_ENABLED = String(process.env.START_DEV_EMBEDDED_REDIS || 'true').toLowerCase() !== 'false';
const RUNTIME_DIR = path.resolve(workspaceRoot, '.runtime');
const MANAGER_PID_FILE = path.resolve(RUNTIME_DIR, 'start-dev.pid');

const ENDPOINTS = {
  frontendRoot: `http://127.0.0.1:${FRONTEND_PORT}`,
  backendHealth: `http://127.0.0.1:${BACKEND_PORT}/v1/system/health`,
  frontendProxyHealth: `http://127.0.0.1:${FRONTEND_PORT}/api/v1/system/health`,
};

function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function runProcess(label, args, envOverrides = {}) {
  const npmExecPath = process.env.npm_execpath;
  const command = npmExecPath ? process.execPath : process.platform === 'win32' ? 'npm.cmd' : 'npm';
  const commandArgs = npmExecPath ? [npmExecPath, ...args] : args;
  const child = spawn(command, commandArgs, {
    cwd: workspaceRoot,
    stdio: 'inherit',
    env: {
      ...process.env,
      ...envOverrides,
    },
  });

  child.on('error', error => {
    console.error(`[${label}] failed to start:`, error.message);
  });

  return child;
}

function isPortAvailable(port) {
  return new Promise(resolve => {
    const tester = net
      .createServer()
      .once('error', error => {
        if (error && error.code === 'EADDRINUSE') {
          resolve(false);
          return;
        }

        resolve(false);
      })
      .once('listening', () => {
        tester.close(() => resolve(true));
      });

    tester.listen(port, '0.0.0.0');
  });
}

function canConnect(host, port) {
  return new Promise(resolve => {
    const socket = new net.Socket();
    let settled = false;
    const finalize = value => {
      if (settled) {
        return;
      }
      settled = true;
      socket.destroy();
      resolve(value);
    };
    socket.setTimeout(600);
    socket.once('connect', () => finalize(true));
    socket.once('timeout', () => finalize(false));
    socket.once('error', () => finalize(false));
    socket.connect(port, host);
  });
}

async function waitForTcpReady(host, port, maxAttempts = 50, intervalMs = 200) {
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    if (await canConnect(host, port)) {
      return;
    }
    await wait(intervalMs);
  }

  throw new Error(`TCP service did not become ready on ${host}:${port}`);
}

function parseInteger(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : null;
}

function getListeningPidsOnPort(port) {
  const normalizedPort = String(port);

  if (process.platform === 'win32') {
    const result = spawnSync('netstat', ['-ano', '-p', 'tcp'], {
      encoding: 'utf8',
    });

    const output = `${result.stdout || ''}\n${result.stderr || ''}`;
    const lines = output.split(/\r?\n/);
    const pids = new Set();

    for (const line of lines) {
      if (!line.includes('LISTENING')) {
        continue;
      }

      if (!line.includes(`:${normalizedPort}`)) {
        continue;
      }

      const parts = line.trim().split(/\s+/);
      const maybePid = parseInteger(parts[parts.length - 1]);
      if (maybePid) {
        pids.add(maybePid);
      }
    }

    return [...pids];
  }

  const lsof = spawnSync('lsof', ['-ti', `tcp:${normalizedPort}`], { encoding: 'utf8' });
  if (lsof.status !== 0 || !lsof.stdout) {
    return [];
  }

  return lsof.stdout
    .split(/\r?\n/)
    .map(value => parseInteger(value.trim()))
    .filter(Boolean);
}

function terminatePid(pid) {
  if (!pid) {
    return true;
  }

  if (process.platform === 'win32') {
    const result = spawnSync('taskkill', ['/pid', String(pid), '/t', '/f'], {
      encoding: 'utf8',
    });
    return result.status === 0;
  }

  const result = spawnSync('kill', ['-TERM', String(pid)], {
    encoding: 'utf8',
  });
  return result.status === 0;
}

async function freePort(label, port) {
  const pids = getListeningPidsOnPort(port);
  if (!pids.length) {
    return true;
  }

  console.warn(`[startup] recovering ${label} port ${port}; stopping process(es): ${pids.join(', ')}`);

  for (const pid of pids) {
    terminatePid(pid);
  }

  for (let attempt = 1; attempt <= 20; attempt += 1) {
    if (await isPortAvailable(port)) {
      return true;
    }

    await wait(250);
  }

  return false;
}

async function fetchEndpoint(url, timeoutMs = 2500) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      method: 'GET',
      signal: controller.signal,
      headers: {
        Accept: 'application/json,text/html,*/*',
      },
    });

    return {
      ok: response.ok,
      status: response.status,
    };
  } catch (error) {
    return {
      ok: false,
      status: 0,
      error: error instanceof Error ? error.message : 'request failed',
    };
  } finally {
    clearTimeout(timeout);
  }
}

async function waitForHttpOk(url, label, maxAttempts = 80, intervalMs = 500) {
  let last = null;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const result = await fetchEndpoint(url);
    if (result.ok) {
      return;
    }

    last = result;
    await wait(intervalMs);
  }

  throw new Error(
    `${label} did not become ready in time (${url}). Last status: ${last?.status || 'n/a'}${last?.error ? `, error: ${last.error}` : ''
    }`
  );
}

function killTree(pid) {
  if (!pid) {
    return;
  }

  if (process.platform === 'win32') {
    spawn('taskkill', ['/pid', String(pid), '/t', '/f'], { stdio: 'ignore' });
    return;
  }

  process.kill(pid, 'SIGTERM');
}

let backend = null;
let frontend = null;
let embeddedDb = null;
let embeddedRedis = null;
let shuttingDown = false;

function resolveEmbeddedDbCliPath() {
  const candidate = path.resolve(
    backendRoot,
    'node_modules',
    '@electric-sql',
    'pglite-socket',
    'dist',
    'scripts',
    'server.cjs'
  );
  return fs.existsSync(candidate) ? candidate : null;
}

async function startEmbeddedDatabase() {
  const backendDevDefaults = {
    AUTH_MODE: process.env.AUTH_MODE || 'jwt_hs256',
    ALLOW_PUBLIC_REGISTRATION: process.env.ALLOW_PUBLIC_REGISTRATION || 'true',
    ALLOW_INSECURE_DEMO_AUTH: process.env.ALLOW_INSECURE_DEMO_AUTH || 'false',
    AUTH_COOKIE_SECURE: process.env.AUTH_COOKIE_SECURE || 'false',
    AUTH_COOKIE_SAMESITE: process.env.AUTH_COOKIE_SAMESITE || 'lax',
    CSRF_ENABLED: process.env.CSRF_ENABLED || 'true',
    DEFAULT_TENANT_PLAN_TIER: process.env.DEFAULT_TENANT_PLAN_TIER || 'enterprise',
    DB_POOL_MAX: process.env.DB_POOL_MAX || '1',
    DB_CONNECT_TIMEOUT_MS: process.env.DB_CONNECT_TIMEOUT_MS || '20000',
  };

  if (process.env.DATABASE_URL) {
    return backendDevDefaults;
  }

  const cliPath = resolveEmbeddedDbCliPath();
  if (!cliPath) {
    throw new Error(
      'DATABASE_URL is not set and embedded DB runtime is unavailable. Run npm install in workspace/app/backend or configure DATABASE_URL.'
    );
  }

  if (!(await freePort('embedded-db', EMBEDDED_DB_PORT))) {
    throw new Error(`Could not recover embedded DB port ${EMBEDDED_DB_PORT}.`);
  }

  if (!String(EMBEDDED_DB_PATH).startsWith('memory://')) {
    fs.mkdirSync(path.dirname(EMBEDDED_DB_PATH), { recursive: true });
  }

  const dbTarget = String(EMBEDDED_DB_PATH).startsWith('memory://')
    ? EMBEDDED_DB_PATH
    : path.resolve(EMBEDDED_DB_PATH);

  embeddedDb = spawn(
    process.execPath,
    [cliPath, `--db=${dbTarget}`, `--port=${String(EMBEDDED_DB_PORT)}`, '--host=127.0.0.1'],
    {
      cwd: backendRoot,
      stdio: 'ignore',
      env: {
        ...process.env,
      },
    }
  );

  embeddedDb.on('exit', code => {
    if (!shuttingDown && code !== 0) {
      console.error(`[startup] embedded DB exited unexpectedly with code ${code ?? 0}.`);
      shutdown(code ?? 1);
    }
  });

  await waitForTcpReady('127.0.0.1', EMBEDDED_DB_PORT);
  console.log(`[startup] embedded DB is ready on 127.0.0.1:${EMBEDDED_DB_PORT}`);
  return {
    ...backendDevDefaults,
    DATABASE_URL: EMBEDDED_DB_URL,
  };
}

function resolveRedisMemoryServerCtor() {
  try {
    return backendPackageRequire('redis-memory-server').RedisMemoryServer;
  } catch {
    return null;
  }
}

async function startEmbeddedRedis() {
  if (process.env.REDIS_URL) {
    return process.env.REDIS_URL;
  }

  if (!EMBEDDED_REDIS_ENABLED) {
    return '';
  }

  const RedisMemoryServer = resolveRedisMemoryServerCtor();
  if (!RedisMemoryServer) {
    throw new Error(
      'REDIS_URL is not set and redis-memory-server is unavailable. Run npm install in workspace/app/backend or set REDIS_URL.'
    );
  }

  embeddedRedis = new RedisMemoryServer();
  const host = await embeddedRedis.getHost();
  const port = await embeddedRedis.getPort();
  const redisUrl = `redis://${host}:${port}`;
  console.log(`[startup] embedded redis is ready at ${redisUrl}`);
  return redisUrl;
}

const OLLAMA_DEFAULT_PORT = 11434;
const OLLAMA_DEFAULT_URL = `http://127.0.0.1:${OLLAMA_DEFAULT_PORT}`;

async function detectOllama() {
  if (process.env.LLM_PROVIDER && process.env.LLM_PROVIDER !== 'none') {
    console.log(`[startup] LLM_PROVIDER already set to "${process.env.LLM_PROVIDER}". Skipping Ollama auto-detect.`);
    return {};
  }

  const ollamaUrl = process.env.OLLAMA_URL || OLLAMA_DEFAULT_URL;
  const ollamaHost = '127.0.0.1';
  const ollamaPort = Number(process.env.OLLAMA_PORT || OLLAMA_DEFAULT_PORT);

  const isReachable = await canConnect(ollamaHost, ollamaPort);
  if (!isReachable) {
    console.log('[startup] Ollama not detected on localhost. AI features will degrade gracefully.');
    console.log('[startup] To enable AI: install Ollama (https://ollama.com) and run "ollama pull llama3.1".');
    return {};
  }

  try {
    const result = await fetchEndpoint(`${ollamaUrl}/api/tags`, 3000);
    if (result.ok) {
      console.log(`[startup] Ollama detected at ${ollamaUrl}. AI features auto-enabled.`);
      return {
        LLM_PROVIDER: 'ollama',
        OLLAMA_URL: ollamaUrl,
        OLLAMA_MODEL: process.env.OLLAMA_MODEL || 'llama3.1',
      };
    }
  } catch {
    // Ollama port is open but API didn't respond; skip.
  }

  console.log('[startup] Ollama port open but API unavailable. AI features disabled.');
  return {};
}

function shutdown(code = 0) {
  if (shuttingDown) {
    return;
  }

  shuttingDown = true;
  try {
    fs.unlinkSync(MANAGER_PID_FILE);
  } catch {
    // Ignore cleanup failures.
  }
  killTree(frontend && frontend.pid);
  killTree(backend && backend.pid);
  killTree(embeddedDb && embeddedDb.pid);
  if (embeddedRedis) {
    embeddedRedis.stop().catch(() => { });
    embeddedRedis = null;
  }

  setTimeout(() => process.exit(code), 220);
}

async function inspectCurrentRuntime() {
  const [frontendAvailable, backendAvailable] = await Promise.all([
    isPortAvailable(FRONTEND_PORT),
    isPortAvailable(BACKEND_PORT),
  ]);

  const frontendInUse = !frontendAvailable;
  const backendInUse = !backendAvailable;

  const [frontendStatus, backendStatus, proxyStatus] = await Promise.all([
    frontendInUse ? fetchEndpoint(ENDPOINTS.frontendRoot) : Promise.resolve({ ok: false, status: 0 }),
    backendInUse ? fetchEndpoint(ENDPOINTS.backendHealth) : Promise.resolve({ ok: false, status: 0 }),
    frontendInUse ? fetchEndpoint(ENDPOINTS.frontendProxyHealth) : Promise.resolve({ ok: false, status: 0 }),
  ]);

  return {
    frontendInUse,
    backendInUse,
    frontendStatus,
    backendStatus,
    proxyStatus,
  };
}

function attachExitHandler(name, child) {
  child.on('exit', code => {
    if (!shuttingDown) {
      console.error(`[${name}] exited with code ${code ?? 0}`);
      shutdown(code ?? 1);
    }
  });
}

async function main() {
  fs.mkdirSync(RUNTIME_DIR, { recursive: true });
  fs.writeFileSync(MANAGER_PID_FILE, String(process.pid));

  const forceFreshStart = String(process.env.START_DEV_FORCE_FRESH || 'true').toLowerCase() !== 'false';

  if (forceFreshStart) {
    const frontendReleased = await freePort('frontend', FRONTEND_PORT);
    if (!frontendReleased) {
      console.error(`[startup] could not recover frontend port ${FRONTEND_PORT}.`);
      process.exit(1);
      return;
    }

    const backendReleased = await freePort('backend', BACKEND_PORT);
    if (!backendReleased) {
      console.error(`[startup] could not recover backend port ${BACKEND_PORT}.`);
      process.exit(1);
      return;
    }

    const [backendEnv, redisUrl, ollamaEnv] = await Promise.all([
      startEmbeddedDatabase(),
      startEmbeddedRedis(),
      detectOllama(),
    ]);
    backend = runProcess('backend', ['run', 'dev', '--prefix', 'app/backend'], {
      ...backendEnv,
      ...(redisUrl ? { REDIS_URL: redisUrl } : {}),
      ...ollamaEnv,
    });
    attachExitHandler('backend', backend);
    await waitForHttpOk(ENDPOINTS.backendHealth, 'backend health');
    console.log('[startup] backend is healthy.');

    frontend = runProcess('frontend', ['run', 'dev', '--prefix', 'app/frontend']);
    attachExitHandler('frontend', frontend);
    await waitForHttpOk(ENDPOINTS.frontendRoot, 'frontend root');
    await waitForHttpOk(ENDPOINTS.frontendProxyHealth, 'frontend backend-proxy health');
    console.log('[startup] frontend is healthy.');

    console.log('[startup] full stack is ready.');
    console.log(`[startup] frontend: ${ENDPOINTS.frontendRoot}`);
    console.log(`[startup] backend health: ${ENDPOINTS.backendHealth}`);
    console.log(`[startup] proxy health: ${ENDPOINTS.frontendProxyHealth}`);

    // Auto-seed demo data after full stack is stable (non-blocking, idempotent).
    const seedScript = path.resolve(__dirname, 'seed-demo-data.js');
    if (fs.existsSync(seedScript)) {
      setTimeout(() => {
        const seed = spawn(process.execPath, [seedScript], {
          cwd: workspaceRoot,
          stdio: 'inherit',
          env: { ...process.env, BACKEND_URL: `http://127.0.0.1:${BACKEND_PORT}` },
        });
        seed.on('exit', code => {
          if (code !== 0) console.warn('[startup] seed script exited with code', code);
        });
      }, 3000); // Wait for nodemon to settle
    }
    return;
  }

  let runtime = await inspectCurrentRuntime();

  if (runtime.frontendInUse && !runtime.frontendStatus.ok) {
    const released = await freePort('frontend', FRONTEND_PORT);
    if (!released) {
      console.error(
        `[startup] frontend port ${FRONTEND_PORT} is occupied by an unhealthy process and could not be recovered.`
      );
      process.exit(1);
      return;
    }
    runtime = await inspectCurrentRuntime();
  }

  if (runtime.backendInUse && !runtime.backendStatus.ok) {
    const released = await freePort('backend', BACKEND_PORT);
    if (!released) {
      console.error(
        `[startup] backend port ${BACKEND_PORT} is occupied by an unhealthy process and could not be recovered.`
      );
      process.exit(1);
      return;
    }
    runtime = await inspectCurrentRuntime();
  }

  let shouldStartBackend = !runtime.backendInUse;
  let shouldStartFrontend = !runtime.frontendInUse;

  if (!shouldStartBackend && !shouldStartFrontend) {
    if (!runtime.proxyStatus.ok) {
      const released = await freePort('frontend', FRONTEND_PORT);
      if (!released) {
        console.error(
          `[startup] proxy path ${ENDPOINTS.frontendProxyHealth} is unhealthy and frontend restart failed.`
        );
        process.exit(1);
        return;
      }
      runtime = await inspectCurrentRuntime();
      shouldStartFrontend = !runtime.frontendInUse;
      shouldStartBackend = !runtime.backendInUse;
    }

    if (!shouldStartBackend && !shouldStartFrontend && runtime.proxyStatus.ok) {
      console.log('[startup] frontend + backend are already running and healthy.');
      console.log(`[startup] frontend: ${ENDPOINTS.frontendRoot}`);
      console.log(`[startup] backend health: ${ENDPOINTS.backendHealth}`);
      console.log(`[startup] proxy health: ${ENDPOINTS.frontendProxyHealth}`);
      return;
    }
  }

  if (shouldStartBackend) {
    const [backendEnv, redisUrl, ollamaEnv] = await Promise.all([
      startEmbeddedDatabase(),
      startEmbeddedRedis(),
      detectOllama(),
    ]);
    backend = runProcess('backend', ['run', 'dev', '--prefix', 'app/backend'], {
      ...backendEnv,
      ...(redisUrl ? { REDIS_URL: redisUrl } : {}),
      ...ollamaEnv,
    });
    attachExitHandler('backend', backend);
    await waitForHttpOk(ENDPOINTS.backendHealth, 'backend health');
    console.log('[startup] backend is healthy.');
  } else {
    console.log('[startup] backend already running. Reusing existing process.');
  }

  if (shouldStartFrontend) {
    frontend = runProcess('frontend', ['run', 'dev', '--prefix', 'app/frontend']);
    attachExitHandler('frontend', frontend);
    await waitForHttpOk(ENDPOINTS.frontendRoot, 'frontend root');
    console.log('[startup] frontend is healthy.');
  } else {
    console.log('[startup] frontend already running. Reusing existing process.');
  }

  await waitForHttpOk(ENDPOINTS.frontendProxyHealth, 'frontend backend-proxy health');

  console.log('[startup] full stack is ready.');
  console.log(`[startup] frontend: ${ENDPOINTS.frontendRoot}`);
  console.log(`[startup] backend health: ${ENDPOINTS.backendHealth}`);
  console.log(`[startup] proxy health: ${ENDPOINTS.frontendProxyHealth}`);
}

process.on('SIGINT', () => shutdown(0));
process.on('SIGTERM', () => shutdown(0));

main().catch(error => {
  console.error('[startup] failed to start dev stack:', error instanceof Error ? error.message : error);
  shutdown(1);
});
