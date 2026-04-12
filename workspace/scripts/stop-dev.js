#!/usr/bin/env node

const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const workspaceRoot = path.resolve(__dirname, '..');
const managerPidFile = path.resolve(workspaceRoot, '.runtime', 'start-dev.pid');

const ports = [
  Number(process.env.START_DEV_FRONTEND_PORT || 3000),
  Number(process.env.START_DEV_BACKEND_PORT || 8001),
  Number(process.env.START_DEV_EMBEDDED_DB_PORT || 55432),
];

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
      if (!line.includes('LISTENING') || !line.includes(`:${normalizedPort}`)) {
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

  if (!isPidRunning(pid)) {
    return true;
  }

  if (process.platform === 'win32') {
    const result = spawnSync('taskkill', ['/pid', String(pid), '/t', '/f'], {
      encoding: 'utf8',
    });
    return result.status === 0 || !isPidRunning(pid);
  }

  const result = spawnSync('kill', ['-TERM', String(pid)], {
    encoding: 'utf8',
  });
  return result.status === 0 || !isPidRunning(pid);
}

function isPidRunning(pid) {
  if (!pid) {
    return false;
  }

  if (process.platform === 'win32') {
    const result = spawnSync('tasklist', ['/fi', `PID eq ${String(pid)}`, '/fo', 'csv', '/nh'], {
      encoding: 'utf8',
    });
    if (result.status !== 0) {
      return false;
    }

    const output = `${result.stdout || ''}`.trim();
    return Boolean(output && !output.startsWith('INFO:') && output.includes(`\"${String(pid)}\"`));
  }

  const result = spawnSync('kill', ['-0', String(pid)], {
    encoding: 'utf8',
  });
  return result.status === 0;
}

function main() {
  const targets = new Set();

  try {
    const managerPid = parseInteger(fs.readFileSync(managerPidFile, 'utf8').trim());
    if (managerPid) {
      targets.add(managerPid);
    }
  } catch {
    // No manager pid recorded.
  }

  for (const port of ports) {
    if (!Number.isFinite(port) || port <= 0) {
      continue;
    }

    for (const pid of getListeningPidsOnPort(port)) {
      targets.add(pid);
    }
  }

  if (targets.size === 0) {
    process.stdout.write('No Cybertron dev processes were listening on managed ports.\n');
    return;
  }

  const stopped = [];
  const failed = [];

  for (const pid of targets) {
    if (terminatePid(pid)) {
      stopped.push(pid);
    } else {
      failed.push(pid);
    }
  }

  if (stopped.length > 0) {
    process.stdout.write(`Stopped Cybertron dev process(es): ${stopped.join(', ')}\n`);
  }

  if (failed.length > 0) {
    process.stderr.write(`Failed to stop process(es): ${failed.join(', ')}\n`);
    process.exitCode = 1;
  }

  try {
    fs.unlinkSync(managerPidFile);
  } catch {
    // Ignore cleanup failures.
  }
}

main();
