#!/usr/bin/env node

const fs = require('node:fs/promises');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const workspaceRoot = path.resolve(__dirname, '..');
const repoRoot = path.resolve(workspaceRoot, '..');
const cliArgs = new Set(process.argv.slice(2));
const gitContextEnvKeys = [
  'GIT_DIR',
  'GIT_WORK_TREE',
  'GIT_INDEX_FILE',
  'GIT_OBJECT_DIRECTORY',
  'GIT_ALTERNATE_OBJECT_DIRECTORIES',
  'GIT_COMMON_DIR',
  'GIT_PREFIX',
];

const trackedForbiddenMatchers = [
  /(^|\/)node_modules(\/|$)/,
  /(^|\/)\.runtime(\/|$)/,
  /(^|\/)\.cache(\/|$)/,
  /(^|\/)cover(\/|$)/,
  /(^|\/)coverage(\/|$)/,
  /(^|\/)dist(\/|$)/,
  /(^|\/)build(\/|$)/,
  /(^|\/)uploads(\/|$)/,
];

const runtimeArtifactDirs = [
  path.join(repoRoot, '.cache'),
  path.join(repoRoot, 'workspace', '.runtime'),
  path.join(repoRoot, 'workspace', 'uploads'),
  path.join(repoRoot, 'cover'),
  path.join(repoRoot, 'coverage'),
];

function normalizePath(value) {
  return String(value || '').replace(/\\/g, '/').trim();
}

function assertCondition(condition, label, details = '') {
  if (!condition) {
    const suffix = details ? `\n${details}` : '';
    throw new Error(`FAIL: ${label}${suffix}`);
  }

  process.stdout.write(`PASS: ${label}\n`);
}

function createGitNeutralEnv() {
  const env = { ...process.env };
  for (const key of gitContextEnvKeys) {
    delete env[key];
  }

  env.GIT_CEILING_DIRECTORIES = repoRoot;
  return env;
}

function listTrackedFiles() {
  try {
    const env = createGitNeutralEnv();
    const topLevel = execFileSync('git', ['rev-parse', '--show-toplevel'], {
      cwd: repoRoot,
      encoding: 'utf8',
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const normalizedTopLevel = normalizePath(path.resolve(topLevel));
    if (normalizedTopLevel !== normalizePath(repoRoot)) {
      return null;
    }

    const output = execFileSync('git', ['ls-files'], {
      cwd: repoRoot,
      encoding: 'utf8',
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    return output
      .split(/\r?\n/)
      .map(normalizePath)
      .filter(Boolean);
  } catch {
    return null;
  }
}

async function directoryHasPayload(dirPath) {
  try {
    const entries = await fs.readdir(dirPath, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name === '.gitkeep') {
        continue;
      }

      return true;
    }

    return false;
  } catch {
    return false;
  }
}

async function run() {
  let warningCount = 0;
  const enforceRuntimePayloadGate =
    cliArgs.has('--strict') ||
    String(process.env.CI || 'false').toLowerCase() === 'true' ||
    String(process.env.STRICT_RELEASE_PREFLIGHT || 'false').toLowerCase() === 'true';
  const tracked = listTrackedFiles();

  if (tracked === null) {
    warningCount += 1;
    process.stdout.write(
      'SKIP: git metadata not available - tracked-file artifact checks cannot run. This is expected inside Docker builds but must not be relied on as a pass.\n'
    );

    if (enforceRuntimePayloadGate) {
      assertCondition(
        false,
        'Git metadata is available for strict tracked-file checks',
        'Strict release preflight requires git metadata. Run from a real git checkout or disable strict mode explicitly.'
      );
    }
  } else {
    const trackedViolations = tracked.filter(filePath =>
      trackedForbiddenMatchers.some(pattern => pattern.test(filePath))
    );

    assertCondition(
      trackedViolations.length === 0,
      'No forbidden tracked artifacts in git index',
      trackedViolations.length
        ? `Tracked forbidden paths:\n${trackedViolations.map(item => `- ${item}`).join('\n')}`
        : ''
    );
  }

  const localRuntimeViolations = [];
  for (const artifactDir of runtimeArtifactDirs) {
    // eslint-disable-next-line no-await-in-loop
    const hasPayload = await directoryHasPayload(artifactDir);
    if (hasPayload) {
      localRuntimeViolations.push(path.relative(repoRoot, artifactDir).replace(/\\/g, '/'));
    }
  }

  if (localRuntimeViolations.length > 0) {
    if (enforceRuntimePayloadGate) {
      assertCondition(
        false,
        'No runtime artifact payload directories are present',
        `Runtime artifact directories with files:\n${localRuntimeViolations
          .map(item => `- ${item}`)
          .join('\n')}\nClean these paths before creating a strict release artifact.`
      );
    }

    warningCount += 1;
    process.stdout.write(
      `WARN: runtime artifact directories contain files in local environment:\n${localRuntimeViolations
        .map(item => `- ${item}`)
        .join('\n')}\n`
    );
  } else {
    assertCondition(true, 'No runtime artifact payload directories are present');
  }

  process.stdout.write(
    warningCount > 0 ? 'Release preflight completed with warnings.\n' : 'Release preflight checks passed.\n'
  );
}

run().catch(error => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
