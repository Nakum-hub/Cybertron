#!/usr/bin/env node

const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');

const sourceScriptPath = path.resolve(__dirname, 'release-preflight.js');
const gitContextEnvKeys = [
  'GIT_DIR',
  'GIT_WORK_TREE',
  'GIT_INDEX_FILE',
  'GIT_OBJECT_DIRECTORY',
  'GIT_ALTERNATE_OBJECT_DIRECTORIES',
  'GIT_COMMON_DIR',
  'GIT_PREFIX',
];

function assertCondition(condition, label, details = '') {
  if (!condition) {
    const suffix = details ? `\n${details}` : '';
    throw new Error(`FAIL: ${label}${suffix}`);
  }

  process.stdout.write(`PASS: ${label}\n`);
}

function createGitNeutralEnv(cwd = process.cwd()) {
  const env = { ...process.env };
  for (const key of gitContextEnvKeys) {
    delete env[key];
  }

  env.GIT_CEILING_DIRECTORIES = cwd;
  return env;
}

async function writeFile(filePath, content = '') {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, content, 'utf8');
}

async function createScenarioRoot(label, { withGit = false, withUploadPayload = false, withRuntimePayload = false } = {}) {
  const scenarioRoot = await fs.mkdtemp(path.join(os.tmpdir(), `cybertron-${label}-`));
  const workspaceRoot = path.join(scenarioRoot, 'workspace');
  const scriptsDir = path.join(workspaceRoot, 'scripts');
  const uploadsDir = path.join(workspaceRoot, 'uploads');
  const runtimeDir = path.join(workspaceRoot, '.runtime');

  await fs.mkdir(scriptsDir, { recursive: true });
  await fs.copyFile(sourceScriptPath, path.join(scriptsDir, 'release-preflight.js'));
  await fs.mkdir(uploadsDir, { recursive: true });
  await fs.mkdir(runtimeDir, { recursive: true });
  await writeFile(path.join(workspaceRoot, '.gitignore'), 'uploads/\n');

  if (withUploadPayload) {
    await writeFile(path.join(uploadsDir, 'payload.txt'), 'runtime-only payload');
  } else {
    await writeFile(path.join(uploadsDir, '.gitkeep'), '');
  }

  if (withRuntimePayload) {
    await writeFile(path.join(runtimeDir, 'logs', 'manager.log'), 'runtime-only log');
  }

  if (withGit) {
    const env = createGitNeutralEnv(scenarioRoot);
    execFileSync('git', ['init'], { cwd: scenarioRoot, env, stdio: 'ignore' });
    execFileSync('git', ['config', 'user.email', 'ci@example.com'], { cwd: scenarioRoot, env, stdio: 'ignore' });
    execFileSync('git', ['config', 'user.name', 'Cybertron CI'], { cwd: scenarioRoot, env, stdio: 'ignore' });
    execFileSync('git', ['add', '.'], { cwd: scenarioRoot, env, stdio: 'ignore' });
  }

  return scenarioRoot;
}

function runPreflight(repoRoot, args = []) {
  const result = spawnSync(
    process.execPath,
    [path.join(repoRoot, 'workspace', 'scripts', 'release-preflight.js'), ...args],
    {
      cwd: repoRoot,
      encoding: 'utf8',
      env: createGitNeutralEnv(repoRoot),
    }
  );

  return {
    status: result.status ?? 1,
    output: `${result.stdout || ''}${result.stderr || ''}`,
  };
}

async function main() {
  const roots = [];

  try {
    const warningRoot = await createScenarioRoot('release-warning', {
      withGit: false,
      withUploadPayload: true,
      withRuntimePayload: true,
    });
    roots.push(warningRoot);

    const warningRun = runPreflight(warningRoot);
    assertCondition(warningRun.status === 0, 'non-strict preflight passes with warnings in non-git workspace');
    assertCondition(
      warningRun.output.includes('SKIP: git metadata not available - tracked-file artifact checks cannot run.'),
      'non-strict preflight reports missing git metadata explicitly'
    );
    assertCondition(
      warningRun.output.includes('WARN: runtime artifact directories contain files in local environment:'),
      'non-strict preflight reports runtime artifact warnings explicitly'
    );
    assertCondition(
      warningRun.output.includes('- workspace/.runtime'),
      'non-strict preflight reports workspace runtime payload explicitly'
    );
    assertCondition(
      warningRun.output.includes('Release preflight completed with warnings.'),
      'non-strict preflight ends with warning summary'
    );
    assertCondition(
      !warningRun.output.includes('PASS: No runtime artifact payload directories are present'),
      'non-strict preflight avoids a false clean-artifact pass'
    );

    const strictNoGitRoot = await createScenarioRoot('release-strict-no-git', {
      withGit: false,
      withUploadPayload: false,
    });
    roots.push(strictNoGitRoot);

    const strictNoGitRun = runPreflight(strictNoGitRoot, ['--strict']);
    assertCondition(strictNoGitRun.status !== 0, 'strict preflight fails when git metadata is unavailable');
    assertCondition(
      strictNoGitRun.output.includes('FAIL: Git metadata is available for strict tracked-file checks'),
      'strict preflight explains the missing git metadata failure'
    );

    const strictCleanRoot = await createScenarioRoot('release-strict-clean', {
      withGit: true,
      withUploadPayload: false,
    });
    roots.push(strictCleanRoot);

    const strictCleanRun = runPreflight(strictCleanRoot, ['--strict']);
    assertCondition(strictCleanRun.status === 0, 'strict preflight passes for clean git-backed workspace');
    assertCondition(
      strictCleanRun.output.includes('PASS: No forbidden tracked artifacts in git index'),
      'strict preflight checks tracked artifacts when git metadata exists'
    );
    assertCondition(
      strictCleanRun.output.includes('PASS: No runtime artifact payload directories are present'),
      'strict preflight passes clean runtime artifact check'
    );
    assertCondition(
      strictCleanRun.output.includes('Release preflight checks passed.'),
      'strict preflight ends with clean success summary'
    );

    process.stdout.write('Release preflight self-checks passed.\n');
  } finally {
    await Promise.all(roots.map(rootPath => fs.rm(rootPath, { recursive: true, force: true })));
  }
}

main().catch(error => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
