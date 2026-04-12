const path = require('node:path');
const { spawnSync } = require('node:child_process');

function normalizePath(value) {
  return String(value || '')
    .trim()
    .replace(/\\/g, '/')
    .replace(/\/+$/, '')
    .toLowerCase();
}

function runDockerCommand(args) {
  const result = spawnSync('docker', args, {
    cwd: path.resolve(__dirname, '..'),
    encoding: 'utf8',
  });

  if (result.error) {
    throw result.error;
  }

  if (result.status !== 0) {
    const message = String(result.stderr || result.stdout || 'Docker command failed.').trim();
    throw new Error(message);
  }

  return String(result.stdout || '');
}

function findComposeServiceContainer(serviceName) {
  const workingDir = normalizePath(path.resolve(__dirname, '..'));
  const output = runDockerCommand([
    'ps',
    '--filter',
    `label=com.docker.compose.service=${String(serviceName || '').trim()}`,
    '--format',
    '{{.Names}}',
  ]);

  const candidates = output
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(Boolean)
    .map(name => {
      const labelsOutput = runDockerCommand([
        'inspect',
        String(name || '').trim(),
        '--format',
        '{{json .Config.Labels}}',
      ]);
      const labels = JSON.parse(labelsOutput.trim() || '{}');
      return {
        name: String(name || '').trim(),
        workingDir: normalizePath(labels['com.docker.compose.project.working_dir']),
      };
    })
    .filter(item => item.name);

  const exactMatch = candidates.find(item => item.workingDir === workingDir);
  if (exactMatch) {
    return exactMatch.name;
  }

  if (candidates.length === 1) {
    return candidates[0].name;
  }

  throw new Error(
    candidates.length
      ? `Found multiple ${serviceName} containers and could not disambiguate the active workspace.`
      : `No running ${serviceName} compose container was found for this workspace.`
  );
}

function readContainerEnv(containerName) {
  const output = runDockerCommand([
    'inspect',
    containerName,
    '--format',
    '{{json .Config.Env}}',
  ]);

  const envList = JSON.parse(output.trim() || '[]');
  const env = {};

  for (const entry of envList) {
    const separator = String(entry || '').indexOf('=');
    if (separator <= 0) {
      continue;
    }

    const key = entry.slice(0, separator);
    const value = entry.slice(separator + 1);
    env[key] = value;
  }

  return env;
}

module.exports = {
  findComposeServiceContainer,
  readContainerEnv,
  runDockerCommand,
};
