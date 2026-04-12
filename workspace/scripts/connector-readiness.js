#!/usr/bin/env node

const fs = require('node:fs');
const path = require('node:path');

const workspaceRoot = path.resolve(__dirname, '..');
const defaultEnvFilePath = path.join(workspaceRoot, '.env');

function parseArgs(argv) {
  const args = {};

  for (let index = 0; index < argv.length; index += 1) {
    const token = String(argv[index] || '');
    if (!token.startsWith('--')) {
      continue;
    }

    const key = token.slice(2);
    const next = argv[index + 1];
    if (next && !String(next).startsWith('--')) {
      args[key] = String(next);
      index += 1;
      continue;
    }

    args[key] = 'true';
  }

  return args;
}

function usage() {
  return [
    'Usage:',
    '  node scripts/connector-readiness.js [options]',
    '',
    'Options:',
    '  --env-file <path>      Env file to load (default: workspace/.env)',
    '  --require-any          Fail if no connectors are configured',
    '  --require-healthy      Fail if any configured connector is not healthy',
    '  --json                 Print only the JSON report',
  ].join('\n');
}

function readEnvFile(filePath) {
  const source = fs.readFileSync(filePath, 'utf8');
  const values = {};

  for (const rawLine of source.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) {
      continue;
    }

    const separatorIndex = line.indexOf('=');
    if (separatorIndex === -1) {
      continue;
    }

    const key = line.slice(0, separatorIndex).trim();
    const value = line.slice(separatorIndex + 1).trim();
    values[key] = value.replace(/^"(.*)"$/, '$1').replace(/^'(.*)'$/, '$1');
  }

  return values;
}

function assertCondition(condition, label, details = '') {
  if (!condition) {
    const suffix = details ? `\n${details}` : '';
    throw new Error(`FAIL: ${label}${suffix}`);
  }

  process.stdout.write(`PASS: ${label}\n`);
}

function warn(label, details = '') {
  const suffix = details ? `\n${details}` : '';
  process.stdout.write(`WARN: ${label}${suffix}\n`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help === 'true') {
    process.stdout.write(`${usage()}\n`);
    return;
  }

  const envFile = path.resolve(args['env-file'] || defaultEnvFilePath);
  if (!fs.existsSync(envFile)) {
    throw new Error(`FAIL: connector env file exists\n${envFile}`);
  }

  const fileEnv = readEnvFile(envFile);
  Object.assign(process.env, fileEnv);

  const { config, validateRuntimeConfig } = require(path.join(workspaceRoot, 'app', 'backend', 'src', 'config.js'));
  const { getConnectorStatus } = require(path.join(workspaceRoot, 'app', 'backend', 'src', 'threat-connectors.js'));

  const validation = validateRuntimeConfig(config);
  assertCondition(
    validation.ok === true,
    'backend runtime config validation passes before connector probing',
    (validation.errors || []).map(item => `- ${item}`).join('\n')
  );

  const report = await getConnectorStatus(config);
  const configured = report.filter(item => item.configured);
  const healthy = configured.filter(item => item.status === 'healthy');
  const unhealthy = configured.filter(item => item.status !== 'healthy');

  if (args.json !== 'true') {
    if (configured.length === 0) {
      warn(
        'no external threat connectors are configured',
        'Cybertron can still operate truthfully via NVD, but SOC ingestion depth remains limited until connectors are added.'
      );
    } else {
      assertCondition(
        healthy.length === configured.length,
        'all configured threat connectors are healthy',
        unhealthy
          .map(item => `- ${item.name}: ${item.message || item.status}`)
          .join('\n')
      );
    }
  }

  if (args['require-any'] === 'true') {
    assertCondition(
      configured.length > 0,
      'at least one threat connector is configured'
    );
  }

  if (args['require-healthy'] === 'true') {
    assertCondition(
      unhealthy.length === 0,
      'every configured threat connector is healthy',
      unhealthy
        .map(item => `- ${item.name}: ${item.message || item.status}`)
        .join('\n')
    );
  }

  const payload = {
    ok: unhealthy.length === 0 || configured.length === 0,
    envFile,
    configuredCount: configured.length,
    healthyCount: healthy.length,
    connectors: report,
  };
  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
