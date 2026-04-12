#!/usr/bin/env node

const { spawn } = require('node:child_process');
const path = require('node:path');

const backendRoot = path.resolve(__dirname, '..');

function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function runtimeReportPath(scope) {
  return path.resolve(backendRoot, '..', '..', '.runtime', 'qa', scope, 'reports');
}

function assertCondition(condition, label) {
  if (!condition) {
    throw new Error(`Assertion failed: ${label}`);
  }

  process.stdout.write(`PASS: ${label}\n`);
}

async function waitForEndpoint(url, expectedStatus, maxAttempts = 40) {
  let lastStatus = 0;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      const response = await fetch(url);
      lastStatus = response.status;
      if (response.status === expectedStatus) {
        return response;
      }
    } catch {
      // service booting
    }

    await wait(250);
  }

  throw new Error(`Endpoint ${url} did not return ${expectedStatus} (last status ${lastStatus}).`);
}

async function runScenario(name, envOverrides, expectedReadinessStatus, verifyFn) {
  const port = Number(envOverrides.PORT);
  const base = `http://127.0.0.1:${port}`;

  process.stdout.write(`\nScenario: ${name}\n`);

  const child = spawn(process.execPath, ['server.js'], {
    cwd: backendRoot,
    env: {
      ...process.env,
      ...envOverrides,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  child.stdout.on('data', chunk => {
    process.stdout.write(chunk.toString());
  });
  child.stderr.on('data', chunk => {
    process.stderr.write(chunk.toString());
  });

  try {
    await waitForEndpoint(`${base}/v1/system/health`, 200);
    const readinessResponse = await waitForEndpoint(
      `${base}/v1/system/readiness`,
      expectedReadinessStatus
    );
    const readinessBody = await readinessResponse.json();
    await verifyFn(readinessBody);
  } finally {
    child.kill('SIGTERM');
  }
}

async function run() {
  await runScenario(
    'strict_missing_dependencies',
    {
      PORT: '8110',
      NODE_ENV: 'development',
      AUTH_MODE: 'jwt_hs256',
      JWT_SECRET: 'failure-check-secret',
      DATABASE_URL: '',
      REDIS_URL: '',
      STRICT_DEPENDENCIES: 'true',
      DB_AUTO_MIGRATE: 'false',
      REPORT_STORAGE_DRIVER: 'local',
      REPORT_STORAGE_LOCAL_PATH: runtimeReportPath('strict-missing-dependencies'),
    },
    200,
    async readiness => {
      assertCondition(
        readiness.ready === true,
        'readiness stays true when strict mode deps are unset but not configured'
      );
      assertCondition(
        readiness.dependencies?.database?.status === 'not_configured',
        'readiness marks database as not_configured when missing'
      );
      assertCondition(
        readiness.dependencies?.redis?.status === 'not_configured',
        'readiness marks redis as not_configured when missing'
      );
      assertCondition(
        Array.isArray(readiness.warnings) &&
          readiness.warnings.some(message =>
            String(message).includes('database will not be required for readiness until a URL is provided')
          ),
        'readiness warns that database is not required until configured in strict mode'
      );
      assertCondition(
        Array.isArray(readiness.warnings) &&
          readiness.warnings.some(message =>
            String(message).includes('Redis will not be required for readiness until a URL is provided')
          ),
        'readiness warns that redis is not required until configured in strict mode'
      );
    }
  );

  await runScenario(
    'db_failure_readiness',
    {
      PORT: '8111',
      NODE_ENV: 'development',
      AUTH_MODE: 'jwt_hs256',
      JWT_SECRET: 'failure-check-secret',
      DATABASE_URL: 'postgresql://cybertron:bad@127.0.0.1:65530/cybertron',
      STRICT_DEPENDENCIES: 'true',
      DB_AUTO_MIGRATE: 'false',
      REPORT_STORAGE_DRIVER: 'local',
      REPORT_STORAGE_LOCAL_PATH: runtimeReportPath('db-failure-readiness'),
    },
    503,
    async readiness => {
      assertCondition(readiness.ready === false, 'readiness false when database is unreachable');
      assertCondition(
        readiness.dependencies?.database?.status === 'unavailable',
        'readiness marks database as unavailable'
      );
    }
  );

  await runScenario(
    'storage_failure_readiness',
    {
      PORT: '8112',
      NODE_ENV: 'development',
      AUTH_MODE: 'jwt_hs256',
      JWT_SECRET: 'failure-check-secret',
      DATABASE_URL: '',
      DB_AUTO_MIGRATE: 'false',
      REPORT_STORAGE_DRIVER: 's3',
      REPORT_STORAGE_S3_BUCKET: 'cybertron-failure-check',
      REPORT_STORAGE_S3_REGION: 'us-east-1',
      REPORT_STORAGE_S3_ENDPOINT: 'http://127.0.0.1:9',
      REPORT_STORAGE_S3_ACCESS_KEY_ID: 'dummy',
      REPORT_STORAGE_S3_SECRET_ACCESS_KEY: 'dummy',
      REPORT_STORAGE_S3_FORCE_PATH_STYLE: 'true',
    },
    503,
    async readiness => {
      assertCondition(readiness.ready === false, 'readiness false when storage is unreachable');
      assertCondition(
        readiness.dependencies?.storage?.status === 'unavailable',
        'readiness marks storage as unavailable'
      );
    }
  );

  process.stdout.write('Failure handling checks passed.\n');
}

run().catch(error => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
