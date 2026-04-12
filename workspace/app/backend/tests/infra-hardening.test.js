const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

// =====================================================================
// Source file loading
// =====================================================================

const workspaceRoot = path.resolve(__dirname, '..', '..', '..');
const backendBase = path.resolve(__dirname, '..', 'src');
const frontendBase = path.resolve(__dirname, '..', '..', 'frontend');

const backendDockerfile = fs.readFileSync(
  path.join(workspaceRoot, 'app', 'backend', 'Dockerfile'),
  'utf8'
);
const frontendDockerfile = fs.readFileSync(
  path.join(workspaceRoot, 'app', 'frontend', 'Dockerfile'),
  'utf8'
);
const composeBase = fs.readFileSync(
  path.join(workspaceRoot, 'docker-compose.yml'),
  'utf8'
);
const composeDev = fs.readFileSync(
  path.join(workspaceRoot, 'docker-compose.dev.yml'),
  'utf8'
);
const composeProd = fs.readFileSync(
  path.join(workspaceRoot, 'docker-compose.prod.yml'),
  'utf8'
);
const serverSource = fs.readFileSync(
  path.join(backendBase, 'server.js'),
  'utf8'
);
const configSource = fs.readFileSync(
  path.join(backendBase, 'config.js'),
  'utf8'
);
const nginxHttp = fs.readFileSync(
  path.join(frontendBase, 'nginx', 'default.conf'),
  'utf8'
);
const nginxTls = fs.readFileSync(
  path.join(frontendBase, 'nginx', 'default-tls.conf'),
  'utf8'
);
const ciWorkflow = fs.readFileSync(
  path.join(workspaceRoot, '..', '.github', 'workflows', 'ci.yml'),
  'utf8'
);

// =====================================================================
// I1: Backend Dockerfile healthcheck uses correct path
// =====================================================================

describe('I1: Backend Dockerfile healthcheck path', () => {
  it('uses /v1/system/readiness (not /api/v1/system/health)', () => {
    assert.ok(
      backendDockerfile.includes('/v1/system/readiness'),
      'HEALTHCHECK should reference /v1/system/readiness'
    );
    assert.ok(
      !backendDockerfile.includes('/api/v1/system/health'),
      'HEALTHCHECK must not use proxied /api/v1/system/health path'
    );
  });

  it('uses wget, not curl (curl not in alpine base)', () => {
    const healthLine = backendDockerfile.split('\n').find(l => l.includes('HEALTHCHECK') || l.includes('wget'));
    assert.ok(healthLine, 'should have a HEALTHCHECK line');
    assert.ok(
      backendDockerfile.includes('wget'),
      'HEALTHCHECK should use wget (available in alpine)'
    );
  });

  it('does not install curl', () => {
    assert.ok(
      !backendDockerfile.includes('apk add') || !backendDockerfile.includes('curl'),
      'Dockerfile should not install curl — wget is already available in alpine'
    );
  });

  it('uses node directly, not npm run start', () => {
    assert.ok(
      backendDockerfile.includes('CMD ["node"'),
      'CMD should invoke node directly for faster startup'
    );
    assert.ok(
      !backendDockerfile.includes('CMD ["npm"'),
      'CMD should not use npm (adds overhead and PID1 issues)'
    );
  });

  it('runs as non-root user', () => {
    assert.ok(
      backendDockerfile.includes('USER node'),
      'Dockerfile must switch to non-root user before CMD'
    );
  });

  it('uses multi-stage build', () => {
    const fromLines = backendDockerfile.split('\n').filter(l => l.startsWith('FROM '));
    assert.ok(fromLines.length >= 2, 'Dockerfile should have at least 2 FROM stages');
  });
});

// =====================================================================
// I2: Frontend Dockerfile target in compose files
// =====================================================================

describe('I2: Frontend Dockerfile target in compose files', () => {
  it('frontend Dockerfile has named default and tls stages', () => {
    assert.ok(
      frontendDockerfile.includes('AS default'),
      'Frontend Dockerfile must have an AS default stage'
    );
    assert.ok(
      frontendDockerfile.includes('AS tls'),
      'Frontend Dockerfile must have an AS tls stage'
    );
  });

  it('base compose specifies target: default for frontend', () => {
    const frontendBlock = composeBase.substring(composeBase.indexOf('frontend:'));
    const nextService = frontendBlock.indexOf('\nvolumes:');
    const section = frontendBlock.substring(0, nextService > 0 ? nextService : undefined);
    assert.ok(
      section.includes('target: default'),
      'docker-compose.yml frontend build must specify target: default'
    );
  });

  it('dev compose specifies target: default for frontend', () => {
    const frontendBlock = composeDev.substring(composeDev.indexOf('frontend:'));
    const nextService = frontendBlock.indexOf('\nvolumes:');
    const section = frontendBlock.substring(0, nextService > 0 ? nextService : undefined);
    assert.ok(
      section.includes('target: default'),
      'docker-compose.dev.yml frontend build must specify target: default'
    );
  });

  it('prod compose specifies target: default for frontend', () => {
    const frontendBlock = composeProd.substring(composeProd.indexOf('frontend:'));
    const nextService = frontendBlock.indexOf('\nvolumes:');
    const section = frontendBlock.substring(0, nextService > 0 ? nextService : undefined);
    assert.ok(
      section.includes('target: default'),
      'docker-compose.prod.yml frontend build must specify target: default'
    );
  });

  it('base compose does not expose port 443 or 8443', () => {
    assert.ok(
      !composeBase.includes('443:8443'),
      'Base compose must not expose TLS port 443:8443'
    );
  });
});

// =====================================================================
// I3: isDependencyRequired respects strictDependencies
// =====================================================================

describe('I3: isDependencyRequired respects strictDependencies', () => {
  it('storage is always required', () => {
    const funcBlock = serverSource.substring(
      serverSource.indexOf('function isDependencyRequired'),
      serverSource.indexOf('function isDependencyRequired') + 600
    );
    assert.ok(
      funcBlock.includes("dependency === 'storage'") && funcBlock.includes('return true'),
      'storage dependency must always return true'
    );
  });

  it('database checks strictDependencies AND databaseUrl', () => {
    const funcBlock = serverSource.substring(
      serverSource.indexOf('function isDependencyRequired'),
      serverSource.indexOf('function isDependencyRequired') + 600
    );
    assert.ok(
      funcBlock.includes('config.strictDependencies') && funcBlock.includes('config.databaseUrl'),
      'database dependency must check config.strictDependencies && config.databaseUrl'
    );
  });

  it('redis checks strictDependencies AND redisUrl', () => {
    const funcBlock = serverSource.substring(
      serverSource.indexOf('function isDependencyRequired'),
      serverSource.indexOf('function isDependencyRequired') + 600
    );
    assert.ok(
      funcBlock.includes('config.strictDependencies') && funcBlock.includes('config.redisUrl'),
      'redis dependency must check config.strictDependencies && config.redisUrl'
    );
  });

  it('unknown dependencies return false', () => {
    const funcBlock = serverSource.substring(
      serverSource.indexOf('function isDependencyRequired'),
      serverSource.indexOf('function isDependencyRequired') + 600
    );
    assert.ok(
      funcBlock.includes('return false'),
      'unknown dependencies should return false at the end of the function'
    );
  });
});

// =====================================================================
// I4: Database migration retry at startup
// =====================================================================

describe('I4: Database migration retry at startup', () => {
  it('has migration retry loop', () => {
    assert.ok(
      serverSource.includes('maxMigrationAttempts'),
      'server.js must define maxMigrationAttempts for migration retries'
    );
  });

  it('production uses 5 retry attempts', () => {
    assert.ok(
      serverSource.includes("=== 'production' ? 5"),
      'production should retry migrations up to 5 times'
    );
  });

  it('non-production uses 2 retry attempts', () => {
    assert.ok(
      serverSource.includes('? 5 : 2'),
      'non-production should retry migrations up to 2 times'
    );
  });

  it('logs failed migration attempts', () => {
    assert.ok(
      serverSource.includes('database.migration_attempt_failed'),
      'failed migration attempts should be logged with structured event'
    );
  });

  it('logs final migration failure', () => {
    assert.ok(
      serverSource.includes('database.migration_failed'),
      'final migration failure should be logged'
    );
  });

  it('exits on final migration failure', () => {
    // Find the migration failure block
    const failIdx = serverSource.indexOf('database.migration_failed');
    assert.ok(failIdx > 0, 'database.migration_failed event must exist');
    const afterFail = serverSource.substring(failIdx, failIdx + 200);
    assert.ok(
      afterFail.includes('process.exit(1)'),
      'process must exit(1) after all migration attempts exhausted'
    );
  });

  it('waits between retry attempts', () => {
    const migrationBlock = serverSource.substring(
      serverSource.indexOf('maxMigrationAttempts'),
      serverSource.indexOf('maxMigrationAttempts') + 800
    );
    assert.ok(
      migrationBlock.includes('setTimeout') && migrationBlock.includes('2000'),
      'should wait 2s between migration attempts'
    );
  });
});

// =====================================================================
// I5: No stale pnpm-lock.yaml in frontend
// =====================================================================

describe('I5: No stale pnpm lockfile', () => {
  it('frontend has no pnpm-lock.yaml', () => {
    const pnpmPath = path.join(frontendBase, 'pnpm-lock.yaml');
    assert.ok(
      !fs.existsSync(pnpmPath),
      'frontend/pnpm-lock.yaml should not exist (project uses npm)'
    );
  });

  it('frontend has package-lock.json', () => {
    const npmLockPath = path.join(frontendBase, 'package-lock.json');
    assert.ok(
      fs.existsSync(npmLockPath),
      'frontend/package-lock.json must exist (npm is the package manager)'
    );
  });
});

// =====================================================================
// I6: Dead workspace CI merged into root CI
// =====================================================================

describe('I6: CI workflow consolidation', () => {
  it('workspace .github/workflows/ci.yml does not exist', () => {
    const deadCiPath = path.join(workspaceRoot, '.github', 'workflows', 'ci.yml');
    assert.ok(
      !fs.existsSync(deadCiPath),
      'workspace/.github/workflows/ci.yml should be deleted — GitHub cannot reach it'
    );
  });

  it('root CI includes security-audit job', () => {
    assert.ok(
      ciWorkflow.includes('security-audit'),
      'root CI must include the security-audit job'
    );
    assert.ok(
      ciWorkflow.includes('npm audit'),
      'security-audit job must run npm audit'
    );
  });

  it('root CI includes container-scan job', () => {
    assert.ok(
      ciWorkflow.includes('container-scan'),
      'root CI must include the container-scan job'
    );
    assert.ok(
      ciWorkflow.includes('trivy-action'),
      'container-scan must use Trivy security scanner'
    );
  });

  it('root CI has security-events write permission', () => {
    assert.ok(
      ciWorkflow.includes('security-events: write'),
      'CI must have security-events write permission for Trivy results'
    );
  });

  it('root CI quality-gate job has postgres and redis services', () => {
    assert.ok(
      ciWorkflow.includes('postgres:') && ciWorkflow.includes('redis:'),
      'quality-gate job needs postgres and redis services'
    );
  });

  it('container-scan depends on quality-gate', () => {
    const scanBlock = ciWorkflow.substring(ciWorkflow.indexOf('container-scan:'));
    assert.ok(
      scanBlock.includes('needs: [quality-gate]'),
      'container-scan should depend on quality-gate (no point scanning if QA fails)'
    );
  });

  it('container-scan builds frontend with --target default', () => {
    const scanBlock = ciWorkflow.substring(ciWorkflow.indexOf('container-scan:'));
    assert.ok(
      scanBlock.includes('--target default'),
      'container-scan must build frontend with --target default to match compose files'
    );
  });
});

// =====================================================================
// I7: METRICS_AUTH_TOKEN placeholder validation
// =====================================================================

describe('I7: METRICS_AUTH_TOKEN placeholder validation', () => {
  it('validates METRICS_AUTH_TOKEN is not empty when auth required', () => {
    assert.ok(
      configSource.includes('metricsRequireAuth') && configSource.includes('metricsAuthToken'),
      'config must validate METRICS_AUTH_TOKEN when METRICS_REQUIRE_AUTH=true'
    );
  });

  it('rejects placeholder values like CHANGE_ME', () => {
    assert.ok(
      configSource.includes("change.?me") && configSource.includes('metricsAuthToken'),
      'config must reject METRICS_AUTH_TOKEN placeholder values matching /change.?me/i'
    );
  });

  it('provides helpful generation command in error message', () => {
    const blockStart = configSource.indexOf('metricsAuthToken appears');
    if (blockStart < 0) {
      // Find the error message about metrics auth token placeholder
      const altStart = configSource.indexOf('METRICS_AUTH_TOKEN appears');
      assert.ok(altStart > 0, 'must have error message about METRICS_AUTH_TOKEN placeholder');
      const msg = configSource.substring(altStart, altStart + 200);
      assert.ok(
        msg.includes('crypto') && msg.includes('randomBytes'),
        'error message should suggest using crypto.randomBytes to generate a token'
      );
    } else {
      const msg = configSource.substring(blockStart, blockStart + 200);
      assert.ok(
        msg.includes('crypto') && msg.includes('randomBytes'),
        'error message should suggest using crypto.randomBytes to generate a token'
      );
    }
  });
});

// =====================================================================
// I8: TLS nginx config has rate limiting parity with HTTP
// =====================================================================

describe('I8: TLS nginx rate limiting', () => {
  it('HTTP config has limit_req_zone directives', () => {
    assert.ok(
      nginxHttp.includes('limit_req_zone'),
      'HTTP nginx config must define rate limit zones'
    );
  });

  it('TLS config has limit_req_zone directives', () => {
    assert.ok(
      nginxTls.includes('limit_req_zone'),
      'TLS nginx config must define rate limit zones'
    );
  });

  it('TLS has api_global rate limit zone', () => {
    assert.ok(
      nginxTls.includes('zone=api_global'),
      'TLS config must define api_global rate limit zone'
    );
  });

  it('TLS has api_auth rate limit zone', () => {
    assert.ok(
      nginxTls.includes('zone=api_auth'),
      'TLS config must define api_auth rate limit zone'
    );
  });

  it('TLS api_global matches HTTP rate (30r/s)', () => {
    assert.ok(
      nginxTls.includes('rate=30r/s'),
      'TLS api_global rate must match HTTP config (30r/s)'
    );
  });

  it('TLS api_auth matches HTTP rate (5r/s)', () => {
    assert.ok(
      nginxTls.includes('rate=5r/s'),
      'TLS api_auth rate must match HTTP config (5r/s)'
    );
  });

  it('TLS has separate /api/v1/auth/ location with auth rate limit', () => {
    assert.ok(
      nginxTls.includes('location /api/v1/auth/'),
      'TLS config must have a separate /api/v1/auth/ location block'
    );
    const authBlock = nginxTls.substring(
      nginxTls.indexOf('location /api/v1/auth/'),
      nginxTls.indexOf('location /api/v1/auth/') + 400
    );
    assert.ok(
      authBlock.includes('limit_req zone=api_auth'),
      '/api/v1/auth/ block must apply api_auth rate limit'
    );
  });

  it('TLS /api/ location has global rate limit', () => {
    // Find the general /api/ block (not /api/v1/auth/)
    const apiIdx = nginxTls.indexOf('location /api/ {');
    assert.ok(apiIdx > 0, 'TLS config must have a general /api/ location block');
    const apiBlock = nginxTls.substring(apiIdx, apiIdx + 400);
    assert.ok(
      apiBlock.includes('limit_req zone=api_global'),
      '/api/ block must apply api_global rate limit'
    );
  });

  it('TLS returns 429 for rate-limited requests', () => {
    assert.ok(
      nginxTls.includes('limit_req_status 429'),
      'TLS config must return 429 status for rate-limited requests'
    );
  });
});

// =====================================================================
// I9: No stale tracked files
// =====================================================================

describe('I9: No stale tracked files', () => {
  it('nul file does not exist in repo root', () => {
    const nulPath = path.join(workspaceRoot, '..', 'nul');
    assert.ok(
      !fs.existsSync(nulPath),
      'Stale "nul" file should not exist in repo root'
    );
  });

  it('tmp_test.js does not exist in repo root', () => {
    const tmpPath = path.join(workspaceRoot, '..', 'tmp_test.js');
    assert.ok(
      !fs.existsSync(tmpPath),
      'Stale "tmp_test.js" file should not exist in repo root'
    );
  });
});

// =====================================================================
// Docker Compose production hardening
// =====================================================================

// Helper to extract a top-level service block from compose YAML
function getComposeServiceBlock(composeSrc, serviceName) {
  const pattern = new RegExp(`^  ${serviceName}:`, 'gm');
  const match = pattern.exec(composeSrc);
  if (!match) return '';
  const startIdx = match.index;
  const rest = composeSrc.substring(startIdx + match[0].length);
  // Next top-level key (0-indent) like 'volumes:', 'networks:'
  const nextTopMatch = rest.match(/\n[a-z]/);
  // Next 2-indent service key: line starting with exactly 2 spaces + letter
  const nextSvcMatch = rest.match(/\n  [a-z]/);
  const ends = [];
  if (nextTopMatch) ends.push(nextTopMatch.index);
  if (nextSvcMatch) ends.push(nextSvcMatch.index);
  const relEnd = ends.length > 0 ? Math.min(...ends) : rest.length;
  return composeSrc.substring(startIdx, startIdx + match[0].length + relEnd);
}

describe('Compose production hardening', () => {
  it('prod compose sets no-new-privileges on all services', () => {
    const services = ['redis', 'postgres', 'backend', 'frontend'];
    for (const svc of services) {
      const block = getComposeServiceBlock(composeProd, svc);
      assert.ok(block.length > 0, `${svc} must exist in prod compose`);
      assert.ok(
        block.includes('no-new-privileges:true'),
        `${svc} must have no-new-privileges:true in prod`
      );
    }
  });

  it('prod compose drops ALL capabilities on all services', () => {
    const services = ['redis', 'postgres', 'backend', 'frontend'];
    for (const svc of services) {
      const block = getComposeServiceBlock(composeProd, svc);
      assert.ok(
        block.includes('cap_drop') && block.includes('ALL'),
        `${svc} must drop ALL capabilities in prod`
      );
    }
  });

  it('prod compose redis retains only the capabilities needed for its official entrypoint', () => {
    const redisBlock = getComposeServiceBlock(composeProd, 'redis');
    assert.ok(redisBlock.includes('CHOWN'), 'redis needs CHOWN for entrypoint ownership fixes on persisted data');
    assert.ok(redisBlock.includes('DAC_OVERRIDE'), 'redis needs DAC_OVERRIDE to traverse persisted appendonly data during bootstrap');
    assert.ok(redisBlock.includes('FOWNER'), 'redis needs FOWNER for volume ownership repair during bootstrap');
    assert.ok(redisBlock.includes('SETGID'), 'redis keeps SETGID for privilege drop');
    assert.ok(redisBlock.includes('SETUID'), 'redis keeps SETUID for privilege drop');
  });

  it('prod compose backend has read_only: true', () => {
    const backendBlock = composeProd.substring(
      composeProd.indexOf('  backend:'),
      composeProd.indexOf('  frontend:')
    );
    assert.ok(
      backendBlock.includes('read_only: true'),
      'backend must have read_only: true in prod'
    );
  });

  it('prod compose redis has read_only: true', () => {
    const redisBlock = composeProd.substring(
      composeProd.indexOf('  redis:'),
      composeProd.indexOf('  postgres:')
    );
    assert.ok(
      redisBlock.includes('read_only: true'),
      'redis must have read_only: true in prod'
    );
  });

  it('prod compose has resource limits on all services', () => {
    const services = ['redis', 'postgres', 'backend', 'frontend'];
    for (const svc of services) {
      const block = getComposeServiceBlock(composeProd, svc);
      assert.ok(
        block.includes('memory:') && block.includes('cpus:'),
        `${svc} must have memory and cpu limits in prod`
      );
    }
  });

  it('all compose files use depends_on with service_healthy', () => {
    for (const [name, src] of [['base', composeBase], ['dev', composeDev], ['prod', composeProd]]) {
      assert.ok(
        src.includes('condition: service_healthy'),
        `${name} compose must use condition: service_healthy for startup ordering`
      );
    }
  });
});

// =====================================================================
// Backend Dockerfile security
// =====================================================================

describe('Backend Dockerfile security', () => {
  it('uses alpine base image', () => {
    assert.ok(
      backendDockerfile.includes('node:22-alpine'),
      'Backend must use alpine base for minimal attack surface'
    );
  });

  it('uses npm ci --omit=dev in deps stage', () => {
    assert.ok(
      backendDockerfile.includes('npm ci --omit=dev'),
      'Must use npm ci --omit=dev to exclude devDependencies'
    );
  });

  it('sets NODE_ENV=production', () => {
    assert.ok(
      backendDockerfile.includes('NODE_ENV=production'),
      'Must set NODE_ENV=production'
    );
  });

  it('owns files as node user', () => {
    assert.ok(
      backendDockerfile.includes('chown -R node:node'),
      'Files must be owned by node user'
    );
  });
});

// =====================================================================
// Frontend Dockerfile security
// =====================================================================

describe('Frontend Dockerfile security', () => {
  it('uses nginx-unprivileged base', () => {
    assert.ok(
      frontendDockerfile.includes('nginxinc/nginx-unprivileged'),
      'Frontend production stage must use nginx-unprivileged'
    );
  });

  it('default stage only exposes port 8080', () => {
    // Extract just the EXPOSE line in the default stage
    const defaultStageStart = frontendDockerfile.indexOf('AS default');
    const tlsFromLine = frontendDockerfile.indexOf('FROM', defaultStageStart + 10);
    const defaultStage = frontendDockerfile.substring(defaultStageStart, tlsFromLine > 0 ? tlsFromLine : undefined);
    const exposeLines = defaultStage.split('\n').filter(l => l.startsWith('EXPOSE'));
    assert.ok(exposeLines.length === 1, 'Default stage should have exactly one EXPOSE directive');
    assert.ok(
      exposeLines[0].includes('8080') && !exposeLines[0].includes('8443'),
      'Default stage EXPOSE must only include 8080, not 8443'
    );
  });

  it('TLS stage exposes both 8080 and 8443', () => {
    const tlsStage = frontendDockerfile.substring(
      frontendDockerfile.indexOf('AS tls')
    );
    assert.ok(
      tlsStage.includes('8080') && tlsStage.includes('8443'),
      'TLS stage must expose both 8080 (redirect) and 8443 (HTTPS)'
    );
  });
});

// =====================================================================
// Nginx security headers
// =====================================================================

describe('Nginx security headers', () => {
  for (const [name, src] of [['HTTP', nginxHttp], ['TLS', nginxTls]]) {
    it(`${name} config has X-Frame-Options DENY`, () => {
      assert.ok(
        src.includes('X-Frame-Options') && src.includes('DENY'),
        `${name} config must set X-Frame-Options: DENY`
      );
    });

    it(`${name} config has X-Content-Type-Options nosniff`, () => {
      assert.ok(
        src.includes('X-Content-Type-Options') && src.includes('nosniff'),
        `${name} config must set X-Content-Type-Options: nosniff`
      );
    });

    it(`${name} config has Content-Security-Policy`, () => {
      assert.ok(
        src.includes('Content-Security-Policy'),
        `${name} config must set Content-Security-Policy`
      );
    });

    it(`${name} config has Referrer-Policy`, () => {
      assert.ok(
        src.includes('Referrer-Policy'),
        `${name} config must set Referrer-Policy`
      );
    });

    it(`${name} config has Permissions-Policy`, () => {
      assert.ok(
        src.includes('Permissions-Policy'),
        `${name} config must set Permissions-Policy`
      );
    });

    it(`${name} config disables server_tokens`, () => {
      assert.ok(
        src.includes('server_tokens off'),
        `${name} config must disable server_tokens`
      );
    });
  }

  it('TLS config has HSTS header', () => {
    assert.ok(
      nginxTls.includes('Strict-Transport-Security'),
      'TLS config must set HSTS header'
    );
    assert.ok(
      nginxTls.includes('includeSubDomains'),
      'HSTS must include subdomains'
    );
  });

  it('TLS config disables session tickets', () => {
    assert.ok(
      nginxTls.includes('ssl_session_tickets off'),
      'TLS config must disable session tickets for forward secrecy'
    );
  });

  it('TLS config enables OCSP stapling', () => {
    assert.ok(
      nginxTls.includes('ssl_stapling on'),
      'TLS config must enable OCSP stapling'
    );
  });
});

// =====================================================================
// Config validation integrity
// =====================================================================

describe('Config validation rules', () => {
  it('validates JWT_SECRET placeholder in production', () => {
    assert.ok(
      configSource.includes("jwtSecret === 'dev-jwt-secret-change-me'"),
      'config must reject default dev JWT secret in production'
    );
  });

  it('validates JWT_SECRET placeholder pattern', () => {
    assert.ok(
      configSource.includes('change.?me') && configSource.includes('jwtSecret'),
      'config must reject JWT_SECRET matching placeholder pattern'
    );
  });

  it('validates required OIDC fields', () => {
    assert.ok(
      configSource.includes('OIDC_CLIENT_ID is required') &&
      configSource.includes('OIDC_CLIENT_SECRET is required'),
      'config must validate OIDC_CLIENT_ID and OIDC_CLIENT_SECRET when issuer is set'
    );
  });

  it('validates auth cookie samesite values', () => {
    assert.ok(
      configSource.includes("'lax', 'strict', 'none'") ||
      configSource.includes("lax") && configSource.includes("strict") && configSource.includes("AUTH_COOKIE_SAMESITE"),
      'config must validate AUTH_COOKIE_SAMESITE against allowed values'
    );
  });

  it('has fail-fast on invalid config', () => {
    assert.ok(
      configSource.includes('process.exit(1)') || serverSource.includes("config.invalid"),
      'config validation must cause process exit on failure'
    );
  });
});

// =====================================================================
// Server boot sequence
// =====================================================================

describe('Server boot sequence', () => {
  it('validates config before starting listeners', () => {
    const configValidIdx = serverSource.indexOf('config.invalid');
    const listenIdx = serverSource.indexOf('server.listen');
    if (configValidIdx > 0 && listenIdx > 0) {
      assert.ok(
        configValidIdx < listenIdx,
        'config validation must occur before server.listen'
      );
    }
  });

  it('asserts redis readiness before migrations', () => {
    const redisIdx = serverSource.indexOf('assertProductionRedisReady()');
    const migrateIdx = serverSource.indexOf('runMigrations(', serverSource.indexOf('await runMigrations') > 0 ? serverSource.indexOf('await runMigrations') : 0);
    if (redisIdx > 0 && migrateIdx > 0) {
      assert.ok(
        redisIdx < migrateIdx,
        'Redis readiness check must occur before database migrations'
      );
    } else {
      // Just verify both patterns exist
      assert.ok(
        serverSource.includes('assertProductionRedisReady'),
        'server must assert production Redis readiness'
      );
    }
  });

  it('handles graceful shutdown signals', () => {
    assert.ok(
      serverSource.includes('SIGTERM') || serverSource.includes('SIGINT'),
      'server must handle shutdown signals'
    );
  });

  it('has health, readiness, and liveness endpoints', () => {
    assert.ok(
      serverSource.includes('registerSystemRoutes'),
      'server must register system routes (health/readiness/liveness)'
    );
  });
});

// =====================================================================
// Compose healthcheck alignment
// =====================================================================

describe('Compose healthcheck alignment', () => {
  it('all compose backend healthchecks use /v1/system/readiness', () => {
    for (const [name, src] of [['base', composeBase], ['dev', composeDev], ['prod', composeProd]]) {
      const backendIdx = src.indexOf('backend:');
      if (backendIdx < 0) continue;
      const backendBlock = src.substring(backendIdx, src.indexOf('\n\n', backendIdx + 1));
      assert.ok(
        backendBlock.includes('/v1/system/readiness') ||
        src.includes('http://127.0.0.1:8001/v1/system/readiness'),
        `${name} compose backend healthcheck must use /v1/system/readiness`
      );
    }
  });

  it('prod compose healthchecks have retries configured', () => {
    const retryCount = (composeProd.match(/retries:/g) || []).length;
    assert.ok(
      retryCount >= 3,
      `prod compose should have retries configured on services (found ${retryCount})`
    );
  });
});
