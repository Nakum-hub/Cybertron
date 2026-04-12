const { Pool } = require('pg');
const fs = require('node:fs/promises');
const path = require('node:path');

let pool = null;

function useSsl(mode) {
  const normalized = String(mode || 'disable').toLowerCase().trim();
  if (normalized === 'verify-full' || normalized === 'verify-ca') {
    return { rejectUnauthorized: true };
  }
  if (normalized === 'require' || normalized === 'true') {
    // In require mode, connect via TLS but do not verify the server certificate.
    // Use DB_SSL_MODE=verify-full in production for full certificate validation.
    return { rejectUnauthorized: false };
  }

  return false;
}

function getPool(config) {
  if (!config.databaseUrl) {
    return null;
  }

  if (pool) {
    return pool;
  }

  pool = new Pool({
    connectionString: config.databaseUrl,
    max: config.dbPoolMax,
    idleTimeoutMillis: config.dbIdleTimeoutMs,
    connectionTimeoutMillis: config.dbConnectTimeoutMs,
    statement_timeout: config.dbStatementTimeoutMs,
    ssl: useSsl(config.dbSslMode),
  });

  pool.on('error', (err) => {
    console.error('[database] Idle client error:', err.message);
  });

  return pool;
}

async function query(config, text, values = []) {
  const activePool = getPool(config);
  if (!activePool) {
    return null;
  }

  return activePool.query(text, values);
}

// Execute a query with RLS tenant context set for the duration of the call.
// Sets the session variable 'app.current_tenant' so RLS policies can enforce
// tenant isolation as defense-in-depth alongside app-level parameterized filtering.
async function queryWithTenant(config, tenant, text, values = []) {
  const activePool = getPool(config);
  if (!activePool) {
    return null;
  }

  const client = await activePool.connect();
  try {
    await client.query('SET LOCAL app.current_tenant = $1', [String(tenant)]);
    return await client.query(text, values);
  } finally {
    // RESET clears session variables before returning connection to pool
    await client.query('RESET app.current_tenant').catch(() => {});
    client.release();
  }
}

async function withClient(config, fn) {
  const activePool = getPool(config);
  if (!activePool) {
    throw new Error('Database is not configured');
  }

  const client = await activePool.connect();
  try {
    return await fn(client);
  } finally {
    client.release();
  }
}

async function ensureMigrationTable(client) {
  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      id BIGSERIAL PRIMARY KEY,
      version TEXT UNIQUE NOT NULL,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

async function runMigrations(config, log = () => {}) {
  if (!config.databaseUrl) {
    return {
      enabled: false,
      applied: [],
      skipped: true,
    };
  }

  const migrationsDir = path.resolve(__dirname, '..', 'migrations');
  const files = (await fs.readdir(migrationsDir))
    .filter(name => name.endsWith('.sql'))
    .sort();

  const applied = [];

  await withClient(config, async client => {
    await client.query('BEGIN');

    try {
      await ensureMigrationTable(client);
      const existing = await client.query('SELECT version FROM schema_migrations');
      const done = new Set(existing.rows.map(row => row.version));

      for (const file of files) {
        if (done.has(file)) {
          continue;
        }

        const sql = await fs.readFile(path.join(migrationsDir, file), 'utf8');
        await client.query(sql);
        await client.query('INSERT INTO schema_migrations(version) VALUES($1)', [file]);
        applied.push(file);
      }

      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    }
  });

  if (applied.length) {
    log('info', 'database.migrations_applied', { files: applied });
  }

  return {
    enabled: true,
    applied,
    skipped: false,
  };
}

async function closeDatabase() {
  if (!pool) {
    return;
  }

  await pool.end();
  pool = null;
}

module.exports = {
  getPool,
  query,
  queryWithTenant,
  withClient,
  runMigrations,
  closeDatabase,
};
