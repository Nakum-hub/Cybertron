#!/usr/bin/env node

const { config } = require('../src/config');
const { runMigrations, closeDatabase } = require('../src/database');

async function run() {
  if (!config.databaseUrl) {
    throw new Error('DATABASE_URL is not configured.');
  }

  const result = await runMigrations(config, () => {});
  process.stdout.write(`Applied migrations: ${result.applied.length}\n`);
  result.applied.forEach(file => process.stdout.write(`- ${file}\n`));
}

run()
  .catch(error => {
    process.stderr.write(`${error instanceof Error ? error.message : 'Migration failed'}\n`);
    process.exitCode = 1;
  })
  .finally(async () => {
    try {
      await closeDatabase();
    } catch {
      // ignore close errors in CLI
    }
  });