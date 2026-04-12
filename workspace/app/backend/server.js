const { startServer } = require('./src/server');

startServer().catch(error => {
  const message = error instanceof Error ? error.message : 'Unknown startup error';
  // eslint-disable-next-line no-console
  console.error('[startup] backend failed to start:', message);
  process.exit(1);
});