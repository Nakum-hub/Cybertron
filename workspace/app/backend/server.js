const { startServer } = require('./src/server');

// P0-2: Global error handlers — prevent silent process crashes
process.on('unhandledRejection', (reason, promise) => {
  console.error('[fatal] Unhandled Promise Rejection:', reason);
  // Do NOT exit — log and continue, but alert via structured log
});

process.on('uncaughtException', (error) => {
  console.error('[fatal] Uncaught Exception:', error);
  process.exit(1); // This one IS fatal — Node state may be corrupted
});

startServer().catch(error => {
  const message = error instanceof Error ? error.message : 'Unknown startup error';
  // eslint-disable-next-line no-console
  console.error('[startup] backend failed to start:', message);
  process.exit(1);
});