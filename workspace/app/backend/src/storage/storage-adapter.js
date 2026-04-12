const { createLocalStorageAdapter } = require('./local-storage');
const { createS3StorageAdapter } = require('./s3-storage');

function createStorageAdapter(config, log = () => {}) {
  const driver = String(config.reportStorageDriver || 'local').toLowerCase().trim();

  if (driver === 's3') {
    try {
      return createS3StorageAdapter(config);
    } catch (error) {
      log('error', 'storage.adapter_init_failed', {
        driver: 's3',
        error: error instanceof Error ? error.message : 'unknown adapter initialization error',
      });
      throw error;
    }
  }

  return createLocalStorageAdapter(config);
}

module.exports = {
  createStorageAdapter,
};
