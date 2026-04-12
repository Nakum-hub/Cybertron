const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { config, validateRuntimeConfig } = require('../src/config');

function buildConfig(overrides = {}) {
  return {
    ...config,
    ...overrides,
  };
}

describe('S3 production-validation config rules', () => {
  it('allows an http MinIO endpoint only during explicit local production validation', () => {
    const result = validateRuntimeConfig(
      buildConfig({
        environment: 'production',
        localProductionValidation: true,
        frontendOrigin: 'http://127.0.0.1:8088',
        allowedOrigins: ['http://127.0.0.1:8088'],
        authCookieSecure: false,
        reportStorageDriver: 's3',
        reportStorageS3Bucket: 'cybertron-reports',
        reportStorageS3Region: 'us-east-1',
        reportStorageS3Endpoint: 'http://minio:9000',
        databaseUrl: 'postgresql://cybertron:secret@postgres:5432/cybertron',
        redisUrl: 'redis://:secret@redis:6379',
        metricsRequireAuth: true,
        metricsAuthToken: 'real-metrics-token-1234567890',
        requireAuthForThreatEndpoints: true,
        requireAuthForPlatformEndpoints: true,
        enforceOriginValidation: true,
        authMode: 'jwt_hs256',
        jwtSecret: 'cybertron-local-validation-secret-12345678901234567890',
        allowInsecureDemoAuth: false,
        csrfEnabled: true,
      })
    );

    assert.deepEqual(result.errors, []);
  });

  it('still rejects insecure non-local S3 endpoints in production', () => {
    const result = validateRuntimeConfig(
      buildConfig({
        environment: 'production',
        localProductionValidation: false,
        frontendOrigin: 'https://cybertron.example.com',
        allowedOrigins: ['https://cybertron.example.com'],
        authCookieSecure: true,
        reportStorageDriver: 's3',
        reportStorageS3Bucket: 'cybertron-reports',
        reportStorageS3Region: 'us-east-1',
        reportStorageS3Endpoint: 'http://object-storage.example.internal',
        databaseUrl: 'postgresql://cybertron:secret@db.example.com:5432/cybertron',
        redisUrl: 'redis://:secret@redis.example.com:6379',
        metricsRequireAuth: true,
        metricsAuthToken: 'real-metrics-token-1234567890',
        requireAuthForThreatEndpoints: true,
        requireAuthForPlatformEndpoints: true,
        enforceOriginValidation: true,
        authMode: 'jwt_hs256',
        jwtSecret: 'cybertron-production-secret-12345678901234567890',
        allowInsecureDemoAuth: false,
        csrfEnabled: true,
      })
    );

    assert.ok(result.errors.includes('REPORT_STORAGE_S3_ENDPOINT must use https in production.'));
  });
});
