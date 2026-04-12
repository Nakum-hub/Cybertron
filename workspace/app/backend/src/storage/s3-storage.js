const crypto = require('node:crypto');
const path = require('node:path');

const { sanitizeTenant } = require('../validators');

function requireAwsSdk() {
  try {
    // Lazy load so local-only deployments do not require AWS dependencies.
    // eslint-disable-next-line global-require
    return require('@aws-sdk/client-s3');
  } catch {
    throw new Error(
      's3_sdk_missing_install_aws_sdk_client_s3'
    );
  }
}

function toBoolean(value, fallback = false) {
  const normalized = String(value ?? '').toLowerCase().trim();
  if (!normalized) {
    return fallback;
  }

  if (normalized === 'true') return true;
  if (normalized === 'false') return false;
  return fallback;
}

function buildStorageKey(tenant, fileName) {
  const now = new Date();
  const year = String(now.getUTCFullYear());
  const month = String(now.getUTCMonth() + 1).padStart(2, '0');
  const safeTenant = sanitizeTenant(tenant);
  return path.posix.join('reports', safeTenant, year, month, `${crypto.randomUUID()}-${fileName}`);
}

function createS3StorageAdapter(config) {
  const {
    S3Client,
    PutObjectCommand,
    GetObjectCommand,
    DeleteObjectCommand,
    HeadBucketCommand,
  } = requireAwsSdk();

  const endpoint = String(config.reportStorageS3Endpoint || '').trim() || undefined;
  const region = String(config.reportStorageS3Region || 'us-east-1').trim();
  const bucket = String(config.reportStorageS3Bucket || '').trim();
  const forcePathStyle = toBoolean(config.reportStorageS3ForcePathStyle, true);

  const client = new S3Client({
    region,
    endpoint,
    forcePathStyle,
    credentials:
      config.reportStorageS3AccessKeyId && config.reportStorageS3SecretAccessKey
        ? {
            accessKeyId: config.reportStorageS3AccessKeyId,
            secretAccessKey: config.reportStorageS3SecretAccessKey,
          }
        : undefined,
  });

  return {
    type: 's3',
    async healthCheck() {
      if (!bucket) {
        return {
          status: 'unavailable',
          details: {
            message: 'REPORT_STORAGE_S3_BUCKET is required for s3 storage driver.',
          },
        };
      }

      try {
        await client.send(new HeadBucketCommand({ Bucket: bucket }));
        return {
          status: 'healthy',
          details: {
            bucket,
            endpoint: endpoint || null,
            region,
          },
        };
      } catch (error) {
        return {
          status: 'unavailable',
          details: {
            bucket,
            endpoint: endpoint || null,
            region,
            message: error instanceof Error ? error.message : 's3 probe failed',
          },
        };
      }
    },
    async saveFile(payload) {
      if (!bucket) {
        throw new Error('s3_bucket_not_configured');
      }

      const key = buildStorageKey(payload.tenant, payload.fileName);
      await client.send(
        new PutObjectCommand({
          Bucket: bucket,
          Key: key,
          Body: payload.buffer,
          ContentType: payload.mimeType || 'application/octet-stream',
        })
      );

      return {
        storagePath: key,
        sizeBytes: payload.buffer.length,
      };
    },
    async getFileStream(payload) {
      if (!bucket) {
        throw new Error('s3_bucket_not_configured');
      }

      const key = String(payload.storagePath || '').trim();
      if (!key) {
        throw new Error('storage_path_missing');
      }

      const response = await client.send(
        new GetObjectCommand({
          Bucket: bucket,
          Key: key,
        })
      );

      if (!response.Body) {
        throw new Error('storage_file_not_found');
      }

      return {
        stream: response.Body,
        sizeBytes: Number(response.ContentLength || 0),
      };
    },
    async deleteFile(payload) {
      if (!bucket) {
        throw new Error('s3_bucket_not_configured');
      }

      const key = String(payload.storagePath || '').trim();
      if (!key) {
        return;
      }

      await client.send(
        new DeleteObjectCommand({
          Bucket: bucket,
          Key: key,
        })
      );
    },
  };
}

module.exports = {
  createS3StorageAdapter,
};
