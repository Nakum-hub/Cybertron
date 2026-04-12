const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

const { sanitizeTenant } = require('../validators');

function safeRelativePath(rootPath, relativePath) {
  const normalizedRoot = path.resolve(rootPath);
  const candidate = path.resolve(normalizedRoot, relativePath);
  const rootWithSep = normalizedRoot.endsWith(path.sep) ? normalizedRoot : `${normalizedRoot}${path.sep}`;

  if (!candidate.startsWith(rootWithSep)) {
    throw new Error('storage_path_outside_root');
  }

  return candidate;
}

function buildRelativeStoragePath(tenant, fileName) {
  const now = new Date();
  const year = String(now.getUTCFullYear());
  const month = String(now.getUTCMonth() + 1).padStart(2, '0');
  const safeTenant = sanitizeTenant(tenant);
  const randomPart = crypto.randomUUID();
  return path.posix.join(safeTenant, year, month, `${randomPart}-${fileName}`);
}

function createLocalStorageAdapter(config) {
  const rootPath = path.resolve(config.reportStorageLocalPath);

  async function ensureRoot() {
    await fsp.mkdir(rootPath, { recursive: true });
  }

  return {
    type: 'local',
    async healthCheck() {
      try {
        await ensureRoot();
        await fsp.access(rootPath, fs.constants.R_OK | fs.constants.W_OK);
        return {
          status: 'healthy',
          details: { rootPath },
        };
      } catch (error) {
        return {
          status: 'unavailable',
          details: {
            rootPath,
            message: error instanceof Error ? error.message : 'local storage not writable',
          },
        };
      }
    },
    async saveFile(payload) {
      await ensureRoot();
      const relativePath = buildRelativeStoragePath(payload.tenant, payload.fileName);
      const absolutePath = safeRelativePath(rootPath, relativePath);
      await fsp.mkdir(path.dirname(absolutePath), { recursive: true });
      await fsp.writeFile(absolutePath, payload.buffer, { flag: 'wx' });

      return {
        storagePath: relativePath,
        sizeBytes: payload.buffer.length,
      };
    },
    async getFileStream(payload) {
      const relativePath = String(payload.storagePath || '').replace(/\\/g, '/');
      if (!relativePath) {
        throw new Error('storage_path_missing');
      }

      const absolutePath = safeRelativePath(rootPath, relativePath);
      const stat = await fsp.stat(absolutePath);
      if (!stat.isFile()) {
        throw new Error('storage_file_not_found');
      }

      return {
        stream: fs.createReadStream(absolutePath),
        sizeBytes: stat.size,
      };
    },
    async deleteFile(payload) {
      const relativePath = String(payload.storagePath || '').replace(/\\/g, '/');
      if (!relativePath) {
        return;
      }

      const absolutePath = safeRelativePath(rootPath, relativePath);
      try {
        await fsp.unlink(absolutePath);
      } catch (error) {
        if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') {
          return;
        }
        throw error;
      }
    },
  };
}

module.exports = {
  createLocalStorageAdapter,
};
