/**
 * P1-10: Connector Configuration Service
 *
 * Manages connector configs for Wazuh, MISP, OpenCTI, TheHive.
 * API tokens are encrypted at rest using AES-256-GCM.
 */

const crypto = require('node:crypto');
const { ServiceError } = require('./auth-service');
const { query } = require('./database');

const VALID_CONNECTORS = new Set(['wazuh', 'misp', 'opencti', 'thehive']);

function getEncryptionKey(config) {
  const keyHex = String(config.connectorSecretsKey || '').trim();
  if (!keyHex || keyHex.length < 32) {
    return null;
  }
  return Buffer.from(keyHex.slice(0, 64), 'hex');
}

function encrypt(plaintext, key) {
  if (!key) return plaintext; // Fallback: store unencrypted if no key
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  // Format: iv:authTag:encrypted (all hex)
  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
}

function decrypt(ciphertext, key) {
  if (!key) return ciphertext; // No key = stored as plaintext
  const parts = ciphertext.split(':');
  if (parts.length !== 3) return ciphertext; // Not encrypted format
  try {
    const iv = Buffer.from(parts[0], 'hex');
    const authTag = Buffer.from(parts[1], 'hex');
    const encrypted = Buffer.from(parts[2], 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
  } catch {
    return ciphertext; // Decryption failed — possibly stored before encryption was enabled
  }
}

function maskToken(token) {
  if (!token) return '';
  if (token.length <= 8) return '****';
  return token.slice(0, 4) + '****' + token.slice(-4);
}

async function listConnectorConfigs(config, tenant) {
  const result = await query(
    config,
    `SELECT id, connector, api_url, api_token, enabled, last_sync_at, last_sync_status, created_at, updated_at
     FROM connector_configs
     WHERE tenant_slug = $1
     ORDER BY connector ASC`,
    [tenant]
  );

  const key = getEncryptionKey(config);
  return (result?.rows || []).map(row => ({
    id: String(row.id),
    connector: row.connector,
    apiUrl: row.api_url,
    apiTokenMasked: maskToken(row.api_token ? decrypt(row.api_token, key) : ''),
    enabled: row.enabled,
    lastSyncAt: row.last_sync_at,
    lastSyncStatus: row.last_sync_status || 'never',
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }));
}

async function upsertConnectorConfig(config, tenant, { connector, apiUrl, apiToken, enabled }) {
  if (!connector || !VALID_CONNECTORS.has(connector)) {
    throw new ServiceError(400, 'invalid_connector', `Connector must be one of: ${[...VALID_CONNECTORS].join(', ')}`);
  }
  if (!apiUrl) {
    throw new ServiceError(400, 'api_url_required', 'API URL is required.');
  }

  const key = getEncryptionKey(config);
  const encryptedToken = apiToken ? encrypt(apiToken, key) : null;

  const result = await query(
    config,
    `INSERT INTO connector_configs (tenant_slug, connector, api_url, api_token, enabled, updated_at)
     VALUES ($1, $2, $3, $4, $5, NOW())
     ON CONFLICT (tenant_slug, connector) DO UPDATE SET
       api_url = EXCLUDED.api_url,
       api_token = COALESCE(EXCLUDED.api_token, connector_configs.api_token),
       enabled = EXCLUDED.enabled,
       updated_at = NOW()
     RETURNING id, connector, api_url, enabled, last_sync_at, last_sync_status, updated_at`,
    [tenant, connector, apiUrl, encryptedToken, enabled !== false]
  );

  const row = result?.rows?.[0];
  return {
    id: String(row?.id),
    connector: row?.connector,
    apiUrl: row?.api_url,
    enabled: row?.enabled,
    lastSyncAt: row?.last_sync_at,
    lastSyncStatus: row?.last_sync_status || 'never',
    updatedAt: row?.updated_at,
  };
}

async function deleteConnectorConfig(config, tenant, connector) {
  if (!connector || !VALID_CONNECTORS.has(connector)) {
    throw new ServiceError(400, 'invalid_connector', 'Invalid connector name.');
  }

  const result = await query(
    config,
    `DELETE FROM connector_configs WHERE tenant_slug = $1 AND connector = $2 RETURNING id`,
    [tenant, connector]
  );

  if (!result?.rows?.length) {
    throw new ServiceError(404, 'connector_not_found', 'Connector configuration not found.');
  }

  return { deleted: true };
}

async function testConnectorConnection(config, tenant, connector) {
  if (!connector || !VALID_CONNECTORS.has(connector)) {
    throw new ServiceError(400, 'invalid_connector', 'Invalid connector name.');
  }

  const result = await query(
    config,
    `SELECT api_url, api_token FROM connector_configs WHERE tenant_slug = $1 AND connector = $2`,
    [tenant, connector]
  );

  const row = result?.rows?.[0];
  if (!row) {
    throw new ServiceError(404, 'connector_not_configured', 'Connector is not configured.');
  }

  const key = getEncryptionKey(config);
  const apiUrl = row.api_url;
  const apiToken = row.api_token ? decrypt(row.api_token, key) : '';

  const startedAt = Date.now();
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), config.connectorTimeoutMs || 6000);

    const response = await fetch(apiUrl, {
      method: 'GET',
      headers: apiToken ? { Authorization: `Bearer ${apiToken}` } : {},
      signal: controller.signal,
    });
    clearTimeout(timeout);

    const latencyMs = Date.now() - startedAt;

    // Update sync status
    const status = response.ok ? 'ok' : 'error';
    await query(
      config,
      `UPDATE connector_configs SET last_sync_at = NOW(), last_sync_status = $1 WHERE tenant_slug = $2 AND connector = $3`,
      [status, tenant, connector]
    );

    return {
      connector,
      reachable: response.ok,
      statusCode: response.status,
      latencyMs,
    };
  } catch (error) {
    await query(
      config,
      `UPDATE connector_configs SET last_sync_at = NOW(), last_sync_status = 'error' WHERE tenant_slug = $1 AND connector = $2`,
      [tenant, connector]
    );

    return {
      connector,
      reachable: false,
      statusCode: null,
      latencyMs: Date.now() - startedAt,
      error: error.name === 'AbortError' ? 'Connection timed out' : (error.message || 'Connection failed'),
    };
  }
}

module.exports = {
  listConnectorConfigs,
  upsertConnectorConfig,
  deleteConnectorConfig,
  testConnectorConnection,
};
