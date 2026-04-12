const path = require('node:path');

const { ServiceError } = require('../auth-service');

const EXTENSION_MIME_ALLOWLIST = {
  '.pdf': 'application/pdf',
  '.csv': 'text/csv',
  '.json': 'application/json',
};

function normalizeMimeType(value) {
  const normalized = String(value || '').toLowerCase().trim();
  if (!normalized) {
    return '';
  }

  return normalized.split(';')[0].trim();
}

function sanitizeFileName(inputName) {
  const base = path.basename(String(inputName || '').trim());
  const noControlChars = base.replace(/[\u0000-\u001F\u007F]/g, '');
  const safe = noControlChars.replace(/[^a-zA-Z0-9._-]/g, '_');
  const trimmed = safe.replace(/^_+|_+$/g, '').slice(0, 200);
  return trimmed || 'upload.bin';
}

function parseAllowedMimeTypes(rawList) {
  const values = String(rawList || '')
    .split(',')
    .map(item => normalizeMimeType(item))
    .filter(Boolean);

  return new Set(values);
}

function normalizeIdempotencyKey(value) {
  const key = String(value || '').trim();
  if (!key) {
    return null;
  }

  if (!/^[a-zA-Z0-9._:-]{8,128}$/.test(key)) {
    throw new ServiceError(
      400,
      'invalid_idempotency_key',
      'Idempotency key must match [a-zA-Z0-9._:-] and be 8-128 characters.'
    );
  }

  return key;
}

function enforceUploadPolicy(payload) {
  const safeName = sanitizeFileName(payload.fileName);
  const extension = path.extname(safeName).toLowerCase();
  const sniffedMimeType = normalizeMimeType(payload.sniffedMimeType);
  const clientMimeType = normalizeMimeType(payload.clientMimeType);
  const allowed = payload.allowedMimeTypes instanceof Set
    ? payload.allowedMimeTypes
    : parseAllowedMimeTypes(payload.allowedMimeTypes || '');
  const maxBytes = Number(payload.maxBytes) || 0;
  const sizeBytes = Number(payload.sizeBytes) || 0;

  if (!sizeBytes || sizeBytes <= 0) {
    throw new ServiceError(400, 'invalid_upload_size', 'Uploaded file is empty.');
  }

  if (maxBytes > 0 && sizeBytes > maxBytes) {
    throw new ServiceError(413, 'upload_too_large', `File exceeds maximum size of ${maxBytes} bytes.`);
  }

  const extensionExpectedMime = EXTENSION_MIME_ALLOWLIST[extension];
  if (!extensionExpectedMime) {
    throw new ServiceError(
      415,
      'unsupported_file_extension',
      'File extension is not allowed. Allowed extensions: .pdf, .csv, .json.'
    );
  }

  const effectiveMimeType = sniffedMimeType || clientMimeType || extensionExpectedMime;
  if (!allowed.has(effectiveMimeType)) {
    throw new ServiceError(
      415,
      'unsupported_media_type',
      `Detected mime type ${effectiveMimeType} is not allowed.`
    );
  }

  if (sniffedMimeType && sniffedMimeType !== extensionExpectedMime) {
    throw new ServiceError(
      415,
      'mime_extension_mismatch',
      `File content type ${sniffedMimeType} does not match extension ${extension}.`
    );
  }

  if (clientMimeType && clientMimeType !== extensionExpectedMime) {
    throw new ServiceError(
      415,
      'client_mime_mismatch',
      `Client declared mime type ${clientMimeType} does not match extension ${extension}.`
    );
  }

  return {
    safeFileName: safeName,
    extension,
    mimeType: extensionExpectedMime,
  };
}

module.exports = {
  sanitizeFileName,
  parseAllowedMimeTypes,
  normalizeIdempotencyKey,
  enforceUploadPolicy,
};
