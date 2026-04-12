#!/usr/bin/env node

const assert = require('node:assert/strict');

const { computeSha256Hex } = require('../src/utils/file-hash');
const { sniffMimeType } = require('../src/utils/mime-sniff');
const {
  parseAllowedMimeTypes,
  normalizeIdempotencyKey,
  enforceUploadPolicy,
} = require('../src/validators/upload-policy');

function pass(label) {
  process.stdout.write(`PASS: ${label}\n`);
}

function run() {
  const sha = computeSha256Hex(Buffer.from('cybertron'));
  assert.equal(sha.length, 64);
  pass('sha256 hash length');

  assert.equal(sniffMimeType(Buffer.from('%PDF-1.4\ncontent')), 'application/pdf');
  pass('mime sniff pdf');

  assert.equal(sniffMimeType(Buffer.from('{"ok":true}')), 'application/json');
  pass('mime sniff json');

  assert.equal(sniffMimeType(Buffer.from('col1,col2\na,b\n')), 'text/csv');
  pass('mime sniff csv');

  const allowed = parseAllowedMimeTypes('application/pdf,text/csv,application/json');
  assert.equal(allowed.has('application/pdf'), true);
  pass('allowed mime parser');

  const idempotencyKey = normalizeIdempotencyKey('global.report-001:retry');
  assert.equal(idempotencyKey, 'global.report-001:retry');
  pass('idempotency key normalization');

  let invalidKeyRejected = false;
  try {
    normalizeIdempotencyKey('bad key with spaces');
  } catch {
    invalidKeyRejected = true;
  }
  assert.equal(invalidKeyRejected, true);
  pass('invalid idempotency key rejected');

  const policy = enforceUploadPolicy({
    fileName: 'report.pdf',
    clientMimeType: 'application/pdf',
    sniffedMimeType: 'application/pdf',
    sizeBytes: 1024,
    maxBytes: 2048,
    allowedMimeTypes: allowed,
  });
  assert.equal(policy.mimeType, 'application/pdf');
  pass('upload policy accept valid pdf');

  let mismatchRejected = false;
  try {
    enforceUploadPolicy({
      fileName: 'report.pdf',
      clientMimeType: 'application/pdf',
      sniffedMimeType: 'application/json',
      sizeBytes: 100,
      maxBytes: 2048,
      allowedMimeTypes: allowed,
    });
  } catch {
    mismatchRejected = true;
  }
  assert.equal(mismatchRejected, true);
  pass('upload policy rejects mime mismatch');

  process.stdout.write('Report upload unit checks passed.\n');
}

run();
