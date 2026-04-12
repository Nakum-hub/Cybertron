const crypto = require('node:crypto');

function computeSha256Hex(buffer) {
  if (!Buffer.isBuffer(buffer)) {
    throw new Error('sha256_input_must_be_buffer');
  }

  return crypto.createHash('sha256').update(buffer).digest('hex');
}

module.exports = {
  computeSha256Hex,
};
