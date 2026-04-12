function isLikelyText(buffer) {
  if (!Buffer.isBuffer(buffer) || !buffer.length) {
    return false;
  }

  const sample = buffer.subarray(0, Math.min(buffer.length, 4096));
  let suspicious = 0;
  for (const byte of sample) {
    const isControl = byte < 0x09 || (byte > 0x0d && byte < 0x20);
    if (isControl) {
      suspicious += 1;
    }
  }

  return suspicious / sample.length < 0.05;
}

function sniffMimeType(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    return 'application/octet-stream';
  }

  if (buffer.length >= 5 && buffer.subarray(0, 5).toString('ascii') === '%PDF-') {
    return 'application/pdf';
  }

  if (!isLikelyText(buffer)) {
    return 'application/octet-stream';
  }

  const textSample = buffer.subarray(0, Math.min(buffer.length, 64 * 1024)).toString('utf8').trim();
  if (!textSample) {
    return 'application/octet-stream';
  }

  if (textSample.startsWith('{') || textSample.startsWith('[')) {
    try {
      JSON.parse(textSample);
      return 'application/json';
    } catch {
      // keep evaluating as possible CSV/plain text.
    }
  }

  const hasLineBreak = textSample.includes('\n');
  const hasComma = textSample.includes(',');
  if (hasLineBreak && hasComma) {
    return 'text/csv';
  }

  return 'text/plain';
}

module.exports = {
  sniffMimeType,
};
