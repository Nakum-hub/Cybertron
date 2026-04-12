const fs = require('node:fs/promises');

async function readJsonl(filePath) {
  const raw = await fs.readFile(filePath, 'utf8');
  return raw
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(Boolean)
    .map(line => JSON.parse(line));
}

async function writeJsonl(filePath, rows) {
  await fs.mkdir(require('node:path').dirname(filePath), { recursive: true });
  const content = rows.map(row => JSON.stringify(row)).join('\n') + '\n';
  await fs.writeFile(filePath, content, 'utf8');
}

function validateReviewedRow(row, index) {
  const errors = [];
  const review = row?.review || {};

  if (!String(row?.id || '').trim()) {
    errors.push(`row ${index + 1}: id is required`);
  }
  if (!String(row?.taskType || '').trim()) {
    errors.push(`row ${index + 1}: taskType is required`);
  }
  if (!Array.isArray(row?.messages) || row.messages.length < 2) {
    errors.push(`row ${index + 1}: messages must contain at least two chat turns`);
  } else {
    for (const [messageIndex, message] of row.messages.entries()) {
      if (!['system', 'user', 'assistant'].includes(String(message?.role || '').trim())) {
        errors.push(`row ${index + 1}: messages[${messageIndex}] has an invalid role`);
      }
      if (!String(message?.content || '').trim()) {
        errors.push(`row ${index + 1}: messages[${messageIndex}] content is required`);
      }
    }
  }
  if (String(review.status || '').trim().toLowerCase() !== 'approved') {
    errors.push(`row ${index + 1}: review.status must be approved`);
  }
  if (!String(review.reviewer || '').trim()) {
    errors.push(`row ${index + 1}: review.reviewer is required`);
  }
  if (!String(review.reviewedAt || '').trim()) {
    errors.push(`row ${index + 1}: review.reviewedAt is required`);
  } else if (Number.isNaN(Date.parse(String(review.reviewedAt)))) {
    errors.push(`row ${index + 1}: review.reviewedAt must be a valid ISO timestamp`);
  }

  return errors;
}

function validateReviewedRows(rows) {
  const errors = [];
  const ids = new Set();
  const taskCounts = {};

  rows.forEach((row, index) => {
    errors.push(...validateReviewedRow(row, index));
    const id = String(row?.id || '').trim();
    if (id) {
      if (ids.has(id)) {
        errors.push(`row ${index + 1}: duplicate id "${id}"`);
      }
      ids.add(id);
    }

    const taskType = String(row?.taskType || 'unknown').trim() || 'unknown';
    taskCounts[taskType] = (taskCounts[taskType] || 0) + 1;
  });

  return {
    ok: errors.length === 0,
    errors,
    taskCounts,
    records: rows.length,
  };
}

module.exports = {
  readJsonl,
  writeJsonl,
  validateReviewedRows,
};
