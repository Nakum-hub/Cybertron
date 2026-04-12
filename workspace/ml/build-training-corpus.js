#!/usr/bin/env node

const fs = require('node:fs/promises');
const path = require('node:path');
const { validateReviewedRows } = require('./reviewed-corpus-utils');

const DEFAULT_BOOTSTRAP = path.resolve(__dirname, 'data', 'cybertron_bootstrap_sft.jsonl');
const DEFAULT_TEACHER = path.resolve(__dirname, 'data', 'cybertron_teacher_sft.jsonl');
const DEFAULT_OUTPUT = path.resolve(__dirname, 'data', 'cybertron_training_corpus.jsonl');
const DEFAULT_REVIEWED = path.resolve(__dirname, 'data', 'cybertron_reviewed_sft.jsonl');
const DEFAULT_OFFICIAL = path.resolve(__dirname, 'data', 'cybertron_official_realworld_sft.jsonl');

function parseArgs(argv) {
  const args = {
    bootstrap: DEFAULT_BOOTSTRAP,
    teacher: DEFAULT_TEACHER,
    output: DEFAULT_OUTPUT,
    reviewed: DEFAULT_REVIEWED,
    official: DEFAULT_OFFICIAL,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const current = argv[index];
    if (current === '--bootstrap' && argv[index + 1]) {
      args.bootstrap = path.resolve(argv[index + 1]);
      index += 1;
      continue;
    }
    if (current === '--teacher' && argv[index + 1]) {
      args.teacher = path.resolve(argv[index + 1]);
      index += 1;
      continue;
    }
    if (current === '--out' && argv[index + 1]) {
      args.output = path.resolve(argv[index + 1]);
      index += 1;
      continue;
    }
    if (current === '--reviewed' && argv[index + 1]) {
      args.reviewed = path.resolve(argv[index + 1]);
      index += 1;
      continue;
    }
    if (current === '--official' && argv[index + 1]) {
      args.official = path.resolve(argv[index + 1]);
      index += 1;
    }
  }

  return args;
}

async function readJsonl(filePath) {
  const raw = await fs.readFile(filePath, 'utf8');
  return raw
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(Boolean)
    .map(line => JSON.parse(line));
}

async function writeJsonl(filePath, rows) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  const content = rows.map(row => JSON.stringify(row)).join('\n') + '\n';
  await fs.writeFile(filePath, content, 'utf8');
}

function upsertRow(rows, rowById, row) {
  const existingIndex = rowById.get(row.id);
  if (existingIndex === undefined) {
    rowById.set(row.id, rows.length);
    rows.push(row);
    return;
  }
  rows[existingIndex] = row;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const bootstrapRows = await readJsonl(args.bootstrap);
  const teacherRows = await readJsonl(args.teacher).catch(() => []);
  const reviewedRows = await readJsonl(args.reviewed).catch(() => []);
  const officialRows = await readJsonl(args.official).catch(() => []);
  const reviewedReport = validateReviewedRows(reviewedRows);
  if (!reviewedReport.ok) {
    throw new Error(`Reviewed corpus is invalid:\n${reviewedReport.errors.join('\n')}`);
  }

  const teacherByParent = teacherRows.reduce((accumulator, row) => {
    const key = row.parentId || row.id;
    const existing = accumulator.get(key) || [];
    existing.push(row);
    accumulator.set(key, existing);
    return accumulator;
  }, new Map());

  const reviewedById = new Map(reviewedRows.map(row => [row.id, row]));
  const merged = [];
  const mergedById = new Map();
  for (const bootstrap of bootstrapRows) {
    upsertRow(merged, mergedById, reviewedById.get(bootstrap.id) || bootstrap);
    const teacherVariants = teacherByParent.get(bootstrap.id) || [];
    for (const teacher of teacherVariants) {
      upsertRow(merged, mergedById, teacher);
    }
  }

  for (const official of officialRows) {
    upsertRow(merged, mergedById, official);
  }

  for (const reviewed of reviewedRows) {
    upsertRow(merged, mergedById, reviewed);
  }

  await writeJsonl(args.output, merged);

  console.log(
    JSON.stringify(
      {
        ok: true,
        bootstrapRecords: bootstrapRows.length,
        teacherRecords: teacherRows.length,
        reviewedRecords: reviewedRows.length,
        officialRecords: officialRows.length,
        outputRecords: merged.length,
        output: args.output,
      },
      null,
      2
    )
  );
}

main().catch(error => {
  console.error(
    JSON.stringify(
      {
        ok: false,
        message: error.message,
      },
      null,
      2
    )
  );
  process.exitCode = 1;
});
