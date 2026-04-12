#!/usr/bin/env node

const path = require('node:path');
const { readJsonl, validateReviewedRows } = require('./reviewed-corpus-utils');

const defaultInput = path.resolve(__dirname, 'data', 'cybertron_reviewed_sft.jsonl');

function parseArgs(argv) {
  const args = {
    input: defaultInput,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const current = String(argv[index] || '');
    if (current === '--input' && argv[index + 1]) {
      args.input = path.resolve(argv[index + 1]);
      index += 1;
    }
  }

  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const rows = await readJsonl(args.input);
  const report = validateReviewedRows(rows);

  process.stdout.write(
    `${JSON.stringify({ input: args.input, ...report }, null, 2)}\n`
  );

  if (!report.ok) {
    process.exitCode = 1;
  }
}

main().catch(error => {
  process.stderr.write(
    `${JSON.stringify({ ok: false, input: defaultInput, message: error.message }, null, 2)}\n`
  );
  process.exitCode = 1;
});
