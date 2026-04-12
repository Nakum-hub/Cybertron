#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const JS_BUDGET_KB = Number(process.env.JS_BUDGET_KB || 260);
const CSS_BUDGET_KB = Number(process.env.CSS_BUDGET_KB || 120);
const VENDOR_PATTERN = /vendor|polyfill/i;

function toKb(bytes) {
  return Number((bytes / 1024).toFixed(2));
}

async function run() {
  const projectRoot = path.resolve(__dirname, '..');
  const assetsDir = path.join(projectRoot, 'dist', 'assets');

  const entries = await fs.readdir(assetsDir, { withFileTypes: true });
  const files = entries.filter(entry => entry.isFile()).map(entry => entry.name);

  let jsMax = 0;
  let jsMaxName = '';
  let cssMax = 0;

  for (const name of files) {
    const stat = await fs.stat(path.join(assetsDir, name));
    if (name.endsWith('.js') && !VENDOR_PATTERN.test(name)) {
      if (toKb(stat.size) > jsMax) {
        jsMax = toKb(stat.size);
        jsMaxName = name;
      }
    }
    if (name.endsWith('.css')) {
      cssMax = Math.max(cssMax, toKb(stat.size));
    }
  }

  process.stdout.write(`Largest app JS asset: ${jsMax} KB [${jsMaxName}] (budget ${JS_BUDGET_KB} KB, vendor chunks excluded)\n`);
  process.stdout.write(`Largest CSS asset: ${cssMax} KB (budget ${CSS_BUDGET_KB} KB)\n`);

  if (jsMax > JS_BUDGET_KB || cssMax > CSS_BUDGET_KB) {
    throw new Error('Bundle budget exceeded.');
  }

  process.stdout.write('Bundle budget check passed.\n');
}

run().catch(error => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});