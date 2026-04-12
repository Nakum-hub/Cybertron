#!/usr/bin/env node

const fs = require('node:fs/promises');
const path = require('node:path');

const BUNDLE_ROOT = path.resolve(__dirname, 'bundles', 'lightning-train');

const FILES = [
  {
    source: path.resolve(__dirname, 'train_cybertron_lora.py'),
    destination: path.join(BUNDLE_ROOT, 'train_cybertron_lora.py'),
  },
  {
    source: path.resolve(__dirname, 'requirements-colab.txt'),
    destination: path.join(BUNDLE_ROOT, 'requirements.txt'),
  },
  {
    source: path.resolve(__dirname, 'data', 'cybertron_training_corpus.jsonl'),
    destination: path.join(BUNDLE_ROOT, 'data', 'cybertron_training_corpus.jsonl'),
  },
  {
    source: path.resolve(__dirname, 'lightning', 'run_lightning_train.sh'),
    destination: path.join(BUNDLE_ROOT, 'run_lightning_train.sh'),
  },
  {
    source: path.resolve(__dirname, 'lightning', 'README.md'),
    destination: path.join(BUNDLE_ROOT, 'README.md'),
  },
];

async function ensureDir(filePath) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
}

async function copyFilePair(file) {
  await ensureDir(file.destination);
  await fs.copyFile(file.source, file.destination);
}

async function main() {
  await fs.rm(BUNDLE_ROOT, { recursive: true, force: true });

  for (const file of FILES) {
    await copyFilePair(file);
  }

  const manifest = {
    generatedAt: new Date().toISOString(),
    bundleRoot: BUNDLE_ROOT,
    files: FILES.map(file => ({
      source: file.source,
      destination: file.destination,
    })),
    notes: [
      'Upload this folder to Lightning AI Studio or copy it into a Git-connected Studio workspace.',
      'Run bash run_lightning_train.sh after the GPU machine is ready.',
      'Download the output adapter artifacts after training completes.',
    ],
  };

  await fs.writeFile(
    path.join(BUNDLE_ROOT, 'bundle_manifest.json'),
    JSON.stringify(manifest, null, 2) + '\n',
    'utf8'
  );

  console.log(
    JSON.stringify(
      {
        ok: true,
        bundleRoot: BUNDLE_ROOT,
        files: FILES.length + 1,
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
