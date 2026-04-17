# GitHub ML Backups

## Current release backup

- Release: `ml-backup-2026-04-17`
- URL: `https://github.com/Nakum-hub/Cybertron/releases/tag/ml-backup-2026-04-17`

## Included assets

- `cybertron-qwen25-1_5b-t4-lora-final.zip`
  - Final inference-ready T4 LoRA adapter bundle.
- `cybertron-qwen25-3b-lora-final.zip`
  - Final inference-ready 3B adapter bundle.
- `cybertron-qwen25-14b-lora-final.zip`
  - Final inference-ready 14B H100 adapter bundle.
- `ml-backup-manifest.json`
  - SHA-256 checksums and training metadata for the uploaded archives.

## Scope

These backups contain the final deployable adapter artifacts and tokenizer files only.
They intentionally exclude intermediate checkpoint folders and optimizer state files.

## Important note

This protects against local-disk loss, but it is not a true deletion-proof backup if the same GitHub repository is removed.
For stronger protection, mirror the same archives to a second repository, GitHub organization, object store, or model registry.
