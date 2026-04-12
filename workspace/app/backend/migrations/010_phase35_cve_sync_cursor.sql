-- Phase 3.5: Harden NVD sync cursor metadata and backoff discipline.

ALTER TABLE cve_sync_state
  ADD COLUMN IF NOT EXISTS last_success_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_attempt_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_error TEXT,
  ADD COLUMN IF NOT EXISTS failure_count INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS backoff_until TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

UPDATE cve_sync_state
SET
  last_success_at = COALESCE(last_success_at, synced_at),
  updated_at = NOW();

CREATE INDEX IF NOT EXISTS cve_sync_state_backoff_idx
  ON cve_sync_state (backoff_until);
