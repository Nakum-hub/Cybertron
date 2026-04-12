ALTER TABLE reports
  ADD COLUMN IF NOT EXISTS idempotency_key VARCHAR(128),
  ADD COLUMN IF NOT EXISTS storage_provider VARCHAR(32) NOT NULL DEFAULT 'local',
  ADD COLUMN IF NOT EXISTS uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS reports_tenant_checksum_idx
  ON reports (tenant_slug, checksum_sha256);

CREATE INDEX IF NOT EXISTS reports_tenant_uploaded_idx
  ON reports (tenant_slug, uploaded_at DESC);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_indexes
    WHERE schemaname = 'public'
      AND indexname = 'reports_tenant_idempotency_unique_idx'
  ) THEN
    CREATE UNIQUE INDEX reports_tenant_idempotency_unique_idx
      ON reports (tenant_slug, idempotency_key)
      WHERE idempotency_key IS NOT NULL;
  END IF;
END $$;
