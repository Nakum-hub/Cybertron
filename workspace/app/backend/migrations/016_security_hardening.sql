-- Migration 016: Security hardening - policy approval workflow + data erasure support

-- Add policy approval fields for governance workflow (prevents AI-generated policies
-- from being stored without human review)
ALTER TABLE policies
  ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'draft',
  ADD COLUMN IF NOT EXISTS approved_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS rejected_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS rejected_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS rejection_reason TEXT;

-- Enforce valid status values
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'policies_status_check'
  ) THEN
    ALTER TABLE policies ADD CONSTRAINT policies_status_check
      CHECK (status IN ('draft', 'pending_approval', 'approved', 'rejected', 'archived'));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS policies_status_idx ON policies (tenant_slug, status);

-- Add user deletion support for GDPR right to erasure
-- This table tracks deletion requests and their completion
CREATE TABLE IF NOT EXISTS data_erasure_requests (
  id BIGSERIAL PRIMARY KEY,
  tenant_slug VARCHAR(64) NOT NULL,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  requested_by BIGINT NOT NULL REFERENCES users(id) ON DELETE SET NULL,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  status VARCHAR(20) NOT NULL DEFAULT 'pending',
  anonymized_tables TEXT[] NOT NULL DEFAULT '{}',
  CONSTRAINT erasure_status_check CHECK (status IN ('pending', 'in_progress', 'completed', 'failed'))
);

CREATE INDEX IF NOT EXISTS erasure_requests_tenant_idx
  ON data_erasure_requests (tenant_slug, status);

-- Add soft-delete and anonymization support to users table
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS anonymized_at TIMESTAMPTZ;
