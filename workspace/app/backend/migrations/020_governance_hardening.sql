-- Migration 020: Governance hardening
-- Adds review_due_at for staleness detection on compliance control status.

ALTER TABLE soc2_status
  ADD COLUMN IF NOT EXISTS review_due_at TIMESTAMPTZ;

ALTER TABLE compliance_control_status
  ADD COLUMN IF NOT EXISTS review_due_at TIMESTAMPTZ;

-- Partial index for stale controls (review overdue)
CREATE INDEX IF NOT EXISTS soc2_status_review_due_idx
  ON soc2_status (tenant_slug, review_due_at)
  WHERE review_due_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS compliance_control_status_review_due_idx
  ON compliance_control_status (tenant_slug, review_due_at)
  WHERE review_due_at IS NOT NULL;
