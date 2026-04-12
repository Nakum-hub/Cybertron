-- Migration 021: Risk management hardening
-- Adds risk treatment lifecycle, ownership, and review tracking to risk_findings.

ALTER TABLE risk_findings
  ADD COLUMN IF NOT EXISTS treatment_status TEXT DEFAULT 'open'
    CHECK (treatment_status IN ('open', 'mitigating', 'mitigated', 'accepted', 'transferred', 'avoided')),
  ADD COLUMN IF NOT EXISTS owner_user_id INT,
  ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS review_notes TEXT,
  ADD COLUMN IF NOT EXISTS residual_score NUMERIC(6,2);

-- Index for treatment status queries
CREATE INDEX IF NOT EXISTS risk_findings_treatment_status_idx
  ON risk_findings (tenant_slug, treatment_status)
  WHERE treatment_status != 'open';

-- Index for owner queries
CREATE INDEX IF NOT EXISTS risk_findings_owner_idx
  ON risk_findings (tenant_slug, owner_user_id)
  WHERE owner_user_id IS NOT NULL;
