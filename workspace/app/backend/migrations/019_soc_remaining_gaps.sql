-- Migration 019: SOC Remaining Gaps
-- SOAR auto-trigger columns on playbooks, for correlation engine auto-fire.

ALTER TABLE playbooks
  ADD COLUMN IF NOT EXISTS auto_trigger BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS severity_trigger TEXT,
  ADD COLUMN IF NOT EXISTS category_trigger TEXT;

CREATE INDEX IF NOT EXISTS playbooks_auto_trigger_idx
  ON playbooks (tenant_slug)
  WHERE auto_trigger = TRUE AND is_active = TRUE;
