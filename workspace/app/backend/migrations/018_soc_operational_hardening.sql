-- Migration 018: SOC Operational Hardening
-- Adds alert lifecycle, incident assignment, incident state machine support.

-- ============================================================
-- PART 1: SIEM Alert Lifecycle
-- Add status field, assigned_to, acknowledged_at, acknowledged_by
-- ============================================================

ALTER TABLE siem_alerts
  ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'new'
    CHECK (status IN ('new', 'acknowledged', 'in_triage', 'escalated', 'resolved', 'dismissed')),
  ADD COLUMN IF NOT EXISTS assigned_to BIGINT REFERENCES users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS acknowledged_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS notes TEXT;

CREATE INDEX IF NOT EXISTS siem_alerts_status_idx
  ON siem_alerts (tenant_slug, status);

CREATE INDEX IF NOT EXISTS siem_alerts_assigned_idx
  ON siem_alerts (tenant_slug, assigned_to)
  WHERE assigned_to IS NOT NULL;

-- ============================================================
-- PART 2: Incident Assignment + State Machine
-- Add assigned_to, closed status, priority
-- ============================================================

ALTER TABLE incidents
  ADD COLUMN IF NOT EXISTS assigned_to BIGINT REFERENCES users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS assigned_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS priority TEXT NOT NULL DEFAULT 'medium'
    CHECK (priority IN ('critical', 'high', 'medium', 'low'));

-- Expand status CHECK to include 'closed' as terminal state and preserve existing data.
-- Drop old constraint if exists, add new one.
DO $$ BEGIN
  -- Check if the old constraint exists and if it lacks 'closed'
  IF EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'incidents_status_check'
      AND contype = 'c'
  ) THEN
    ALTER TABLE incidents DROP CONSTRAINT incidents_status_check;
  END IF;
END $$;

ALTER TABLE incidents ADD CONSTRAINT incidents_status_check
  CHECK (status IN ('open', 'investigating', 'resolved', 'closed'));

CREATE INDEX IF NOT EXISTS incidents_assigned_idx
  ON incidents (tenant_slug, assigned_to)
  WHERE assigned_to IS NOT NULL;

CREATE INDEX IF NOT EXISTS incidents_status_idx
  ON incidents (tenant_slug, status);

CREATE INDEX IF NOT EXISTS incidents_priority_idx
  ON incidents (tenant_slug, priority);

-- ============================================================
-- PART 3: Alert-to-Incident escalation tracking
-- ============================================================

-- Add escalated_from_alert_id to incidents for direct escalation tracking
ALTER TABLE incidents
  ADD COLUMN IF NOT EXISTS escalated_from_alert_id BIGINT REFERENCES siem_alerts(id) ON DELETE SET NULL;
