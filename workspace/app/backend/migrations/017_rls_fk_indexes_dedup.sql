-- Migration 017: Row-Level Security, missing FK constraints, indexes, and dedup support
-- Part of remaining hardening phases from security audit.

-- ============================================================
-- PART 1: Missing Foreign Key Constraints on threat tables
-- ============================================================

-- tenant_slug FK for tables created in migration 013 (TEXT type)
-- These tables use TEXT for tenant_slug; tenants.slug is VARCHAR(64).
-- PostgreSQL allows FK across compatible types (TEXT ↔ VARCHAR).

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'iocs_tenant_slug_fk') THEN
    ALTER TABLE iocs ADD CONSTRAINT iocs_tenant_slug_fk
      FOREIGN KEY (tenant_slug) REFERENCES tenants(slug) ON DELETE CASCADE;
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'incident_iocs_tenant_slug_fk') THEN
    ALTER TABLE incident_iocs ADD CONSTRAINT incident_iocs_tenant_slug_fk
      FOREIGN KEY (tenant_slug) REFERENCES tenants(slug) ON DELETE CASCADE;
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'incident_timeline_tenant_slug_fk') THEN
    ALTER TABLE incident_timeline ADD CONSTRAINT incident_timeline_tenant_slug_fk
      FOREIGN KEY (tenant_slug) REFERENCES tenants(slug) ON DELETE CASCADE;
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'tenant_cve_views_tenant_slug_fk') THEN
    ALTER TABLE tenant_cve_views ADD CONSTRAINT tenant_cve_views_tenant_slug_fk
      FOREIGN KEY (tenant_slug) REFERENCES tenants(slug) ON DELETE CASCADE;
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'cve_summaries_tenant_slug_fk') THEN
    ALTER TABLE cve_summaries ADD CONSTRAINT cve_summaries_tenant_slug_fk
      FOREIGN KEY (tenant_slug) REFERENCES tenants(slug) ON DELETE CASCADE;
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'incident_mitre_mappings_tenant_slug_fk') THEN
    ALTER TABLE incident_mitre_mappings ADD CONSTRAINT incident_mitre_mappings_tenant_slug_fk
      FOREIGN KEY (tenant_slug) REFERENCES tenants(slug) ON DELETE CASCADE;
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'playbooks_tenant_slug_fk') THEN
    ALTER TABLE playbooks ADD CONSTRAINT playbooks_tenant_slug_fk
      FOREIGN KEY (tenant_slug) REFERENCES tenants(slug) ON DELETE CASCADE;
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'playbook_executions_tenant_slug_fk') THEN
    ALTER TABLE playbook_executions ADD CONSTRAINT playbook_executions_tenant_slug_fk
      FOREIGN KEY (tenant_slug) REFERENCES tenants(slug) ON DELETE CASCADE;
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'siem_alerts_tenant_slug_fk') THEN
    ALTER TABLE siem_alerts ADD CONSTRAINT siem_alerts_tenant_slug_fk
      FOREIGN KEY (tenant_slug) REFERENCES tenants(slug) ON DELETE CASCADE;
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'alert_correlation_rules_tenant_slug_fk') THEN
    ALTER TABLE alert_correlation_rules ADD CONSTRAINT alert_correlation_rules_tenant_slug_fk
      FOREIGN KEY (tenant_slug) REFERENCES tenants(slug) ON DELETE CASCADE;
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'threat_hunt_queries_tenant_slug_fk') THEN
    ALTER TABLE threat_hunt_queries ADD CONSTRAINT threat_hunt_queries_tenant_slug_fk
      FOREIGN KEY (tenant_slug) REFERENCES tenants(slug) ON DELETE CASCADE;
  END IF;
END $$;

-- Missing FK: incident_mitre_mappings.technique_id → mitre_attack_techniques.id
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'incident_mitre_mappings_technique_fk') THEN
    ALTER TABLE incident_mitre_mappings ADD CONSTRAINT incident_mitre_mappings_technique_fk
      FOREIGN KEY (technique_id) REFERENCES mitre_attack_techniques(id) ON DELETE CASCADE;
  END IF;
END $$;

-- Missing FK: created_by / started_by / completed_by → users(id)
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'incident_mitre_mappings_created_by_fk') THEN
    ALTER TABLE incident_mitre_mappings ADD CONSTRAINT incident_mitre_mappings_created_by_fk
      FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL;
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'playbooks_created_by_fk') THEN
    ALTER TABLE playbooks ADD CONSTRAINT playbooks_created_by_fk
      FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL;
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'playbook_executions_started_by_fk') THEN
    ALTER TABLE playbook_executions ADD CONSTRAINT playbook_executions_started_by_fk
      FOREIGN KEY (started_by) REFERENCES users(id) ON DELETE SET NULL;
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'playbook_step_results_completed_by_fk') THEN
    ALTER TABLE playbook_step_results ADD CONSTRAINT playbook_step_results_completed_by_fk
      FOREIGN KEY (completed_by) REFERENCES users(id) ON DELETE SET NULL;
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'alert_correlation_rules_created_by_fk') THEN
    ALTER TABLE alert_correlation_rules ADD CONSTRAINT alert_correlation_rules_created_by_fk
      FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL;
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'threat_hunt_queries_created_by_fk') THEN
    ALTER TABLE threat_hunt_queries ADD CONSTRAINT threat_hunt_queries_created_by_fk
      FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL;
  END IF;
END $$;

-- ============================================================
-- PART 2: Missing Indexes
-- ============================================================

-- playbook_step_results has NO indexes besides PK
CREATE INDEX IF NOT EXISTS playbook_step_results_execution_idx
  ON playbook_step_results (execution_id);
CREATE INDEX IF NOT EXISTS playbook_step_results_step_idx
  ON playbook_step_results (step_id);
CREATE INDEX IF NOT EXISTS playbook_step_results_status_idx
  ON playbook_step_results (execution_id, status);

-- alert_correlation_rules: index on is_active for filtered queries
CREATE INDEX IF NOT EXISTS alert_correlation_rules_active_idx
  ON alert_correlation_rules (tenant_slug, is_active) WHERE is_active = TRUE;

-- playbooks: index on is_active
CREATE INDEX IF NOT EXISTS playbooks_active_idx
  ON playbooks (tenant_slug, is_active) WHERE is_active = TRUE;

-- ============================================================
-- PART 3: SIEM alert deduplication support
-- ============================================================

-- Add unique constraint on (tenant_slug, source, alert_id) to prevent duplicate ingestion.
-- alert_id can be NULL for alerts without external IDs, so use a partial unique index.
CREATE UNIQUE INDEX IF NOT EXISTS siem_alerts_dedup_idx
  ON siem_alerts (tenant_slug, source, alert_id)
  WHERE alert_id IS NOT NULL;

-- ============================================================
-- PART 4: Row-Level Security Policies
-- ============================================================

-- Enable RLS on all tenant-scoped threat tables.
-- The app sets session variable 'app.current_tenant' per request.
-- Policies restrict SELECT/INSERT/UPDATE/DELETE to matching tenant_slug.

ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE iocs ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_iocs ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_timeline ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_cve_views ENABLE ROW LEVEL SECURITY;
ALTER TABLE cve_summaries ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_mitre_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE playbooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE playbook_executions ENABLE ROW LEVEL SECURITY;
ALTER TABLE siem_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_correlation_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_hunt_queries ENABLE ROW LEVEL SECURITY;

-- Create RLS policies for each table.
-- current_setting('app.current_tenant', true) returns NULL if not set,
-- which makes the policy deny all rows (safe default).

CREATE POLICY tenant_isolation_incidents ON incidents
  USING (tenant_slug = current_setting('app.current_tenant', true))
  WITH CHECK (tenant_slug = current_setting('app.current_tenant', true));

CREATE POLICY tenant_isolation_iocs ON iocs
  USING (tenant_slug = current_setting('app.current_tenant', true))
  WITH CHECK (tenant_slug = current_setting('app.current_tenant', true));

CREATE POLICY tenant_isolation_incident_iocs ON incident_iocs
  USING (tenant_slug = current_setting('app.current_tenant', true))
  WITH CHECK (tenant_slug = current_setting('app.current_tenant', true));

CREATE POLICY tenant_isolation_incident_timeline ON incident_timeline
  USING (tenant_slug = current_setting('app.current_tenant', true))
  WITH CHECK (tenant_slug = current_setting('app.current_tenant', true));

CREATE POLICY tenant_isolation_tenant_cve_views ON tenant_cve_views
  USING (tenant_slug = current_setting('app.current_tenant', true))
  WITH CHECK (tenant_slug = current_setting('app.current_tenant', true));

CREATE POLICY tenant_isolation_cve_summaries ON cve_summaries
  USING (tenant_slug = current_setting('app.current_tenant', true))
  WITH CHECK (tenant_slug = current_setting('app.current_tenant', true));

CREATE POLICY tenant_isolation_incident_mitre_mappings ON incident_mitre_mappings
  USING (tenant_slug = current_setting('app.current_tenant', true))
  WITH CHECK (tenant_slug = current_setting('app.current_tenant', true));

CREATE POLICY tenant_isolation_playbooks ON playbooks
  USING (tenant_slug = current_setting('app.current_tenant', true))
  WITH CHECK (tenant_slug = current_setting('app.current_tenant', true));

CREATE POLICY tenant_isolation_playbook_executions ON playbook_executions
  USING (tenant_slug = current_setting('app.current_tenant', true))
  WITH CHECK (tenant_slug = current_setting('app.current_tenant', true));

CREATE POLICY tenant_isolation_siem_alerts ON siem_alerts
  USING (tenant_slug = current_setting('app.current_tenant', true))
  WITH CHECK (tenant_slug = current_setting('app.current_tenant', true));

CREATE POLICY tenant_isolation_alert_correlation_rules ON alert_correlation_rules
  USING (tenant_slug = current_setting('app.current_tenant', true))
  WITH CHECK (tenant_slug = current_setting('app.current_tenant', true));

CREATE POLICY tenant_isolation_threat_hunt_queries ON threat_hunt_queries
  USING (tenant_slug = current_setting('app.current_tenant', true))
  WITH CHECK (tenant_slug = current_setting('app.current_tenant', true));

-- RLS bypass: The connection pool user (typically 'cybertron_app') needs to bypass
-- RLS for migrations and background tasks. Only the app role should have RLS enforced.
-- To enforce RLS on the pool owner, use: ALTER TABLE ... FORCE ROW LEVEL SECURITY;
-- We intentionally do NOT force RLS here -- the pool owner bypasses RLS,
-- and app-level isolation via parameterized tenant_slug queries remains the primary control.
-- RLS acts as defense-in-depth if a code path ever omits the tenant filter.
