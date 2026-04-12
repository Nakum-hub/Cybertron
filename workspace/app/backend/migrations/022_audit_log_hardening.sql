-- Migration 022: Audit log RLS + indexes for filtering
-- Adds Row Level Security to audit_logs table and indexes for common filter patterns.

-- Enable RLS on audit_logs
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_audit_logs ON audit_logs
  USING (tenant_slug = current_setting('app.current_tenant', true))
  WITH CHECK (tenant_slug = current_setting('app.current_tenant', true));

-- Index for action filtering
CREATE INDEX IF NOT EXISTS audit_logs_tenant_action_filter_idx
  ON audit_logs (tenant_slug, action, created_at DESC);

-- Index for actor filtering
CREATE INDEX IF NOT EXISTS audit_logs_tenant_actor_idx
  ON audit_logs (tenant_slug, actor_email, created_at DESC);
