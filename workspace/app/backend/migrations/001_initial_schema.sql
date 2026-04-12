CREATE TABLE IF NOT EXISTS tenants (
  id BIGSERIAL PRIMARY KEY,
  slug VARCHAR(64) UNIQUE NOT NULL,
  name VARCHAR(160) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  tenant_slug VARCHAR(64) NOT NULL DEFAULT 'global',
  external_id VARCHAR(191),
  email VARCHAR(191) NOT NULL,
  display_name VARCHAR(191),
  role VARCHAR(32) NOT NULL DEFAULT 'viewer',
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (email)
);

CREATE INDEX IF NOT EXISTS users_tenant_slug_idx ON users (tenant_slug);
CREATE INDEX IF NOT EXISTS users_role_idx ON users (role);

CREATE TABLE IF NOT EXISTS incidents (
  id BIGSERIAL PRIMARY KEY,
  tenant_slug VARCHAR(64) NOT NULL DEFAULT 'global',
  title TEXT NOT NULL,
  severity VARCHAR(16) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
  status VARCHAR(16) NOT NULL CHECK (status IN ('open', 'investigating', 'resolved')),
  blocked BOOLEAN NOT NULL DEFAULT FALSE,
  source VARCHAR(64),
  detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  resolved_at TIMESTAMPTZ,
  response_time_minutes INTEGER,
  raw_event JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS incidents_tenant_detected_idx ON incidents (tenant_slug, detected_at DESC);
CREATE INDEX IF NOT EXISTS incidents_status_idx ON incidents (status);
CREATE INDEX IF NOT EXISTS incidents_severity_idx ON incidents (severity);

CREATE TABLE IF NOT EXISTS service_requests (
  id BIGSERIAL PRIMARY KEY,
  tenant_slug VARCHAR(64) NOT NULL DEFAULT 'global',
  requester_email VARCHAR(191) NOT NULL,
  category VARCHAR(64) NOT NULL,
  priority VARCHAR(16) NOT NULL DEFAULT 'medium',
  status VARCHAR(24) NOT NULL DEFAULT 'open',
  subject VARCHAR(255) NOT NULL,
  description TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS service_requests_tenant_status_idx
  ON service_requests (tenant_slug, status, created_at DESC);

CREATE TABLE IF NOT EXISTS reports (
  id BIGSERIAL PRIMARY KEY,
  tenant_slug VARCHAR(64) NOT NULL DEFAULT 'global',
  report_type VARCHAR(64) NOT NULL,
  report_date DATE NOT NULL,
  storage_path TEXT,
  checksum_sha256 VARCHAR(128),
  metadata JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS reports_tenant_type_date_idx
  ON reports (tenant_slug, report_type, report_date DESC);

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  tenant_slug VARCHAR(64) NOT NULL DEFAULT 'global',
  actor_id VARCHAR(191),
  actor_email VARCHAR(191),
  action VARCHAR(191) NOT NULL,
  target_type VARCHAR(64),
  target_id VARCHAR(191),
  ip_address VARCHAR(64),
  user_agent TEXT,
  trace_id VARCHAR(128),
  payload JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS audit_logs_tenant_action_idx
  ON audit_logs (tenant_slug, action, created_at DESC);

INSERT INTO tenants (slug, name)
VALUES ('global', 'Global Tenant')
ON CONFLICT (slug) DO NOTHING;