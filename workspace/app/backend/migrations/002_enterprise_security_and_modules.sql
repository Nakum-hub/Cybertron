-- Strengthen existing user model for real authentication + lockout controls.
ALTER TABLE users
  DROP CONSTRAINT IF EXISTS users_email_key;

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS password_hash TEXT,
  ADD COLUMN IF NOT EXISTS failed_login_count INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS last_failed_login_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'users_tenant_email_unique'
  ) THEN
    ALTER TABLE users
      ADD CONSTRAINT users_tenant_email_unique UNIQUE (tenant_slug, email);
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'users_role_check'
  ) THEN
    ALTER TABLE users
      ADD CONSTRAINT users_role_check CHECK (role IN ('client', 'viewer', 'analyst', 'operator', 'admin', 'executive'));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS users_tenant_email_idx ON users (tenant_slug, email);
CREATE INDEX IF NOT EXISTS users_locked_until_idx ON users (locked_until);

-- Refresh token storage with rotation support.
CREATE TABLE IF NOT EXISTS auth_refresh_tokens (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tenant_slug VARCHAR(64) NOT NULL,
  token_hash VARCHAR(128) NOT NULL UNIQUE,
  issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  replaced_by_token_hash VARCHAR(128),
  created_ip VARCHAR(64),
  user_agent TEXT
);

CREATE INDEX IF NOT EXISTS auth_refresh_tokens_user_idx
  ON auth_refresh_tokens (user_id, tenant_slug, issued_at DESC);
CREATE INDEX IF NOT EXISTS auth_refresh_tokens_expiry_idx
  ON auth_refresh_tokens (expires_at);

-- Password reset request tokens.
CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tenant_slug VARCHAR(64) NOT NULL,
  token_hash VARCHAR(128) NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  created_ip VARCHAR(64),
  user_agent TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS password_reset_tokens_user_idx
  ON password_reset_tokens (user_id, tenant_slug, created_at DESC);
CREATE INDEX IF NOT EXISTS password_reset_tokens_expiry_idx
  ON password_reset_tokens (expires_at);

-- Service request comments and workflow notes.
CREATE TABLE IF NOT EXISTS service_request_comments (
  id BIGSERIAL PRIMARY KEY,
  request_id BIGINT NOT NULL REFERENCES service_requests(id) ON DELETE CASCADE,
  tenant_slug VARCHAR(64) NOT NULL,
  author_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
  author_email VARCHAR(191),
  body TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS service_request_comments_request_idx
  ON service_request_comments (request_id, created_at ASC);

-- IOC vault and correlation mapping.
CREATE TABLE IF NOT EXISTS iocs (
  id BIGSERIAL PRIMARY KEY,
  tenant_slug VARCHAR(64) NOT NULL,
  ioc_type VARCHAR(24) NOT NULL CHECK (ioc_type IN ('ip', 'domain', 'url', 'hash')),
  value TEXT NOT NULL,
  source VARCHAR(128),
  confidence SMALLINT NOT NULL DEFAULT 50 CHECK (confidence >= 0 AND confidence <= 100),
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ,
  tags JSONB,
  created_by_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_slug, ioc_type, value)
);

CREATE INDEX IF NOT EXISTS iocs_tenant_type_idx ON iocs (tenant_slug, ioc_type);
CREATE INDEX IF NOT EXISTS iocs_tenant_last_seen_idx ON iocs (tenant_slug, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS incident_iocs (
  id BIGSERIAL PRIMARY KEY,
  tenant_slug VARCHAR(64) NOT NULL,
  incident_id BIGINT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  ioc_id BIGINT NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_slug, incident_id, ioc_id)
);

CREATE INDEX IF NOT EXISTS incident_iocs_incident_idx
  ON incident_iocs (incident_id, created_at DESC);

CREATE TABLE IF NOT EXISTS incident_timeline (
  id BIGSERIAL PRIMARY KEY,
  tenant_slug VARCHAR(64) NOT NULL,
  incident_id BIGINT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  event_type VARCHAR(48) NOT NULL,
  message TEXT NOT NULL,
  actor_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS incident_timeline_incident_idx
  ON incident_timeline (incident_id, created_at ASC);

-- Report storage metadata enhancement + download audits.
ALTER TABLE reports
  ADD COLUMN IF NOT EXISTS file_name VARCHAR(255),
  ADD COLUMN IF NOT EXISTS mime_type VARCHAR(128),
  ADD COLUMN IF NOT EXISTS size_bytes BIGINT;

CREATE TABLE IF NOT EXISTS report_download_logs (
  id BIGSERIAL PRIMARY KEY,
  tenant_slug VARCHAR(64) NOT NULL,
  report_id BIGINT NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
  actor_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
  actor_email VARCHAR(191),
  ip_address VARCHAR(64),
  user_agent TEXT,
  trace_id VARCHAR(128),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS report_download_logs_report_idx
  ON report_download_logs (report_id, created_at DESC);

-- Optional connector sync event tracking for truthful status reporting.
CREATE TABLE IF NOT EXISTS connector_sync_events (
  id BIGSERIAL PRIMARY KEY,
  connector VARCHAR(32) NOT NULL,
  status VARCHAR(24) NOT NULL,
  message TEXT,
  checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS connector_sync_events_connector_idx
  ON connector_sync_events (connector, checked_at DESC);

-- Seed a tenant-scoped admin user for local development if missing.
INSERT INTO users (tenant_slug, email, display_name, role, is_active)
VALUES ('global', 'admin@cybertron.local', 'Cybertron Admin', 'admin', TRUE)
ON CONFLICT (tenant_slug, email) DO NOTHING;
