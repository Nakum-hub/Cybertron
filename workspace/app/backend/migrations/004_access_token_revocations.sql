CREATE TABLE IF NOT EXISTS auth_access_token_revocations (
  id BIGSERIAL PRIMARY KEY,
  tenant_slug VARCHAR(64) NOT NULL,
  user_id VARCHAR(191),
  token_hash CHAR(64) NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ip_address VARCHAR(64),
  user_agent TEXT,
  trace_id VARCHAR(128),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS auth_access_token_revocations_tenant_idx
  ON auth_access_token_revocations (tenant_slug, revoked_at DESC);

CREATE INDEX IF NOT EXISTS auth_access_token_revocations_expires_idx
  ON auth_access_token_revocations (expires_at);
