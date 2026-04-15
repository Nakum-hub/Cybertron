-- P2-4: API keys table
CREATE TABLE IF NOT EXISTS api_keys (
  id           BIGSERIAL PRIMARY KEY,
  tenant_slug  VARCHAR(64) NOT NULL,
  user_id      BIGINT REFERENCES users(id) ON DELETE CASCADE,
  name         VARCHAR(128) NOT NULL,
  key_hash     VARCHAR(128) NOT NULL UNIQUE,
  key_prefix   VARCHAR(12) NOT NULL,  -- First 8 chars, for display
  last_used_at TIMESTAMPTZ,
  expires_at   TIMESTAMPTZ,
  scopes       TEXT[] NOT NULL DEFAULT '{}',
  revoked      BOOLEAN NOT NULL DEFAULT false,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_user ON api_keys (tenant_slug, user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys (key_hash);
