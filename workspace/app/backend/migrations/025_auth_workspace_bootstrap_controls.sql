CREATE TABLE IF NOT EXISTS auth_workspace_bootstrap_events (
  id BIGSERIAL PRIMARY KEY,
  tenant_slug TEXT NOT NULL REFERENCES tenants(slug) ON DELETE CASCADE,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  bootstrap_mode TEXT NOT NULL,
  provider TEXT NULL,
  fingerprint_hash TEXT NULL,
  network_hash TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_workspace_bootstrap_created_at
  ON auth_workspace_bootstrap_events(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_auth_workspace_bootstrap_fingerprint
  ON auth_workspace_bootstrap_events(fingerprint_hash, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_auth_workspace_bootstrap_network
  ON auth_workspace_bootstrap_events(network_hash, created_at DESC);
