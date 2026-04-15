-- P1-10: Connector configuration table
CREATE TABLE IF NOT EXISTS connector_configs (
  id           BIGSERIAL PRIMARY KEY,
  tenant_slug  VARCHAR(64) NOT NULL,
  connector    VARCHAR(32) NOT NULL,  -- wazuh | misp | opencti | thehive
  api_url      TEXT NOT NULL,
  api_token    TEXT,                  -- stored encrypted (AES-256-GCM)
  enabled      BOOLEAN NOT NULL DEFAULT false,
  last_sync_at TIMESTAMPTZ,
  last_sync_status VARCHAR(16),       -- ok | error | never
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(tenant_slug, connector)
);
