CREATE TABLE IF NOT EXISTS products (
  id BIGSERIAL PRIMARY KEY,
  product_id VARCHAR(64) NOT NULL UNIQUE,
  name VARCHAR(160) NOT NULL,
  description TEXT,
  module_path VARCHAR(191) NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS products_active_idx
  ON products (is_active, name);

CREATE TABLE IF NOT EXISTS tenant_products (
  id BIGSERIAL PRIMARY KEY,
  tenant_slug VARCHAR(64) NOT NULL,
  product_id VARCHAR(64) NOT NULL REFERENCES products(product_id) ON DELETE CASCADE,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_slug, product_id)
);

CREATE INDEX IF NOT EXISTS tenant_products_tenant_idx
  ON tenant_products (tenant_slug, enabled, updated_at DESC);

CREATE TABLE IF NOT EXISTS feature_flags (
  id BIGSERIAL PRIMARY KEY,
  tenant_slug VARCHAR(64) NOT NULL,
  flag_key VARCHAR(96) NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT FALSE,
  scope JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_slug, flag_key)
);

CREATE INDEX IF NOT EXISTS feature_flags_tenant_idx
  ON feature_flags (tenant_slug, enabled);

INSERT INTO products (product_id, name, description, module_path, is_active)
VALUES
  (
    'threat-command',
    'Threat Command',
    'Real-time threat intelligence and SOC orchestration.',
    '/modules/threat-intel',
    TRUE
  ),
  (
    'identity-guardian',
    'Identity Guardian',
    'Adaptive identity trust and access governance.',
    '/modules/core',
    TRUE
  ),
  (
    'resilience-hq',
    'Resilience HQ',
    'Executive reliability and security KPI cockpit.',
    '/modules/compliance',
    TRUE
  ),
  (
    'risk-copilot',
    'Risk Copilot',
    'AI-assisted risk analysis and prioritization.',
    '/modules/risk-copilot',
    FALSE
  )
ON CONFLICT (product_id) DO NOTHING;
