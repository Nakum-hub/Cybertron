-- Phase 2 platform shell migration:
-- - role system expansion
-- - product registry enrichment
-- - feature flag cataloging
-- - billing usage stub tables

-- 1) Expand and normalize role model to canonical enterprise roles.
-- Drop the legacy role constraint before rewriting role values so fresh
-- databases can migrate from legacy -> canonical role names in one pass.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'users_role_check'
  ) THEN
    ALTER TABLE users DROP CONSTRAINT users_role_check;
  END IF;
END $$;

UPDATE users
SET role = CASE role
  WHEN 'client' THEN 'executive_viewer'
  WHEN 'viewer' THEN 'executive_viewer'
  WHEN 'analyst' THEN 'security_analyst'
  WHEN 'operator' THEN 'compliance_officer'
  WHEN 'admin' THEN 'tenant_admin'
  WHEN 'executive' THEN 'super_admin'
  ELSE role
END
WHERE role IN ('client', 'viewer', 'analyst', 'operator', 'admin', 'executive');

ALTER TABLE users
  ADD CONSTRAINT users_role_check
  CHECK (
    role IN (
      'executive_viewer',
      'compliance_officer',
      'security_analyst',
      'tenant_admin',
      'super_admin'
    )
  );

-- 2) Enrich product registry with product_key + role minimum + explicit enabled state.
ALTER TABLE products
  ADD COLUMN IF NOT EXISTS product_key VARCHAR(64),
  ADD COLUMN IF NOT EXISTS enabled BOOLEAN,
  ADD COLUMN IF NOT EXISTS role_min VARCHAR(64);

UPDATE products
SET
  product_key = COALESCE(NULLIF(product_key, ''), product_id),
  enabled = COALESCE(enabled, is_active, TRUE),
  role_min = COALESCE(NULLIF(role_min, ''), 'executive_viewer');

ALTER TABLE products
  ALTER COLUMN product_key SET NOT NULL,
  ALTER COLUMN enabled SET NOT NULL,
  ALTER COLUMN role_min SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS products_product_key_idx
  ON products (product_key);

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'products_role_min_check'
  ) THEN
    ALTER TABLE products DROP CONSTRAINT products_role_min_check;
  END IF;
END $$;

ALTER TABLE products
  ADD CONSTRAINT products_role_min_check
  CHECK (
    role_min IN (
      'executive_viewer',
      'compliance_officer',
      'security_analyst',
      'tenant_admin',
      'super_admin'
    )
  );

ALTER TABLE tenant_products
  ADD COLUMN IF NOT EXISTS role_min VARCHAR(64);

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'tenant_products_role_min_check'
  ) THEN
    ALTER TABLE tenant_products DROP CONSTRAINT tenant_products_role_min_check;
  END IF;
END $$;

ALTER TABLE tenant_products
  ADD CONSTRAINT tenant_products_role_min_check
  CHECK (
    role_min IS NULL OR
    role_min IN (
      'executive_viewer',
      'compliance_officer',
      'security_analyst',
      'tenant_admin',
      'super_admin'
    )
  );

-- 3) Replace legacy feature flag table shape with catalog + tenant + product mappings.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'feature_flags'
      AND column_name = 'tenant_slug'
  ) THEN
    ALTER TABLE feature_flags RENAME TO legacy_feature_flags;
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS feature_flags (
  id BIGSERIAL PRIMARY KEY,
  flag_key VARCHAR(96) NOT NULL UNIQUE,
  description TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tenant_feature_flags (
  id BIGSERIAL PRIMARY KEY,
  tenant_slug VARCHAR(64) NOT NULL,
  flag_key VARCHAR(96) NOT NULL REFERENCES feature_flags(flag_key) ON DELETE CASCADE,
  enabled BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_slug, flag_key)
);

CREATE INDEX IF NOT EXISTS tenant_feature_flags_tenant_idx
  ON tenant_feature_flags (tenant_slug, flag_key, enabled);

CREATE TABLE IF NOT EXISTS product_feature_flags (
  id BIGSERIAL PRIMARY KEY,
  product_key VARCHAR(64) NOT NULL REFERENCES products(product_key) ON DELETE CASCADE,
  flag_key VARCHAR(96) NOT NULL REFERENCES feature_flags(flag_key) ON DELETE CASCADE,
  enabled_by_default BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (product_key, flag_key)
);

CREATE INDEX IF NOT EXISTS product_feature_flags_product_idx
  ON product_feature_flags (product_key, flag_key);

-- 4) Billing and usage metering scaffolding.
CREATE TABLE IF NOT EXISTS usage_events (
  id BIGSERIAL PRIMARY KEY,
  tenant_slug VARCHAR(64) NOT NULL,
  user_id BIGINT,
  product_key VARCHAR(64) NOT NULL,
  action_key VARCHAR(128) NOT NULL,
  units INTEGER NOT NULL DEFAULT 1,
  meta_json JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (units > 0)
);

CREATE INDEX IF NOT EXISTS usage_events_tenant_created_idx
  ON usage_events (tenant_slug, created_at DESC);

CREATE INDEX IF NOT EXISTS usage_events_product_action_idx
  ON usage_events (product_key, action_key, created_at DESC);

CREATE TABLE IF NOT EXISTS credits (
  tenant_slug VARCHAR(64) PRIMARY KEY,
  balance_units BIGINT NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO credits (tenant_slug, balance_units)
SELECT slug, 0
FROM tenants
ON CONFLICT (tenant_slug) DO NOTHING;

-- 5) Align seeded products to module architecture.
UPDATE products
SET
  product_key = product_id,
  module_path = CASE product_id
    WHEN 'threat-command' THEN '/modules/threat-intel'
    WHEN 'identity-guardian' THEN '/modules/core'
    WHEN 'resilience-hq' THEN '/modules/compliance-engine'
    WHEN 'risk-copilot' THEN '/modules/risk-copilot'
    ELSE module_path
  END,
  role_min = CASE product_id
    WHEN 'threat-command' THEN 'executive_viewer'
    WHEN 'identity-guardian' THEN 'security_analyst'
    WHEN 'resilience-hq' THEN 'compliance_officer'
    WHEN 'risk-copilot' THEN 'security_analyst'
    ELSE role_min
  END,
  enabled = CASE product_id
    WHEN 'risk-copilot' THEN FALSE
    ELSE COALESCE(enabled, TRUE)
  END;

INSERT INTO feature_flags (flag_key, description)
VALUES
  ('platform_shell_v2', 'Enable Phase 2 platform shell experience'),
  ('risk_copilot_beta', 'Enable risk copilot module access'),
  ('billing_usage_stub', 'Enable billing usage metering APIs')
ON CONFLICT (flag_key) DO NOTHING;

INSERT INTO product_feature_flags (product_key, flag_key, enabled_by_default)
VALUES
  ('threat-command', 'platform_shell_v2', TRUE),
  ('identity-guardian', 'platform_shell_v2', TRUE),
  ('resilience-hq', 'platform_shell_v2', TRUE),
  ('risk-copilot', 'risk_copilot_beta', FALSE)
ON CONFLICT (product_key, flag_key) DO NOTHING;

INSERT INTO tenant_feature_flags (tenant_slug, flag_key, enabled)
SELECT slug, 'platform_shell_v2', TRUE
FROM tenants
ON CONFLICT (tenant_slug, flag_key) DO NOTHING;

INSERT INTO tenant_feature_flags (tenant_slug, flag_key, enabled)
SELECT slug, 'billing_usage_stub', TRUE
FROM tenants
ON CONFLICT (tenant_slug, flag_key) DO NOTHING;
