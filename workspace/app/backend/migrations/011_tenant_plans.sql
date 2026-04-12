-- Migration 011: Tenant Plans for License Tier Enforcement
-- Tracks which plan tier (free/pro/enterprise) each tenant is on.

CREATE TABLE IF NOT EXISTS tenant_plans (
  tenant_slug    VARCHAR(128) PRIMARY KEY,
  tier           VARCHAR(32)  NOT NULL DEFAULT 'free'
                   CHECK (tier IN ('free', 'pro', 'enterprise')),
  active_since   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  expires_at     TIMESTAMPTZ,
  created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tenant_plans_tier ON tenant_plans (tier);
CREATE INDEX IF NOT EXISTS idx_tenant_plans_expires ON tenant_plans (expires_at) WHERE expires_at IS NOT NULL;
