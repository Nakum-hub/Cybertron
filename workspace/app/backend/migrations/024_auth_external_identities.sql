CREATE TABLE IF NOT EXISTS auth_external_identities (
  id BIGSERIAL PRIMARY KEY,
  provider VARCHAR(32) NOT NULL,
  provider_subject VARCHAR(191) NOT NULL,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tenant_slug VARCHAR(64) NOT NULL REFERENCES tenants(slug) ON DELETE CASCADE,
  email VARCHAR(191) NOT NULL,
  email_verified BOOLEAN,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (provider, provider_subject)
);

CREATE INDEX IF NOT EXISTS auth_external_identities_user_idx
  ON auth_external_identities (user_id, tenant_slug, provider);

CREATE INDEX IF NOT EXISTS auth_external_identities_tenant_idx
  ON auth_external_identities (tenant_slug, provider, created_at DESC);
