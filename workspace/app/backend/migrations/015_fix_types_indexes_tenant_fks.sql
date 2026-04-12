-- Fix auth_access_token_revocations.user_id type mismatch (VARCHAR(191) → BIGINT)
-- Add missing indexes on frequently queried columns
-- Add tenant foreign key enforcement where feasible

-- HIGH-02: Fix user_id type mismatch in auth_access_token_revocations
ALTER TABLE auth_access_token_revocations
  ALTER COLUMN user_id TYPE BIGINT USING user_id::BIGINT;

-- Add FK constraint now that user_id is the correct type
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'auth_access_token_revocations_user_id_fk'
  ) THEN
    ALTER TABLE auth_access_token_revocations
      ADD CONSTRAINT auth_access_token_revocations_user_id_fk
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
  END IF;
END $$;

-- MED-10: Add missing indexes on frequently queried columns
CREATE INDEX IF NOT EXISTS playbooks_category_idx
  ON playbooks (category);

CREATE INDEX IF NOT EXISTS playbook_executions_tenant_status_idx
  ON playbook_executions (tenant_slug, status);

CREATE INDEX IF NOT EXISTS mitre_attack_techniques_tactic_idx
  ON mitre_attack_techniques (tactic);

CREATE INDEX IF NOT EXISTS auth_access_token_revocations_user_idx
  ON auth_access_token_revocations (user_id);

-- MED-11: Add tenant FK constraints to core tables
-- Only add FKs where the table exists and the column references tenants.slug

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'users_tenant_slug_fk'
  ) THEN
    ALTER TABLE users
      ADD CONSTRAINT users_tenant_slug_fk
      FOREIGN KEY (tenant_slug) REFERENCES tenants(slug) ON DELETE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'incidents_tenant_slug_fk'
  ) THEN
    ALTER TABLE incidents
      ADD CONSTRAINT incidents_tenant_slug_fk
      FOREIGN KEY (tenant_slug) REFERENCES tenants(slug) ON DELETE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'auth_refresh_tokens_tenant_slug_fk'
  ) THEN
    ALTER TABLE auth_refresh_tokens
      ADD CONSTRAINT auth_refresh_tokens_tenant_slug_fk
      FOREIGN KEY (tenant_slug) REFERENCES tenants(slug) ON DELETE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'auth_access_token_revocations_tenant_slug_fk'
  ) THEN
    ALTER TABLE auth_access_token_revocations
      ADD CONSTRAINT auth_access_token_revocations_tenant_slug_fk
      FOREIGN KEY (tenant_slug) REFERENCES tenants(slug) ON DELETE CASCADE;
  END IF;
END $$;
