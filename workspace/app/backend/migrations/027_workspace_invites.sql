-- P1-8: Workspace invites table
CREATE TABLE IF NOT EXISTS workspace_invites (
  id           BIGSERIAL PRIMARY KEY,
  tenant_slug  VARCHAR(64) NOT NULL,
  email        VARCHAR(191) NOT NULL,
  role         VARCHAR(32) NOT NULL DEFAULT 'executive_viewer',
  token_hash   VARCHAR(128) NOT NULL UNIQUE,
  invited_by   BIGINT REFERENCES users(id),
  expires_at   TIMESTAMPTZ NOT NULL,
  accepted_at  TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_workspace_invites_tenant_email ON workspace_invites (tenant_slug, email);
CREATE INDEX IF NOT EXISTS idx_workspace_invites_token_hash ON workspace_invites (token_hash);
