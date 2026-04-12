-- Phase 3 migration: Three real AI products (risk, compliance, threat intel)
-- All data is tenant-scoped and auditable.

-- Product A: AI Cyber Risk Copilot
CREATE TABLE IF NOT EXISTS aws_ingest_jobs (
  id BIGSERIAL PRIMARY KEY,
  tenant_slug VARCHAR(64) NOT NULL,
  user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
  status VARCHAR(24) NOT NULL CHECK (status IN ('queued', 'processing', 'completed', 'failed')),
  meta_json JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS aws_ingest_jobs_tenant_created_idx
  ON aws_ingest_jobs (tenant_slug, created_at DESC);

CREATE TABLE IF NOT EXISTS risk_findings (
  id BIGSERIAL PRIMARY KEY,
  tenant_slug VARCHAR(64) NOT NULL,
  asset_id VARCHAR(191),
  category VARCHAR(64) NOT NULL,
  severity VARCHAR(16) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
  score NUMERIC(6,2) NOT NULL CHECK (score >= 0 AND score <= 100),
  details_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS risk_findings_tenant_created_idx
  ON risk_findings (tenant_slug, created_at DESC);

CREATE INDEX IF NOT EXISTS risk_findings_tenant_severity_idx
  ON risk_findings (tenant_slug, severity, created_at DESC);

CREATE TABLE IF NOT EXISTS risk_reports (
  id BIGSERIAL PRIMARY KEY,
  tenant_slug VARCHAR(64) NOT NULL,
  created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  pdf_storage_path TEXT NOT NULL,
  summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS risk_reports_tenant_created_idx
  ON risk_reports (tenant_slug, created_at DESC);

-- Product B: AI Startup Compliance Engine
CREATE TABLE IF NOT EXISTS soc2_controls (
  control_id VARCHAR(64) PRIMARY KEY,
  family VARCHAR(64) NOT NULL,
  title VARCHAR(255) NOT NULL,
  description TEXT NOT NULL,
  default_weight NUMERIC(6,2) NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS soc2_status (
  id BIGSERIAL PRIMARY KEY,
  tenant_slug VARCHAR(64) NOT NULL,
  control_id VARCHAR(64) NOT NULL REFERENCES soc2_controls(control_id) ON DELETE CASCADE,
  status VARCHAR(24) NOT NULL CHECK (
    status IN ('not_started', 'in_progress', 'implemented', 'validated', 'not_applicable')
  ),
  owner_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
  evidence_count INTEGER NOT NULL DEFAULT 0,
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_slug, control_id)
);

CREATE INDEX IF NOT EXISTS soc2_status_tenant_updated_idx
  ON soc2_status (tenant_slug, updated_at DESC);

CREATE TABLE IF NOT EXISTS soc2_evidence (
  id BIGSERIAL PRIMARY KEY,
  tenant_slug VARCHAR(64) NOT NULL,
  control_id VARCHAR(64) NOT NULL REFERENCES soc2_controls(control_id) ON DELETE CASCADE,
  filename VARCHAR(255) NOT NULL,
  mime VARCHAR(128) NOT NULL,
  size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
  storage_key TEXT NOT NULL,
  checksum_sha256 VARCHAR(128) NOT NULL,
  uploaded_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS soc2_evidence_tenant_created_idx
  ON soc2_evidence (tenant_slug, created_at DESC);

CREATE INDEX IF NOT EXISTS soc2_evidence_tenant_control_idx
  ON soc2_evidence (tenant_slug, control_id, created_at DESC);

CREATE TABLE IF NOT EXISTS policies (
  id BIGSERIAL PRIMARY KEY,
  tenant_slug VARCHAR(64) NOT NULL,
  policy_key VARCHAR(96) NOT NULL,
  content TEXT NOT NULL,
  created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS policies_tenant_created_idx
  ON policies (tenant_slug, created_at DESC);

CREATE TABLE IF NOT EXISTS audit_packages (
  id BIGSERIAL PRIMARY KEY,
  tenant_slug VARCHAR(64) NOT NULL,
  pdf_storage_path TEXT NOT NULL,
  manifest_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS audit_packages_tenant_created_idx
  ON audit_packages (tenant_slug, created_at DESC);

-- Product C: AI Threat Intelligence Summarizer
CREATE TABLE IF NOT EXISTS cves (
  cve_id VARCHAR(64) PRIMARY KEY,
  published_at TIMESTAMPTZ,
  last_modified_at TIMESTAMPTZ,
  cvss_score NUMERIC(4,1),
  severity VARCHAR(16) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  description TEXT,
  raw_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS cves_severity_published_idx
  ON cves (severity, published_at DESC);

CREATE TABLE IF NOT EXISTS tenant_cve_views (
  id BIGSERIAL PRIMARY KEY,
  tenant_slug VARCHAR(64) NOT NULL,
  cve_id VARCHAR(64) NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
  relevance_score NUMERIC(6,2) NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_slug, cve_id)
);

CREATE INDEX IF NOT EXISTS tenant_cve_views_tenant_created_idx
  ON tenant_cve_views (tenant_slug, created_at DESC);

CREATE INDEX IF NOT EXISTS tenant_cve_views_tenant_relevance_idx
  ON tenant_cve_views (tenant_slug, relevance_score DESC, created_at DESC);

CREATE TABLE IF NOT EXISTS cve_summaries (
  id BIGSERIAL PRIMARY KEY,
  tenant_slug VARCHAR(64) NOT NULL,
  cve_id VARCHAR(64) NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
  summary_text TEXT NOT NULL,
  model VARCHAR(128) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS cve_summaries_tenant_created_idx
  ON cve_summaries (tenant_slug, created_at DESC);

CREATE INDEX IF NOT EXISTS cve_summaries_tenant_cve_idx
  ON cve_summaries (tenant_slug, cve_id, created_at DESC);

CREATE TABLE IF NOT EXISTS cve_sync_state (
  source VARCHAR(32) PRIMARY KEY,
  etag TEXT,
  last_modified TEXT,
  synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed SOC2 controls baseline.
INSERT INTO soc2_controls (control_id, family, title, description, default_weight)
VALUES
  ('CC1.1', 'Control Environment', 'Integrity and Ethical Values', 'Management demonstrates commitment to integrity and ethical values.', 1.00),
  ('CC2.1', 'Communication', 'Internal Communication', 'The entity obtains and uses quality information to support internal control.', 1.00),
  ('CC3.1', 'Risk Assessment', 'Risk Identification', 'The entity specifies objectives with sufficient clarity to identify and assess risks.', 1.20),
  ('CC4.1', 'Monitoring', 'Control Monitoring', 'The entity evaluates and communicates internal control deficiencies.', 1.10),
  ('CC5.1', 'Control Activities', 'Logical Access Controls', 'The entity selects and develops control activities that contribute to risk mitigation.', 1.40),
  ('CC6.1', 'Logical and Physical Access', 'Identity and Access Management', 'The entity implements logical access controls to protect system assets.', 1.60),
  ('CC7.1', 'System Operations', 'Change and Vulnerability Management', 'The entity monitors systems and resolves security events.', 1.50),
  ('CC8.1', 'Change Management', 'Configuration and Release Control', 'Changes are authorized, tested, and approved before deployment.', 1.30)
ON CONFLICT (control_id) DO NOTHING;

-- Seed feature flags required by Phase 3.
INSERT INTO feature_flags (flag_key, description)
VALUES
  ('product_risk_copilot_enabled', 'Enable Product A: AI Cyber Risk Copilot'),
  ('product_compliance_engine_enabled', 'Enable Product B: AI Startup Compliance Engine'),
  ('product_threat_intel_enabled', 'Enable Product C: AI Threat Intelligence Summarizer'),
  ('llm_features_enabled', 'Enable LLM-backed generation and summarization capabilities')
ON CONFLICT (flag_key) DO NOTHING;

-- Product gating map for current product keys.
INSERT INTO product_feature_flags (product_key, flag_key, enabled_by_default)
VALUES
  ('risk-copilot', 'product_risk_copilot_enabled', TRUE),
  ('resilience-hq', 'product_compliance_engine_enabled', TRUE),
  ('threat-command', 'product_threat_intel_enabled', TRUE),
  ('risk-copilot', 'llm_features_enabled', FALSE),
  ('resilience-hq', 'llm_features_enabled', FALSE),
  ('threat-command', 'llm_features_enabled', FALSE)
ON CONFLICT (product_key, flag_key) DO NOTHING;

INSERT INTO tenant_feature_flags (tenant_slug, flag_key, enabled)
SELECT slug, 'product_risk_copilot_enabled', TRUE
FROM tenants
ON CONFLICT (tenant_slug, flag_key) DO NOTHING;

INSERT INTO tenant_feature_flags (tenant_slug, flag_key, enabled)
SELECT slug, 'product_compliance_engine_enabled', TRUE
FROM tenants
ON CONFLICT (tenant_slug, flag_key) DO NOTHING;

INSERT INTO tenant_feature_flags (tenant_slug, flag_key, enabled)
SELECT slug, 'product_threat_intel_enabled', TRUE
FROM tenants
ON CONFLICT (tenant_slug, flag_key) DO NOTHING;

INSERT INTO tenant_feature_flags (tenant_slug, flag_key, enabled)
SELECT slug, 'llm_features_enabled', FALSE
FROM tenants
ON CONFLICT (tenant_slug, flag_key) DO NOTHING;
