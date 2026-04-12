-- MITRE ATT&CK technique mappings for incidents and IOCs
CREATE TABLE IF NOT EXISTS mitre_attack_techniques (
  id            TEXT PRIMARY KEY,
  tactic        TEXT NOT NULL,
  name          TEXT NOT NULL,
  description   TEXT,
  url           TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS incident_mitre_mappings (
  id            BIGSERIAL PRIMARY KEY,
  tenant_slug   TEXT NOT NULL,
  incident_id   BIGINT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  technique_id  TEXT NOT NULL,
  confidence    SMALLINT DEFAULT 50 CHECK (confidence BETWEEN 0 AND 100),
  notes         TEXT,
  created_by    BIGINT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_slug, incident_id, technique_id)
);

CREATE INDEX IF NOT EXISTS idx_incident_mitre_tenant ON incident_mitre_mappings (tenant_slug);
CREATE INDEX IF NOT EXISTS idx_incident_mitre_technique ON incident_mitre_mappings (technique_id);

-- Incident response playbooks
CREATE TABLE IF NOT EXISTS playbooks (
  id              BIGSERIAL PRIMARY KEY,
  tenant_slug     TEXT NOT NULL,
  name            TEXT NOT NULL,
  description     TEXT,
  severity_filter TEXT CHECK (severity_filter IN ('critical', 'high', 'medium', 'low')),
  category        TEXT DEFAULT 'general',
  is_active       BOOLEAN DEFAULT TRUE,
  created_by      BIGINT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_playbooks_tenant ON playbooks (tenant_slug);

CREATE TABLE IF NOT EXISTS playbook_steps (
  id              BIGSERIAL PRIMARY KEY,
  playbook_id     BIGINT NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
  step_order      SMALLINT NOT NULL,
  title           TEXT NOT NULL,
  description     TEXT,
  action_type     TEXT DEFAULT 'manual' CHECK (action_type IN ('manual', 'automated', 'notification', 'approval')),
  assigned_role   TEXT DEFAULT 'security_analyst',
  timeout_minutes INT DEFAULT 60,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_playbook_steps_playbook ON playbook_steps (playbook_id);

CREATE TABLE IF NOT EXISTS playbook_executions (
  id              BIGSERIAL PRIMARY KEY,
  tenant_slug     TEXT NOT NULL,
  playbook_id     BIGINT NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
  incident_id     BIGINT REFERENCES incidents(id) ON DELETE SET NULL,
  status          TEXT DEFAULT 'running' CHECK (status IN ('running', 'completed', 'failed', 'cancelled')),
  started_by      BIGINT,
  started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at    TIMESTAMPTZ,
  result_summary  JSONB DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_playbook_exec_tenant ON playbook_executions (tenant_slug);

CREATE TABLE IF NOT EXISTS playbook_step_results (
  id              BIGSERIAL PRIMARY KEY,
  execution_id    BIGINT NOT NULL REFERENCES playbook_executions(id) ON DELETE CASCADE,
  step_id         BIGINT NOT NULL REFERENCES playbook_steps(id) ON DELETE CASCADE,
  status          TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'in_progress', 'completed', 'skipped', 'failed')),
  started_at      TIMESTAMPTZ,
  completed_at    TIMESTAMPTZ,
  notes           TEXT,
  completed_by    BIGINT
);

-- SIEM alert correlation
CREATE TABLE IF NOT EXISTS siem_alerts (
  id              BIGSERIAL PRIMARY KEY,
  tenant_slug     TEXT NOT NULL,
  source          TEXT NOT NULL DEFAULT 'unknown',
  alert_id        TEXT,
  rule_name       TEXT,
  severity        TEXT DEFAULT 'medium' CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  category        TEXT DEFAULT 'generic',
  raw_payload     JSONB DEFAULT '{}',
  source_ip       TEXT,
  dest_ip         TEXT,
  hostname        TEXT,
  correlated      BOOLEAN DEFAULT FALSE,
  incident_id     BIGINT REFERENCES incidents(id) ON DELETE SET NULL,
  ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  event_time      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_siem_alerts_tenant ON siem_alerts (tenant_slug);
CREATE INDEX IF NOT EXISTS idx_siem_alerts_severity ON siem_alerts (tenant_slug, severity);
CREATE INDEX IF NOT EXISTS idx_siem_alerts_source ON siem_alerts (tenant_slug, source);
CREATE INDEX IF NOT EXISTS idx_siem_alerts_uncorrelated ON siem_alerts (tenant_slug) WHERE correlated = FALSE;
CREATE INDEX IF NOT EXISTS idx_siem_alerts_event_time ON siem_alerts (tenant_slug, event_time DESC);

CREATE TABLE IF NOT EXISTS alert_correlation_rules (
  id              BIGSERIAL PRIMARY KEY,
  tenant_slug     TEXT NOT NULL,
  name            TEXT NOT NULL,
  description     TEXT,
  rule_type       TEXT DEFAULT 'threshold' CHECK (rule_type IN ('threshold', 'sequence', 'aggregation', 'anomaly')),
  conditions      JSONB NOT NULL DEFAULT '{}',
  severity_output TEXT DEFAULT 'high',
  is_active       BOOLEAN DEFAULT TRUE,
  created_by      BIGINT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_correlation_rules_tenant ON alert_correlation_rules (tenant_slug);

-- Threat hunting saved queries
CREATE TABLE IF NOT EXISTS threat_hunt_queries (
  id              BIGSERIAL PRIMARY KEY,
  tenant_slug     TEXT NOT NULL,
  name            TEXT NOT NULL,
  description     TEXT,
  query_type      TEXT DEFAULT 'kql' CHECK (query_type IN ('kql', 'sql', 'regex', 'yara')),
  query_text      TEXT NOT NULL,
  data_source     TEXT DEFAULT 'siem_alerts',
  last_run_at     TIMESTAMPTZ,
  last_result_count INT DEFAULT 0,
  created_by      BIGINT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_threat_hunt_tenant ON threat_hunt_queries (tenant_slug);

-- Seed core MITRE ATT&CK techniques (top 20 most common)
INSERT INTO mitre_attack_techniques (id, tactic, name, description, url) VALUES
  ('T1566',     'initial-access',       'Phishing',                        'Adversaries send phishing messages to gain access to victim systems.', 'https://attack.mitre.org/techniques/T1566/'),
  ('T1566.001', 'initial-access',       'Spearphishing Attachment',        'Adversaries send spearphishing emails with a malicious attachment.', 'https://attack.mitre.org/techniques/T1566/001/'),
  ('T1566.002', 'initial-access',       'Spearphishing Link',              'Adversaries send spearphishing emails with a malicious link.', 'https://attack.mitre.org/techniques/T1566/002/'),
  ('T1190',     'initial-access',       'Exploit Public-Facing Application','Adversaries exploit vulnerabilities in internet-facing applications.', 'https://attack.mitre.org/techniques/T1190/'),
  ('T1133',     'initial-access',       'External Remote Services',        'Adversaries leverage external remote services to gain initial access.', 'https://attack.mitre.org/techniques/T1133/'),
  ('T1059',     'execution',            'Command and Scripting Interpreter','Adversaries abuse command and script interpreters to execute commands.', 'https://attack.mitre.org/techniques/T1059/'),
  ('T1059.001', 'execution',            'PowerShell',                      'Adversaries abuse PowerShell commands and scripts for execution.', 'https://attack.mitre.org/techniques/T1059/001/'),
  ('T1053',     'execution',            'Scheduled Task/Job',              'Adversaries abuse task scheduling functionality.', 'https://attack.mitre.org/techniques/T1053/'),
  ('T1547',     'persistence',          'Boot or Logon Autostart Execution','Adversaries configure system settings to automatically execute a program during boot or logon.', 'https://attack.mitre.org/techniques/T1547/'),
  ('T1078',     'persistence',          'Valid Accounts',                  'Adversaries obtain and abuse credentials of existing accounts.', 'https://attack.mitre.org/techniques/T1078/'),
  ('T1548',     'privilege-escalation', 'Abuse Elevation Control Mechanism','Adversaries circumvent privilege escalation mechanisms.', 'https://attack.mitre.org/techniques/T1548/'),
  ('T1068',     'privilege-escalation', 'Exploitation for Privilege Escalation','Adversaries exploit software vulnerabilities to elevate privileges.', 'https://attack.mitre.org/techniques/T1068/'),
  ('T1562',     'defense-evasion',      'Impair Defenses',                 'Adversaries maliciously modify components of the victim environment to hinder defenses.', 'https://attack.mitre.org/techniques/T1562/'),
  ('T1070',     'defense-evasion',      'Indicator Removal',               'Adversaries delete or modify artifacts generated within systems.', 'https://attack.mitre.org/techniques/T1070/'),
  ('T1003',     'credential-access',    'OS Credential Dumping',           'Adversaries attempt to dump credentials to obtain account login and credential material.', 'https://attack.mitre.org/techniques/T1003/'),
  ('T1110',     'credential-access',    'Brute Force',                     'Adversaries use brute force techniques to gain access to accounts.', 'https://attack.mitre.org/techniques/T1110/'),
  ('T1046',     'discovery',            'Network Service Discovery',       'Adversaries attempt to get a listing of services running on remote hosts.', 'https://attack.mitre.org/techniques/T1046/'),
  ('T1021',     'lateral-movement',     'Remote Services',                 'Adversaries move laterally using remote service protocols.', 'https://attack.mitre.org/techniques/T1021/'),
  ('T1041',     'exfiltration',         'Exfiltration Over C2 Channel',    'Adversaries steal data by exfiltrating it over an existing C2 channel.', 'https://attack.mitre.org/techniques/T1041/'),
  ('T1486',     'impact',               'Data Encrypted for Impact',       'Adversaries encrypt data on target systems to interrupt availability (ransomware).', 'https://attack.mitre.org/techniques/T1486/')
ON CONFLICT (id) DO NOTHING;
