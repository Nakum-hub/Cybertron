-- Multi-framework compliance support
-- Extends the existing SOC2-only compliance engine

CREATE TABLE IF NOT EXISTS compliance_frameworks (
  id              TEXT PRIMARY KEY,
  name            TEXT NOT NULL,
  version         TEXT DEFAULT '1.0',
  description     TEXT,
  category        TEXT DEFAULT 'security',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS compliance_controls (
  id              BIGSERIAL PRIMARY KEY,
  framework_id    TEXT NOT NULL REFERENCES compliance_frameworks(id) ON DELETE CASCADE,
  control_id      TEXT NOT NULL,
  family          TEXT NOT NULL,
  title           TEXT NOT NULL,
  description     TEXT,
  default_weight  SMALLINT DEFAULT 1 CHECK (default_weight BETWEEN 1 AND 10),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (framework_id, control_id)
);

CREATE INDEX IF NOT EXISTS idx_compliance_controls_framework ON compliance_controls (framework_id);

CREATE TABLE IF NOT EXISTS compliance_control_status (
  id              BIGSERIAL PRIMARY KEY,
  tenant_slug     TEXT NOT NULL,
  framework_id    TEXT NOT NULL REFERENCES compliance_frameworks(id) ON DELETE CASCADE,
  control_id      TEXT NOT NULL,
  status          TEXT DEFAULT 'not_started' CHECK (status IN ('not_started','in_progress','implemented','validated','not_applicable')),
  owner_user_id   BIGINT,
  notes           TEXT,
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_slug, framework_id, control_id)
);

CREATE INDEX IF NOT EXISTS idx_compliance_status_tenant ON compliance_control_status (tenant_slug, framework_id);

-- Seed frameworks
INSERT INTO compliance_frameworks (id, name, version, description, category) VALUES
  ('soc2',     'SOC 2 Type II',      '2017',  'Service Organization Control 2 trust services criteria', 'security'),
  ('iso27001', 'ISO/IEC 27001',       '2022',  'Information security management systems requirements', 'security'),
  ('pci-dss',  'PCI DSS',            '4.0',   'Payment Card Industry Data Security Standard', 'payment'),
  ('hipaa',    'HIPAA Security Rule', '2013',  'Health Insurance Portability and Accountability Act security requirements', 'healthcare'),
  ('nist-csf', 'NIST CSF',           '2.0',   'NIST Cybersecurity Framework core functions', 'security')
ON CONFLICT (id) DO NOTHING;

-- ISO 27001:2022 key controls (Annex A)
INSERT INTO compliance_controls (framework_id, control_id, family, title, description, default_weight) VALUES
  ('iso27001', 'A.5.1',  'Organizational',  'Policies for information security',    'Management direction for information security established and reviewed.', 3),
  ('iso27001', 'A.5.2',  'Organizational',  'Information security roles',            'Information security roles and responsibilities defined and allocated.', 2),
  ('iso27001', 'A.5.3',  'Organizational',  'Segregation of duties',                'Conflicting duties segregated to reduce opportunity for unauthorized modification.', 2),
  ('iso27001', 'A.5.7',  'Organizational',  'Threat intelligence',                  'Information relating to information security threats collected and analyzed.', 3),
  ('iso27001', 'A.5.23', 'Organizational',  'Information security for cloud services','Processes for acquisition, use, management and exit from cloud services established.', 2),
  ('iso27001', 'A.5.24', 'Organizational',  'Incident management planning',         'Management responsibilities and procedures for incident response established.', 3),
  ('iso27001', 'A.5.29', 'Organizational',  'ICT readiness for business continuity','ICT readiness planned, implemented, maintained and tested.', 2),
  ('iso27001', 'A.6.1',  'People',          'Screening',                            'Background verification checks on candidates carried out.', 1),
  ('iso27001', 'A.6.3',  'People',          'Information security awareness',       'Personnel and relevant interested parties receive appropriate awareness education.', 2),
  ('iso27001', 'A.7.1',  'Physical',        'Physical security perimeters',         'Security perimeters defined and used to protect sensitive areas.', 1),
  ('iso27001', 'A.8.1',  'Technological',   'User endpoint devices',               'Information stored on, processed by or accessible via user endpoint devices protected.', 2),
  ('iso27001', 'A.8.5',  'Technological',   'Secure authentication',               'Secure authentication technologies and procedures established.', 3),
  ('iso27001', 'A.8.7',  'Technological',   'Protection against malware',           'Protection against malware implemented.', 2),
  ('iso27001', 'A.8.8',  'Technological',   'Management of technical vulnerabilities','Information about technical vulnerabilities obtained and appropriate measures taken.', 3),
  ('iso27001', 'A.8.9',  'Technological',   'Configuration management',            'Configurations including security configurations managed.', 2),
  ('iso27001', 'A.8.15', 'Technological',   'Logging',                             'Logs that record activities, exceptions, faults and other relevant events produced and protected.', 3),
  ('iso27001', 'A.8.16', 'Technological',   'Monitoring activities',               'Networks, systems and applications monitored for anomalous behavior.', 3),
  ('iso27001', 'A.8.24', 'Technological',   'Use of cryptography',                 'Rules for effective use of cryptography defined and implemented.', 2),
  ('iso27001', 'A.8.25', 'Technological',   'Secure development life cycle',       'Rules for secure development of software and systems established.', 2),
  ('iso27001', 'A.8.28', 'Technological',   'Secure coding',                       'Secure coding principles applied to software development.', 2)
ON CONFLICT (framework_id, control_id) DO NOTHING;

-- PCI DSS 4.0 key requirements
INSERT INTO compliance_controls (framework_id, control_id, family, title, description, default_weight) VALUES
  ('pci-dss', '1.1',  'Network Security',        'Network security controls',            'Network security controls installed and maintained.', 3),
  ('pci-dss', '1.2',  'Network Security',        'Network security configurations',      'Network security controls configured and maintained.', 2),
  ('pci-dss', '2.1',  'Secure Configuration',    'Secure configuration standards',       'Configuration standards developed for all system components.', 2),
  ('pci-dss', '2.2',  'Secure Configuration',    'System components configured securely','System components configured and managed securely.', 3),
  ('pci-dss', '3.1',  'Account Data Protection', 'Account data storage minimized',       'Stored account data storage is kept to a minimum.', 3),
  ('pci-dss', '3.5',  'Account Data Protection', 'Primary account number secured',       'PAN is secured wherever it is stored.', 3),
  ('pci-dss', '4.1',  'Encryption in Transit',   'Strong cryptography in transit',       'Strong cryptography protects CHD during transmission over open public networks.', 3),
  ('pci-dss', '5.1',  'Malware Protection',      'Anti-malware solutions',              'Malicious software is prevented or detected and addressed.', 2),
  ('pci-dss', '5.2',  'Malware Protection',      'Anti-malware mechanisms active',      'Anti-malware mechanisms and processes are active, maintained, and monitored.', 2),
  ('pci-dss', '6.1',  'Secure Development',      'Secure development processes',        'Secure development processes established and maintained.', 2),
  ('pci-dss', '6.2',  'Secure Development',      'Custom software developed securely',  'Bespoke and custom software developed securely.', 2),
  ('pci-dss', '7.1',  'Access Control',          'Access restricted by need',           'Access to system components and CHD limited to need to know.', 3),
  ('pci-dss', '8.1',  'Authentication',          'User identification',                 'User identification and related accounts managed throughout their lifecycle.', 2),
  ('pci-dss', '8.3',  'Authentication',          'Strong authentication',               'Strong authentication for users and administrators established.', 3),
  ('pci-dss', '9.1',  'Physical Security',       'Physical access restricted',          'Physical access to CHD is restricted.', 1),
  ('pci-dss', '10.1', 'Logging & Monitoring',    'Audit logs implemented',              'Audit logs are implemented to support detection of anomalies.', 3),
  ('pci-dss', '10.2', 'Logging & Monitoring',    'Audit logs record required info',     'Audit logs record sufficient info to support detection.', 2),
  ('pci-dss', '11.1', 'Security Testing',        'Security of systems tested regularly','Security of systems and networks is regularly tested.', 2),
  ('pci-dss', '11.3', 'Security Testing',        'Vulnerabilities identified & managed','External and internal vulns are regularly identified and managed.', 3),
  ('pci-dss', '12.1', 'Security Policy',         'Information security policy',         'Comprehensive information security policy maintained.', 2)
ON CONFLICT (framework_id, control_id) DO NOTHING;

-- HIPAA Security Rule key safeguards
INSERT INTO compliance_controls (framework_id, control_id, family, title, description, default_weight) VALUES
  ('hipaa', '164.308.a.1', 'Administrative', 'Security management process',      'Implement policies and procedures to prevent, detect, contain, and correct security violations.', 3),
  ('hipaa', '164.308.a.2', 'Administrative', 'Assigned security responsibility', 'Identify the security official responsible for developing and implementing policies.', 2),
  ('hipaa', '164.308.a.3', 'Administrative', 'Workforce security',               'Implement policies ensuring workforce members have appropriate access to ePHI.', 2),
  ('hipaa', '164.308.a.4', 'Administrative', 'Information access management',    'Implement policies authorizing access to ePHI consistent with applicable requirements.', 3),
  ('hipaa', '164.308.a.5', 'Administrative', 'Security awareness and training',  'Implement a security awareness and training program for all workforce.', 2),
  ('hipaa', '164.308.a.6', 'Administrative', 'Security incident procedures',     'Implement policies and procedures to address security incidents.', 3),
  ('hipaa', '164.308.a.7', 'Administrative', 'Contingency plan',                'Establish policies and procedures for responding to emergencies.', 2),
  ('hipaa', '164.308.a.8', 'Administrative', 'Evaluation',                       'Perform periodic technical and nontechnical evaluation.', 1),
  ('hipaa', '164.310.a.1', 'Physical',       'Facility access controls',         'Implement policies limiting physical access to electronic information systems.', 1),
  ('hipaa', '164.310.b',   'Physical',       'Workstation use',                  'Implement policies specifying proper functions and physical attributes of workstations.', 1),
  ('hipaa', '164.310.c',   'Physical',       'Workstation security',             'Implement physical safeguards for workstations that access ePHI.', 1),
  ('hipaa', '164.310.d.1', 'Physical',       'Device and media controls',        'Implement policies governing receipt and removal of hardware and electronic media.', 2),
  ('hipaa', '164.312.a.1', 'Technical',      'Access control',                   'Implement technical policies allowing access only to authorized persons.', 3),
  ('hipaa', '164.312.b',   'Technical',      'Audit controls',                   'Implement hardware, software, and procedures that record and examine system activity.', 3),
  ('hipaa', '164.312.c.1', 'Technical',      'Integrity',                        'Implement policies to protect ePHI from improper alteration or destruction.', 2),
  ('hipaa', '164.312.d',   'Technical',      'Person or entity authentication',  'Implement procedures to verify that a person seeking access to ePHI is the one claimed.', 2),
  ('hipaa', '164.312.e.1', 'Technical',      'Transmission security',            'Implement technical security measures to guard against unauthorized access to ePHI during transmission.', 3)
ON CONFLICT (framework_id, control_id) DO NOTHING;

-- NIST CSF 2.0 core functions
INSERT INTO compliance_controls (framework_id, control_id, family, title, description, default_weight) VALUES
  ('nist-csf', 'GV.OC-01', 'Govern',    'Organizational context',                 'Organizational mission is understood and informs cybersecurity risk management.', 2),
  ('nist-csf', 'GV.RM-01', 'Govern',    'Risk management objectives',             'Risk management objectives are established and agreed to by organizational stakeholders.', 2),
  ('nist-csf', 'GV.SC-01', 'Govern',    'Supply chain risk management program',   'Cyber supply chain risk management program is established.', 2),
  ('nist-csf', 'ID.AM-01', 'Identify',  'Hardware inventory',                     'Inventories of hardware managed by the organization are maintained.', 2),
  ('nist-csf', 'ID.AM-02', 'Identify',  'Software inventory',                     'Inventories of software, services managed by the organization are maintained.', 2),
  ('nist-csf', 'ID.RA-01', 'Identify',  'Vulnerabilities identified',             'Vulnerabilities in assets are identified, validated, and recorded.', 3),
  ('nist-csf', 'PR.AA-01', 'Protect',   'Identity management',                    'Identities and credentials for authorized users, services are managed.', 3),
  ('nist-csf', 'PR.AT-01', 'Protect',   'Awareness and training',                 'Personnel are provided cybersecurity awareness and training.', 2),
  ('nist-csf', 'PR.DS-01', 'Protect',   'Data-at-rest protection',                'Data-at-rest is protected.', 2),
  ('nist-csf', 'PR.DS-02', 'Protect',   'Data-in-transit protection',             'Data-in-transit is protected.', 2),
  ('nist-csf', 'PR.PS-01', 'Protect',   'Configuration management',               'Configuration management practices are established and applied.', 2),
  ('nist-csf', 'DE.CM-01', 'Detect',    'Continuous monitoring',                  'Networks and network services are monitored to find potentially adverse events.', 3),
  ('nist-csf', 'DE.AE-02', 'Detect',    'Anomalous activity analysis',            'Potentially adverse events are analyzed to better characterize/detect them.', 3),
  ('nist-csf', 'RS.MA-01', 'Respond',   'Incident management',                   'Incident response plan is executed once an incident is declared.', 3),
  ('nist-csf', 'RS.AN-03', 'Respond',   'Incident analysis',                     'Analysis is performed to determine what has taken place during an incident.', 2),
  ('nist-csf', 'RC.RP-01', 'Recover',   'Recovery plan execution',               'Recovery plan is executed during or after an incident.', 2)
ON CONFLICT (framework_id, control_id) DO NOTHING;
