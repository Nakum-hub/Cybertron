export type PlatformRole =
  | 'executive_viewer'
  | 'compliance_officer'
  | 'security_analyst'
  | 'tenant_admin'
  | 'super_admin';

type LegacyRole =
  | 'viewer'
  | 'analyst'
  | 'operator'
  | 'admin'
  | 'executive'
  | 'client';

export const roleAliases: Record<LegacyRole | PlatformRole, PlatformRole> = {
  client: 'executive_viewer',
  viewer: 'executive_viewer',
  analyst: 'security_analyst',
  operator: 'compliance_officer',
  admin: 'tenant_admin',
  executive: 'super_admin',
  executive_viewer: 'executive_viewer',
  compliance_officer: 'compliance_officer',
  security_analyst: 'security_analyst',
  tenant_admin: 'tenant_admin',
  super_admin: 'super_admin',
};

export const roleLabels: Record<PlatformRole, string> = {
  executive_viewer: 'Executive Viewer',
  compliance_officer: 'Compliance Officer',
  security_analyst: 'Security Analyst',
  tenant_admin: 'Tenant Admin',
  super_admin: 'Super Admin',
};

export const roleOptions: PlatformRole[] = [
  'executive_viewer',
  'compliance_officer',
  'security_analyst',
  'tenant_admin',
  'super_admin',
];

export interface PlatformApp {
  id: string;
  moduleId?: string;
  name: string;
  tagline: string;
  description: string;
  path: string;
  requiredRole: PlatformRole;
  statusEndpoint: string;
  capabilities: string[];
}

export const roleRank: Record<PlatformRole, number> = {
  executive_viewer: 1,
  compliance_officer: 2,
  security_analyst: 3,
  tenant_admin: 4,
  super_admin: 5,
};

export const platformApps: PlatformApp[] = [
  {
    id: 'threat-command',
    moduleId: 'threat-intel',
    name: 'Threat Command',
    tagline: 'Real-time threat intelligence and SOC orchestration',
    description:
      'Unified command interface for threat triage, investigation workflows, and incident response playbooks.',
    path: '/platform/threat-command',
    requiredRole: 'executive_viewer',
    statusEndpoint: '/v1/apps/threat-command/status',
    capabilities: ['Alert prioritization', 'Incident timelines', 'Response orchestration'],
  },
  {
    id: 'identity-guardian',
    moduleId: 'core',
    name: 'Identity Guardian',
    tagline: 'Adaptive identity trust and access governance',
    description:
      'Zero-trust policy controls, risk-adaptive authentication, and cross-tenant identity posture dashboards.',
    path: '/platform/identity-guardian',
    requiredRole: 'security_analyst',
    statusEndpoint: '/v1/apps/identity-guardian/status',
    capabilities: ['Risk-based access', 'Session trust analytics', 'SSO policy enforcement'],
  },
  {
    id: 'resilience-hq',
    moduleId: 'compliance-engine',
    name: 'Resilience HQ',
    tagline: 'Executive reliability and security KPI cockpit',
    description:
      'Board-level visibility into uptime, security posture, and resilience trajectories across all business units.',
    path: '/platform/resilience-hq',
    requiredRole: 'executive_viewer',
    statusEndpoint: '/v1/apps/resilience-hq/status',
    capabilities: ['Global KPI views', 'Business risk scorecards', 'Quarterly strategy snapshots'],
  },
  {
    id: 'risk-copilot',
    moduleId: 'risk-copilot',
    name: 'Risk Copilot',
    tagline: 'AI-assisted risk prioritization and response sequencing',
    description:
      'Context-aware prioritization over incidents and IOC confidence to focus analyst effort where risk is highest.',
    path: '/platform/risk-copilot',
    requiredRole: 'executive_viewer',
    statusEndpoint: '/v1/apps/risk-copilot/status',
    capabilities: ['Priority score generation', 'Analyst queue suggestions', 'Tenant-scoped risk trend tracking'],
  },
];

export function hasRoleAccess(role: PlatformRole, requiredRole: PlatformRole): boolean {
  return roleRank[role] >= roleRank[requiredRole];
}

export function getAccessibleApps(role: PlatformRole): PlatformApp[] {
  return platformApps.filter(app => hasRoleAccess(role, app.requiredRole));
}

export function normalizeRole(value: string | null | undefined): PlatformRole {
  const normalized = (value ?? '').toLowerCase();
  return roleAliases[normalized as LegacyRole | PlatformRole] || 'executive_viewer';
}
