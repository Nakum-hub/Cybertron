import {
  ArrowRight,
  Shield,
  Link2,
  Fingerprint,
  Brain,
  Lock,
  Eye,
  Server,
  Scan,
} from 'lucide-react';
import { useState, useEffect, Suspense, lazy } from 'react';
import { useStaggeredAnimation } from '@/lib/animations';
import { useReducedMotionPreference } from '@/lib/animations';
import { useWebglCompatibility } from '@/hooks/use-webgl-compatibility';

const CyberShieldScene = lazy(() => import('./CyberShieldScene'));
import { type PlatformRole } from '@/lib/platform-registry';
import { resolveWorkspaceNavigation, type WorkspaceNavigationResolution } from '@/lib/workspace-access';
import WorkspaceAccessNotice from './WorkspaceAccessNotice';

type FeatureAction = {
  appId: string;
  label: string;
  path: string;
  role: PlatformRole;
};

const FEATURES = [
  {
    icon: Shield,
    title: 'Threat Operations',
    subtitle: 'Incident + IOC Workflows',
    description:
      'Create, update, and triage incidents with timeline events, severity tracking, and IOC correlation from a tenant-scoped command workflow.',
    highlights: [
      'Incident Timeline',
      'Severity Filters',
      'IOC Correlation',
      'Tenant Isolation',
    ],
    gradient: 'from-cyan-500 to-blue-600',
    glowColor: 'rgba(0,240,255,0.15)',
    iconBg: 'bg-cyan-500/10',
    iconColor: 'text-cyan-400',
    action: {
      appId: 'threat-command',
      label: 'Open Threat Command',
      path: '/products/threat-intel',
      role: 'security_analyst',
    } satisfies FeatureAction,
  },
  {
    icon: Link2,
    title: 'Service Request Portal',
    subtitle: 'Client-to-Security Analyst Workflow',
    description:
      'Clients submit operational requests while Security Analysts triage status, append comments, and maintain full traceability in the request lifecycle.',
    highlights: [
      'Request Intake',
      'Priority Tracking',
      'Comment Threads',
      'Workflow Status',
    ],
    gradient: 'from-purple-500 to-pink-600',
    glowColor: 'rgba(139,92,246,0.15)',
    iconBg: 'bg-purple-500/10',
    iconColor: 'text-purple-400',
    action: {
      appId: 'identity-guardian',
      label: 'Open Identity Guardian',
      path: '/platform/identity-guardian',
      role: 'security_analyst',
    } satisfies FeatureAction,
  },
  {
    icon: Fingerprint,
    title: 'Identity Governance',
    subtitle: 'RBAC + Session Controls',
    description:
      'Role enforcement, tenant-scoped access, refresh-token rotation, lockout protection, and authenticated API sessions are integrated end-to-end.',
    highlights: [
      'JWT Sessions',
      'Role Enforcement',
      'Lockout Control',
      'Audit Logging',
    ],
    gradient: 'from-emerald-500 to-teal-600',
    glowColor: 'rgba(0,255,136,0.15)',
    iconBg: 'bg-emerald-500/10',
    iconColor: 'text-emerald-400',
    action: {
      appId: 'resilience-hq',
      label: 'Open Governance Console',
      path: '/products/compliance-engine',
      role: 'tenant_admin',
    } satisfies FeatureAction,
  },
  {
    icon: Brain,
    title: 'Connector Framework',
    subtitle: 'Truthful Data Ingestion',
    description:
      'Connector health and ingestion contracts support real external sources (Wazuh, MISP, OpenCTI, TheHive) with honest empty states when not configured.',
    highlights: [
      'Connector Status',
      'Live Ingestion Hooks',
      'No Fabricated Signals',
      'Operational Visibility',
    ],
    gradient: 'from-amber-500 to-orange-600',
    glowColor: 'rgba(255,184,0,0.15)',
    iconBg: 'bg-amber-500/10',
    iconColor: 'text-amber-400',
    action: {
      appId: 'risk-copilot',
      label: 'Open Risk Copilot',
      path: '/products/risk-copilot',
      role: 'security_analyst',
    } satisfies FeatureAction,
  },
];

export default function FeaturesSection() {
  const { ref, visibleItems } = useStaggeredAnimation(FEATURES.length, 200);
  const [notice, setNotice] = useState<WorkspaceNavigationResolution | null>(null);
  const [activeActionId, setActiveActionId] = useState<string | null>(null);
  const reducedMotion = useReducedMotionPreference();
  const webglCompatibility = useWebglCompatibility();
  const [isDesktop, setIsDesktop] = useState(() =>
    typeof window !== 'undefined' ? window.innerWidth >= 768 : false
  );

  useEffect(() => {
    const mql = window.matchMedia('(min-width: 768px)');
    const onChange = (e: MediaQueryListEvent | MediaQueryList) => setIsDesktop(e.matches);
    onChange(mql);
    mql.addEventListener('change', onChange as (e: MediaQueryListEvent) => void);
    return () => mql.removeEventListener('change', onChange as (e: MediaQueryListEvent) => void);
  }, []);

  const showWebGL = isDesktop && !reducedMotion && webglCompatibility === 'supported';

  async function handleFeatureAction(action: FeatureAction) {
    setActiveActionId(action.appId);
    const outcome = await resolveWorkspaceNavigation({
      appId: action.appId,
      path: action.path,
      role: action.role,
      tenant: 'global',
    });
    setActiveActionId(null);

    if (outcome.kind === 'navigate' || outcome.kind === 'login_redirect') {
      window.location.assign(outcome.target);
      return;
    }

    setNotice(outcome);
  }

  return (
    <section id="features" className="relative pt-6 pb-24 sm:pt-10 sm:pb-32 bg-[#0A0A0F] overflow-hidden">
      {/* Background Accent */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[600px] h-[600px] bg-cyan-500/5 rounded-full blur-[120px]" />

      {/* 3D Background Layer */}
      <div className="absolute inset-0 z-0 opacity-40 pointer-events-none">
        {showWebGL ? (
          <Suspense fallback={null}>
            <CyberShieldScene />
          </Suspense>
        ) : (
          <div
            className="w-full h-full"
            style={{
              background:
                'radial-gradient(ellipse at 50% 40%, rgba(0,240,255,0.08) 0%, rgba(139,92,246,0.06) 40%, transparent 70%)',
            }}
          />
        )}
        {/* Fade overlays to blend 3D into section */}
        <div className="absolute inset-0 bg-gradient-to-b from-[#0A0A0F] via-transparent to-[#0A0A0F]" />
        <div className="absolute inset-0 bg-gradient-to-r from-[#0A0A0F]/60 via-transparent to-[#0A0A0F]/60" />
      </div>

      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6" ref={ref}>
        {/* Section Header */}
        <div className="text-center mb-16 sm:mb-20">
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-cyan-500/20 bg-cyan-500/5 mb-6">
            <Lock className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-cyan-300 text-xs font-semibold tracking-widest uppercase">
              Core Capabilities
            </span>
          </div>
          <h2 className="text-3xl sm:text-4xl md:text-5xl font-bold text-white mb-4">
            Enterprise-Grade{' '}
            <span className="bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
              Defense Systems
            </span>
          </h2>
          <p className="text-slate-400 text-lg max-w-2xl mx-auto">
            Core platform modules wired to real backend workflows with secure
            contracts and deploy-ready infrastructure.
          </p>
        </div>

        {/* Feature Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 lg:gap-8">
          {FEATURES.map((feature, index) => (
            <div
              key={feature.title}
              className={`panel-3d group relative rounded-2xl border border-white/[0.06] bg-slate-900/50 backdrop-blur-xl p-8 transition-all duration-700 hover:border-white/[0.12] hover:-translate-y-1 ${
                visibleItems[index]
                  ? 'opacity-100 translate-y-0'
                  : 'opacity-0 translate-y-12'
              }`}
              style={{
                boxShadow: `0 0 0px ${feature.glowColor}`,
                transition:
                  'opacity 0.7s, transform 0.7s, box-shadow 0.4s, border-color 0.4s',
              }}
              onMouseEnter={(e) => {
                (e.currentTarget as HTMLElement).style.boxShadow = `0 0 60px ${feature.glowColor}`;
              }}
              onMouseLeave={(e) => {
                (e.currentTarget as HTMLElement).style.boxShadow = `0 0 0px ${feature.glowColor}`;
              }}
            >
              {/* Icon */}
              <div
                className={`w-14 h-14 rounded-xl ${feature.iconBg} flex items-center justify-center mb-6 group-hover:scale-110 transition-transform duration-300`}
              >
                <feature.icon className={`w-7 h-7 ${feature.iconColor}`} />
              </div>

              {/* Title & Subtitle */}
              <h3 className="text-xl sm:text-2xl font-bold text-white mb-1">
                {feature.title}
              </h3>
              <p
                className={`text-sm font-medium bg-gradient-to-r ${feature.gradient} bg-clip-text text-transparent mb-4`}
              >
                {feature.subtitle}
              </p>

              {/* Description */}
              <p className="text-slate-400 text-sm leading-relaxed mb-6">
                {feature.description}
              </p>

              <button
                type="button"
                disabled={activeActionId === feature.action.appId}
                title={
                  activeActionId === feature.action.appId
                    ? 'Validating tenant, role, and product access...'
                    : undefined
                }
                className="inline-flex items-center gap-2 text-xs font-semibold tracking-wide uppercase text-cyan-300 hover:text-cyan-200 transition-colors mb-6"
                onClick={() => void handleFeatureAction(feature.action)}
              >
                {activeActionId === feature.action.appId ? 'Checking Access...' : feature.action.label}
                <ArrowRight className="w-3.5 h-3.5" />
              </button>

              {/* Highlights */}
              <div className="flex flex-wrap gap-2">
                {feature.highlights.map((h) => (
                  <span
                    key={h}
                    className="px-3 py-1 text-xs font-medium rounded-full bg-white/5 text-slate-300 border border-white/[0.06]"
                  >
                    {h}
                  </span>
                ))}
              </div>

              {/* Corner Decorations */}
              <div className="absolute top-0 right-0 w-20 h-20 overflow-hidden rounded-tr-2xl">
                <div
                  className={`absolute top-0 right-0 w-[1px] h-12 bg-gradient-to-b ${feature.gradient} opacity-30`}
                />
                <div
                  className={`absolute top-0 right-0 h-[1px] w-12 bg-gradient-to-l ${feature.gradient} opacity-30`}
                />
              </div>
            </div>
          ))}
        </div>

        {/* Bottom Stats */}
        <div className="mt-16 grid grid-cols-2 sm:grid-cols-4 gap-4">
          {[
            { icon: Shield, value: 'RBAC', label: 'Role Enforcement' },
            { icon: Eye, value: 'Audit', label: 'Traceability' },
            { icon: Server, value: 'API', label: 'Open Contracts' },
            { icon: Scan, value: 'Docker', label: 'Deploy Ready' },
          ].map((stat) => (
            <div
              key={stat.label}
              className="text-center p-5 rounded-xl bg-white/[0.02] border border-white/[0.04] transition-all duration-300 hover:border-cyan-500/20 hover:-translate-y-0.5"
            >
              <stat.icon className="w-5 h-5 text-cyan-400/60 mx-auto mb-2" />
              <div className="text-2xl font-bold text-white">{stat.value}</div>
              <div className="text-xs text-slate-500 mt-1">{stat.label}</div>
            </div>
          ))}
        </div>
      </div>
      <WorkspaceAccessNotice notice={notice} onClose={() => setNotice(null)} />
    </section>
  );
}
