import {
  Server,
  Database,
  Cloud,
  Lock,
  Key,
  FileCheck,
  Layers,
  GitBranch,
  Container,
  Cpu,
} from 'lucide-react';
import { useStaggeredAnimation, useInView } from '@/lib/animations';

const PLATFORM_INTEGRITY_IMG = '/assets/architecture-platform-integrity.png';
const SHIELD_IMG = '/assets/architecture-shield.png';

const ARCH_LAYERS = [
  {
    title: 'Frontend Security',
    icon: Lock,
    items: [
      'CSP + Security Headers',
      'Runtime Config via /api/config',
      'Reduced-Motion Accessibility',
      'Error Boundary Protection',
    ],
    color: 'cyan',
  },
  {
    title: 'Backend Services',
    icon: Server,
    items: [
      'JWT + Refresh Token Auth',
      'Auth Abuse Rate Limiting',
      'Tenant + RBAC Enforcement',
      'OpenAPI Contract Surface',
    ],
    color: 'purple',
  },
  {
    title: 'Data Layer',
    icon: Database,
    items: [
      'PostgreSQL Persistence',
      'Migration Pipeline',
      'Incident + IOC + Reports',
      'Audit Log Retention',
    ],
    color: 'emerald',
  },
  {
    title: 'Infrastructure',
    icon: Cloud,
    items: [
      'Docker Compose Dev/Prod',
      'CI Quality Gates',
      'Nginx API Proxying',
      'Environment-Driven Config',
    ],
    color: 'amber',
  },
];

const WEB3_FEATURES = [
  {
    icon: FileCheck,
    title: 'Contract Transparency',
    desc: 'OpenAPI and typed frontend contracts keep backend integrations explicit, testable, and version-friendly.',
  },
  {
    icon: Key,
    title: 'Credential Hardening',
    desc: 'Password hashing, lockout policy, refresh rotation, and revocation provide secure session lifecycle control.',
  },
  {
    icon: Layers,
    title: 'Operational Modules',
    desc: 'Threat, identity, and resilience modules are wired to real tenant-scoped workflows and persistence.',
  },
  {
    icon: GitBranch,
    title: 'Integration Ready',
    desc: 'Connector contracts support Wazuh, MISP, OpenCTI, and TheHive without fabricated fallback threat signals.',
  },
];

const TECH_STACK = [
  { category: 'Frontend', items: ['React', 'TypeScript', 'Vite', 'TailwindCSS'], icon: Cpu },
  { category: 'Backend', items: ['Node.js', 'HTTP API', 'OpenAPI', 'Validation'], icon: Server },
  { category: 'Security', items: ['RBAC', 'Rate Limiting', 'Audit Logs', 'CSP Headers'], icon: Lock },
  { category: 'Data', items: ['PostgreSQL', 'Migrations', 'Tenant Scoping', 'Trace IDs'], icon: Container },
  { category: 'DevOps', items: ['Docker', 'GitHub CI', 'Nginx Proxy', 'Env Templates'], icon: Cloud },
];

export default function ArchitectureSection() {
  const { ref: archRef, visibleItems: archVisible } = useStaggeredAnimation(
    ARCH_LAYERS.length,
    200
  );
  const { ref: web3Ref, isInView: web3InView } = useInView(0.1);
  const { ref: stackRef, isInView: stackInView } = useInView(0.1);

  const colorMap: Record<string, { border: string; text: string; bg: string; glow: string }> = {
    cyan: {
      border: 'border-cyan-500/20',
      text: 'text-cyan-400',
      bg: 'bg-cyan-500/10',
      glow: 'rgba(0, 240, 255, 0.15)',
    },
    purple: {
      border: 'border-purple-500/20',
      text: 'text-purple-400',
      bg: 'bg-purple-500/10',
      glow: 'rgba(168, 85, 247, 0.15)',
    },
    emerald: {
      border: 'border-emerald-500/20',
      text: 'text-emerald-400',
      bg: 'bg-emerald-500/10',
      glow: 'rgba(52, 211, 153, 0.15)',
    },
    amber: {
      border: 'border-amber-500/20',
      text: 'text-amber-400',
      bg: 'bg-amber-500/10',
      glow: 'rgba(251, 191, 36, 0.15)',
    },
  };

  return (
    <section id="architecture" className="relative py-24 sm:py-32 bg-[#0A0A0F]">
      <div className="absolute bottom-0 right-0 w-[500px] h-[500px] bg-purple-600/5 rounded-full blur-[120px]" />

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6">
        {/* Section Header */}
        <div className="text-center mb-16">
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-purple-500/20 bg-purple-500/5 mb-6">
            <Layers className="w-3.5 h-3.5 text-purple-400" />
            <span className="text-purple-300 text-xs font-semibold tracking-widest uppercase">
              Architecture
            </span>
          </div>
          <h2 className="text-3xl sm:text-4xl md:text-5xl font-bold text-white mb-4">
            Security-First{' '}
            <span className="bg-gradient-to-r from-purple-400 to-pink-500 bg-clip-text text-transparent">
              Architecture
            </span>
          </h2>
          <p className="text-slate-400 text-lg max-w-2xl mx-auto">
            Every layer engineered for defense with implementation details that
            map directly to this production codebase.
          </p>
        </div>

        {/* Architecture Layers */}
        <div
          ref={archRef}
          className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-20"
        >
          {ARCH_LAYERS.map((layer, index) => {
            const colors = colorMap[layer.color];
            return (
              <div
                key={layer.title}
                className={`panel-3d p-6 rounded-2xl bg-slate-900/50 backdrop-blur-sm border ${colors.border} transition-all duration-700 hover:bg-slate-900/70 ${
                  archVisible[index]
                    ? 'opacity-100 translate-y-0'
                    : 'opacity-0 translate-y-12'
                }`}
                style={{ boxShadow: `0 0 0px ${colors.glow}` }}
                onMouseEnter={(e) => {
                  (e.currentTarget as HTMLElement).style.boxShadow = `0 0 60px ${colors.glow}, 0 0 100px ${colors.glow}`;
                }}
                onMouseLeave={(e) => {
                  (e.currentTarget as HTMLElement).style.boxShadow = `0 0 0px ${colors.glow}`;
                }}
              >
                <div
                  className={`w-12 h-12 rounded-xl ${colors.bg} flex items-center justify-center mb-4`}
                >
                  <layer.icon className={`w-6 h-6 ${colors.text}`} />
                </div>
                <h3 className="text-lg font-bold text-white mb-3">
                  {layer.title}
                </h3>
                <ul className="space-y-2">
                  {layer.items.map((item) => (
                    <li
                      key={item}
                      className="flex items-start gap-2 text-sm text-slate-400"
                    >
                      <span className={`mt-1.5 w-1.5 h-1.5 rounded-full ${colors.bg} flex-shrink-0`} />
                      {item}
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
        </div>

        {/* Platform Integrity */}
        <div ref={web3Ref} className="mb-20">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-center">
            {/* Left: Image */}
            <div
              className={`relative rounded-2xl overflow-hidden transition-all duration-1000 ${
                web3InView
                  ? 'opacity-100 translate-x-0'
                  : 'opacity-0 -translate-x-12'
              }`}
            >
              <img src={PLATFORM_INTEGRITY_IMG} alt="Cybertron Platform Integrity" className="w-full rounded-2xl" loading="lazy" />
              <div className="absolute inset-0 bg-gradient-to-r from-[#0A0A0F]/50 to-transparent" />
            </div>

            {/* Right: Integrity Features */}
            <div
              className={`transition-all duration-1000 delay-300 ${
                web3InView
                  ? 'opacity-100 translate-x-0'
                  : 'opacity-0 translate-x-12'
              }`}
            >
              <h3 className="text-2xl sm:text-3xl font-bold text-white mb-2">
                Platform Integrity
              </h3>
              <p className="text-slate-400 mb-8">
                Security and reliability controls that are implemented, testable,
                and deployable today.
              </p>
              <div className="space-y-4">
                {WEB3_FEATURES.map((feature) => (
                  <div
                    key={feature.title}
                    className="flex gap-4 p-4 rounded-xl bg-white/[0.02] border border-white/[0.06] hover:border-purple-500/20 transition-colors"
                  >
                    <div className="w-10 h-10 rounded-lg bg-purple-500/10 flex items-center justify-center flex-shrink-0">
                      <feature.icon className="w-5 h-5 text-purple-400" />
                    </div>
                    <div>
                      <h4 className="text-sm font-semibold text-white mb-1">
                        {feature.title}
                      </h4>
                      <p className="text-xs text-slate-400 leading-relaxed">
                        {feature.desc}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Zero Trust Visual */}
        <div className="mb-20">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-center">
            <div>
              <h3 className="text-2xl sm:text-3xl font-bold text-white mb-2">
                Zero-Trust Model
              </h3>
              <p className="text-slate-400 mb-6">
                Every request authenticated. Every action verified. No implicit
                trust - ever.
              </p>
              <div className="space-y-3">
                {[
                  {
                    step: '01',
                    title: 'Identity Verification',
                    desc: 'Credential checks with role normalization and tenant scoping',
                  },
                  {
                    step: '02',
                    title: 'Authorization Enforcement',
                    desc: 'Role checks gate incidents, reports, users, tenants, and audit endpoints',
                  },
                  {
                    step: '03',
                    title: 'Token Lifecycle',
                    desc: 'Access expiry + refresh rotation + revocation on logout/password reset',
                  },
                  {
                    step: '04',
                    title: 'Operational Traceability',
                    desc: 'Audit logs record critical actions with trace IDs and actor metadata',
                  },
                ].map((item) => (
                  <div
                    key={item.step}
                    className="flex items-start gap-4 p-4 rounded-xl bg-white/[0.02] border border-white/[0.06]"
                  >
                    <span className="text-2xl font-bold bg-gradient-to-r from-emerald-400 to-teal-500 bg-clip-text text-transparent">
                      {item.step}
                    </span>
                    <div>
                      <h4 className="text-sm font-semibold text-white">
                        {item.title}
                      </h4>
                      <p className="text-xs text-slate-400">{item.desc}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div className="relative rounded-2xl overflow-hidden">
              <img
                src={SHIELD_IMG}
                alt="Zero Trust Shield"
                className="w-full rounded-2xl"
                loading="lazy"
              />
              <div className="absolute inset-0 bg-gradient-to-l from-[#0A0A0F]/50 to-transparent" />
            </div>
          </div>
        </div>

        {/* Tech Stack */}
        <div ref={stackRef}>
          <h3 className="text-2xl font-bold text-white text-center mb-8">
            Tech Stack
          </h3>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
            {TECH_STACK.map((stack, i) => (
              <div
                key={stack.category}
                className={`p-5 rounded-xl bg-white/[0.02] border border-white/[0.06] text-center transition-all duration-700 hover:border-cyan-500/20 ${
                  stackInView
                    ? 'opacity-100 translate-y-0'
                    : 'opacity-0 translate-y-8'
                }`}
                style={{ transitionDelay: `${i * 100}ms` }}
              >
                <stack.icon className="w-6 h-6 text-cyan-400 mx-auto mb-3" />
                <h4 className="text-sm font-semibold text-white mb-2">
                  {stack.category}
                </h4>
                <div className="space-y-1">
                  {stack.items.map((item) => (
                    <div
                      key={item}
                      className="text-[11px] text-slate-400 font-mono"
                    >
                      {item}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

