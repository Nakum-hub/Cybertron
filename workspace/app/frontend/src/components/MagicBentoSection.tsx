import {
  Shield,
  Radar,
  BrainCircuit,
  Network,
  Scan,
  Lock,
  BarChart3,
  Fingerprint,
  Workflow,
} from 'lucide-react';
import ScrollStack, { ScrollStackItem } from './ScrollStack';

const CAPABILITY_CARDS = [
  {
    id: 'threat-detection',
    title: 'AI Threat Detection',
    subtitle: 'Autonomous & Adaptive',
    description:
      'ML-powered threat identification that evolves with emerging attack vectors. Autonomous detection across your entire infrastructure with zero-day coverage and behavioral anomaly recognition.',
    icon: BrainCircuit,
    gradient: 'from-violet-500 to-purple-600',
    glowColor: 'rgba(139, 92, 246, 0.15)',
    iconColor: 'text-violet-400',
    iconBg: 'bg-violet-500/10',
    borderAccent: 'border-violet-500/20',
    stats: [
      { label: 'Detection Rate', value: '99.7%', projected: true },
      { label: 'Avg Response', value: '<2s', projected: true },
      { label: 'False Positive', value: '0.02%', projected: true },
    ],
    features: ['Behavioral Analysis', 'Zero-Day Coverage', 'Adaptive ML Models', 'Cross-Infrastructure'],
  },
  {
    id: 'soc-operations',
    title: 'SOC Automation & Network Visibility',
    subtitle: 'Orchestrate & Monitor',
    description:
      'Automated triage, enrichment, and response workflows paired with full-spectrum network monitoring. Deep packet inspection and behavioral analytics reduce analyst fatigue while maximizing coverage.',
    icon: Workflow,
    gradient: 'from-cyan-500 to-blue-600',
    glowColor: 'rgba(0, 240, 255, 0.15)',
    iconColor: 'text-cyan-400',
    iconBg: 'bg-cyan-500/10',
    borderAccent: 'border-cyan-500/20',
    stats: [
      { label: 'Automation Rate', value: '87%', projected: true },
      { label: 'MTTR Reduction', value: '64%', projected: true },
      { label: 'Coverage', value: '100%', projected: true },
    ],
    features: ['Automated Triage', 'Response Playbooks', 'Deep Packet Inspection', 'Behavioral Analytics'],
    secondaryIcon: Network,
    secondaryIconColor: 'text-emerald-400',
  },
  {
    id: 'vulnerability-identity',
    title: 'Vulnerability Assessment & Identity Fabric',
    subtitle: 'Scan & Govern',
    description:
      'Persistent scanning across endpoints, containers, and cloud assets with prioritized remediation. Unified identity governance across hybrid environments with adaptive access policies.',
    icon: Scan,
    gradient: 'from-amber-500 to-orange-600',
    glowColor: 'rgba(255, 184, 0, 0.15)',
    iconColor: 'text-amber-400',
    iconBg: 'bg-amber-500/10',
    borderAccent: 'border-amber-500/20',
    stats: [
      { label: 'CVEs Tracked', value: '12K+', projected: true },
      { label: 'Scan Frequency', value: 'Real-time', projected: true },
      { label: 'Identity Sources', value: '40+', projected: true },
    ],
    features: ['Auto-Prioritization', 'Container Scanning', 'Adaptive Access', 'Hybrid IAM'],
    secondaryIcon: Fingerprint,
    secondaryIconColor: 'text-pink-400',
  },
  {
    id: 'compliance',
    title: 'Compliance Intelligence',
    subtitle: 'Map & Report',
    description:
      'Automated compliance mapping across frameworks with continuous evidence collection and audit-ready reporting. Stay compliant across multiple regulatory standards simultaneously.',
    icon: BarChart3,
    gradient: 'from-blue-500 to-indigo-600',
    glowColor: 'rgba(59, 130, 246, 0.15)',
    iconColor: 'text-blue-400',
    iconBg: 'bg-blue-500/10',
    borderAccent: 'border-blue-500/20',
    stats: [
      { label: 'Frameworks', value: '15+', projected: true },
      { label: 'Evidence Points', value: '2.4K', projected: true },
      { label: 'Audit Prep', value: 'Auto', projected: true },
    ],
    features: ['SOC 2', 'ISO 27001', 'NIST CSF', 'HIPAA', 'PCI DSS', 'GDPR'],
  },
  {
    id: 'zero-trust-intel',
    title: 'Zero Trust & Threat Intelligence',
    subtitle: 'Verify & Correlate',
    description:
      'Every request verified with micro-segmentation and continuous validation at every layer. Correlated intelligence from global feeds, dark web monitoring, and industry-specific IOC databases.',
    icon: Lock,
    gradient: 'from-teal-500 to-cyan-600',
    glowColor: 'rgba(20, 184, 166, 0.15)',
    iconColor: 'text-teal-400',
    iconBg: 'bg-teal-500/10',
    borderAccent: 'border-teal-500/20',
    stats: [
      { label: 'Policies Active', value: '840+', projected: true },
      { label: 'Intel Feeds', value: '200+', projected: true },
      { label: 'IOC Database', value: '18M+', projected: true },
    ],
    features: ['Micro-Segmentation', 'Continuous Validation', 'Dark Web Monitoring', 'Global IOC Feeds'],
    secondaryIcon: Radar,
    secondaryIconColor: 'text-red-400',
  },
] as const;

export default function MagicBentoSection() {
  return (
    <section id="capabilities" className="relative bg-[#070910]">
      {/* Background accents */}
      <div className="absolute top-1/4 left-0 w-[500px] h-[500px] bg-violet-600/5 rounded-full blur-[140px] pointer-events-none" />
      <div className="absolute bottom-1/4 right-0 w-[400px] h-[400px] bg-cyan-600/5 rounded-full blur-[120px] pointer-events-none" />

      {/* Section Header (outside ScrollStack so it scrolls normally) */}
      <div className="relative z-10 text-center pt-24 sm:pt-32 pb-4 px-4">
        <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-violet-500/20 bg-violet-500/5 mb-6">
          <Shield className="w-3.5 h-3.5 text-violet-400" />
          <span className="text-violet-300 text-xs font-semibold tracking-widest uppercase">
            Platform Capabilities
          </span>
        </div>
        <h2 className="text-3xl sm:text-4xl md:text-5xl font-bold text-white mb-4">
          Everything You Need to{' '}
          <span className="bg-gradient-to-r from-violet-400 via-cyan-400 to-emerald-400 bg-clip-text text-transparent">
            Defend & Operate
          </span>
        </h2>
        <p className="text-slate-400 text-lg max-w-2xl mx-auto">
          Scroll through our modular capabilities engineered for enterprise-scale cyber defense.
        </p>
      </div>

      {/* Scroll Stack */}
      <div className="relative z-10 max-w-5xl mx-auto px-4 sm:px-6">
        <ScrollStack
          useWindowScroll
          itemDistance={120}
          itemScale={0.025}
          itemStackDistance={36}
          stackPosition="18%"
          scaleEndPosition="8%"
          baseScale={0.88}
          blurAmount={1.5}
        >
          {CAPABILITY_CARDS.map((card) => (
            <ScrollStackItem key={card.id}>
              <div
                className="p-6 sm:p-8 lg:p-10"
                style={{ boxShadow: `0 0 0px ${card.glowColor}` }}
                onMouseEnter={(e) => {
                  (e.currentTarget as HTMLElement).style.boxShadow = `0 0 60px ${card.glowColor}, 0 0 100px ${card.glowColor}`;
                }}
                onMouseLeave={(e) => {
                  (e.currentTarget as HTMLElement).style.boxShadow = `0 0 0px ${card.glowColor}`;
                }}
              >
                {/* Top accent line */}
                <div
                  className={`absolute top-0 inset-x-0 h-[2px] bg-gradient-to-r ${card.gradient} opacity-40`}
                />

                {/* Glow */}
                <div
                  className="absolute inset-0 pointer-events-none"
                  style={{
                    background: `radial-gradient(600px circle at 30% 20%, ${card.glowColor}, transparent 70%)`,
                  }}
                />

                <div className="relative z-10">
                  {/* Header row */}
                  <div className="flex items-start gap-4 mb-6">
                    <div
                      className={`flex-shrink-0 w-12 h-12 rounded-xl ${card.iconBg} border ${card.borderAccent} flex items-center justify-center`}
                    >
                      <card.icon className={`w-6 h-6 ${card.iconColor}`} />
                    </div>
                    {'secondaryIcon' in card && card.secondaryIcon && (
                      <div
                        className={`flex-shrink-0 w-12 h-12 rounded-xl bg-white/[0.03] border border-white/[0.06] flex items-center justify-center -ml-2`}
                      >
                        <card.secondaryIcon className={`w-6 h-6 ${card.secondaryIconColor}`} />
                      </div>
                    )}
                    <div>
                      <p className={`text-[11px] font-semibold tracking-wider uppercase bg-gradient-to-r ${card.gradient} bg-clip-text text-transparent mb-1`}>
                        {card.subtitle}
                      </p>
                      <h3 className="text-xl sm:text-2xl font-bold text-white">
                        {card.title}
                      </h3>
                    </div>
                  </div>

                  {/* Description */}
                  <p className="text-slate-400 text-sm sm:text-base leading-relaxed mb-6 max-w-3xl">
                    {card.description}
                  </p>

                  {/* Stats row */}
                  <div className="grid grid-cols-3 gap-4 mb-2">
                    {card.stats.map((stat) => (
                      <div
                        key={stat.label}
                        className="rounded-xl bg-white/[0.03] border border-white/[0.05] p-3 sm:p-4 text-center"
                      >
                        <div
                          className={`text-lg sm:text-2xl font-bold bg-gradient-to-r ${card.gradient} bg-clip-text text-transparent`}
                        >
                          {stat.value}{'projected' in stat && stat.projected && <span className="text-slate-600 text-xs align-super">*</span>}
                        </div>
                        <div className="text-[10px] sm:text-xs text-slate-500 mt-1">{stat.label}</div>
                      </div>
                    ))}
                  </div>
                  {card.stats.some((s) => 'projected' in s && s.projected) && (
                    <p className="text-[10px] text-slate-600 mb-4">* Projected platform targets, not measured from live deployment data.</p>
                  )}

                  {/* Feature pills */}
                  <div className="flex flex-wrap gap-2">
                    {card.features.map((feat) => (
                      <span
                        key={feat}
                        className="px-3 py-1.5 text-[11px] font-medium rounded-full bg-white/[0.04] text-slate-300 border border-white/[0.06]"
                      >
                        {feat}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </ScrollStackItem>
          ))}
        </ScrollStack>
      </div>
    </section>
  );
}
