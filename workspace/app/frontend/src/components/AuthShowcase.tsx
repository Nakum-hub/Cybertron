import {
  ArrowRight,
  Fingerprint,
  Github,
  Globe,
  Mail,
  Monitor,
  ScanFace,
  ShieldCheck,
  Smartphone,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useInView, useStaggeredAnimation } from '@/lib/animations';

const AUTH_FEATURES = [
  {
    icon: Mail,
    title: 'Zero-Trust Authentication',
    desc: 'Every access request is independently verified before granting entry. Multi-layered credential validation ensures only authorized users reach your workspace.',
    cta: 'Get Started',
    href: '/account?mode=register',
    color: 'text-cyan-400',
    bg: 'bg-cyan-500/10',
    glowColor: 'rgba(0, 240, 255, 0.15)',
  },
  {
    icon: Fingerprint,
    title: 'Multi-Tenant Isolation',
    desc: 'Complete data segregation per workspace. Each organization operates in a fully isolated environment with no cross-tenant data leakage.',
    cta: 'View Status',
    href: '/status',
    color: 'text-purple-400',
    bg: 'bg-purple-500/10',
    glowColor: 'rgba(168, 85, 247, 0.15)',
  },
  {
    icon: Smartphone,
    title: 'Granular RBAC Engine',
    desc: 'Five hierarchical roles with precise access control. Users see only what they are authorized to access — from executive dashboards to analyst workbenches.',
    cta: 'See Pricing',
    href: '/pricing',
    color: 'text-emerald-400',
    bg: 'bg-emerald-500/10',
    glowColor: 'rgba(52, 211, 153, 0.15)',
  },
  {
    icon: Monitor,
    title: 'Adaptive Threat Detection',
    desc: 'Intelligent protection against unauthorized access attempts. Automated responses to suspicious activity keep your workspace secure around the clock.',
    cta: 'View Status',
    href: '/status',
    color: 'text-amber-400',
    bg: 'bg-amber-500/10',
    glowColor: 'rgba(251, 191, 36, 0.15)',
  },
  {
    icon: ShieldCheck,
    title: 'Compliance Audit Trail',
    desc: 'Every security-relevant event is recorded with full traceability. Meet SOC2, GDPR, and enterprise compliance requirements out of the box.',
    cta: 'Learn More',
    href: '/products/compliance-engine',
    color: 'text-red-400',
    bg: 'bg-red-500/10',
    glowColor: 'rgba(239, 68, 68, 0.15)',
  },
  {
    icon: ScanFace,
    title: 'Social & Enterprise SSO',
    desc: 'Sign in with Google, Microsoft, or GitHub. Enterprise organizations can integrate their existing identity provider for seamless single sign-on.',
    cta: 'Try Login',
    href: '/account?mode=login',
    color: 'text-blue-400',
    bg: 'bg-blue-500/10',
    glowColor: 'rgba(59, 130, 246, 0.15)',
  },
];

const FOOTER_LINKS = [
  {
    title: 'Product',
    links: [
      { label: 'Features', href: '/#features' },
      { label: 'Pricing', href: '/pricing' },
      { label: 'Security', href: '/#dashboard' },
      { label: 'Enterprise', href: '/#auth' },
    ],
  },
  {
    title: 'Company',
    links: [
      { label: 'About', href: '/about' },
      { label: 'Blog', href: '/blog' },
      { label: 'Careers', href: 'mailto:careers@cybertron.io?subject=Career%20at%20Cybertron' },
      { label: 'Press', href: 'mailto:press@cybertron.io?subject=Cybertron%20Press' },
      { label: 'Partners', href: 'mailto:partners@cybertron.io?subject=Cybertron%20Partnership' },
    ],
  },
  {
    title: 'Resources',
    links: [
      { label: 'Documentation', href: '/docs' },
      { label: 'Status', href: '/status' },
      { label: 'Blog', href: '/blog' },
      { label: 'Pricing', href: '/pricing' },
      { label: 'Community', href: 'mailto:community@cybertron.io?subject=Cybertron%20Community' },
      { label: 'Support', href: 'mailto:support@cybertron.io?subject=Cybertron%20Support' },
    ],
  },
  {
    title: 'Legal',
    links: [
      { label: 'Privacy', href: '/legal/privacy' },
      { label: 'Terms', href: '/legal/terms' },
      { label: 'Cookie Policy', href: '/legal/cookies' },
      { label: 'Licenses', href: 'mailto:legal@cybertron.io?subject=Cybertron%20Licenses' },
      { label: 'GDPR', href: 'mailto:legal@cybertron.io?subject=GDPR%20Request' },
    ],
  },
];

const SOCIAL_LINKS = [
  { icon: Github, href: 'https://github.com/cybertron-io', label: 'GitHub' },
];

function toLinkTarget(href: string): '_self' | '_blank' {
  if (href.startsWith('http://') || href.startsWith('https://')) {
    return '_blank';
  }

  return '_self';
}

export default function AuthShowcase() {
  const { ref: authRef, visibleItems } = useStaggeredAnimation(AUTH_FEATURES.length, 150);
  const { ref: ctaRef, isInView: ctaInView } = useInView(0.2);

  return (
    <>
      <section id="auth" className="relative py-24 sm:py-32 bg-[#0A0A0F]">
        <div className="absolute top-0 right-1/4 w-[400px] h-[400px] bg-purple-600/5 rounded-full blur-[120px]" />

        <div className="relative max-w-7xl mx-auto px-4 sm:px-6">
          <div className="text-center mb-16">
            <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-emerald-500/20 bg-emerald-500/5 mb-6">
              <Fingerprint className="w-3.5 h-3.5 text-emerald-400" />
              <span className="text-emerald-300 text-xs font-semibold tracking-widest uppercase">
                Authentication
              </span>
            </div>
            <h2 className="text-3xl sm:text-4xl md:text-5xl font-bold text-white mb-4">
              Next-Gen{' '}
              <span className="bg-gradient-to-r from-emerald-400 to-teal-500 bg-clip-text text-transparent">
                Identity Security
              </span>
            </h2>
            <p className="text-slate-400 text-lg max-w-2xl mx-auto">
              Enterprise-grade identity infrastructure with zero-trust verification, multi-tenant isolation,
              role-based access control, and full compliance audit coverage — built for global scale.
            </p>
          </div>

          <div ref={authRef} className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-6">
            {AUTH_FEATURES.map((feature, index) => (
              <div
                key={feature.title}
                className={`panel-3d group p-6 rounded-2xl bg-white/[0.02] border border-white/[0.06] hover:border-white/[0.12] transition-all duration-700 hover:-translate-y-1 ${visibleItems[index] ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-12'
                  }`}
                style={{ boxShadow: `0 0 0px ${feature.glowColor}` }}
                onMouseEnter={(e) => {
                  (e.currentTarget as HTMLElement).style.boxShadow = `0 0 60px ${feature.glowColor}, 0 0 100px ${feature.glowColor}`;
                }}
                onMouseLeave={(e) => {
                  (e.currentTarget as HTMLElement).style.boxShadow = `0 0 0px ${feature.glowColor}`;
                }}
              >
                <div
                  className={`w-12 h-12 rounded-xl ${feature.bg} flex items-center justify-center mb-4 group-hover:scale-110 transition-transform duration-300`}
                >
                  <feature.icon className={`w-6 h-6 ${feature.color}`} />
                </div>
                <h3 className="text-lg font-bold text-white mb-2">{feature.title}</h3>
                <p className="text-sm text-slate-400 leading-relaxed">{feature.desc}</p>
                <button
                  type="button"
                  onClick={() => window.location.assign(feature.href)}
                  className="mt-4 inline-flex items-center gap-1.5 rounded-lg border border-cyan-300/25 bg-cyan-400/10 px-3 py-1.5 text-[11px] font-semibold uppercase tracking-wide text-cyan-100 hover:bg-cyan-400/15"
                >
                  {feature.cta}
                  <ArrowRight className="h-3.5 w-3.5" />
                </button>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="relative py-24 sm:py-32 bg-[#080810]" ref={ctaRef}>
        <div className="absolute inset-0 bg-gradient-to-b from-cyan-500/5 via-transparent to-transparent" />

        <div
          className={`relative max-w-4xl mx-auto px-4 sm:px-6 text-center transition-all duration-1000 ${ctaInView ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-12'
            }`}
        >
          <h2 className="text-3xl sm:text-4xl md:text-5xl font-bold text-white mb-6">
            Ready to Defend the{' '}
            <span className="bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-500 bg-clip-text text-transparent">
              Future?
            </span>
          </h2>
          <p className="text-slate-400 text-lg mb-10 max-w-2xl mx-auto">
            Join enterprises already using Cybertron to protect digital infrastructure. Start free
            and scale with confidence.
          </p>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-16">
            <Button
              size="lg"
              type="button"
              className="magnetic-btn bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-semibold px-10 py-6 text-lg rounded-xl shadow-[0_0_40px_rgba(0,240,255,0.3)] hover:shadow-[0_0_60px_rgba(0,240,255,0.5)] transition-all duration-300 hover:-translate-y-1"
              onClick={() => {
                window.location.assign('/account?mode=register');
              }}
            >
              Start Free Trial
              <ArrowRight className="w-5 h-5 ml-2" />
            </Button>
            <Button
              size="lg"
              type="button"
              variant="outline"
              className="magnetic-btn !bg-transparent border-white/20 text-white hover:!bg-white/5 font-semibold px-10 py-6 text-lg rounded-xl transition-all duration-300 hover:-translate-y-1"
              onClick={() =>
                window.location.assign(
                  'mailto:sales@cybertron.io?subject=Cybertron%20Live%20Demo%20Request'
                )
              }
            >
              Request Demo
            </Button>
          </div>

          <div className="p-8 rounded-2xl bg-white/[0.02] border border-white/[0.06] text-left max-w-3xl mx-auto">
            <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
              <Globe className="w-5 h-5 text-cyan-400" />
              Investor Summary
            </h3>
            <div className="space-y-3 text-sm text-slate-400">
              <p>
                <strong className="text-white">Elevator Pitch:</strong> Cybertron is a full-stack
                cyber operations platform combining secure identity, tenant-isolated workflows,
                incident operations, and auditable enterprise modules in one command center.
              </p>
              <p>
                <strong className="text-white">Why We Win:</strong> Real backend contracts,
                production-ready deployment paths, and truthful telemetry make execution reliable,
                not speculative.
              </p>
              <p>
                <strong className="text-white">5-Year Vision:</strong> A global standard for
                autonomous cyber defense protecting enterprises across 100+ countries.
              </p>
            </div>
          </div>
        </div>
      </section>

      <footer className="relative bg-[#060608] border-t border-white/[0.04]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 py-16">
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-5 gap-8">
            <div className="col-span-2 sm:col-span-4 lg:col-span-1 mb-4 lg:mb-0">
              <div className="flex items-center gap-3 mb-4">
                <img
                  src="/assets/auth-showcase-team.png"
                  alt="Cybertron"
                  className="w-10 h-10 rounded-lg"
                  loading="lazy"
                />
                <span className="text-lg font-bold text-white">Cybertron</span>
              </div>
              <p className="text-sm text-slate-500 mb-4 max-w-xs">
                Enterprise Cyber Operations Platform for autonomous defense at scale.
              </p>
              <div className="flex items-center gap-3">
                {SOCIAL_LINKS.map(item => (
                  <a
                    key={item.label}
                    href={item.href}
                    target={toLinkTarget(item.href)}
                    rel="noreferrer"
                    className="w-9 h-9 rounded-lg bg-white/[0.04] border border-white/[0.06] flex items-center justify-center hover:border-cyan-500/30 hover:bg-cyan-500/5 transition-colors"
                    aria-label={item.label}
                  >
                    <item.icon className="w-4 h-4 text-slate-400" />
                  </a>
                ))}
              </div>
            </div>

            {FOOTER_LINKS.map(col => (
              <div key={col.title}>
                <h4 className="text-sm font-semibold text-white mb-4">{col.title}</h4>
                <ul className="space-y-2.5">
                  {col.links.map(link => (
                    <li key={link.label}>
                      <a
                        href={link.href}
                        target={toLinkTarget(link.href)}
                        rel="noreferrer"
                        className="text-sm text-slate-500 hover:text-cyan-400 transition-colors"
                      >
                        {link.label}
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>

          <div className="mt-12 pt-8 border-t border-white/[0.04] flex flex-col sm:flex-row items-center justify-between gap-4">
            <p className="text-xs text-slate-600">
              Copyright 2026 Cybertron. All rights reserved. Built for the future.
            </p>
            <div className="flex items-center gap-4">
              <a
                href="/legal/privacy"
                className="text-xs text-slate-600 hover:text-slate-400 transition-colors"
              >
                Privacy Policy
              </a>
              <a
                href="/legal/terms"
                className="text-xs text-slate-600 hover:text-slate-400 transition-colors"
              >
                Terms of Service
              </a>
              <a
                href="/legal/cookies"
                className="text-xs text-slate-600 hover:text-slate-400 transition-colors"
              >
                Cookie Policy
              </a>
            </div>
          </div>
        </div>
      </footer>
    </>
  );
}
