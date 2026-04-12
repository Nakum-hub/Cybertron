import { useState, useEffect, useMemo, useRef, type PointerEvent as ReactPointerEvent } from 'react';
import { Shield, UserRound, LayoutDashboard, ChevronDown, Globe, Zap } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  useMouseParallax,
  generateParticles,
  motionParallax,
  useReducedMotionPreference,
} from '@/lib/animations';
import { useAuthStatus } from '@/hooks/use-auth-status';
import { useThreatData } from '@/hooks/use-threat-data';
import { normalizeRole } from '@/lib/platform-registry';
import { buildWorkspaceTarget } from '@/lib/workspace-access';

const HERO_BG = '/assets/hero-bg.png';

export default function HeroSection() {
  const [loaded, setLoaded] = useState(false);
  const reducedMotion = useReducedMotionPreference();
  const { status: authStatus, profile } = useAuthStatus();
  const mouseOffset = useMouseParallax(reducedMotion ? 0.004 : 0.015);
  const particles = useMemo(() => generateParticles(reducedMotion ? 24 : 50), [reducedMotion]);
  const threatDataQuery = useThreatData();
  const logoCardRef = useRef<HTMLDivElement>(null);
  const heroRef = useRef<HTMLElement>(null);
  const primaryPath =
    authStatus === 'authenticated'
      ? buildWorkspaceTarget('/platform', profile?.tenant || 'global', normalizeRole(profile?.role || 'executive_viewer'))
      : '/account?mode=register';
  const primaryLabel = authStatus === 'authenticated' ? 'Open Workspace' : 'Create Account';
  const secondaryPath = authStatus === 'authenticated' ? '/account' : '/account?mode=login';
  const secondaryLabel = authStatus === 'authenticated' ? 'My Account' : 'Login';

  const summary = threatDataQuery.data?.summary;
  const incidents = threatDataQuery.data?.incidents ?? [];
  const openIncidents = useMemo(
    () => incidents.filter(incident => incident.status !== 'resolved').length,
    [incidents]
  );

  const statusBadge = useMemo(() => {
    if (threatDataQuery.isError || threatDataQuery.data?.dataSource === 'unavailable') {
      return {
        label: 'Telemetry Unavailable',
        indicatorClassName: 'bg-red-400',
      };
    }

    if (threatDataQuery.data?.dataSource === 'empty') {
      return {
        label: 'Telemetry Awaiting Data',
        indicatorClassName: 'bg-amber-300',
      };
    }

    return {
      label: 'Telemetry Live',
      indicatorClassName: 'bg-green-400',
    };
  }, [threatDataQuery.data?.dataSource, threatDataQuery.isError]);

  const stats = useMemo(
    () => [
      {
        icon: Shield,
        label: 'Active Threats',
        value: summary ? summary.activeThreats.toLocaleString() : '--',
      },
      {
        icon: Globe,
        label: 'Blocked Today',
        value: summary ? summary.blockedToday.toLocaleString() : '--',
      },
      {
        icon: Zap,
        label: 'Open Incidents',
        value: openIncidents.toLocaleString(),
      },
    ],
    [openIncidents, summary]
  );

  // Globe transform calculations
  const globeTiltX = reducedMotion ? -mouseOffset.y * 0.08 : -mouseOffset.y * 0.32;
  const globeTiltY = reducedMotion ? mouseOffset.x * 0.08 : mouseOffset.x * 0.36;
  const globeTiltZ = reducedMotion ? mouseOffset.x * 0.02 : mouseOffset.x * 0.06;

  const handleLogoPointerMove = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (reducedMotion || !logoCardRef.current) {
      return;
    }

    const rect = event.currentTarget.getBoundingClientRect();
    const x = (event.clientX - rect.left) / rect.width - 0.5;
    const y = (event.clientY - rect.top) / rect.height - 0.5;
    const tiltX = (-y * 16).toFixed(2);
    const tiltY = (x * 16).toFixed(2);
    const glowX = ((x + 0.5) * 100).toFixed(2);
    const glowY = ((y + 0.5) * 100).toFixed(2);

    logoCardRef.current.style.transform = `perspective(1100px) rotateX(${tiltX}deg) rotateY(${tiltY}deg) scale3d(1.02, 1.02, 1.02)`;
    logoCardRef.current.style.setProperty('--logo-glow-x', `${glowX}%`);
    logoCardRef.current.style.setProperty('--logo-glow-y', `${glowY}%`);
  };

  const resetLogoPointerTilt = () => {
    if (!logoCardRef.current) {
      return;
    }

    logoCardRef.current.style.transform = 'perspective(1100px) rotateX(0deg) rotateY(0deg) scale3d(1, 1, 1)';
    logoCardRef.current.style.setProperty('--logo-glow-x', '50%');
    logoCardRef.current.style.setProperty('--logo-glow-y', '50%');
  };

  const scrollToSection = (sectionId: string) => {
    if (typeof window === 'undefined') {
      return;
    }

    const target = document.getElementById(sectionId);
    if (!target) {
      return;
    }

    const navOffset = window.innerWidth < 768 ? 76 : 88;
    const top = Math.max(0, Math.round(window.scrollY + target.getBoundingClientRect().top - navOffset));
    window.scrollTo({
      top,
      behavior: reducedMotion ? 'auto' : 'smooth',
    });
  };

  useEffect(() => {
    const timer = setTimeout(() => setLoaded(true), 200);
    return () => clearTimeout(timer);
  }, []);

  return (
    <section
      id="hero"
      ref={heroRef}
      className="relative min-h-[30rem] md:min-h-[calc(62svh-4rem)] lg:min-h-[calc(66vh-4rem)] flex items-center justify-center overflow-hidden bg-[#0A0A0F]"
    >
      {/* Background Image with Parallax */}
      <div
        className="absolute -inset-[8%] z-0"
        style={{
          transform: `perspective(1600px) translate3d(${motionParallax(mouseOffset.x, reducedMotion)}px, ${motionParallax(mouseOffset.y, reducedMotion)}px, 0) rotateX(${globeTiltX.toFixed(2)}deg) rotateY(${globeTiltY.toFixed(2)}deg) rotateZ(${globeTiltZ.toFixed(2)}deg) scale(1.06)`,
          transformOrigin: 'center 42%',
          transition: reducedMotion ? 'transform 0.14s linear' : 'transform 0.32s cubic-bezier(0.22, 1, 0.36, 1)',
          willChange: 'auto',
        }}
      >
        <div
          className={reducedMotion ? 'absolute inset-0' : 'absolute inset-0 hero-globe-layer'}
          style={!reducedMotion ? { animationDuration: '30s' } : undefined}
        >
          <img
            src={HERO_BG}
            alt=""
            className="w-full h-full object-cover opacity-40 scale-[1.02]"
            fetchpriority="high"
            loading="eager"
          />
        </div>
        <div className="absolute inset-0 bg-gradient-to-b from-[#0A0A0F]/60 via-[#0A0A0F]/40 to-[#0A0A0F]" />
      </div>

      {/* Animated Grid Lines */}
      <div className="absolute inset-0 z-[1] opacity-10">
        <div
          className="w-full h-full"
          style={{
            backgroundImage: `
              linear-gradient(rgba(0,240,255,0.3) 1px, transparent 1px),
              linear-gradient(90deg, rgba(0,240,255,0.3) 1px, transparent 1px)
            `,
            backgroundSize: '80px 80px',
            animation: reducedMotion ? 'none' : 'gridMove 20s linear infinite',
          }}
        />
      </div>

      {/* Floating Particles */}
      <div className="absolute inset-0 z-[2] pointer-events-none">
        {particles.map((p) => (
          <div
            key={p.id}
            className="absolute rounded-full bg-cyan-400"
            style={{
              left: `${p.x}%`,
              top: `${p.y}%`,
              width: `${p.size}px`,
              height: `${p.size}px`,
              opacity: p.opacity,
              animation: reducedMotion
                ? 'none'
                : `float ${p.duration}s ease-in-out ${p.delay}s infinite alternate`,
            }}
          />
        ))}
      </div>

      {/* Animated SVG Network Graph Overlay */}
      <div className="absolute inset-0 z-[3] pointer-events-none overflow-hidden">
        <svg
          viewBox="0 0 1200 600"
          className="w-full h-full"
          preserveAspectRatio="xMidYMid slice"
          xmlns="http://www.w3.org/2000/svg"
        >
          <defs>
            <linearGradient id="edge-grad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.4" />
              <stop offset="50%" stopColor="#8b5cf6" stopOpacity="0.25" />
              <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.1" />
            </linearGradient>
            <radialGradient id="node-glow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#22d3ee" stopOpacity="0" />
            </radialGradient>
            <filter id="glow-sm">
              <feGaussianBlur stdDeviation="2" result="blur" />
              <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
            </filter>
          </defs>

          {/* Connection Lines */}
          {[
            [120, 140, 320, 90], [320, 90, 500, 200], [500, 200, 680, 120], [680, 120, 900, 180],
            [900, 180, 1080, 100], [120, 140, 260, 320], [260, 320, 500, 200], [500, 200, 720, 340],
            [720, 340, 900, 180], [900, 180, 1060, 320], [320, 90, 540, 60], [540, 60, 680, 120],
            [260, 320, 480, 420], [480, 420, 720, 340], [720, 340, 960, 440], [1060, 320, 1080, 100],
            [120, 140, 180, 400], [180, 400, 260, 320], [480, 420, 680, 500], [680, 500, 960, 440],
            [540, 60, 760, 40], [760, 40, 900, 180], [180, 400, 480, 420],
          ].map(([x1, y1, x2, y2], i) => (
            <g key={`edge-${i}`}>
              <line
                x1={x1} y1={y1} x2={x2} y2={y2}
                stroke="url(#edge-grad)" strokeWidth="1"
                opacity={0.5}
              />
              {!reducedMotion && (
                <circle r="2" fill="#22d3ee" opacity="0.7" filter="url(#glow-sm)">
                  <animateMotion
                    dur={`${3 + (i % 5) * 0.8}s`}
                    repeatCount="indefinite"
                    begin={`${(i * 0.4) % 4}s`}
                    path={`M${x1},${y1} L${x2},${y2}`}
                  />
                  <animate attributeName="opacity" values="0;0.8;0" dur={`${3 + (i % 5) * 0.8}s`} repeatCount="indefinite" begin={`${(i * 0.4) % 4}s`} />
                </circle>
              )}
            </g>
          ))}

          {/* Network Nodes */}
          {[
            [120, 140, 5], [320, 90, 4], [500, 200, 6], [680, 120, 4], [900, 180, 5],
            [1080, 100, 4], [260, 320, 4], [720, 340, 5], [1060, 320, 4], [540, 60, 3],
            [760, 40, 3], [480, 420, 4], [680, 500, 3], [960, 440, 4], [180, 400, 3],
          ].map(([cx, cy, r], i) => (
            <g key={`node-${i}`}>
              <circle cx={cx} cy={cy} r={Number(r) * 3} fill="url(#node-glow)" opacity="0.3">
                {!reducedMotion && (
                  <animate attributeName="opacity" values="0.15;0.4;0.15" dur={`${2.5 + (i % 4) * 0.6}s`} repeatCount="indefinite" begin={`${i * 0.3}s`} />
                )}
              </circle>
              <circle cx={cx} cy={cy} r={r} fill="#0e1117" stroke="#22d3ee" strokeWidth="1.5" opacity="0.85" filter="url(#glow-sm)">
                {!reducedMotion && (
                  <animate attributeName="r" values={`${r};${Number(r) * 1.3};${r}`} dur={`${3 + (i % 3) * 0.5}s`} repeatCount="indefinite" begin={`${i * 0.2}s`} />
                )}
              </circle>
              <circle cx={cx} cy={cy} r={Number(r) * 0.4} fill="#22d3ee" opacity="0.9" />
            </g>
          ))}
        </svg>
      </div>

      {/* Scanning Line Effect */}
      <div className="absolute inset-0 z-[4] pointer-events-none overflow-hidden">
        <div
          className="w-full h-[2px] bg-gradient-to-r from-transparent via-cyan-400/60 to-transparent"
          style={{ animation: reducedMotion ? 'none' : 'scanLine 4s ease-in-out infinite' }}
        />
      </div>

      {/* Main Content */}
      <div className="relative z-10 text-center px-4 max-w-5xl mx-auto py-8 sm:py-10">
        {/* Logo */}
        <div
          className={`mb-8 transition-all duration-1000 ${loaded ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'
            }`}
        >
          <div
            ref={logoCardRef}
            onPointerMove={handleLogoPointerMove}
            onPointerLeave={resetLogoPointerTilt}
            className="relative w-24 h-24 mx-auto rounded-2xl border border-cyan-500/30 shadow-[0_0_44px_rgba(0,240,255,0.28)] transition-transform duration-300"
            style={{
              transform: 'perspective(1100px) rotateX(0deg) rotateY(0deg) scale3d(1, 1, 1)',
              transformStyle: 'preserve-3d',
            }}
          >
            <div
              className="absolute inset-0 rounded-2xl pointer-events-none"
              style={{
                background:
                  'radial-gradient(130px circle at var(--logo-glow-x, 50%) var(--logo-glow-y, 50%), rgba(45, 220, 255, 0.26), transparent 68%)',
              }}
            />
            <img
              src="/assets/cybertron-logo.jpeg"
              alt="Cybertron"
              className="w-full h-full rounded-2xl object-cover"
              fetchpriority="high"
            loading="eager"
            />
          </div>
        </div>

        {/* Status Badge */}
        <div
          className={`inline-flex items-center gap-2 px-4 py-2 rounded-full border border-cyan-500/30 bg-cyan-500/10 backdrop-blur-sm mb-8 transition-all duration-1000 delay-200 ${loaded ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'
            }`}
        >
          <span className={`w-2 h-2 rounded-full ${statusBadge.indicatorClassName} animate-pulse`} />
          <span className="text-cyan-300 text-sm font-medium tracking-wider uppercase">
            {statusBadge.label}
          </span>
        </div>

        {/* Title */}
        <h1
          className={`text-5xl sm:text-6xl md:text-7xl lg:text-8xl font-extrabold mb-6 transition-all duration-1000 delay-300 ${loaded ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'
            }`}
        >
          <span className="bg-gradient-to-r from-white via-cyan-200 to-white bg-clip-text text-transparent">
            CYBER
          </span>
          <span className="bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-500 bg-clip-text text-transparent">
            TRON
          </span>
        </h1>

        {/* Subtitle */}
        <p
          className={`text-lg sm:text-xl md:text-2xl text-slate-300 mb-4 max-w-3xl mx-auto transition-all duration-1000 delay-500 ${loaded ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'
            }`}
        >
          Enterprise Cyber Operations Platform
        </p>

        <p
          className={`text-sm sm:text-base text-slate-400 mb-10 max-w-2xl mx-auto transition-all duration-1000 delay-700 ${loaded ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'
            }`}
        >
          Real-time incident workflows, tenant-aware access control, and auditable
          security operations with truthful telemetry and no fabricated signals.
        </p>

        {/* Stats Bar */}
        <div
          className={`grid grid-cols-3 gap-4 sm:gap-8 max-w-2xl mx-auto transition-all duration-1000 ${loaded ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'
            }`}
          style={{ transitionDelay: '1100ms' }}
        >
          {stats.map((stat) => (
            <div
              key={stat.label}
              className="text-center p-4 rounded-xl bg-white/5 backdrop-blur-sm border border-white/10 transition-all duration-300 hover:-translate-y-1 hover:border-cyan-400/30"
            >
              <stat.icon className="w-5 h-5 text-cyan-400 mx-auto mb-2" />
              <div className="text-xl sm:text-2xl font-bold text-white">
                {stat.value}
              </div>
              <div className="text-xs sm:text-sm text-slate-400">
                {stat.label}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Scroll Indicator */}
      <div className="absolute bottom-5 sm:bottom-7 left-1/2 -translate-x-1/2 z-10">
        <button
          type="button"
          aria-label="Scroll to features"
          className="p-0 bg-transparent border-none cursor-pointer"
          onClick={() => scrollToSection('features')}
        >
          <ChevronDown
            className={`w-8 h-8 text-cyan-400/60 ${reducedMotion ? '' : 'animate-bounce'}`}
          />
        </button>
      </div>
    </section>
  );
}
