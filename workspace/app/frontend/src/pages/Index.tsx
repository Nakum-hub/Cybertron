import { memo, useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { LayoutDashboard, LogIn, Menu, Shield, UserRound, X } from 'lucide-react';
import AuthShowcaseBase from '@/components/AuthShowcase';
import ExecutionSectionBase from '@/components/ExecutionSection';
import FeaturesSectionBase from '@/components/FeaturesSection';
import HeroSectionBase from '@/components/HeroSection';
import MagicBentoSectionBase from '@/components/MagicBentoSection';
import PricingSectionBase from '@/components/PricingSection';
import ThreatDashboardBase from '@/components/ThreatDashboard';
import { motionParallax, useReducedMotionPreference } from '@/lib/animations';
import { trackEvent } from '@/lib/analytics';
import { useAuthStatus } from '@/hooks/use-auth-status';
import { buildWorkspaceTarget } from '@/lib/workspace-access';
import { normalizeRole } from '@/lib/platform-registry';

const AuthShowcase = memo(AuthShowcaseBase);
const ExecutionSection = memo(ExecutionSectionBase);
const FeaturesSection = memo(FeaturesSectionBase);
const HeroSection = memo(HeroSectionBase);
const MagicBentoSection = memo(MagicBentoSectionBase);
const PricingSection = memo(PricingSectionBase);
const ThreatDashboard = memo(ThreatDashboardBase);

const NAV_ITEMS = [
  { label: 'Features', href: '#features' },
  { label: 'Capabilities', href: '#capabilities' },
  { label: 'Dashboard', href: '#dashboard' },
  { label: 'Execution', href: '#execution' },
  { label: 'Pricing', href: '#pricing' },
  { label: 'Auth', href: '#auth' },
];

export default function CybertronLanding() {
  const [scrolled, setScrolled] = useState(false);
  const scrolledRef = useRef(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const reducedMotion = useReducedMotionPreference();
  const { status: authStatus, profile } = useAuthStatus();

  const accountPath = authStatus === 'authenticated' ? '/account' : '/account?mode=login';
  const primaryPath =
    authStatus === 'authenticated'
      ? buildWorkspaceTarget('/platform', profile?.tenant || 'global', normalizeRole(profile?.role || 'executive_viewer'))
      : '/account?mode=register';
  const primaryLabel = authStatus === 'authenticated' ? 'Open Workspace' : 'Create Account';
  const accountLabel = authStatus === 'authenticated' ? 'My Account' : 'Login';

  useEffect(() => {
    const handleScroll = () => {
      const isScrolled = window.scrollY > 50;
      if (scrolledRef.current !== isScrolled) {
        scrolledRef.current = isScrolled;
        setScrolled(isScrolled);
      }
    };
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  useEffect(() => {
    const root = document.documentElement;
    const parallaxZones = Array.from(document.querySelectorAll<HTMLElement>('.parallax-zone'));
    const hasFinePointer =
      typeof window !== 'undefined' &&
      typeof window.matchMedia === 'function' &&
      window.matchMedia('(pointer: fine)').matches;
    const canRunParallax =
      !reducedMotion && hasFinePointer;
    let pointerFrame = 0;
    let scrollFrame = 0;
    let lastScrollSampleAt = 0;

    const applyMotion = (xNorm: number, yNorm: number) => {
      const sceneTilt = motionParallax(16, reducedMotion);
      const cardTilt = motionParallax(5, reducedMotion);
      const layerShift = motionParallax(40, reducedMotion);

      root.style.setProperty('--scene-tilt-x', `${(-yNorm * sceneTilt).toFixed(2)}deg`);
      root.style.setProperty('--scene-tilt-y', `${(xNorm * sceneTilt).toFixed(2)}deg`);
      root.style.setProperty('--card-tilt-x', `${(-yNorm * cardTilt).toFixed(2)}deg`);
      root.style.setProperty('--card-tilt-y', `${(xNorm * cardTilt).toFixed(2)}deg`);
      root.style.setProperty('--parallax-x', `${(xNorm * layerShift).toFixed(2)}px`);
      root.style.setProperty('--parallax-y', `${(yNorm * layerShift).toFixed(2)}px`);
      root.style.setProperty('--pointer-glow-x', `${((xNorm + 0.5) * 100).toFixed(2)}%`);
      root.style.setProperty('--pointer-glow-y', `${((yNorm + 0.5) * 100).toFixed(2)}%`);
    };

    const updateScrollEffects = (force = false) => {
      const now = performance.now();
      if (!force && now - lastScrollSampleAt < 40) {
        return;
      }

      lastScrollSampleAt = now;
      const scrollTop = window.scrollY;
      const scrollHeight = document.documentElement.scrollHeight - window.innerHeight;
      const progress = scrollHeight <= 0 ? 0 : (scrollTop / scrollHeight) * 100;

      root.style.setProperty('--page-progress', `${Math.max(0, Math.min(100, progress)).toFixed(2)}%`);
      root.style.setProperty('--scroll-depth', `${Math.min(180, scrollTop * 0.12).toFixed(2)}px`);

      if (!canRunParallax) {
        parallaxZones.forEach(zone => {
          zone.style.setProperty('--section-shift', '0px');
        });
        return;
      }

      parallaxZones.forEach((zone, index) => {
        const rect = zone.getBoundingClientRect();
        const centerOffset = rect.top + rect.height * 0.5 - window.innerHeight * 0.5;
        const strength = motionParallax(0.008 + index * 0.0015, reducedMotion);
        const maxShift = index === 0 ? 1.5 : 2.5;
        const shift = Math.max(-maxShift, Math.min(maxShift, -centerOffset * strength));
        zone.style.setProperty('--section-shift', `${shift.toFixed(2)}px`);
      });
    };

    const onPointerMove = (event: PointerEvent) => {
      if (document.visibilityState !== 'visible') {
        return;
      }

      const xNorm = event.clientX / window.innerWidth - 0.5;
      const yNorm = event.clientY / window.innerHeight - 0.5;

      cancelAnimationFrame(pointerFrame);
      pointerFrame = window.requestAnimationFrame(() => applyMotion(xNorm, yNorm));
    };

    const onScroll = () => {
      cancelAnimationFrame(scrollFrame);
      scrollFrame = window.requestAnimationFrame(() => updateScrollEffects(false));
    };
    const onResize = () => updateScrollEffects(true);

    applyMotion(0, 0);
    updateScrollEffects(true);

    if (canRunParallax) {
      window.addEventListener('pointermove', onPointerMove, { passive: true });
    }
    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('resize', onResize);

    return () => {
      cancelAnimationFrame(pointerFrame);
      cancelAnimationFrame(scrollFrame);
      window.removeEventListener('pointermove', onPointerMove);
      window.removeEventListener('scroll', onScroll);
      window.removeEventListener('resize', onResize);
    };
  }, [reducedMotion]);

  useEffect(() => {
    const reveals = Array.from(document.querySelectorAll<HTMLElement>('.reveal-up'));
    const hasFinePointer =
      typeof window !== 'undefined' &&
      typeof window.matchMedia === 'function' &&
      window.matchMedia('(pointer: fine)').matches;

    if (reducedMotion) {
      reveals.forEach(node => node.classList.add('is-visible'));
      return;
    }

    const revealObserver = new IntersectionObserver(
      entries => {
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            entry.target.classList.add('is-visible');
            revealObserver.unobserve(entry.target);
          }
        });
      },
      {
        threshold: 0.18,
        rootMargin: '0px 0px -6% 0px',
      }
    );

    reveals.forEach(node => revealObserver.observe(node));

    const panels = Array.from(document.querySelectorAll<HTMLElement>('.panel-3d'));
    const cleanup: Array<() => void> = [];

    if (!hasFinePointer) {
      return () => {
        revealObserver.disconnect();
      };
    }

    panels.forEach(panel => {
      let panelFrame = 0;
      let latestX = 0;
      let latestY = 0;

      const applyPanelTilt = () => {
        panelFrame = 0;
        panel.style.setProperty('--local-tilt-x', `${(-latestY * 10).toFixed(2)}deg`);
        panel.style.setProperty('--local-tilt-y', `${(latestX * 10).toFixed(2)}deg`);
        panel.style.setProperty('--pointer-glow-x', `${((latestX + 0.5) * 100).toFixed(2)}%`);
        panel.style.setProperty('--pointer-glow-y', `${((latestY + 0.5) * 100).toFixed(2)}%`);
      };

      const onMove = (event: PointerEvent) => {
        const rect = panel.getBoundingClientRect();
        latestX = (event.clientX - rect.left) / rect.width - 0.5;
        latestY = (event.clientY - rect.top) / rect.height - 0.5;

        if (panelFrame) {
          return;
        }

        panelFrame = requestAnimationFrame(applyPanelTilt);
      };

      const onLeave = () => {
        if (panelFrame) {
          cancelAnimationFrame(panelFrame);
          panelFrame = 0;
        }

        panel.style.setProperty('--local-tilt-x', '0deg');
        panel.style.setProperty('--local-tilt-y', '0deg');
        panel.style.setProperty('--pointer-glow-x', '50%');
        panel.style.setProperty('--pointer-glow-y', '50%');
      };

      panel.addEventListener('pointermove', onMove);
      panel.addEventListener('pointerleave', onLeave);

      cleanup.push(() => {
        if (panelFrame) {
          cancelAnimationFrame(panelFrame);
          panelFrame = 0;
        }

        panel.removeEventListener('pointermove', onMove);
        panel.removeEventListener('pointerleave', onLeave);
      });
    });

    return () => {
      revealObserver.disconnect();
      cleanup.forEach(dispose => dispose());
    };
  }, [reducedMotion]);

  useEffect(() => {
    const hasFinePointer =
      typeof window !== 'undefined' &&
      typeof window.matchMedia === 'function' &&
      window.matchMedia('(pointer: fine)').matches;

    if (reducedMotion || !hasFinePointer) {
      return;
    }

    const nodes = Array.from(document.querySelectorAll<HTMLElement>('.magnetic-btn'));
    const cleanups: Array<() => void> = [];

    nodes.forEach(node => {
      let magneticFrame = 0;
      let nextX = 0;
      let nextY = 0;

      const applyMagnet = () => {
        magneticFrame = 0;
        node.style.setProperty('--magnetic-x', `${(nextX * 7).toFixed(2)}px`);
        node.style.setProperty('--magnetic-y', `${(nextY * 7).toFixed(2)}px`);
      };

      const onMove = (event: PointerEvent) => {
        const rect = node.getBoundingClientRect();
        nextX = (event.clientX - rect.left) / rect.width - 0.5;
        nextY = (event.clientY - rect.top) / rect.height - 0.5;

        if (magneticFrame) {
          return;
        }

        magneticFrame = requestAnimationFrame(applyMagnet);
      };

      const onLeave = () => {
        if (magneticFrame) {
          cancelAnimationFrame(magneticFrame);
          magneticFrame = 0;
        }

        node.style.setProperty('--magnetic-x', '0px');
        node.style.setProperty('--magnetic-y', '0px');
      };

      node.addEventListener('pointermove', onMove);
      node.addEventListener('pointerleave', onLeave);

      cleanups.push(() => {
        if (magneticFrame) {
          cancelAnimationFrame(magneticFrame);
          magneticFrame = 0;
        }

        node.removeEventListener('pointermove', onMove);
        node.removeEventListener('pointerleave', onLeave);
      });
    });

    return () => cleanups.forEach(dispose => dispose());
  }, [reducedMotion]);

  const scrollTo = (href: string) => {
    setMobileMenuOpen(false);
    const el = document.querySelector<HTMLElement>(href);
    if (!el) {
      return;
    }

    const navOffset = window.innerWidth < 768 ? 76 : 88;
    const top = Math.max(0, Math.round(window.scrollY + el.getBoundingClientRect().top - navOffset));
    window.scrollTo({
      top,
      behavior: reducedMotion ? 'auto' : 'smooth',
    });
  };

  const onNavigate = (label: string, href: string) => {
    trackEvent('nav_click', { label, href });
    scrollTo(href);
  };

  return (
    <div className="cyber-page min-h-screen text-white antialiased">
      <div className="page-progress-track" aria-hidden>
        <div className="page-progress-fill" />
      </div>
      <div className="ambient-mesh" aria-hidden />
      <div className="grid-overlay" aria-hidden />
      <div className="orb orb-a" aria-hidden />
      <div className="orb orb-b" aria-hidden />
      <div className="orb orb-c" aria-hidden />

      <nav
        className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
          scrolled
            ? 'bg-[#030813]/80 backdrop-blur-2xl border-b border-sky-300/20 shadow-[0_12px_42px_rgba(2,11,25,0.6)]'
            : 'bg-transparent'
        }`}
      >
        <div className="section-wrap px-0">
          <div className="flex items-center justify-between h-16 sm:h-20">
            <div className="flex items-center gap-3 reveal-up">
              <img
                src="/assets/cybertron-logo.jpeg"
                alt="Cybertron"
                className="w-10 h-10 rounded-xl object-cover border border-sky-300/30 shadow-[0_8px_24px_rgba(38,204,255,0.28)]"
                fetchpriority="high"
                loading="eager"
              />
              <div>
                <span className="text-lg font-bold tracking-wide bg-gradient-to-r from-white via-sky-100 to-cyan-200 bg-clip-text text-transparent">
                  CYBERTRON
                </span>
                <p className="text-[10px] text-cyan-100/80 tracking-[0.22em] uppercase">Security OS</p>
              </div>
            </div>

            <div className="hidden md:flex items-center gap-1 panel-3d rounded-full px-1.5 py-1">
              {NAV_ITEMS.map(item => (
                <button
                  key={item.label}
                  onClick={() => onNavigate(item.label, item.href)}
                  className="px-3.5 py-2 text-sm text-slate-300 hover:text-white font-medium transition-all duration-300 rounded-full hover:bg-sky-200/[0.08] hover:-translate-y-0.5"
                >
                  {item.label}
                </button>
              ))}
            </div>

            <div className="flex items-center gap-2 sm:gap-3">
              <Link
                to={accountPath}
                onClick={() => {
                  setMobileMenuOpen(false);
                  trackEvent('cta_click', { location: 'navbar_account', target: accountPath });
                }}
                className="hidden lg:inline-flex items-center gap-2 rounded-full micro-pill px-3 py-1.5 text-[11px] font-semibold tracking-wide text-cyan-100 transition hover:bg-white/[0.08]"
              >
                <UserRound className="w-3.5 h-3.5 text-cyan-200" />
                {accountLabel}
              </Link>
              <button
                onClick={() => {
                  setMobileMenuOpen(false);
                  trackEvent('cta_click', { location: 'navbar_primary', target: primaryPath });
                  window.location.assign(primaryPath);
                }}
                className="hidden sm:inline-flex items-center gap-2 px-5 py-2.5 rounded-full cta-primary text-sm font-bold magnetic-btn"
              >
                <LayoutDashboard className="w-4 h-4" />
                {primaryLabel}
              </button>
              <button
                className="md:hidden p-2 text-slate-300 hover:text-white"
                onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                type="button"
                aria-label={mobileMenuOpen ? 'Close menu' : 'Open navigation'}
              >
                {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
              </button>
            </div>
          </div>
        </div>

        {mobileMenuOpen && (
          <div className="md:hidden bg-[#071021]/95 backdrop-blur-2xl border-b border-sky-300/20">
            <div className="section-wrap py-4 space-y-2">
              {NAV_ITEMS.map(item => (
                <button
                  key={item.label}
                  onClick={() => onNavigate(item.label, item.href)}
                  className="block w-full text-left px-4 py-3 text-sm text-slate-300 hover:text-white hover:bg-sky-200/[0.08] rounded-xl transition-all duration-300 hover:translate-x-1"
                >
                  {item.label}
                </button>
              ))}
              <button
                onClick={() => {
                  setMobileMenuOpen(false);
                  trackEvent('cta_click', { location: 'mobile_menu_account', target: accountPath });
                  window.location.assign(accountPath);
                }}
                className="block w-full text-left px-4 py-3 text-sm text-slate-100 font-semibold rounded-xl border border-white/10 bg-white/[0.04] transition-all duration-300 hover:translate-x-1 hover:border-white/20"
              >
                {accountLabel}
              </button>
              <button
                onClick={() => {
                  setMobileMenuOpen(false);
                  trackEvent('cta_click', { location: 'mobile_menu_primary', target: primaryPath });
                  window.location.assign(primaryPath);
                }}
                className="block w-full text-left px-4 py-3 text-sm text-cyan-200 font-bold rounded-xl cta-secondary magnetic-btn"
              >
                {primaryLabel} {'>'}
              </button>
            </div>
          </div>
        )}
      </nav>

      <main id="main-content" className="relative z-10 pt-16 sm:pt-20">
        <div className="parallax-zone">
          <HeroSection />
        </div>
        <div className="parallax-zone">
          <FeaturesSection />
        </div>
        <div className="parallax-zone">
          <MagicBentoSection />
        </div>
        <div className="parallax-zone">
          <ThreatDashboard />
        </div>
        <div className="parallax-zone">
          <ExecutionSection />
        </div>
        <div className="parallax-zone">
          <PricingSection />
        </div>
        <div className="parallax-zone">
          <AuthShowcase />
        </div>
      </main>
    </div>
  );
}
