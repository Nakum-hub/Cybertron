import { ArrowRight, Building2, Check, Star, Zap } from 'lucide-react';
import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { useStaggeredAnimation } from '@/lib/animations';

type RegisterAction = {
  type: 'register';
  plan: string;
};

type ExternalAction = {
  type: 'external';
  href: string;
};

type PlanAction = RegisterAction | ExternalAction;

type Plan = {
  name: string;
  price: string;
  period: string;
  description: string;
  features: string[];
  cta: string;
  popular: boolean;
  gradient: string;
  borderColor: string;
  glowColor: string;
  icon: typeof Zap;
  action: PlanAction;
};

const PLANS: Plan[] = [
  {
    name: 'Starter',
    price: 'Free',
    period: 'Forever',
    description: 'For teams validating core security workflows with tenant-aware incident and IOC operations.',
    features: [
      'Incident Queue + Timeline',
      'IOC Vault Correlation',
      'Service Request Tracking',
      'Role-Based Access Controls',
      'API Contracts + Health Checks',
      'Single Tenant Workspace',
    ],
    cta: 'Get Started Free',
    popular: false,
    gradient: 'from-amber-400 to-yellow-500',
    borderColor: 'border-amber-500/20',
    glowColor: 'rgba(251, 191, 36, 0.18)',
    icon: Zap,
    action: {
      type: 'register',
      plan: 'starter',
    },
  },
  {
    name: 'Pro',
    price: '$18',
    period: '/month',
    description: 'For security teams that need authenticated workflows, auditability, and connector visibility.',
    features: [
      'Everything in Starter',
      'User + Tenant Administration',
      'Audit Trail Access',
      'Report Metadata Registry',
      'Connector Health Diagnostics',
      'Priority Support',
      'Up to 10 Team Members',
      'Operational KPI Dashboard',
    ],
    cta: 'Start Pro Trial',
    popular: true,
    gradient: 'from-cyan-500 to-blue-600',
    borderColor: 'border-cyan-500/30',
    glowColor: 'rgba(0, 240, 255, 0.25)',
    icon: Star,
    action: {
      type: 'register',
      plan: 'pro',
    },
  },
  {
    name: 'Enterprise',
    price: 'Custom',
    period: 'Contact Us',
    description: 'Full zero-trust deployment with dedicated SOC team, white-label options, and SLA guarantees.',
    features: [
      'Everything in Pro',
      'Zero-Trust Architecture',
      'Dedicated SOC Team',
      'White-Label Option',
      'Custom Integrations',
      'Unlimited Team Members',
      '99.99% Uptime SLA',
      'On-Premise Deployment',
      '24/7 Phone Support',
    ],
    cta: 'Contact Sales',
    popular: false,
    gradient: 'from-purple-500 to-pink-600',
    borderColor: 'border-purple-500/20',
    glowColor: 'rgba(168, 85, 247, 0.22)',
    icon: Building2,
    action: {
      type: 'external',
      href: 'mailto:sales@cybertron.io?subject=Cybertron%20Enterprise%20Demo%20Request',
    },
  },
];

const ANNUAL_PRICES: Record<string, { monthly: string; annual: string; saved: string }> = {
  Starter: { monthly: 'Free', annual: 'Free', saved: '' },
  Pro: { monthly: '$18', annual: '$14', saved: 'Save 22%' },
  Enterprise: { monthly: 'Custom', annual: 'Custom', saved: '' },
};

function navigateToPlanAction(action: PlanAction, billingCycle: 'monthly' | 'annual' = 'monthly'): void {
  if (typeof window === 'undefined') {
    return;
  }

  if (action.type === 'external') {
    window.location.assign(action.href);
    return;
  }

  // P2-6: Check if user is authenticated via cookie presence
  const hasSession = document.cookie.split(';').some(c => c.trim().startsWith('ct_access='));

  if (!hasSession || action.plan === 'starter') {
    // Not authenticated or free plan — send to register
    window.location.assign(`/account?mode=register&plan=${encodeURIComponent(action.plan)}`);
    return;
  }

  // Authenticated user wanting pro/enterprise — redirect to Stripe checkout
  // The checkout endpoint will create the Stripe session and return a URL
  const tenant = new URLSearchParams(window.location.search).get('tenant') || '';
  fetch(`/api/v1/billing/checkout?tenant=${encodeURIComponent(tenant)}`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      plan: action.plan,
      billingCycle,
      successUrl: `${window.location.origin}/billing/success`,
      cancelUrl: `${window.location.origin}/billing/cancel`,
    }),
  })
    .then(res => res.json())
    .then(data => {
      if (data.url) {
        window.location.assign(data.url);
      } else {
        // Fallback: go to register with plan param
        window.location.assign(`/account?mode=register&plan=${encodeURIComponent(action.plan)}`);
      }
    })
    .catch(() => {
      window.location.assign(`/account?mode=register&plan=${encodeURIComponent(action.plan)}`);
    });
}

export default function PricingSection() {
  const { ref, visibleItems } = useStaggeredAnimation(PLANS.length, 200);
  const [billingCycle, setBillingCycle] = useState<'monthly' | 'annual'>('monthly');

  return (
    <section id="pricing" className="relative py-24 sm:py-32 bg-[#080810]">
      <div className="absolute top-1/3 left-0 w-[400px] h-[400px] bg-cyan-600/5 rounded-full blur-[120px]" />
      <div className="absolute bottom-1/3 right-0 w-[400px] h-[400px] bg-purple-600/5 rounded-full blur-[120px]" />

      <div className="relative max-w-6xl mx-auto px-4 sm:px-6" ref={ref}>
        <div className="text-center mb-16">
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-cyan-500/20 bg-cyan-500/5 mb-6">
            <Star className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-cyan-300 text-xs font-semibold tracking-widest uppercase">Pricing</span>
          </div>
          <h2 className="text-3xl sm:text-4xl md:text-5xl font-bold text-white mb-4">
            Affordable{' '}
            <span className="bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
              Cyber Defense
            </span>
          </h2>
          <p className="text-slate-400 text-lg max-w-2xl mx-auto mb-8">
            Enterprise-grade security should not break the bank. Start free, scale as you grow.
            Built for startups and enterprises alike.
          </p>

          {/* Billing Cycle Toggle */}
          <div className="inline-flex items-center gap-1 p-1 rounded-full bg-white/[0.06] border border-white/[0.08]">
            <button
              type="button"
              onClick={() => setBillingCycle('monthly')}
              className={`px-5 py-2 rounded-full text-sm font-medium transition-all duration-300 ${billingCycle === 'monthly'
                ? 'bg-gradient-to-r from-cyan-500 to-blue-600 text-white shadow-lg'
                : 'text-slate-400 hover:text-white'
                }`}
            >
              Monthly
            </button>
            <button
              type="button"
              onClick={() => setBillingCycle('annual')}
              className={`px-5 py-2 rounded-full text-sm font-medium transition-all duration-300 flex items-center gap-2 ${billingCycle === 'annual'
                ? 'bg-gradient-to-r from-cyan-500 to-blue-600 text-white shadow-lg'
                : 'text-slate-400 hover:text-white'
                }`}
            >
              Annual
              <span className="px-1.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 text-[10px] font-bold">
                -20%
              </span>
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 lg:gap-8">
          {PLANS.map((plan, index) => (
            <div
              key={plan.name}
              className={`panel-3d relative rounded-2xl border ${plan.borderColor} transition-all duration-700 hover:-translate-y-1 ${plan.popular
                ? 'bg-slate-900/80 backdrop-blur-xl scale-[1.02] md:scale-105'
                : 'bg-slate-900/40 backdrop-blur-sm'
                } ${visibleItems[index] ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-12'}`}
              style={{
                boxShadow: plan.popular
                  ? `0 0 60px ${plan.glowColor}`
                  : `0 0 0px ${plan.glowColor}`,
              }}
              onMouseEnter={(e) => {
                (e.currentTarget as HTMLElement).style.boxShadow = `0 0 80px ${plan.glowColor}, 0 0 120px ${plan.glowColor}`;
              }}
              onMouseLeave={(e) => {
                (e.currentTarget as HTMLElement).style.boxShadow = plan.popular
                  ? `0 0 60px ${plan.glowColor}`
                  : `0 0 0px ${plan.glowColor}`;
              }}
            >
              {plan.popular && (
                <div className="absolute -top-4 left-1/2 -translate-x-1/2">
                  <span className="px-4 py-1.5 rounded-full bg-gradient-to-r from-cyan-500 to-blue-600 text-white text-xs font-bold tracking-wider uppercase shadow-lg">
                    Most Popular
                  </span>
                </div>
              )}

              <div className="p-8">
                <div className="flex items-center gap-3 mb-4">
                  <div
                    className={`w-10 h-10 rounded-xl bg-gradient-to-br ${plan.gradient} flex items-center justify-center`}
                  >
                    <plan.icon className="w-5 h-5 text-white" />
                  </div>
                  <h3 className="text-xl font-bold text-white">{plan.name}</h3>
                </div>

                <div className="mb-4">
                  <span className="text-4xl font-extrabold text-white">
                    {billingCycle === 'annual'
                      ? ANNUAL_PRICES[plan.name]?.annual ?? plan.price
                      : plan.price}
                  </span>
                  <span className="text-slate-400 text-sm ml-1">
                    {plan.price === 'Free' || plan.price === 'Custom'
                      ? plan.period
                      : billingCycle === 'annual'
                        ? '/mo billed yearly'
                        : plan.period}
                  </span>
                  {billingCycle === 'annual' && ANNUAL_PRICES[plan.name]?.saved && (
                    <span className="ml-2 inline-flex px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-300 text-xs font-bold">
                      {ANNUAL_PRICES[plan.name].saved}
                    </span>
                  )}
                </div>

                <p className="text-sm text-slate-400 mb-6 leading-relaxed">{plan.description}</p>

                <Button
                  type="button"
                  className={`w-full mb-8 py-5 rounded-xl font-semibold transition-all duration-300 ${plan.popular
                    ? 'magnetic-btn bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white shadow-[0_0_20px_rgba(0,240,255,0.2)] hover:shadow-[0_0_30px_rgba(0,240,255,0.4)] hover:-translate-y-0.5'
                    : 'magnetic-btn !bg-white/5 !hover:bg-white/10 text-white border border-white/10 hover:-translate-y-0.5'
                    }`}
                  onClick={() => {
                    navigateToPlanAction(plan.action, billingCycle);
                  }}
                >
                  {plan.cta}
                  <ArrowRight className="w-4 h-4 ml-2" />
                </Button>

                <ul className="space-y-3">
                  {plan.features.map(feature => (
                    <li key={feature} className="flex items-center gap-3 text-sm">
                      <Check
                        className={`w-4 h-4 flex-shrink-0 ${plan.popular ? 'text-cyan-400' : 'text-slate-500'
                          }`}
                      />
                      <span className="text-slate-300">{feature}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          ))}
        </div>

        <div className="text-center mt-12">
          <p className="text-sm text-slate-500">
            All plans include secure auth, rate limiting, and deploy-ready Docker infrastructure.
          </p>
          <p className="text-sm text-slate-500 mt-1">
            All plans include zero-trust architecture and deploy-ready Docker infrastructure.
          </p>
        </div>
      </div>
    </section>
  );
}
