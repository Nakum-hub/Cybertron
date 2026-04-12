import { ArrowLeft } from 'lucide-react';
import { Link, useSearchParams } from 'react-router-dom';
import PricingSection from '@/components/PricingSection';

export default function PricingPage() {
  const [searchParams] = useSearchParams();
  const reason = (searchParams.get('reason') || '').trim();
  const tier = (searchParams.get('tier') || searchParams.get('planLabel') || 'free').trim();
  const limit = (searchParams.get('limit') || '').trim();
  const remaining = (searchParams.get('remaining') || '').trim();
  const periodEndsAt = (searchParams.get('periodEndsAt') || '').trim();
  const returnTo = (searchParams.get('returnTo') || '/platform').trim();
  const periodLabel = periodEndsAt ? new Date(periodEndsAt).toLocaleDateString() : '';
  const showUpgradeBanner = reason === 'billing_quota_exhausted' || reason === 'plan_upgrade_required';

  return (
    <div className="min-h-screen bg-[#0A0A0F] text-white">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 py-10">
        <Link
          to="/"
          className="inline-flex items-center gap-2 text-sm text-slate-400 hover:text-cyan-300 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Home
        </Link>
        {showUpgradeBanner && (
          <section className="mt-6 rounded-2xl border border-amber-300/20 bg-amber-400/10 p-5 text-sm text-amber-50">
            <p className="text-xs uppercase tracking-[0.18em] text-amber-200/90 mb-2">Upgrade Required</p>
            <h1 className="text-2xl font-semibold text-white mb-2">
              {reason === 'billing_quota_exhausted'
                ? 'Free plan quota is exhausted'
                : 'Current plan does not include this module'}
            </h1>
            <p className="text-amber-50/90">
              {reason === 'billing_quota_exhausted'
                ? `Your ${tier || 'free'} plan has reached its usage allowance${limit ? ` (${limit} units)` : ''}${periodLabel ? ` until ${periodLabel}` : ''}. Upgrade to continue using Cybertron.`
                : `Your ${tier || 'current'} plan does not include the module you tried to open. Upgrade to continue.`}
            </p>
            <p className="mt-2 text-xs text-amber-100/80">
              {remaining
                ? `${remaining} units remain in the current billing window.`
                : 'Higher plans unlock continued access and additional product coverage.'}
            </p>
            <div className="mt-4">
              <Link
                to={returnTo}
                className="inline-flex rounded-lg border border-white/15 bg-white/5 px-4 py-2 text-xs text-white hover:bg-white/10 transition-colors"
              >
                Return to workspace
              </Link>
            </div>
          </section>
        )}
      </div>
      <PricingSection />
    </div>
  );
}
