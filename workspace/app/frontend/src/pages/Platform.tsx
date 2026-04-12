import { useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { Activity, Building2, Coins, Lock, ShieldCheck, UserCog } from 'lucide-react';
import { useAuthStatus } from '@/hooks/use-auth-status';
import { useBackendHealth } from '@/hooks/use-backend-health';
import { usePlatformApps } from '@/hooks/use-platform-apps';
import { trackEvent } from '@/lib/analytics';
import { ApiError } from '@/lib/api';
import { fetchAppStatus, fetchBillingCredits, fetchBillingUsage, fetchTenants } from '@/lib/backend';
import { getConfig } from '@/lib/config';
import { getInternalOperationsPath } from '@/lib/internal-access';
import {
  hasRoleAccess,
  normalizeRole,
  roleLabels,
  roleOptions,
  type PlatformApp,
  type PlatformRole,
} from '@/lib/platform-registry';
import ThreatCommandConsole from '@/components/platform/ThreatCommandConsole';
import IdentityGuardianConsole from '@/components/platform/IdentityGuardianConsole';
import ResilienceHQConsole from '@/components/platform/ResilienceHQConsole';
import RiskCopilotConsole from '@/components/platform/RiskCopilotConsole';
import PlatformGovernancePanel from '@/components/platform/PlatformGovernancePanel';
import AiAgentsPanel from '@/components/platform/AiAgentsPanel';
import NotificationBell from '@/components/platform/NotificationBell';

function AppStatusCard({
  app,
  tenant,
  role,
}: {
  app: PlatformApp;
  tenant: string;
  role: PlatformRole;
}) {
  const statusQuery = useQuery({
    queryKey: ['app-status', app.id, tenant, role],
    queryFn: () => fetchAppStatus(app.id, tenant, role),
    staleTime: 30_000,
  });

  const status = statusQuery.data?.status ?? (statusQuery.isLoading ? 'checking' : 'unavailable');
  const latency = statusQuery.data?.latencyMs;
  const errorMessage =
    statusQuery.error instanceof ApiError
      ? statusQuery.error.message
      : statusQuery.isError
        ? 'Service status endpoint is unavailable.'
        : '';

  return (
    <article className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
      <p className="text-sm text-slate-300 mb-1">Service Status</p>
      <p className="text-lg font-semibold capitalize mb-2">{status}</p>
      <p className="text-xs text-slate-400">
        {latency !== undefined ? `Latency ${latency}ms` : 'Latency unavailable'}
      </p>
      {errorMessage && <p className="text-xs text-amber-300 mt-2">{errorMessage}</p>}
    </article>
  );
}

export default function Platform() {
  const { appId } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const runtimeConfig = getConfig();
  const { status: authStatus, profile, loginUrl } = useAuthStatus();
  const backendHealth = useBackendHealth();

  const initialRole = normalizeRole(searchParams.get('role') ?? profile?.role ?? 'executive_viewer');
  const initialTenant = searchParams.get('tenant') ?? profile?.tenant ?? 'global';

  const [role, setRole] = useState<PlatformRole>(initialRole);
  const [tenant, setTenant] = useState<string>(initialTenant);

  useEffect(() => {
    if (authStatus !== 'authenticated' || !profile) {
      return;
    }

    const requestedRole = searchParams.get('role');
    const requestedTenant = searchParams.get('tenant');

    if (!requestedRole && profile.role) {
      const sessionRole = normalizeRole(profile.role);
      if (sessionRole !== role) {
        setRole(sessionRole);
      }
    }

    if (!requestedTenant && profile.tenant && profile.tenant !== tenant) {
      setTenant(profile.tenant);
    }
  }, [authStatus, profile?.role, profile?.tenant, role, searchParams, tenant]);

  const appsQuery = usePlatformApps(role, tenant, authStatus === 'authenticated');
  const tenantsQuery = useQuery({
    queryKey: ['tenants-list'],
    queryFn: () => fetchTenants(200),
    enabled: authStatus === 'authenticated',
    staleTime: 60_000,
  });
  const billingCreditsQuery = useQuery({
    queryKey: ['billing-credits', tenant],
    queryFn: () => fetchBillingCredits(tenant),
    enabled: authStatus === 'authenticated',
    staleTime: 30_000,
  });
  const billingUsageQuery = useQuery({
    queryKey: ['billing-usage', tenant],
    queryFn: () => fetchBillingUsage(tenant, { limit: 1 }),
    enabled: authStatus === 'authenticated' && hasRoleAccess(role, 'security_analyst'),
    staleTime: 30_000,
  });

  const tenantOptions = useMemo(() => {
    const backendTenants = (tenantsQuery.data || [])
      .map(item => item.slug)
      .filter(Boolean);

    if (backendTenants.length > 0) {
      return [...new Set([tenant, ...backendTenants])];
    }

    if (!runtimeConfig.enterpriseMode) {
      return [tenant];
    }

    return [];
  }, [runtimeConfig.enterpriseMode, tenant, tenantsQuery.data]);

  const platformConfigError =
    backendHealth.isError ||
    backendHealth.data?.status !== 'ok';
  const operationsPath = getInternalOperationsPath(profile?.role || role);
  const operationsLabel = operationsPath === '/diagnostics' ? 'diagnostics' : 'status';
  const billingInfo = billingCreditsQuery.data;
  const billingQuotaEnforced = billingInfo?.quotaEnforced === true;
  const billingQuotaExhausted = billingInfo?.exhausted === true;
  const billingRemainingLabel = billingQuotaEnforced
    ? `${billingInfo?.quotaRemainingUnits ?? 0}`
    : billingInfo
      ? String(billingInfo.balanceUnits)
      : 'checking';
  const billingWindowLabel = billingInfo?.periodEndsAt
    ? new Date(billingInfo.periodEndsAt).toLocaleDateString()
    : null;

  const apps = useMemo(() => {
    const source = Array.isArray(appsQuery.data) ? appsQuery.data : [];
    return source.filter(
      app => app.path.startsWith('/platform/') && hasRoleAccess(role, app.requiredRole)
    );
  }, [appsQuery.data, role]);

  const selectedApp = useMemo(() => {
    if (!appId) {
      return apps[0];
    }

    const fromLoadedApps = apps.find(app => app.id === appId);
    if (fromLoadedApps) {
      return fromLoadedApps;
    }

    return apps[0];
  }, [appId, apps]);
  const pricingRedirectTarget = useMemo(() => {
    if (!billingInfo || !billingQuotaEnforced || !billingQuotaExhausted) {
      return null;
    }

    const params = new URLSearchParams();
    params.set('reason', 'billing_quota_exhausted');
    params.set('tier', billingInfo.planTier || 'free');
    if (billingInfo.planLabel) {
      params.set('planLabel', billingInfo.planLabel);
    }
    if (billingInfo.quotaLimitUnits !== null && billingInfo.quotaLimitUnits !== undefined) {
      params.set('limit', String(billingInfo.quotaLimitUnits));
    }
    if (billingInfo.quotaRemainingUnits !== null && billingInfo.quotaRemainingUnits !== undefined) {
      params.set('remaining', String(billingInfo.quotaRemainingUnits));
    }
    if (billingInfo.usedUnits !== null && billingInfo.usedUnits !== undefined) {
      params.set('used', String(billingInfo.usedUnits));
    }
    if (billingInfo.periodEndsAt) {
      params.set('periodEndsAt', billingInfo.periodEndsAt);
    }
    params.set(
      'returnTo',
      `${selectedApp?.path || '/platform'}?tenant=${encodeURIComponent(tenant)}&role=${encodeURIComponent(role)}`
    );
    return `/pricing?${params.toString()}`;
  }, [billingInfo, billingQuotaEnforced, billingQuotaExhausted, role, selectedApp?.path, tenant]);

  useEffect(() => {
    if (!selectedApp) {
      return;
    }

    if (!appId || appId !== selectedApp.id) {
      navigate(selectedApp.path, { replace: true });
      return;
    }

    trackEvent('platform_app_open', {
      app_id: selectedApp.id,
      tenant,
      role,
    });
  }, [appId, navigate, role, selectedApp, tenant]);

  const currentParamTenant = searchParams.get('tenant');
  const currentParamRole = searchParams.get('role');

  useEffect(() => {
    if (currentParamTenant === tenant && currentParamRole === role) {
      return;
    }

    const next = new URLSearchParams(searchParams);
    next.set('tenant', tenant);
    next.set('role', role);
    setSearchParams(next, { replace: true });
  }, [role, tenant, currentParamTenant, currentParamRole, setSearchParams]);

  useEffect(() => {
    if (authStatus !== 'authenticated' || billingCreditsQuery.isLoading || !pricingRedirectTarget) {
      return;
    }

    navigate(pricingRedirectTarget, { replace: true });
  }, [authStatus, billingCreditsQuery.isLoading, navigate, pricingRedirectTarget]);

  if (authStatus === 'loading') {
    return (
      <div className="min-h-screen bg-[#07080D] text-white flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-400 mx-auto mb-4" />
          <p className="text-slate-300">Verifying session...</p>
        </div>
      </div>
    );
  }

  if (authStatus === 'anonymous' || authStatus === 'session-error') {
    return (
      <div className="min-h-screen bg-[#07080D] text-white px-6 py-16">
        <div className="max-w-3xl mx-auto rounded-2xl border border-white/10 bg-white/[0.03] p-8">
          <h1 className="text-3xl font-bold mb-3">Platform Workspace</h1>
          <p className="text-slate-300 mb-6">
            Sign in to access Cybertron multi-app workspace with tenant-aware and role-aware views.
          </p>
          {authStatus === 'session-error' && (
            <p className="text-sm text-amber-200 mb-4">
              Session verification failed. This may be a temporary network issue. Try logging in again.
            </p>
          )}
          <a
            href={loginUrl}
            className="inline-flex rounded-lg bg-cyan-600 hover:bg-cyan-500 px-5 py-2.5 font-medium"
          >
            Continue To Secure Login
          </a>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#07080D] text-white px-4 sm:px-6 py-8">
      <div className="max-w-7xl mx-auto space-y-6">
        <header className="rounded-2xl border border-white/10 bg-white/[0.03] p-5 sm:p-6">
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
            <div>
              <p className="text-xs uppercase tracking-[0.2em] text-cyan-300 mb-2">Cybertron Platform</p>
              <h1 className="text-2xl sm:text-3xl font-bold mb-1">Multi-App Operations Shell</h1>
              <p className="text-sm text-slate-300">
                Tenant-aware security operations workspace for global teams.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 sm:min-w-[440px]">
              <label className="text-sm">
                <span className="text-slate-300 mb-1 block">Tenant</span>
                <select
                  className="w-full rounded-lg border border-white/15 bg-white/[0.05] px-3 py-2"
                  value={tenant}
                  disabled={tenantOptions.length === 0}
                  title={
                    tenantOptions.length === 0
                      ? `No tenant data available from backend. Open ${operationsLabel}.`
                      : undefined
                  }
                  onChange={event => {
                    const nextTenant = event.target.value;
                    setTenant(nextTenant);
                    trackEvent('tenant_switch', { tenant: nextTenant });
                  }}
                >
                  {tenantOptions.length === 0 && <option value={tenant}>No tenants available</option>}
                  {tenantOptions.map(option => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </select>
                {tenantOptions.length === 0 && (
                  <p className="mt-1 text-xs text-amber-200">
                    No tenants available (backend not configured). Open{' '}
                    <Link to={operationsPath} className="underline">
                      {operationsLabel}
                    </Link>
                    .
                  </p>
                )}
              </label>

              <label className="text-sm">
                <span className="text-slate-300 mb-1 block">Role</span>
                <select
                  className="w-full rounded-lg border border-white/15 bg-white/[0.05] px-3 py-2"
                  value={role}
                  onChange={event => {
                    const nextRole = normalizeRole(event.target.value);
                    setRole(nextRole);
                    trackEvent('role_switch', { role: nextRole });
                  }}
                >
                  {roleOptions.map(option => (
                    <option key={option} value={option}>
                      {roleLabels[option]}
                    </option>
                  ))}
                </select>
              </label>

              <div className="flex items-center gap-2">
                <NotificationBell tenant={tenant} enabled={authStatus === 'authenticated'} />
                <div className="rounded-lg border border-white/15 bg-white/[0.05] px-3 py-2 flex flex-col justify-center">
                  <span className="text-xs text-slate-300">Session</span>
                  <span className="text-sm font-medium truncate">{profile?.email ?? profile?.id ?? 'active'}</span>
                </div>
              </div>
            </div>
          </div>
        </header>

        <div className="grid gap-6 lg:grid-cols-[300px_1fr]">
          {platformConfigError && (
            <div className="lg:col-span-2 rounded-xl border border-amber-300/30 bg-amber-400/10 px-4 py-3 text-sm text-amber-100">
              Platform not fully configured. Resolve missing dependencies in{' '}
              <Link to={operationsPath} className="underline capitalize">
                {operationsLabel}
              </Link>
              .
            </div>
          )}
          <aside className="rounded-2xl border border-white/10 bg-white/[0.03] p-4 space-y-3">
            <p className="text-xs uppercase tracking-[0.2em] text-cyan-300 mb-1">Applications</p>

            {appsQuery.isError && (
              <div className="rounded-lg border border-amber-300/30 bg-amber-400/10 px-3 py-2 text-sm text-amber-200">
                {appsQuery.error instanceof ApiError && appsQuery.error.status === 503
                  ? 'Platform backend is not configured yet (database/redis dependency missing). Open runtime status for fix steps.'
                  : appsQuery.error instanceof ApiError
                    ? appsQuery.error.message
                    : 'Unable to load platform applications from backend.'}
              </div>
            )}

            {apps.map(app => (
              <button
                key={app.id}
                type="button"
                onClick={() => navigate(`${app.path}?tenant=${tenant}&role=${role}`)}
                className={`w-full rounded-xl text-left border px-4 py-3 transition-colors ${
                  selectedApp?.id === app.id
                    ? 'border-cyan-400/40 bg-cyan-500/10'
                    : 'border-white/10 bg-white/[0.02] hover:bg-white/[0.06]'
                }`}
              >
                <p className="font-medium mb-1">{app.name}</p>
                <p className="text-xs text-slate-300 leading-relaxed">{app.tagline}</p>
              </button>
            ))}

            <Link
              to="/"
              className="block rounded-lg border border-white/15 bg-white/[0.02] px-3 py-2 text-sm text-slate-200 hover:bg-white/[0.06]"
            >
              Back to Corporate Site
            </Link>
          </aside>

          <main className="rounded-2xl border border-white/10 bg-white/[0.03] p-5 sm:p-6 space-y-6">
            {selectedApp ? (
              <>
                <header>
                  <p className="text-xs uppercase tracking-[0.2em] text-cyan-300 mb-2">Selected Module</p>
                  <h2 className="text-2xl font-bold mb-2">{selectedApp.name}</h2>
                  <p className="text-slate-300 max-w-3xl">{selectedApp.description}</p>
                </header>

                {billingQuotaExhausted && (
                  <section className="rounded-xl border border-amber-300/20 bg-amber-400/10 p-5">
                    <p className="text-xs uppercase tracking-[0.16em] text-amber-200 mb-2">Plan Limit Reached</p>
                    <p className="text-lg font-semibold text-white mb-2">
                      {billingInfo?.planLabel || 'Current'} plan quota is exhausted
                    </p>
                    <p className="text-sm text-amber-100/90">
                      Upgrade the tenant plan to continue using protected product workflows.
                      {billingWindowLabel ? ` Usage resets on ${billingWindowLabel}.` : ''}
                    </p>
                    <div className="mt-4 flex flex-wrap gap-3">
                      <Link
                        to={`/pricing?reason=billing_quota_exhausted&tier=${encodeURIComponent(billingInfo?.planTier || 'free')}${billingInfo?.quotaLimitUnits !== null && billingInfo?.quotaLimitUnits !== undefined ? `&limit=${encodeURIComponent(String(billingInfo.quotaLimitUnits))}` : ''}${billingInfo?.quotaRemainingUnits !== null && billingInfo?.quotaRemainingUnits !== undefined ? `&remaining=${encodeURIComponent(String(billingInfo.quotaRemainingUnits))}` : ''}${billingInfo?.periodEndsAt ? `&periodEndsAt=${encodeURIComponent(billingInfo.periodEndsAt)}` : ''}&returnTo=${encodeURIComponent(`/platform/${selectedApp.id}?tenant=${tenant}&role=${role}`)}`}
                        className="inline-flex rounded-lg border border-cyan-300/30 bg-cyan-400/10 px-4 py-2 text-sm hover:bg-cyan-400/15"
                      >
                        Upgrade Plan
                      </Link>
                    </div>
                  </section>
                )}

                <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
                  <article className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
                    <p className="text-sm text-slate-300 mb-1">Tenant</p>
                    <p className="text-lg font-semibold capitalize flex items-center gap-2">
                      <Building2 className="h-4 w-4 text-cyan-300" />
                      {tenant}
                    </p>
                  </article>

                  <article className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
                    <p className="text-sm text-slate-300 mb-1">Role Scope</p>
                    <p className="text-lg font-semibold capitalize flex items-center gap-2">
                      <UserCog className="h-4 w-4 text-cyan-300" />
                      {roleLabels[role]}
                    </p>
                  </article>

                  <article className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
                    <p className="text-sm text-slate-300 mb-1">Backend Health</p>
                    <p className="text-lg font-semibold capitalize flex items-center gap-2">
                      <Activity className="h-4 w-4 text-cyan-300" />
                      {backendHealth.isError ? 'unavailable' : backendHealth.data?.status ?? 'checking'}
                    </p>
                  </article>

                  <AppStatusCard app={selectedApp} tenant={tenant} role={role} />

                  <article className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
                    <p className="text-sm text-slate-300 mb-1">Billing Credits</p>
                    <p className="text-lg font-semibold capitalize flex items-center gap-2">
                      <Coins className="h-4 w-4 text-cyan-300" />
                      {billingCreditsQuery.isError
                        ? 'unavailable'
                        : billingCreditsQuery.data
                          ? billingQuotaEnforced
                            ? `${billingRemainingLabel} left`
                            : String(billingCreditsQuery.data.balanceUnits)
                          : 'checking'}
                    </p>
                    <p className="text-xs text-slate-400 mt-1">
                      {billingQuotaEnforced && billingInfo
                        ? `${billingInfo.usedUnits ?? 0} used${billingInfo.quotaLimitUnits ? ` of ${billingInfo.quotaLimitUnits}` : ''}${billingWindowLabel ? ` until ${billingWindowLabel}` : ''}`
                        : billingUsageQuery.data?.pagination?.total !== undefined
                          ? `${billingUsageQuery.data.pagination.total} usage events`
                        : billingUsageQuery.isError
                          ? 'Usage data unavailable'
                          : billingUsageQuery.isLoading
                            ? 'Loading usage data...'
                            : 'No usage data'}
                    </p>
                  </article>
                </div>

                <section className="rounded-xl border border-white/10 bg-white/[0.02] p-5">
                  <h3 className="text-lg font-semibold mb-3">Module Capabilities</h3>
                  <ul className="space-y-2">
                    {selectedApp.capabilities.map(capability => (
                      <li key={capability} className="text-sm text-slate-200 flex items-start gap-2">
                        <ShieldCheck className="h-4 w-4 text-cyan-300 mt-0.5" />
                        <span>{capability}</span>
                      </li>
                    ))}
                  </ul>
                </section>

                <section className="rounded-xl border border-white/10 bg-[#052537]/70 p-5 space-y-4">
                  <h3 className="text-lg font-semibold">Operational Console</h3>
                  {selectedApp.id === 'threat-command' && (
                    <ThreatCommandConsole tenant={tenant} role={role} />
                  )}
                  {selectedApp.id === 'identity-guardian' && (
                    <IdentityGuardianConsole tenant={tenant} role={role} />
                  )}
                  {selectedApp.id === 'resilience-hq' && (
                    <ResilienceHQConsole tenant={tenant} role={role} />
                  )}
                  {selectedApp.id === 'risk-copilot' && (
                    <RiskCopilotConsole tenant={tenant} role={role} />
                  )}
                </section>
              </>
            ) : (
              <div className="rounded-xl border border-white/10 bg-white/[0.02] p-6">
                <p className="text-lg font-semibold mb-2 flex items-center gap-2">
                  <Lock className="h-5 w-5 text-amber-300" />
                  No Accessible Applications
                </p>
                <p className="text-sm text-slate-300">
                  {appsQuery.isLoading
                    ? 'Loading app catalog...'
                    : appsQuery.isError
                      ? 'Backend app catalog is unavailable for this session.'
                      : 'Your current role does not have access to platform applications. Switch role or request elevated permissions.'}
                </p>
                {hasRoleAccess(role, 'tenant_admin') && (
                  <p className="text-xs text-slate-400 mt-3">
                    Tenant Admin can enable products and flags using governance controls below.
                  </p>
                )}
              </div>
            )}

            <PlatformGovernancePanel tenant={tenant} role={role} />
            <AiAgentsPanel tenant={tenant} role={role} />
          </main>
        </div>
      </div>
    </div>
  );
}
