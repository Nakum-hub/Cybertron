import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Activity, Database, HardDrive, Network, ShieldCheck } from 'lucide-react';
import { Link, useLocation } from 'react-router-dom';
import { useAuthStatus } from '@/hooks/use-auth-status';
import {
  fetchSystemHealth,
  fetchSystemReadiness,
  fetchTenantFeatureFlags,
  fetchTenantProducts,
} from '@/lib/backend';
import { canAccessInternalOperations } from '@/lib/internal-access';
import { normalizeRole } from '@/lib/platform-registry';

type DependencyBadgeProps = {
  label: string;
  status?: string;
  latencyMs?: number;
  configured?: boolean;
};

type FixStep = {
  id: string;
  text: string;
};

function DependencyBadge({ label, status, latencyMs, configured }: DependencyBadgeProps) {
  const normalized = String(status || 'unknown').toLowerCase();
  const statusClass =
    normalized === 'healthy'
      ? 'border-emerald-300/30 bg-emerald-400/10 text-emerald-200'
      : normalized === 'unavailable'
        ? 'border-red-300/30 bg-red-400/10 text-red-200'
        : 'border-amber-300/30 bg-amber-400/10 text-amber-100';

  return (
    <article className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
      <p className="text-xs text-slate-400 mb-2">{label}</p>
      <span className={`inline-flex rounded-full border px-2 py-0.5 text-xs uppercase ${statusClass}`}>
        {status || 'unknown'}
      </span>
      <p className="text-xs text-slate-500 mt-2">
        {configured ? `Configured | ${latencyMs ?? 0}ms` : 'Not configured'}
      </p>
    </article>
  );
}

export default function StatusPage() {
  const location = useLocation();
  const { status: authStatus, profile } = useAuthStatus();
  const tenant = profile?.tenant || 'global';
  const role = normalizeRole(profile?.role || 'executive_viewer');
  const canAccessInternal = authStatus === 'authenticated' && canAccessInternalOperations(profile?.role);

  const healthQuery = useQuery({
    queryKey: ['system-health'],
    queryFn: fetchSystemHealth,
    refetchInterval: 20_000,
  });

  const readinessQuery = useQuery({
    queryKey: ['system-readiness'],
    queryFn: fetchSystemReadiness,
    refetchInterval: 20_000,
  });

  const productsQuery = useQuery({
    queryKey: ['status-products', tenant, role],
    queryFn: () => fetchTenantProducts(tenant, role),
    enabled: authStatus === 'authenticated',
    staleTime: 20_000,
  });

  const flagsQuery = useQuery({
    queryKey: ['status-flags', tenant],
    queryFn: () => fetchTenantFeatureFlags(tenant),
    enabled: authStatus === 'authenticated',
    staleTime: 20_000,
  });

  const enabledProducts = useMemo(
    () =>
      (productsQuery.data || []).filter(product => {
        if (typeof product.effectiveEnabled === 'boolean') {
          return product.effectiveEnabled;
        }

        const tenantEnabled = product.tenantEnabled === null ? true : Boolean(product.tenantEnabled);
        return Boolean(product.enabled) && tenantEnabled;
      }),
    [productsQuery.data]
  );

  const disabledFlags = useMemo(
    () => (flagsQuery.data || []).filter(flag => !flag.enabled),
    [flagsQuery.data]
  );

  const dependencies = healthQuery.data?.dependencies || readinessQuery.data?.dependencies;

  const fixSteps = useMemo<FixStep[]>(() => {
    const steps: FixStep[] = [];

    if (!dependencies?.database?.configured) {
      steps.push({
        id: 'db-config',
        text: 'Set DATABASE_URL in workspace/.env or deployment secrets.',
      });
    } else if (dependencies.database.status !== 'healthy') {
      steps.push({
        id: 'db-health',
        text: 'Start PostgreSQL and verify DB credentials/connectivity.',
      });
    }

    if (!dependencies?.redis?.configured) {
      steps.push({
        id: 'redis-config',
        text: 'Set REDIS_URL in workspace/.env or deployment secrets.',
      });
    } else if (dependencies.redis.status !== 'healthy') {
      steps.push({
        id: 'redis-health',
        text: 'Start Redis and verify REDIS_URL connectivity.',
      });
    }

    if (dependencies?.storage?.status !== 'healthy') {
      steps.push({
        id: 'storage-health',
        text: 'Validate report storage settings (REPORT_STORAGE_DRIVER and storage endpoint/path).',
      });
    }

    return steps;
  }, [dependencies?.database?.configured, dependencies?.database?.status, dependencies?.redis?.configured, dependencies?.redis?.status, dependencies?.storage?.status]);

  const diagnosticsMode = location.pathname === '/diagnostics';

  return (
    <div className="min-h-screen bg-[#07080D] text-white px-4 sm:px-6 py-8">
      <div className="max-w-6xl mx-auto space-y-6">
        <header className="rounded-2xl border border-white/10 bg-white/[0.03] p-5 sm:p-6">
          <p className="text-xs uppercase tracking-[0.2em] text-cyan-300 mb-2">
            {diagnosticsMode ? 'Diagnostics' : 'System Status'}
          </p>
          <h1 className="text-3xl font-bold mb-2">
            {diagnosticsMode ? 'Platform Diagnostics' : 'Cybertron Runtime Health'}
          </h1>
          <p className="text-sm text-slate-300">
            Operational status for health/readiness and tenant product-feature visibility.
          </p>
        </header>

        <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <article className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
            <p className="text-xs text-slate-400 mb-1">Health</p>
            <p className="text-lg font-semibold flex items-center gap-2">
              <Activity className="h-4 w-4 text-cyan-300" />
              {healthQuery.data?.status || 'checking'}
            </p>
            <p className="text-xs text-slate-500 mt-1">
              Version {healthQuery.data?.version || '--'} | Region {healthQuery.data?.region || '--'}
            </p>
          </article>

          <article className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
            <p className="text-xs text-slate-400 mb-1">Readiness</p>
            <p className="text-lg font-semibold flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-cyan-300" />
              {readinessQuery.data?.status || 'checking'}
            </p>
            <p className="text-xs text-slate-500 mt-1">
              {readinessQuery.data?.ready ? 'Ready for traffic' : 'Not ready for traffic'}
            </p>
          </article>

          <article className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
            <p className="text-xs text-slate-400 mb-1">Tenant Products</p>
            <p className="text-lg font-semibold">{enabledProducts.length}</p>
            <p className="text-xs text-slate-500 mt-1">Enabled for tenant {tenant}</p>
          </article>

          <article className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
            <p className="text-xs text-slate-400 mb-1">Disabled Flags</p>
            <p className="text-lg font-semibold">{disabledFlags.length}</p>
            <p className="text-xs text-slate-500 mt-1">Feature gate overrides in tenant scope</p>
          </article>
        </section>

        <section className="grid gap-4 sm:grid-cols-3">
          <DependencyBadge
            label="Database"
            status={dependencies?.database?.status}
            latencyMs={dependencies?.database?.latencyMs}
            configured={dependencies?.database?.configured}
          />
          <DependencyBadge
            label="Storage"
            status={dependencies?.storage?.status}
            latencyMs={dependencies?.storage?.latencyMs}
            configured={dependencies?.storage?.configured}
          />
          <DependencyBadge
            label="Redis"
            status={dependencies?.redis?.status}
            latencyMs={dependencies?.redis?.latencyMs}
            configured={dependencies?.redis?.configured}
          />
        </section>

        <section className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
          <h2 className="text-lg font-semibold mb-3">Session Context</h2>
          <div className="grid gap-3 sm:grid-cols-2">
            <p className="text-sm text-slate-300">
              Auth state: <span className="text-white">{authStatus}</span>
            </p>
            <p className="text-sm text-slate-300">
              Tenant: <span className="text-white">{tenant}</span>
            </p>
            <p className="text-sm text-slate-300">
              Role: <span className="text-white">{role}</span>
            </p>
            <p className="text-sm text-slate-300">
              Checked at:{' '}
              <span className="text-white">
                {healthQuery.data?.checkedAt || readinessQuery.data?.checkedAt || '--'}
              </span>
            </p>
          </div>

          {readinessQuery.data?.errors?.length ? (
            <div className="mt-3 rounded-lg border border-red-300/30 bg-red-400/10 p-3">
              <p className="text-sm font-medium text-red-200 mb-1">Readiness Errors</p>
              <ul className="text-xs text-red-100 space-y-1">
                {readinessQuery.data.errors.map(error => (
                  <li key={error}>{error}</li>
                ))}
              </ul>
            </div>
          ) : null}

          {fixSteps.length > 0 ? (
            <div className="mt-3 rounded-lg border border-amber-300/30 bg-amber-400/10 p-3">
              <p className="text-sm font-medium text-amber-100 mb-1">Fix Steps</p>
              <ul className="text-xs text-amber-100 space-y-1">
                {fixSteps.map(step => (
                  <li key={step.id}>{step.text}</li>
                ))}
              </ul>
            </div>
          ) : null}
        </section>

        <div className="flex flex-wrap gap-3">
          {canAccessInternal ? (
            <>
              <Link
                to="/docs"
                className="inline-flex items-center gap-2 rounded-lg border border-cyan-300/30 bg-cyan-400/10 px-4 py-2 text-sm hover:bg-cyan-400/15"
              >
                <Database className="h-4 w-4" />
                Open Developer Docs
              </Link>
              <Link
                to="/diagnostics"
                className="inline-flex items-center gap-2 rounded-lg border border-amber-300/30 bg-amber-400/10 px-4 py-2 text-sm hover:bg-amber-400/15"
              >
                <Activity className="h-4 w-4" />
                Open Diagnostics
              </Link>
              <Link
                to="/qa/ui-checklist"
                className="inline-flex items-center gap-2 rounded-lg border border-white/20 bg-white/[0.04] px-4 py-2 text-sm hover:bg-white/[0.08]"
              >
                <Network className="h-4 w-4" />
                Open UI Checklist
              </Link>
            </>
          ) : null}
          <Link
            to="/"
            className="inline-flex items-center gap-2 rounded-lg border border-white/20 bg-white/[0.04] px-4 py-2 text-sm hover:bg-white/[0.08]"
          >
            <HardDrive className="h-4 w-4" />
            Back To Corporate Site
          </Link>
        </div>
      </div>
    </div>
  );
}
