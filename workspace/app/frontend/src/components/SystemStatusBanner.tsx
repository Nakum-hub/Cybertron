import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { AlertTriangle } from 'lucide-react';
import { Link, useLocation } from 'react-router-dom';
import { fetchSystemHealth, fetchSystemReadiness } from '@/lib/backend';
import { getConfig } from '@/lib/config';

type FixStep = {
  key: string;
  text: string;
};

function buildFixSteps(readiness: Awaited<ReturnType<typeof fetchSystemReadiness>> | undefined): FixStep[] {
  const dependencies = readiness?.dependencies;
  const steps: FixStep[] = [];

  if (!dependencies?.database?.configured) {
    steps.push({
      key: 'db-config',
      text: 'Set DATABASE_URL in workspace/.env (or deploy env).',
    });
  } else if (dependencies.database.status !== 'healthy') {
    steps.push({
      key: 'db-up',
      text: 'Start PostgreSQL and verify database credentials/network.',
    });
  }

  if (!dependencies?.redis?.configured) {
    steps.push({
      key: 'redis-config',
      text: 'Set REDIS_URL in workspace/.env (or deploy env).',
    });
  } else if (dependencies.redis.status !== 'healthy') {
    steps.push({
      key: 'redis-up',
      text: 'Start Redis and verify REDIS_URL connectivity.',
    });
  }

  if (dependencies?.storage?.status !== 'healthy') {
    steps.push({
      key: 'storage',
      text: 'Validate report storage (REPORT_STORAGE_DRIVER and storage connectivity).',
    });
  }

  return steps;
}

function shouldProbeStatusForRoute(pathname: string, publicBackendProbesEnabled: boolean): boolean {
  if (
    pathname === '/status' ||
    pathname === '/diagnostics' ||
    pathname.startsWith('/platform') ||
    pathname.startsWith('/products/') ||
    pathname.startsWith('/qa/')
  ) {
    return true;
  }

  return publicBackendProbesEnabled;
}

export default function SystemStatusBanner() {
  const location = useLocation();
  const { publicBackendProbesEnabled } = getConfig();
  const queryEnabled = shouldProbeStatusForRoute(location.pathname, publicBackendProbesEnabled);

  const healthQuery = useQuery({
    queryKey: ['system-health-banner'],
    queryFn: fetchSystemHealth,
    enabled: queryEnabled,
    refetchInterval: queryEnabled ? 20_000 : false,
  });

  const readinessQuery = useQuery({
    queryKey: ['system-readiness-banner'],
    queryFn: fetchSystemReadiness,
    enabled: queryEnabled,
    refetchInterval: queryEnabled ? 20_000 : false,
  });

  const visible = useMemo(() => {
    if (healthQuery.isLoading || readinessQuery.isLoading) {
      return false;
    }
    if (healthQuery.isError || readinessQuery.isError) {
      return true;
    }
    if (!readinessQuery.data?.ready) {
      return true;
    }
    return healthQuery.data?.status !== 'ok';
  }, [
    healthQuery.data?.status,
    healthQuery.isError,
    healthQuery.isLoading,
    readinessQuery.data?.ready,
    readinessQuery.isError,
    readinessQuery.isLoading,
  ]);

  if (!queryEnabled) {
    return null;
  }

  if (!visible) {
    return null;
  }

  const fixSteps = buildFixSteps(readinessQuery.data);

  return (
    <div className="fixed inset-x-0 top-0 z-[70] border-b border-amber-400/30 bg-[#2e1f00]/92 backdrop-blur-md">
      <div className="mx-auto flex max-w-7xl flex-col gap-2 px-4 py-2.5 text-amber-100 sm:px-6">
        <div className="flex items-center gap-2 text-sm font-medium">
          <AlertTriangle className="h-4 w-4" />
          Platform not fully configured. Some workflows are intentionally locked until required dependencies are healthy.
        </div>
        {fixSteps.length > 0 && (
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
            {fixSteps.map(step => (
              <span key={step.key}>{step.text}</span>
            ))}
          </div>
        )}
        <div className="flex items-center gap-3 text-xs">
          <Link to="/status" className="underline decoration-amber-200/70 underline-offset-2">
            Open status
          </Link>
        </div>
      </div>
    </div>
  );
}
