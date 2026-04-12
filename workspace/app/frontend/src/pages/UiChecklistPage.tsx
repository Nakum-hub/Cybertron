import { useMemo, useState } from 'react';
import { CheckCircle2, Loader2, Play, XCircle } from 'lucide-react';
import { Link, useSearchParams } from 'react-router-dom';
import { ApiError } from '@/lib/api';
import { getConfig } from '@/lib/config';
import { useAuthStatus } from '@/hooks/use-auth-status';
import {
  createIoc,
  fetchBillingUsage,
  fetchIncidents,
  fetchOpenApiSpec,
  fetchTenantFeatureFlags,
  fetchTenantProducts,
  fetchThreatSummary,
  updateTenantFeatureFlag,
  updateTenantProductState,
  uploadReportFile,
} from '@/lib/backend';
import { hasRoleAccess, normalizeRole, roleLabels, type PlatformRole } from '@/lib/platform-registry';

type RunStatus = 'idle' | 'running' | 'pass' | 'fail';

type TestResult = {
  status: RunStatus;
  detail: string;
};

type UiChecklistItem = {
  id: string;
  label: string;
  endpoint: string;
  expected: string;
  roleGate: string;
  run: () => Promise<TestResult>;
};

function toFailureResult(error: unknown): TestResult {
  if (error instanceof ApiError) {
    return {
      status: 'fail',
      detail: `${error.status} ${error.message}`,
    };
  }

  if (error instanceof Error) {
    return {
      status: 'fail',
      detail: error.message,
    };
  }

  return {
    status: 'fail',
    detail: 'Unknown UI checklist failure.',
  };
}

function buildApiProbeUrl(path: string, query?: Record<string, string>): string {
  const { apiBaseUrl } = getConfig();
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  const base = apiBaseUrl === '/' ? '' : apiBaseUrl.replace(/\/+$/, '');
  const url = new URL(`${base}${normalizedPath}`, window.location.origin);
  Object.entries(query || {}).forEach(([key, value]) => {
    if (!value) {
      return;
    }
    url.searchParams.set(key, value);
  });
  return url.toString();
}

function getEffectiveProductEnabled(product: {
  enabled: boolean;
  tenantEnabled: boolean | null;
  effectiveEnabled?: boolean;
}): boolean {
  if (typeof product.effectiveEnabled === 'boolean') {
    return product.effectiveEnabled;
  }

  const tenantEnabled = product.tenantEnabled === null ? true : Boolean(product.tenantEnabled);
  return Boolean(product.enabled) && tenantEnabled;
}

export default function UiChecklistPage() {
  const { status: authStatus, profile, loginUrl } = useAuthStatus();
  const [searchParams] = useSearchParams();

  const tenant = profile?.tenant || searchParams.get('tenant') || 'global';
  const role: PlatformRole = normalizeRole(profile?.role || searchParams.get('role') || 'executive_viewer');

  const canAnalyst = hasRoleAccess(role, 'security_analyst');
  const canTenantAdmin = hasRoleAccess(role, 'tenant_admin');

  const [results, setResults] = useState<Record<string, TestResult>>({});
  const [runningAll, setRunningAll] = useState(false);

  const checklist = useMemo<UiChecklistItem[]>(() => [
    {
      id: 'threat-summary-refresh',
      label: 'Threat dashboard refresh',
      endpoint: 'GET /v1/threats/summary',
      expected: 'Returns summary payload (live, empty, or unavailable fallback).',
      roleGate: 'executive_viewer+',
      run: async () => {
        const summary = await fetchThreatSummary();
        return {
          status: 'pass',
          detail: `Summary payload received: activeThreats=${summary.activeThreats}`,
        };
      },
    },
    {
      id: 'incident-list-load',
      label: 'Incident list load',
      endpoint: 'GET /v1/incidents?tenant=...',
      expected: 'Tenant-scoped incident list with pagination payload.',
      roleGate: 'executive_viewer+',
      run: async () => {
        const incidents = await fetchIncidents(tenant, { limit: 5 });
        return {
          status: 'pass',
          detail: `Loaded ${incidents.data.length} incident record(s).`,
        };
      },
    },
    {
      id: 'ioc-add',
      label: 'IOC add',
      endpoint: 'POST /v1/iocs?tenant=...',
      expected: 'Creates IOC for analyst role; denies lower roles.',
      roleGate: 'security_analyst+',
      run: async () => {
        try {
          const value = `qa-${Date.now()}.cybertron.local`;
          const record = await createIoc(tenant, {
            iocType: 'domain',
            value,
            source: 'ui-checklist',
            confidence: 50,
          });

          if (!canAnalyst) {
            return {
              status: 'fail',
              detail: `Unexpected write success for non-analyst role. IOC ${record.id} was created.`,
            };
          }

          return {
            status: 'pass',
            detail: `IOC created successfully: ${record.id}`,
          };
        } catch (error) {
          if (error instanceof ApiError && (error.status === 401 || error.status === 403) && !canAnalyst) {
            return {
              status: 'pass',
              detail: 'IOC write correctly denied for non-analyst role.',
            };
          }

          return toFailureResult(error);
        }
      },
    },
    {
      id: 'ioc-delete-availability',
      label: 'IOC delete availability',
      endpoint: 'DELETE /v1/iocs/:id (if implemented)',
      expected: 'Delete test only if endpoint exists in OpenAPI.',
      roleGate: 'security_analyst+',
      run: async () => {
        const spec = await fetchOpenApiSpec();
        const hasDelete = Object.entries(spec.paths || {}).some(([path, methods]) => {
          if (!path.includes('/iocs')) {
            return false;
          }
          return Boolean((methods as Record<string, unknown>)?.delete);
        });

        if (!hasDelete) {
          return {
            status: 'pass',
            detail: 'IOC delete endpoint is not exposed; UI correctly avoids delete action.',
          };
        }

        return {
          status: 'fail',
          detail: 'IOC delete endpoint exists but checklist flow for destructive test is not yet wired.',
        };
      },
    },
    {
      id: 'reports-upload-download',
      label: 'Report upload/download',
      endpoint: 'POST /v1/reports/upload + GET /v1/reports/{id}/download',
      expected: 'Uploads allowed files and streams report download for authorized users.',
      roleGate: 'security_analyst+',
      run: async () => {
        try {
          const payload = new File(
            [JSON.stringify({ probe: 'ui-checklist', timestamp: new Date().toISOString() })],
            'ui-checklist.json',
            { type: 'application/json' }
          );

          const reportDate = new Date().toISOString().slice(0, 10);
          const uploadResult = await uploadReportFile(tenant, {
            reportType: 'qa_checklist_probe',
            reportDate,
            file: payload,
            idempotencyKey: `qa-ui-checklist-${tenant}`,
          });

          const template = getConfig().reportDownloadPathTemplate || '/v1/reports/{reportId}/download';
          const path = template.replace('{reportId}', encodeURIComponent(uploadResult.report.id));
          const response = await fetch(
            buildApiProbeUrl(path, { tenant }),
            {
              method: 'GET',
              credentials: 'include',
            }
          );

          if (!response.ok) {
            return {
              status: 'fail',
              detail: `Upload succeeded but download returned ${response.status}.`,
            };
          }

          return {
            status: 'pass',
            detail: `Upload and download probe passed for report ${uploadResult.report.id}.`,
          };
        } catch (error) {
          if (error instanceof ApiError && (error.status === 401 || error.status === 403) && !canAnalyst) {
            return {
              status: 'pass',
              detail: 'Report upload/download correctly denied for non-analyst role.',
            };
          }

          return toFailureResult(error);
        }
      },
    },
    {
      id: 'product-toggle-admin',
      label: 'Product enablement toggle (admin)',
      endpoint: 'PATCH /v1/tenants/{tenant}/products/{productKey}',
      expected: 'Applies tenant product state for admin roles; denies lower roles.',
      roleGate: 'tenant_admin+',
      run: async () => {
        try {
          const products = await fetchTenantProducts(tenant, role);
          if (!products.length) {
            return {
              status: 'fail',
              detail: 'No products available for toggle probe.',
            };
          }

          const target = products[0];
          await updateTenantProductState(tenant, target.productKey, {
            enabled: getEffectiveProductEnabled(target),
            roleMin: target.roleMin,
          });

          if (!canTenantAdmin) {
            return {
              status: 'fail',
              detail: 'Unexpected product toggle success for non-admin role.',
            };
          }

          return {
            status: 'pass',
            detail: `Product governance endpoint accepted update for ${target.productKey}.`,
          };
        } catch (error) {
          if (error instanceof ApiError && (error.status === 401 || error.status === 403) && !canTenantAdmin) {
            return {
              status: 'pass',
              detail: 'Product toggle correctly denied for non-admin role.',
            };
          }

          return toFailureResult(error);
        }
      },
    },
    {
      id: 'feature-flag-toggle-admin',
      label: 'Feature flag toggle (admin)',
      endpoint: 'PATCH /v1/tenants/{tenant}/feature-flags/{flagKey}',
      expected: 'Applies tenant feature flag state for admin roles; denies lower roles.',
      roleGate: 'tenant_admin+',
      run: async () => {
        try {
          const flags = await fetchTenantFeatureFlags(tenant);
          if (!flags.length) {
            return {
              status: 'pass',
              detail: 'No feature flags configured; endpoint list call succeeded.',
            };
          }

          const flag = flags[0];
          await updateTenantFeatureFlag(tenant, flag.flagKey, Boolean(flag.enabled));

          if (!canTenantAdmin) {
            return {
              status: 'fail',
              detail: 'Unexpected feature flag update success for non-admin role.',
            };
          }

          return {
            status: 'pass',
            detail: `Feature flag update endpoint accepted ${flag.flagKey}.`,
          };
        } catch (error) {
          if (error instanceof ApiError && (error.status === 401 || error.status === 403) && !canTenantAdmin) {
            return {
              status: 'pass',
              detail: 'Feature flag update correctly denied for non-admin role.',
            };
          }

          return toFailureResult(error);
        }
      },
    },
    {
      id: 'billing-usage-view',
      label: 'Billing usage view',
      endpoint: 'GET /v1/billing/usage?tenant=...',
      expected: 'Returns metered usage for analyst roles; denies lower roles.',
      roleGate: 'security_analyst+',
      run: async () => {
        try {
          const usage = await fetchBillingUsage(tenant, { limit: 5 });
          if (!canAnalyst) {
            return {
              status: 'fail',
              detail: `Unexpected billing usage success for role ${roleLabels[role]}.`,
            };
          }

          return {
            status: 'pass',
            detail: `Billing usage query returned ${usage.data.length} event(s).`,
          };
        } catch (error) {
          if (error instanceof ApiError && (error.status === 401 || error.status === 403) && !canAnalyst) {
            return {
              status: 'pass',
              detail: 'Billing usage endpoint correctly denied for non-analyst role.',
            };
          }

          return toFailureResult(error);
        }
      },
    },
  ], [canAnalyst, canTenantAdmin, role, tenant]);

  const totals = useMemo(() => {
    const values = Object.values(results);
    return {
      pass: values.filter(result => result.status === 'pass').length,
      fail: values.filter(result => result.status === 'fail').length,
      running: values.filter(result => result.status === 'running').length,
    };
  }, [results]);

  async function runSingle(item: UiChecklistItem) {
    setResults(current => ({
      ...current,
      [item.id]: {
        status: 'running',
        detail: 'Running endpoint verification...',
      },
    }));

    try {
      const next = await item.run();
      setResults(current => ({
        ...current,
        [item.id]: next,
      }));
    } catch (error) {
      setResults(current => ({
        ...current,
        [item.id]: toFailureResult(error),
      }));
    }
  }

  async function runAll() {
    setRunningAll(true);
    for (const item of checklist) {
      // Sequential execution keeps endpoint traffic predictable for auth/rate-limit tests.
      // eslint-disable-next-line no-await-in-loop
      await runSingle(item);
    }
    setRunningAll(false);
  }

  if (authStatus === 'anonymous') {
    return (
      <div className="min-h-screen bg-[#07080D] text-white px-6 py-16">
        <div className="max-w-3xl mx-auto rounded-2xl border border-white/10 bg-white/[0.03] p-8">
          <h1 className="text-3xl font-bold mb-3">UI Checklist</h1>
          <p className="text-slate-300 mb-6">
            Sign in to execute authenticated interface and backend parity checks.
          </p>
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
          <p className="text-xs uppercase tracking-[0.2em] text-cyan-300 mb-2">Phase 2.5 QA</p>
          <h1 className="text-3xl font-bold mb-2">UI Parity Checklist</h1>
          <p className="text-sm text-slate-300">
            Button-by-button verification page for frontend-to-backend interface wiring.
          </p>
          <div className="mt-3 text-sm text-slate-200">
            Tenant <span className="font-semibold">{tenant}</span> | Role <span className="font-semibold">{roleLabels[role]}</span>
          </div>
        </header>

        <section className="grid gap-4 sm:grid-cols-4">
          <article className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
            <p className="text-xs text-slate-400 mb-1">Total Checks</p>
            <p className="text-2xl font-bold">{checklist.length}</p>
          </article>
          <article className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
            <p className="text-xs text-slate-400 mb-1">Passing</p>
            <p className="text-2xl font-bold text-emerald-300">{totals.pass}</p>
          </article>
          <article className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
            <p className="text-xs text-slate-400 mb-1">Failing</p>
            <p className="text-2xl font-bold text-red-300">{totals.fail}</p>
          </article>
          <article className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
            <p className="text-xs text-slate-400 mb-1">Running</p>
            <p className="text-2xl font-bold text-cyan-200">{totals.running}</p>
          </article>
        </section>

        <div className="flex flex-wrap gap-3">
          <button
            type="button"
            onClick={() => void runAll()}
            disabled={runningAll}
            className="inline-flex items-center gap-2 rounded-lg border border-cyan-300/30 bg-cyan-400/10 px-4 py-2 text-sm hover:bg-cyan-400/15 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {runningAll ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
            Run All Checks
          </button>
          <Link to="/status" className="inline-flex rounded-lg border border-white/20 bg-white/[0.04] px-4 py-2 text-sm hover:bg-white/[0.08]">
            Status Page
          </Link>
          <Link to="/qa/ui-wiring" className="inline-flex rounded-lg border border-cyan-300/30 bg-cyan-400/10 px-4 py-2 text-sm hover:bg-cyan-400/15">
            UI Wiring QA
          </Link>
          <Link to="/diagnostics" className="inline-flex rounded-lg border border-amber-300/30 bg-amber-400/10 px-4 py-2 text-sm hover:bg-amber-400/15">
            Diagnostics Page
          </Link>
          <Link to="/docs" className="inline-flex rounded-lg border border-white/20 bg-white/[0.04] px-4 py-2 text-sm hover:bg-white/[0.08]">
            Docs Page
          </Link>
          <Link to="/" className="inline-flex rounded-lg border border-white/20 bg-white/[0.04] px-4 py-2 text-sm hover:bg-white/[0.08]">
            Back To Corporate Site
          </Link>
        </div>

        <section className="space-y-3">
          {checklist.map(item => {
            const result = results[item.id] || { status: 'idle', detail: 'Not run yet.' };
            const icon =
              result.status === 'pass'
                ? <CheckCircle2 className="h-4 w-4 text-emerald-300" />
                : result.status === 'fail'
                  ? <XCircle className="h-4 w-4 text-red-300" />
                  : result.status === 'running'
                    ? <Loader2 className="h-4 w-4 animate-spin text-cyan-200" />
                    : null;

            return (
              <article key={item.id} className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
                <div className="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-3">
                  <div className="space-y-1.5">
                    <p className="font-semibold">{item.label}</p>
                    <p className="text-xs text-slate-400">Endpoint: {item.endpoint}</p>
                    <p className="text-xs text-slate-400">Expected: {item.expected}</p>
                    <p className="text-xs text-slate-400">Gate: {item.roleGate}</p>
                    <p className="text-sm text-slate-200 flex items-center gap-2">
                      {icon}
                      {result.detail}
                    </p>
                  </div>

                  <button
                    type="button"
                    onClick={() => void runSingle(item)}
                    disabled={result.status === 'running' || runningAll}
                    className="inline-flex items-center gap-2 rounded-lg border border-cyan-300/30 bg-cyan-400/10 px-3 py-2 text-sm hover:bg-cyan-400/15 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {result.status === 'running' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
                    Run Test
                  </button>
                </div>
              </article>
            );
          })}
        </section>
      </div>
    </div>
  );
}
