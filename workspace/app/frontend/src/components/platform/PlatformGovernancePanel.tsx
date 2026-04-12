import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Cog, Flag, Lock, Package } from 'lucide-react';
import { pushToast } from '@/components/ui/toaster';
import { ApiError } from '@/lib/api';
import {
  fetchTenantFeatureFlags,
  fetchTenantProducts,
  updateTenantFeatureFlag,
  updateTenantProductState,
} from '@/lib/backend';
import { hasRoleAccess, type PlatformRole } from '@/lib/platform-registry';

function getErrorMessage(error: unknown, fallback: string) {
  return error instanceof ApiError ? error.message : fallback;
}

export default function PlatformGovernancePanel({
  tenant,
  role,
}: {
  tenant: string;
  role: PlatformRole;
}) {
  const queryClient = useQueryClient();
  const canManage = hasRoleAccess(role, 'tenant_admin');
  const productsQuery = useQuery({
    queryKey: ['governance-products', tenant, role],
    queryFn: () => fetchTenantProducts(tenant, role),
    staleTime: 30_000,
  });
  const flagsQuery = useQuery({
    queryKey: ['governance-flags', tenant],
    queryFn: () => fetchTenantFeatureFlags(tenant),
    staleTime: 30_000,
  });

  const productMutation = useMutation({
    mutationFn: ({
      productKey,
      enabled,
      roleMin,
    }: {
      productKey: string;
      enabled: boolean;
      roleMin?: string;
    }) => updateTenantProductState(tenant, productKey, { enabled, roleMin }),
    onSuccess: result => {
      queryClient.invalidateQueries({ queryKey: ['governance-products', tenant, role] });
      pushToast({
        title: 'Product state updated',
        description: `${result.name} is now ${result.enabled ? 'enabled' : 'disabled'} for ${tenant}.`,
      });
    },
    onError: error => {
      pushToast({
        title: 'Product update failed',
        description: getErrorMessage(error, 'Unable to update the product state.'),
        variant: 'destructive',
      });
    },
  });

  const flagMutation = useMutation({
    mutationFn: ({ flagKey, enabled }: { flagKey: string; enabled: boolean }) =>
      updateTenantFeatureFlag(tenant, flagKey, enabled),
    onSuccess: result => {
      queryClient.invalidateQueries({ queryKey: ['governance-flags', tenant] });
      pushToast({
        title: 'Feature flag updated',
        description: `${result.flagKey} is now ${result.enabled ? 'enabled' : 'disabled'}.`,
      });
    },
    onError: error => {
      pushToast({
        title: 'Feature flag update failed',
        description: getErrorMessage(error, 'Unable to update the feature flag.'),
        variant: 'destructive',
      });
    },
  });

  return (
    <section className="rounded-xl border border-white/10 bg-white/[0.02] p-5">
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="text-lg font-semibold text-white">Governance Controls</h3>
          <p className="mt-1 text-sm text-slate-400">
            Product and feature exposure is enforced server-side. This panel only updates live tenant overrides.
          </p>
        </div>
        <div className="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1 text-xs text-slate-300">
          {canManage ? 'Writable by tenant admin+' : 'Read-only for current role'}
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
          <div className="mb-3 flex items-center gap-2">
            <Package className="h-4 w-4 text-cyan-300" />
            <h4 className="text-sm font-semibold text-white">Tenant Products</h4>
          </div>
          {productsQuery.isError ? (
            <p className="text-sm text-amber-200">
              {getErrorMessage(productsQuery.error, 'Product governance data is unavailable.')}
            </p>
          ) : productsQuery.data?.length ? (
            <div className="space-y-3">
              {productsQuery.data.map(product => (
                <div key={product.productKey} className="rounded-lg border border-white/10 bg-[#08111f] p-3">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="text-sm font-medium text-white">{product.name}</p>
                      <p className="mt-1 text-xs text-slate-400">
                        role min {product.roleMin} · plan {product.planTier || 'n/a'}
                      </p>
                    </div>
                    <button
                      type="button"
                      disabled={!canManage || productMutation.isPending}
                      onClick={() =>
                        productMutation.mutate({
                          productKey: product.productKey,
                          enabled: !product.enabled,
                          roleMin: product.roleMin,
                        })
                      }
                      className="rounded-lg border border-cyan-300/20 bg-cyan-400/10 px-3 py-1.5 text-xs text-cyan-100 hover:bg-cyan-400/15 disabled:cursor-not-allowed disabled:opacity-60"
                    >
                      {product.enabled ? 'Disable' : 'Enable'}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-slate-400">No tenant product records are available.</p>
          )}
        </div>

        <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
          <div className="mb-3 flex items-center gap-2">
            <Flag className="h-4 w-4 text-cyan-300" />
            <h4 className="text-sm font-semibold text-white">Feature Flags</h4>
          </div>
          {flagsQuery.isError ? (
            <p className="text-sm text-amber-200">
              {getErrorMessage(flagsQuery.error, 'Feature flags are unavailable.')}
            </p>
          ) : flagsQuery.data?.length ? (
            <div className="space-y-3">
              {flagsQuery.data.map(flag => (
                <div key={flag.flagKey} className="rounded-lg border border-white/10 bg-[#08111f] p-3">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="text-sm font-medium text-white">{flag.flagKey}</p>
                      <p className="mt-1 text-xs text-slate-400">{flag.description || 'No description available.'}</p>
                    </div>
                    <button
                      type="button"
                      disabled={!canManage || flagMutation.isPending}
                      onClick={() => flagMutation.mutate({ flagKey: flag.flagKey, enabled: !flag.enabled })}
                      className="rounded-lg border border-cyan-300/20 bg-cyan-400/10 px-3 py-1.5 text-xs text-cyan-100 hover:bg-cyan-400/15 disabled:cursor-not-allowed disabled:opacity-60"
                    >
                      {flag.enabled ? 'Disable' : 'Enable'}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="rounded-lg border border-white/10 bg-[#08111f] p-4 text-sm text-slate-400">
              <div className="mb-2 flex items-center gap-2 text-slate-300">
                <Lock className="h-4 w-4" />
                No tenant overrides
              </div>
              Feature flags will appear here when tenant-specific overrides are created.
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
