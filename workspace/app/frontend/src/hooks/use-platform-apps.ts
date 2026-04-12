import { useQuery } from '@tanstack/react-query';
import { fetchPlatformApps } from '@/lib/backend';
import { type PlatformRole } from '@/lib/platform-registry';

export function usePlatformApps(role: PlatformRole, tenant = 'global', enabled = true) {
  return useQuery({
    queryKey: ['platform-apps', role, tenant],
    queryFn: async () => fetchPlatformApps(role, tenant),
    enabled,
    staleTime: 120_000,
  });
}
