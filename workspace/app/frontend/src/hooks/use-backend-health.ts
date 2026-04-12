import { useQuery } from '@tanstack/react-query';
import { fetchSystemHealth } from '@/lib/backend';
import { trackEvent } from '@/lib/analytics';

export function useBackendHealth() {
  return useQuery({
    queryKey: ['backend-health'],
    queryFn: async () => {
      const result = await fetchSystemHealth();
      trackEvent('backend_health', {
        status: result.status,
        region: result.region,
      });
      return result;
    },
    staleTime: 30_000,
    refetchInterval: 60_000,
  });
}
