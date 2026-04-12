import { useQuery } from '@tanstack/react-query';
import { fetchThreatBundle } from '@/lib/backend';
import { getConfig } from '@/lib/config';
import { emptyThreatIncidents, emptyThreatSummary, type ThreatIncident, type ThreatSummary } from '@/lib/contracts';

interface ThreatData {
  summary: ThreatSummary;
  incidents: ThreatIncident[];
  dataSource: 'live' | 'empty' | 'unavailable';
  dataAvailable: boolean;
  usingFallbackData: boolean;
}

async function fetchThreatData(): Promise<ThreatData> {
  return fetchThreatBundle();
}

const unavailableThreatData: ThreatData = {
  summary: emptyThreatSummary,
  incidents: emptyThreatIncidents,
  dataSource: 'unavailable',
  dataAvailable: false,
  usingFallbackData: false,
};

export function useThreatData(options: { enabled?: boolean } = {}) {
  const { publicBackendProbesEnabled } = getConfig();
  const enabled = options.enabled ?? publicBackendProbesEnabled;

  return useQuery({
    queryKey: ['threat-data', enabled ? 'live' : 'disabled'],
    queryFn: fetchThreatData,
    enabled,
    initialData: enabled ? undefined : unavailableThreatData,
    staleTime: 60_000,
    refetchInterval: enabled ? 120_000 : false,
  });
}
