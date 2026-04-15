import { useQuery } from '@tanstack/react-query';
import { Globe2, MapPinned } from 'lucide-react';
import { ApiError } from '@/lib/api';
import { fetchAttackMapData } from '@/lib/backend';

function errorMessage(error: unknown, fallback: string) {
  return error instanceof ApiError ? error.message : fallback;
}

function project(lat: number, lon: number) {
  const x = ((lon + 180) / 360) * 1000;
  const y = ((90 - lat) / 180) * 520;
  return { x, y };
}

export default function AttackMapPanel({
  tenant,
}: {
  tenant: string;
}) {
  const attackMapQuery = useQuery({
    queryKey: ['attack-map-panel', tenant],
    queryFn: () => fetchAttackMapData(tenant),
    staleTime: 60_000,
  });

  const nodes = attackMapQuery.data?.nodes || [];
  const edges = attackMapQuery.data?.edges || [];
  const countrySummary = attackMapQuery.data?.countrySummary || [];
  const sourceNodes = nodes.filter(node => node.type === 'source');
  const destinationNodes = nodes.filter(node => node.type === 'destination');

  return (
    <section className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h4 className="text-sm font-semibold text-white">Attack Map</h4>
          <p className="mt-1 text-xs text-slate-400">
            Geospatial plotting is only shown when real alerts include `source_geo_lat`, `source_geo_lon`, `dest_geo_lat`, and `dest_geo_lon`.
          </p>
        </div>
        <div className="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1 text-xs text-slate-300">
          {attackMapQuery.data?.timeRange || '7d'}
        </div>
      </div>

      {attackMapQuery.isError ? (
        <p className="text-sm text-amber-200">
          {errorMessage(attackMapQuery.error, 'Attack map data is unavailable.')}
        </p>
      ) : !nodes.length ? (
        <div className="rounded-lg border border-dashed border-white/10 bg-[#08111f] p-8 text-center">
          <MapPinned className="mx-auto mb-3 h-10 w-10 text-slate-600" />
          <p className="text-base font-semibold text-white">Connect a data source to see live threat activity</p>
          <p className="mt-2 text-sm text-slate-400 max-w-md mx-auto">
            Wazuh, MISP, OpenCTI, or TheHive connections will populate this map with real-time geo-tagged attack paths.
            Alert payloads must include <code className="text-xs bg-white/5 px-1 py-0.5 rounded">source_geo_lat</code>, <code className="text-xs bg-white/5 px-1 py-0.5 rounded">source_geo_lon</code>, <code className="text-xs bg-white/5 px-1 py-0.5 rounded">dest_geo_lat</code>, and <code className="text-xs bg-white/5 px-1 py-0.5 rounded">dest_geo_lon</code>.
          </p>
          <a
            href="/platform/connectors"
            className="mt-4 inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 text-white text-sm font-semibold hover:from-cyan-500 hover:to-blue-500 transition-all duration-200"
          >
            <Globe2 className="h-4 w-4" />
            Configure Connectors
          </a>
        </div>
      ) : (
        <div className="grid gap-4 xl:grid-cols-[1.2fr_0.8fr]">
          <div className="rounded-lg border border-white/10 bg-[#08111f] p-3">
            <svg viewBox="0 0 1000 520" className="h-[320px] w-full rounded-lg bg-[radial-gradient(circle_at_top,#12324d,transparent_55%),linear-gradient(180deg,#04111c,#071826)]">
              <rect x="0" y="0" width="1000" height="520" fill="transparent" />
              {edges.slice(0, 120).map(edge => {
                const sourceNode = nodes.find(node => node.ip === edge.source);
                const destinationNode = nodes.find(node => node.ip === edge.destination);
                if (!sourceNode || !destinationNode) {
                  return null;
                }
                const start = project(sourceNode.lat, sourceNode.lon);
                const end = project(destinationNode.lat, destinationNode.lon);
                const controlX = (start.x + end.x) / 2;
                const controlY = Math.min(start.y, end.y) - 40;
                return (
                  <path
                    key={`${edge.source}-${edge.destination}-${edge.latestEvent}`}
                    d={`M ${start.x} ${start.y} Q ${controlX} ${controlY} ${end.x} ${end.y}`}
                    fill="none"
                    stroke={edge.severity === 'critical' ? '#fb7185' : edge.severity === 'high' ? '#f59e0b' : '#22d3ee'}
                    strokeOpacity="0.55"
                    strokeWidth={Math.min(4, 1 + edge.alertCount / 8)}
                  />
                );
              })}
              {sourceNodes.map(node => {
                const point = project(node.lat, node.lon);
                return (
                  <circle
                    key={`src-${node.ip}`}
                    cx={point.x}
                    cy={point.y}
                    r={Math.min(9, 3 + node.alertCount / 6)}
                    fill="#f97316"
                    fillOpacity="0.9"
                  />
                );
              })}
              {destinationNodes.map(node => {
                const point = project(node.lat, node.lon);
                return (
                  <circle
                    key={`dst-${node.ip}`}
                    cx={point.x}
                    cy={point.y}
                    r={Math.min(9, 3 + node.alertCount / 6)}
                    fill="#22d3ee"
                    fillOpacity="0.85"
                  />
                );
              })}
            </svg>

            <div className="mt-4 grid gap-3 sm:grid-cols-3">
              <div className="rounded-lg border border-white/10 bg-white/[0.03] p-3">
                <p className="text-xs uppercase tracking-[0.16em] text-slate-500">Source IPs</p>
                <p className="mt-2 text-lg font-semibold text-white">{sourceNodes.length}</p>
              </div>
              <div className="rounded-lg border border-white/10 bg-white/[0.03] p-3">
                <p className="text-xs uppercase tracking-[0.16em] text-slate-500">Destination IPs</p>
                <p className="mt-2 text-lg font-semibold text-white">{destinationNodes.length}</p>
              </div>
              <div className="rounded-lg border border-white/10 bg-white/[0.03] p-3">
                <p className="text-xs uppercase tracking-[0.16em] text-slate-500">Observed Paths</p>
                <p className="mt-2 text-lg font-semibold text-white">{edges.length}</p>
              </div>
            </div>
          </div>

          <div className="space-y-3">
            <div className="rounded-lg border border-white/10 bg-[#08111f] p-3">
              <div className="mb-3 flex items-center gap-2">
                <Globe2 className="h-4 w-4 text-cyan-300" />
                <p className="text-sm font-medium text-white">Country Summary</p>
              </div>
              <div className="space-y-2">
                {countrySummary.slice(0, 6).map(country => (
                  <div key={country.country} className="rounded-lg border border-white/10 bg-white/[0.03] p-3">
                    <div className="flex items-center justify-between gap-3">
                      <p className="text-sm font-medium text-white">{country.country}</p>
                      <p className="text-xs text-slate-400">{country.attack_count} alerts</p>
                    </div>
                    <p className="mt-1 text-xs text-slate-500">{country.unique_ips} unique source IPs</p>
                  </div>
                ))}
              </div>
            </div>

            <div className="rounded-lg border border-white/10 bg-[#08111f] p-3">
              <div className="mb-3 flex items-center gap-2">
                <MapPinned className="h-4 w-4 text-cyan-300" />
                <p className="text-sm font-medium text-white">Top Geo Nodes</p>
              </div>
              <div className="space-y-2">
                {nodes.slice(0, 6).map(node => (
                  <div key={`${node.type}-${node.ip}`} className="rounded-lg border border-white/10 bg-white/[0.03] p-3">
                    <p className="text-sm font-medium text-white">{node.ip}</p>
                    <p className="mt-1 text-xs text-slate-400">
                      {node.country}{node.city ? `, ${node.city}` : ''} · {node.type}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
