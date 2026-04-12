import { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock3,
  Monitor,
  ShieldAlert,
  Wifi,
  XCircle,
} from 'lucide-react';
import { useInView } from '@/lib/animations';
import { useThreatData } from '@/hooks/use-threat-data';

const DASHBOARD_BG = '/assets/threat-dashboard-bg.png';

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-400 bg-red-500/10 border-red-500/20',
  high: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
  medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
  low: 'text-green-400 bg-green-500/10 border-green-500/20',
};

function formatDetectedAt(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return 'Unknown';
  }

  return date.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
  });
}

function isSameUtcDay(input: string): boolean {
  const date = new Date(input);
  const now = new Date();
  if (Number.isNaN(date.getTime())) {
    return false;
  }

  return (
    date.getUTCFullYear() === now.getUTCFullYear() &&
    date.getUTCMonth() === now.getUTCMonth() &&
    date.getUTCDate() === now.getUTCDate()
  );
}

export default function ThreatDashboard() {
  const { ref, isInView } = useInView(0.1);
  const threatQuery = useThreatData();
  const [animatedTrustScore, setAnimatedTrustScore] = useState(0);

  const summary = threatQuery.data?.summary ?? {
    activeThreats: 0,
    blockedToday: 0,
    mttrMinutes: 0,
    trustScore: 0,
  };
  const incidents = threatQuery.data?.incidents ?? [];
  const hasData = threatQuery.data?.dataSource === 'live';

  const derived = useMemo(() => {
    const openIncidents = incidents.filter(incident => incident.status !== 'resolved').length;
    const resolvedToday = incidents.filter(
      incident => incident.status === 'resolved' && isSameUtcDay(incident.detectedAt)
    ).length;

    return {
      openIncidents,
      resolvedToday,
    };
  }, [incidents]);

  useEffect(() => {
    if (!isInView) {
      return;
    }

    const target = Math.max(0, Math.min(100, summary.trustScore));
    setAnimatedTrustScore(current => Math.min(current, target));

    const interval = window.setInterval(() => {
      setAnimatedTrustScore(current => {
        if (current >= target) {
          window.clearInterval(interval);
          return target;
        }

        return Math.min(target, current + 1);
      });
    }, 24);

    return () => window.clearInterval(interval);
  }, [isInView, summary.trustScore]);

  const sourceLabel =
    threatQuery.data?.dataSource === 'live'
      ? 'LIVE'
      : threatQuery.data?.dataSource === 'empty'
        ? 'NO DATA'
        : 'UNAVAILABLE';

  const sourceColorClass =
    threatQuery.data?.dataSource === 'live'
      ? 'text-green-400'
      : threatQuery.data?.dataSource === 'empty'
        ? 'text-amber-400'
        : 'text-red-400';

  const sourceDotClass =
    threatQuery.data?.dataSource === 'live'
      ? 'bg-green-400 animate-pulse'
      : threatQuery.data?.dataSource === 'empty'
        ? 'bg-amber-400'
        : 'bg-red-400';

  return (
    <section id="dashboard" className="relative py-24 sm:py-32 bg-[#080810]">
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-blue-600/5 rounded-full blur-[150px]" />

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6" ref={ref}>
        <div className="text-center mb-16">
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-cyan-500/20 bg-cyan-500/5 mb-6">
            <Monitor className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-cyan-300 text-xs font-semibold tracking-widest uppercase">
              Command Center
            </span>
          </div>
          <h2 className="text-3xl sm:text-4xl md:text-5xl font-bold text-white mb-4">
            Live Threat{' '}
            <span className="bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
              Intelligence
            </span>
          </h2>
          <p className="text-slate-400 text-lg max-w-2xl mx-auto">
            Real telemetry from connected systems. If no connector or records are configured,
            this view stays transparent with honest empty states.
          </p>
        </div>

        <div
          className={`panel-3d relative rounded-2xl border border-white/[0.08] bg-[#0C0C18] overflow-hidden transition-all duration-1000 ${
            isInView ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-12'
          }`}
          style={{ boxShadow: '0 0 0px rgba(0, 240, 255, 0.12)' }}
          onMouseEnter={(e) => {
            (e.currentTarget as HTMLElement).style.boxShadow = '0 0 80px rgba(0, 240, 255, 0.12), 0 0 120px rgba(59, 130, 246, 0.08)';
          }}
          onMouseLeave={(e) => {
            (e.currentTarget as HTMLElement).style.boxShadow = '0 0 0px rgba(0, 240, 255, 0.12)';
          }}
        >
          <div className="flex items-center justify-between px-6 py-3 border-b border-white/[0.06] bg-white/[0.02]">
            <div className="flex items-center gap-3">
              <div className="flex gap-1.5">
                <div className="w-3 h-3 rounded-full bg-red-500/80" />
                <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
                <div className="w-3 h-3 rounded-full bg-green-500/80" />
              </div>
              <span className="text-xs text-slate-500 font-mono">cybertron://threat-dashboard</span>
            </div>
            <div className="flex items-center gap-2">
              <Wifi className={`w-3.5 h-3.5 ${sourceColorClass}`} />
              <span className={`text-xs font-mono ${sourceColorClass}`}>{sourceLabel}</span>
              <span className={`w-2 h-2 rounded-full ${sourceDotClass}`} />
            </div>
          </div>

          <div className="p-4 sm:p-6">
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4 mb-6">
              {[
                {
                  label: 'Active Threats',
                  value: hasData ? summary.activeThreats.toLocaleString() : '—',
                  icon: ShieldAlert,
                  color: 'text-red-400',
                  bg: 'bg-red-500/10',
                },
                {
                  label: 'Blocked Today',
                  value: hasData ? summary.blockedToday.toLocaleString() : '—',
                  icon: CheckCircle2,
                  color: 'text-green-400',
                  bg: 'bg-green-500/10',
                },
                {
                  label: 'Open Incidents',
                  value: hasData ? derived.openIncidents.toLocaleString() : '—',
                  icon: AlertTriangle,
                  color: 'text-amber-400',
                  bg: 'bg-amber-500/10',
                },
                {
                  label: 'MTTR',
                  value: !hasData ? '—' : summary.mttrMinutes > 0 ? `${summary.mttrMinutes}m` : 'N/A',
                  icon: Clock3,
                  color: 'text-purple-400',
                  bg: 'bg-purple-500/10',
                },
              ].map(metric => (
                <div
                  key={metric.label}
                  className="p-4 rounded-xl bg-white/[0.03] border border-white/[0.06] hover:border-white/[0.1] transition-colors"
                >
                  <div className="flex items-center justify-between mb-3">
                    <div className={`w-9 h-9 rounded-lg ${metric.bg} flex items-center justify-center`}>
                      <metric.icon className={`w-4.5 h-4.5 ${metric.color}`} />
                    </div>
                  </div>
                  <div className="text-2xl font-bold text-white font-mono">{metric.value}</div>
                  <div className="text-xs text-slate-500 mt-1">{metric.label}</div>
                </div>
              ))}
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-5 gap-4 sm:gap-6">
              <div className="lg:col-span-3 rounded-xl border border-white/[0.06] bg-white/[0.02] overflow-hidden">
                <div className="px-4 py-3 border-b border-white/[0.06] flex items-center justify-between">
                  <span className="text-sm font-medium text-white">Global Attack Map</span>
                  <span className="text-xs text-slate-500 font-mono">{incidents.length > 0 ? `${incidents.length} events` : 'No sources'}</span>
                </div>
                <div className="relative aspect-[16/9] overflow-hidden">
                  <img src={DASHBOARD_BG} alt="Threat Dashboard" className="w-full h-full object-cover opacity-70" loading="lazy" />
                  <div className="absolute inset-0 bg-gradient-to-t from-[#0C0C18] via-transparent to-transparent" />
                  {incidents.length === 0 && (
                    <div className="absolute inset-0 flex items-center justify-center">
                      <p className="text-xs text-slate-500 font-mono">No geo data available</p>
                    </div>
                  )}
                </div>
              </div>

              <div className="lg:col-span-2 rounded-xl border border-white/[0.06] bg-white/[0.02] overflow-hidden">
                <div className="px-4 py-3 border-b border-white/[0.06] flex items-center justify-between">
                  <span className="text-sm font-medium text-white">Live Threat Feed</span>
                  <span className="text-xs text-slate-400">Resolved Today: {derived.resolvedToday}</span>
                </div>
                <div className="divide-y divide-white/[0.04] max-h-[380px] overflow-y-auto scrollbar-thin">
                  {threatQuery.isLoading && (
                    <div className="p-4 space-y-3">
                      {Array.from({ length: 4 }).map((_, index) => (
                        <div key={index} className="rounded-lg border border-white/[0.06] p-3 bg-white/[0.02] skeleton-line" />
                      ))}
                    </div>
                  )}

                  {!threatQuery.isLoading && incidents.length > 0 &&
                    incidents.map(incident => (
                      <div key={incident.id} className="px-4 py-3 hover:bg-white/[0.02] transition-colors">
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-sm text-white font-medium truncate mr-2">{incident.title}</span>
                          {incident.status === 'resolved' ? (
                            <CheckCircle2 className="w-4 h-4 text-green-400 flex-shrink-0" />
                          ) : (
                            <XCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
                          )}
                        </div>
                        <div className="flex items-center gap-2">
                          <span
                            className={`text-[10px] px-2 py-0.5 rounded-full border font-medium ${
                              SEVERITY_COLORS[incident.severity] || SEVERITY_COLORS.medium
                            }`}
                          >
                            {incident.severity}
                          </span>
                          <span className="text-[10px] text-slate-500 font-mono uppercase">{incident.status}</span>
                          <span className="text-[10px] text-slate-600 font-mono ml-auto">
                            {formatDetectedAt(incident.detectedAt)}
                          </span>
                        </div>
                      </div>
                    ))}

                  {!threatQuery.isLoading && incidents.length === 0 && (
                    <div className="px-5 py-8 text-center">
                      <Activity className="w-7 h-7 text-cyan-300/70 mx-auto mb-2" />
                      <p className="text-sm text-slate-200 mb-1">No incidents available yet</p>
                      <p className="text-xs text-slate-400">
                        Connect Postgres or external threat connectors (Wazuh, MISP, OpenCTI, TheHive) to stream live incidents.
                      </p>
                    </div>
                  )}
                </div>
              </div>
            </div>

            <div className="mt-6 p-4 rounded-xl bg-white/[0.02] border border-white/[0.06]">
              <div className="flex items-center justify-between mb-3">
                <span className="text-sm font-medium text-white">Trust Score</span>
                <span className="text-xs text-cyan-400 font-mono">{animatedTrustScore}%</span>
              </div>
              <div className="w-full h-3 rounded-full bg-white/[0.05] overflow-hidden border border-white/[0.08]">
                <div
                  className="h-full bg-gradient-to-r from-cyan-500 via-emerald-400 to-cyan-300 transition-all duration-500"
                  style={{ width: `${Math.max(0, Math.min(100, animatedTrustScore))}%` }}
                />
              </div>
              {threatQuery.isError && (
                <p className="text-xs text-amber-300 mt-3">
                  Threat service is currently unavailable. Retry after backend/database configuration is complete.
                </p>
              )}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
