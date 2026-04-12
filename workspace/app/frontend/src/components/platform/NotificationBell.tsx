import { useMemo, useState } from 'react';
import { Bell, ShieldAlert, TriangleAlert, WifiOff } from 'lucide-react';
import { useBackendHealth } from '@/hooks/use-backend-health';
import { useThreatData } from '@/hooks/use-threat-data';

export default function NotificationBell({
  tenant,
  enabled,
}: {
  tenant: string;
  enabled: boolean;
}) {
  const [open, setOpen] = useState(false);
  const healthQuery = useBackendHealth();
  const threatQuery = useThreatData({ enabled });

  const notifications = useMemo(() => {
    const items: Array<{ id: string; title: string; detail: string; icon: typeof ShieldAlert }> = [];

    if (healthQuery.data && healthQuery.data.status !== 'ok') {
      items.push({
        id: 'backend-health',
        title: 'Backend health degraded',
        detail: `Dependency status is ${healthQuery.data.status}. Review runtime health before deeper operations.`,
        icon: TriangleAlert,
      });
    }

    if (threatQuery.data?.dataSource === 'unavailable') {
      items.push({
        id: 'telemetry-unavailable',
        title: 'Threat telemetry unavailable',
        detail: `Tenant ${tenant} is not returning live threat data right now.`,
        icon: WifiOff,
      });
    } else if ((threatQuery.data?.summary.activeThreats || 0) > 0) {
      items.push({
        id: 'active-threats',
        title: 'Active threats require review',
        detail: `${threatQuery.data?.summary.activeThreats || 0} open threat(s) currently need analyst attention.`,
        icon: ShieldAlert,
      });
    }

    return items;
  }, [healthQuery.data, tenant, threatQuery.data]);

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen(current => !current)}
        className="relative inline-flex h-11 w-11 items-center justify-center rounded-xl border border-white/15 bg-white/[0.05] text-slate-100 hover:bg-white/[0.1]"
        aria-label="Open notifications"
      >
        <Bell className="h-4.5 w-4.5" />
        {notifications.length > 0 ? (
          <span className="absolute right-2 top-2 flex h-2.5 w-2.5 rounded-full bg-cyan-400" />
        ) : null}
      </button>

      {open ? (
        <div className="absolute right-0 top-14 z-20 w-80 rounded-2xl border border-white/10 bg-[#09111f] p-4 shadow-[0_20px_80px_rgba(0,0,0,0.45)]">
          <div className="mb-3 flex items-center justify-between">
            <p className="text-sm font-semibold text-white">Notifications</p>
            <span className="text-xs text-slate-400">{notifications.length || 0} items</span>
          </div>

          {notifications.length === 0 ? (
            <p className="rounded-xl border border-white/10 bg-white/[0.03] px-3 py-3 text-sm text-slate-300">
              No urgent notifications. Live checks will appear here when runtime health or threat posture changes.
            </p>
          ) : (
            <div className="space-y-3">
              {notifications.map(item => {
                const Icon = item.icon;
                return (
                  <div key={item.id} className="rounded-xl border border-white/10 bg-white/[0.03] p-3">
                    <div className="flex items-start gap-3">
                      <div className="rounded-lg border border-cyan-300/20 bg-cyan-400/10 p-2">
                        <Icon className="h-4 w-4 text-cyan-200" />
                      </div>
                      <div className="min-w-0">
                        <p className="text-sm font-medium text-white">{item.title}</p>
                        <p className="mt-1 text-xs leading-relaxed text-slate-300">{item.detail}</p>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      ) : null}
    </div>
  );
}
