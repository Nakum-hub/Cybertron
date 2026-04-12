import { useQuery } from '@tanstack/react-query';
import { Bot, BrainCircuit, Sparkles } from 'lucide-react';
import { ApiError } from '@/lib/api';
import { fetchAppStatus, fetchModuleRegistry } from '@/lib/backend';
import { type PlatformRole } from '@/lib/platform-registry';

function toMessage(error: unknown, fallback: string) {
  return error instanceof ApiError ? error.message : fallback;
}

export default function AiAgentsPanel({
  tenant,
  role,
}: {
  tenant: string;
  role: PlatformRole;
}) {
  const agentsQuery = useQuery({
    queryKey: ['ai-agents-panel', tenant, role],
    queryFn: async () => {
      const registry = await fetchModuleRegistry(tenant, role);
      const apps = registry.apps.filter(app => ['risk-copilot', 'threat-command', 'resilience-hq'].includes(app.id));
      const statuses = await Promise.all(
        apps.map(async app => {
          try {
            const status = await fetchAppStatus(app.id, tenant, role);
            return [app.id, status] as const;
          } catch (error) {
            return [
              app.id,
              {
                status: 'unavailable',
                message: toMessage(error, 'Status probe failed.'),
                latencyMs: 0,
              },
            ] as const;
          }
        })
      );

      return {
        apps,
        statusById: Object.fromEntries(statuses),
      };
    },
    staleTime: 30_000,
  });

  return (
    <section className="rounded-xl border border-white/10 bg-white/[0.02] p-5">
      <div className="mb-4 flex items-start justify-between gap-3">
        <div>
          <h3 className="text-lg font-semibold text-white">AI Agents</h3>
          <p className="mt-1 text-sm text-slate-400">
            These agents use the live module registry and app status endpoints. No agent is claimed active unless the backend exposes it.
          </p>
        </div>
        <div className="rounded-full border border-cyan-300/20 bg-cyan-400/10 px-3 py-1 text-xs text-cyan-100">
          Registry-backed
        </div>
      </div>

      {agentsQuery.isError ? (
        <p className="text-sm text-amber-200">
          {toMessage(agentsQuery.error, 'AI module registry is unavailable.')}
        </p>
      ) : agentsQuery.data?.apps.length ? (
        <div className="grid gap-4 lg:grid-cols-3">
          {agentsQuery.data.apps.map(app => {
            const status = agentsQuery.data?.statusById[app.id] as
              | { status?: string; message?: string }
              | undefined;
            return (
              <article key={app.id} className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
                <div className="mb-3 flex items-center justify-between">
                  <div className="rounded-lg border border-cyan-300/20 bg-cyan-400/10 p-2">
                    <BrainCircuit className="h-4 w-4 text-cyan-200" />
                  </div>
                  <span className="rounded-full border border-white/10 px-2 py-1 text-[10px] uppercase tracking-[0.16em] text-slate-300">
                    {status?.status || 'checking'}
                  </span>
                </div>
                <p className="text-base font-semibold text-white">{app.name}</p>
                <p className="mt-1 text-sm text-slate-300">{app.tagline}</p>
                <ul className="mt-4 space-y-2">
                  {app.capabilities.slice(0, 3).map(capability => (
                    <li key={capability} className="flex items-start gap-2 text-xs text-slate-400">
                      <Sparkles className="mt-0.5 h-3.5 w-3.5 text-cyan-300" />
                      <span>{capability}</span>
                    </li>
                  ))}
                </ul>
                <p className="mt-4 text-xs text-slate-500">
                  {status?.message || 'Live status probe completed.'}
                </p>
              </article>
            );
          })}
        </div>
      ) : (
        <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4 text-sm text-slate-400">
          <div className="mb-2 flex items-center gap-2 text-slate-200">
            <Bot className="h-4 w-4 text-cyan-300" />
            No AI modules currently exposed
          </div>
          The backend registry did not return AI modules for this tenant and role.
        </div>
      )}
    </section>
  );
}
