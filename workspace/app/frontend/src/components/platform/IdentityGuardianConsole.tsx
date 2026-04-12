import { useQuery } from '@tanstack/react-query';
import { ActivitySquare, Fingerprint, ShieldCheck, Users } from 'lucide-react';
import { ApiError } from '@/lib/api';
import { fetchAuditLogs, fetchUsers } from '@/lib/backend';

function errorText(error: unknown, fallback: string) {
  return error instanceof ApiError ? error.message : fallback;
}

export default function IdentityGuardianConsole({
  tenant,
}: {
  tenant: string;
  role: string;
}) {
  const usersQuery = useQuery({
    queryKey: ['identity-users', tenant],
    queryFn: () => fetchUsers(tenant, 8),
    staleTime: 60_000,
  });
  const auditQuery = useQuery({
    queryKey: ['identity-audit', tenant],
    queryFn: () => fetchAuditLogs(tenant, { limit: 8 }),
    staleTime: 30_000,
  });

  const activeUsers = (usersQuery.data || []).filter(user => user.active).length;

  return (
    <div className="space-y-4">
      <div className="grid gap-4 md:grid-cols-4">
        {[
          { label: 'Known Users', value: usersQuery.data?.length || 0, icon: Users },
          { label: 'Active Accounts', value: activeUsers, icon: ShieldCheck },
          { label: 'Audit Events', value: auditQuery.data?.total || auditQuery.data?.data.length || 0, icon: ActivitySquare },
          { label: 'Tenant Scope', value: tenant, icon: Fingerprint },
        ].map(card => (
          <article key={card.label} className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
            <div className="mb-2 flex items-center justify-between">
              <card.icon className="h-4 w-4 text-cyan-300" />
            </div>
            <p className="truncate text-2xl font-semibold text-white">{card.value}</p>
            <p className="mt-1 text-xs text-slate-400">{card.label}</p>
          </article>
        ))}
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <section className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
          <h4 className="mb-3 text-sm font-semibold text-white">Recent Users</h4>
          {usersQuery.isError ? (
            <p className="text-sm text-amber-200">
              {errorText(usersQuery.error, 'User catalog is unavailable.')}
            </p>
          ) : usersQuery.data?.length ? (
            <div className="space-y-3">
              {usersQuery.data.map(user => (
                <div key={`${user.tenant}-${user.email}`} className="rounded-lg border border-white/10 bg-[#08111f] p-3">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <p className="text-sm font-medium text-white">{user.displayName || user.email}</p>
                      <p className="mt-1 text-xs text-slate-400">{user.email}</p>
                    </div>
                    <div className="text-right">
                      <p className="text-xs uppercase tracking-[0.16em] text-cyan-200">{user.role}</p>
                      <p className="mt-1 text-[11px] text-slate-400">{user.active ? 'active' : 'disabled'}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-slate-400">
              No user records are available yet for this tenant.
            </p>
          )}
        </section>

        <section className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
          <h4 className="mb-3 text-sm font-semibold text-white">Recent Audit Trail</h4>
          {auditQuery.isError ? (
            <p className="text-sm text-amber-200">
              {errorText(auditQuery.error, 'Audit trail is unavailable.')}
            </p>
          ) : auditQuery.data?.data.length ? (
            <div className="space-y-3">
              {auditQuery.data.data.map(entry => (
                <div key={entry.id} className="rounded-lg border border-white/10 bg-[#08111f] p-3">
                  <p className="text-sm font-medium text-white">{entry.action}</p>
                  <p className="mt-1 text-xs text-slate-400">
                    {entry.actorEmail || 'system'} · {new Date(entry.createdAt).toLocaleString()}
                  </p>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-slate-400">
              No recent identity audit events are stored yet.
            </p>
          )}
        </section>
      </div>
    </div>
  );
}
