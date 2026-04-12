import { useQuery } from '@tanstack/react-query';
import { ClipboardCheck, FileText, Shield, Waypoints } from 'lucide-react';
import { ApiError } from '@/lib/api';
import { fetchComplianceSummary, fetchPolicies, fetchReports } from '@/lib/backend';

function readError(error: unknown, fallback: string) {
  return error instanceof ApiError ? error.message : fallback;
}

export default function ResilienceHQConsole({
  tenant,
}: {
  tenant: string;
  role: string;
}) {
  const summaryQuery = useQuery({
    queryKey: ['resilience-summary', tenant],
    queryFn: () => fetchComplianceSummary(tenant),
    staleTime: 60_000,
  });
  const policiesQuery = useQuery({
    queryKey: ['resilience-policies', tenant],
    queryFn: () => fetchPolicies(tenant),
    staleTime: 60_000,
  });
  const reportsQuery = useQuery({
    queryKey: ['resilience-reports', tenant],
    queryFn: () => fetchReports(tenant, 6),
    staleTime: 60_000,
  });

  const readinessAverage = summaryQuery.data?.frameworks.length
    ? Math.round(
        summaryQuery.data.frameworks.reduce((total, item) => total + item.readinessScore, 0) /
        summaryQuery.data.frameworks.length
      )
    : 0;

  return (
    <div className="space-y-4">
      <div className="grid gap-4 md:grid-cols-4">
        {[
          { label: 'Frameworks', value: summaryQuery.data?.frameworks.length || 0, icon: Shield },
          { label: 'Avg Readiness', value: `${readinessAverage}%`, icon: ClipboardCheck },
          { label: 'Policies', value: policiesQuery.data?.data.length || 0, icon: FileText },
          { label: 'Reports', value: reportsQuery.data?.length || 0, icon: Waypoints },
        ].map(card => (
          <article key={card.label} className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
            <div className="mb-2 flex items-center justify-between">
              <card.icon className="h-4 w-4 text-cyan-300" />
            </div>
            <p className="text-2xl font-semibold text-white">{card.value}</p>
            <p className="mt-1 text-xs text-slate-400">{card.label}</p>
          </article>
        ))}
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <section className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
          <h4 className="mb-3 text-sm font-semibold text-white">Framework Overview</h4>
          {summaryQuery.isError ? (
            <p className="text-sm text-amber-200">
              {readError(summaryQuery.error, 'Compliance summary is unavailable.')}
            </p>
          ) : summaryQuery.data?.frameworks.length ? (
            <div className="space-y-3">
              {summaryQuery.data.frameworks.map(item => (
                <div key={item.frameworkId} className="rounded-lg border border-white/10 bg-[#08111f] p-3">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <p className="text-sm font-medium text-white">{item.name}</p>
                      <p className="mt-1 text-xs text-slate-400">
                        {item.totalControls} controls · {item.gapCount} gaps
                      </p>
                    </div>
                    <span className="rounded-full border border-cyan-300/20 bg-cyan-400/10 px-2 py-1 text-[11px] font-medium text-cyan-100">
                      {item.readinessScore}%
                    </span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-slate-400">
              No compliance framework data is available for this tenant yet.
            </p>
          )}
        </section>

        <section className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
          <h4 className="mb-3 text-sm font-semibold text-white">Policy and Report Activity</h4>
          {policiesQuery.isError || reportsQuery.isError ? (
            <p className="text-sm text-amber-200">
              {readError(policiesQuery.error || reportsQuery.error, 'Policy or report data is unavailable.')}
            </p>
          ) : (
            <div className="space-y-4">
              <div>
                <p className="mb-2 text-xs uppercase tracking-[0.16em] text-slate-500">Policies</p>
                <div className="space-y-2">
                  {(policiesQuery.data?.data || []).slice(0, 4).map(policy => (
                    <div key={policy.id} className="rounded-lg border border-white/10 bg-[#08111f] p-3">
                      <p className="text-sm font-medium text-white">{policy.policyKey}</p>
                      <p className="mt-1 text-xs text-slate-400">
                        {policy.status} · {new Date(policy.createdAt).toLocaleDateString()}
                      </p>
                    </div>
                  ))}
                  {!policiesQuery.data?.data.length ? (
                    <p className="text-sm text-slate-400">No policy drafts are stored yet.</p>
                  ) : null}
                </div>
              </div>

              <div>
                <p className="mb-2 text-xs uppercase tracking-[0.16em] text-slate-500">Reports</p>
                <div className="space-y-2">
                  {(reportsQuery.data || []).slice(0, 4).map(report => (
                    <div key={report.id} className="rounded-lg border border-white/10 bg-[#08111f] p-3">
                      <p className="text-sm font-medium text-white">{report.type}</p>
                      <p className="mt-1 text-xs text-slate-400">
                        {report.fileName || 'Generated record'} · {report.reportDate}
                      </p>
                    </div>
                  ))}
                  {!reportsQuery.data?.length ? (
                    <p className="text-sm text-slate-400">No compliance reports are available yet.</p>
                  ) : null}
                </div>
              </div>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
