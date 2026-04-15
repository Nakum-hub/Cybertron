import { useMutation, useQuery } from '@tanstack/react-query';
import { AlertTriangle, FileSpreadsheet, Radar, Shield } from 'lucide-react';
import { pushToast } from '@/components/ui/toaster';
import { ApiError } from '@/lib/api';
import { fetchRiskFindings, generateRiskReport } from '@/lib/backend';

function errorMessage(error: unknown, fallback: string) {
  return error instanceof ApiError ? error.message : fallback;
}

export default function RiskCopilotConsole({
  tenant,
}: {
  tenant: string;
  role: string;
}) {
  const findingsQuery = useQuery({
    queryKey: ['risk-console-findings', tenant],
    queryFn: () => fetchRiskFindings(tenant, { limit: 8 }),
    staleTime: 45_000,
  });

  const reportMutation = useMutation({
    mutationFn: () => generateRiskReport(tenant),
    onSuccess: result => {
      pushToast({
        title: 'Risk report generated',
        description: `Report ${result.report.id} was created for ${tenant}.`,
      });
    },
    onError: error => {
      pushToast({
        title: 'Risk report generation failed',
        description: errorMessage(error, 'Unable to generate a risk report right now.'),
        variant: 'destructive',
      });
    },
  });

  const criticalCount =
    findingsQuery.data?.data.filter(item => item.severity === 'critical').length || 0;
  const highCount =
    findingsQuery.data?.data.filter(item => item.severity === 'high').length || 0;

  return (
    <div className="space-y-4">
      <div className="grid gap-4 md:grid-cols-4">
        {[
          { label: 'Findings', value: findingsQuery.data?.data.length || 0, icon: Shield },
          { label: 'Critical', value: criticalCount, icon: AlertTriangle },
          { label: 'High', value: highCount, icon: Radar },
          { label: 'Reports', value: reportMutation.isSuccess ? 1 : 0, icon: FileSpreadsheet },
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

      <section className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h4 className="text-sm font-semibold text-white">Latest Risk Findings</h4>
            <p className="mt-1 text-xs text-slate-400">
              Findings stay empty until AWS logs or equivalent risk evidence is ingested.
            </p>
          </div>
          <button
            type="button"
            onClick={() => reportMutation.mutate()}
            disabled={reportMutation.isPending}
            className="rounded-lg border border-cyan-300/20 bg-cyan-400/10 px-4 py-2 text-sm text-cyan-100 hover:bg-cyan-400/15 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {reportMutation.isPending ? 'Generating...' : 'Generate Risk Report'}
          </button>
        </div>

        {findingsQuery.isError ? (
          <p className="text-sm text-amber-200">
            {errorMessage(findingsQuery.error, 'Risk findings are unavailable.')}
          </p>
        ) : findingsQuery.data?.data.length ? (
          <div className="space-y-3">
            {findingsQuery.data.data.map(finding => (
              <div key={finding.id} className="rounded-lg border border-white/10 bg-[#08111f] p-3">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <p className="text-sm font-medium text-white">
                      {String(finding.details?.title || finding.assetId || finding.id)}
                    </p>
                    <p className="mt-1 text-xs text-slate-400">
                      {finding.category} · asset {finding.assetId || 'unknown'} · treatment {finding.treatmentStatus}
                    </p>
                  </div>
                  <span className="rounded-full border border-cyan-300/20 bg-cyan-400/10 px-2 py-1 text-[11px] font-medium text-cyan-100">
                    score {Math.round(finding.score)}
                  </span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="rounded-lg border border-dashed border-white/10 bg-[#08111f] p-6 text-center">
            <Shield className="mx-auto mb-2 h-8 w-8 text-slate-600" />
            <p className="text-sm font-medium text-white">No risk findings available yet</p>
            <p className="mt-1 text-xs text-slate-400">
              Connect AWS CloudTrail, Azure Activity, or Wazuh log sources to start generating risk findings for this tenant.
            </p>
          </div>
        )}
      </section>
    </div>
  );
}
