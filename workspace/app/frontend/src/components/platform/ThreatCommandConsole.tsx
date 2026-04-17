import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle,
  BookOpenCheck,
  Clock3,
  MapPinned,
  Radar,
  ShieldAlert,
  Siren,
} from 'lucide-react';
import { pushToast } from '@/components/ui/toaster';
import { ApiError } from '@/lib/api';
import {
  fetchAlertSlaMetrics,
  fetchIncidents,
  fetchPlaybooks,
  fetchSiemAlertStats,
  fetchThreatIntelCveFeed,
  fetchThreatLlmRuntime,
  summarizeCve,
  updateIncident,
} from '@/lib/backend';
import { hasRoleAccess, type PlatformRole } from '@/lib/platform-registry';
import AttackMapPanel from './AttackMapPanel';
import SiemAlertsPanel from './SiemAlertsPanel';

function messageFromError(error: unknown, fallback: string) {
  return error instanceof ApiError ? error.message : fallback;
}

function formatMinutes(minutes: number | null | undefined) {
  if (!Number.isFinite(minutes)) {
    return 'No resolved sample';
  }
  if ((minutes || 0) < 60) {
    return `${Math.round(minutes || 0)} min`;
  }
  const hours = (minutes || 0) / 60;
  return `${hours.toFixed(hours >= 10 ? 0 : 1)} hr`;
}

function formatLatency(latencyMs: number | null | undefined) {
  if (!Number.isFinite(latencyMs)) {
    return 'Not measured';
  }
  if ((latencyMs || 0) < 1000) {
    return `${Math.round(latencyMs || 0)} ms`;
  }
  return `${((latencyMs || 0) / 1000).toFixed(1)} s`;
}

function formatDeployment(deployment?: string | null) {
  switch (deployment) {
    case 'hosted_openai':
      return 'Hosted OpenAI';
    case 'self_hosted_tunnel':
      return 'Self-hosted via tunnel';
    case 'self_hosted_openai_compatible':
      return 'Self-hosted OpenAI-compatible';
    case 'ollama':
      return 'Local Ollama';
    case 'fallback_only':
      return 'Local fallback only';
    default:
      return 'Unknown runtime';
  }
}

function severityTone(severity?: string | null) {
  switch ((severity || '').toLowerCase()) {
    case 'critical':
      return 'border-rose-400/30 bg-rose-400/10 text-rose-100';
    case 'high':
      return 'border-amber-400/30 bg-amber-400/10 text-amber-100';
    case 'medium':
      return 'border-cyan-400/30 bg-cyan-400/10 text-cyan-100';
    case 'low':
      return 'border-emerald-400/30 bg-emerald-400/10 text-emerald-100';
    default:
      return 'border-white/10 bg-white/5 text-slate-200';
  }
}

function getAiUnavailableMessage(
  runtime: {
    configured?: boolean;
    reachable?: boolean;
    reason?: string | null;
    featureFlags?: { llmFeaturesEnabled?: boolean };
  } | null | undefined
) {
  if (!runtime) {
    return 'AI provider not configured. Configure an LLM runtime to enable CVE summaries.';
  }

  if (runtime.featureFlags?.llmFeaturesEnabled === false) {
    return 'AI analysis is disabled for this tenant. Enable llm_features_enabled to summarize CVEs.';
  }

  if (runtime.configured === false) {
    return 'AI provider not configured. Set LLM_PROVIDER and model settings to enable CVE summaries.';
  }

  if (runtime.reachable === false) {
    return runtime.reason || 'AI runtime is unavailable. Restore provider connectivity to summarize CVEs.';
  }

  return '';
}

type ThreatCommandTab = 'overview' | 'alerts' | 'attackmap' | 'intel';

export default function ThreatCommandConsole({
  tenant,
  role,
}: {
  tenant: string;
  role: PlatformRole;
}) {
  const queryClient = useQueryClient();
  const canManageIncidents = hasRoleAccess(role, 'security_analyst');
  const [activeTab, setActiveTab] = useState<ThreatCommandTab>('overview');
  const [selectedCveId, setSelectedCveId] = useState<string | null>(null);
  const [selectedCveSummary, setSelectedCveSummary] = useState<Awaited<ReturnType<typeof summarizeCve>> | null>(null);

  const statsQuery = useQuery({
    queryKey: ['threat-command-alert-stats', tenant],
    queryFn: () => fetchSiemAlertStats(tenant),
    staleTime: 30_000,
  });
  const incidentsQuery = useQuery({
    queryKey: ['threat-command-incidents', tenant],
    queryFn: () => fetchIncidents(tenant, { limit: 8, offset: 0 }),
    staleTime: 30_000,
  });
  const slaQuery = useQuery({
    queryKey: ['threat-command-sla', tenant],
    queryFn: () => fetchAlertSlaMetrics(tenant),
    staleTime: 60_000,
  });
  const cveQuery = useQuery({
    queryKey: ['threat-command-cves', tenant],
    queryFn: () => fetchThreatIntelCveFeed(tenant, { limit: 5 }),
    staleTime: 60_000,
  });
  const playbooksQuery = useQuery({
    queryKey: ['threat-command-playbooks', tenant],
    queryFn: () => fetchPlaybooks(tenant, { limit: 5 }),
    staleTime: 60_000,
  });
  const llmRuntimeQuery = useQuery({
    queryKey: ['threat-command-llm-runtime', tenant],
    queryFn: () => fetchThreatLlmRuntime(tenant),
    staleTime: 45_000,
  });

  const updateIncidentMutation = useMutation({
    mutationFn: ({ incidentId, status }: { incidentId: string; status: 'investigating' | 'resolved' | 'closed' | 'open' }) =>
      updateIncident(tenant, incidentId, { status }),
    onSuccess: result => {
      queryClient.invalidateQueries({ queryKey: ['threat-command-incidents', tenant] });
      pushToast({
        title: 'Incident updated',
        description: `${result.title} is now ${result.status}.`,
      });
    },
    onError: error => {
      pushToast({
        title: 'Incident update failed',
        description: messageFromError(error, 'Unable to update incident status.'),
        variant: 'destructive',
      });
    },
  });

  const summarizeMutation = useMutation({
    mutationFn: (cveId: string) => summarizeCve(tenant, cveId),
    onMutate: cveId => {
      setSelectedCveId(cveId);
      setSelectedCveSummary(null);
    },
    onSuccess: (result, cveId) => {
      setSelectedCveId(cveId);
      setSelectedCveSummary(result);
      pushToast({
        title: 'CVE summary generated',
        description: `${cveId} analyzed via ${result.llm.provider}/${result.llm.model}.`,
      });
    },
    onError: error => {
      setSelectedCveSummary(null);
      pushToast({
        title: 'CVE summary failed',
        description: messageFromError(error, 'Unable to generate a threat summary for this CVE.'),
        variant: 'destructive',
      });
    },
  });

  const stats = statsQuery.data?.stats;
  const incidents = incidentsQuery.data?.data || [];
  const sla = slaQuery.data?.metrics;
  const llmRuntime = llmRuntimeQuery.data;
  const aiUnavailableMessage = getAiUnavailableMessage(llmRuntime);
  const aiUnavailable = Boolean(aiUnavailableMessage);

  const tabs: Array<{ key: ThreatCommandTab; label: string }> = [
    { key: 'overview', label: 'Overview' },
    { key: 'alerts', label: 'Alert Queue' },
    { key: 'attackmap', label: 'Attack Map' },
    { key: 'intel', label: 'Intel And SOAR' },
  ];

  return (
    <div className="space-y-4">
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {[
          { label: 'Open Alerts', value: stats?.total_alerts ?? 0, detail: `${stats?.new_count ?? 0} new`, icon: Siren },
          { label: 'Active Incidents', value: incidents.length, detail: `${stats?.escalated_count ?? 0} escalated alerts`, icon: ShieldAlert },
          { label: 'SLA Breaches', value: sla?.total_sla_breached ?? 0, detail: `${sla?.critical_sla_breached ?? 0} critical`, icon: Clock3 },
          { label: 'Playbooks', value: playbooksQuery.data?.data.length ?? 0, detail: `${cveQuery.data?.data.length ?? 0} current CVEs`, icon: BookOpenCheck },
        ].map(card => (
          <article key={card.label} className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
            <div className="mb-2 flex items-center justify-between">
              <card.icon className="h-4 w-4 text-cyan-300" />
              <span className="text-xs uppercase tracking-[0.16em] text-slate-500">Operational</span>
            </div>
            <p className="text-2xl font-semibold text-white">{card.value}</p>
            <p className="mt-1 text-xs text-slate-400">{card.label}</p>
            <p className="mt-2 text-xs text-slate-500">{card.detail}</p>
          </article>
        ))}
      </div>

      <div className="flex flex-wrap gap-2">
        {tabs.map(tab => (
          <button
            key={tab.key}
            type="button"
            onClick={() => setActiveTab(tab.key)}
            className={`rounded-lg border px-3 py-2 text-sm ${
              activeTab === tab.key
                ? 'border-cyan-300/30 bg-cyan-400/10 text-cyan-100'
                : 'border-white/10 bg-white/[0.03] text-slate-300'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {activeTab === 'overview' ? (
        <div className="grid gap-4 xl:grid-cols-[1.15fr_0.85fr]">
          <section className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
            <div className="mb-3 flex items-center justify-between">
              <h4 className="text-sm font-semibold text-white">Incident Watch</h4>
              <Radar className="h-4 w-4 text-cyan-300" />
            </div>
            {incidentsQuery.isError ? (
              <p className="text-sm text-amber-200">
                {messageFromError(incidentsQuery.error, 'Incident list is unavailable.')}
              </p>
            ) : incidents.length ? (
              <div className="space-y-3">
                {incidents.map(incident => (
                  <div key={incident.id} className="rounded-lg border border-white/10 bg-[#08111f] p-3">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div>
                        <p className="text-sm font-medium text-white">{incident.title}</p>
                        <p className="mt-1 text-xs text-slate-400">
                          {incident.status} | {incident.priority || incident.severity} | {incident.source || 'source unknown'}
                        </p>
                        {incident.escalatedFromAlertId ? (
                          <p className="mt-1 text-xs text-slate-500">
                            Escalated from alert #{incident.escalatedFromAlertId}
                          </p>
                        ) : null}
                      </div>
                      <span className={`rounded-full border px-2 py-1 text-[10px] uppercase tracking-[0.16em] ${severityTone(incident.severity)}`}>
                        {incident.severity}
                      </span>
                    </div>

                    <div className="mt-3 flex flex-wrap gap-2">
                      {[
                        { label: 'Investigating', status: 'investigating', tone: 'border-cyan-300/30 bg-cyan-400/10 text-cyan-100' },
                        { label: 'Resolve', status: 'resolved', tone: 'border-emerald-300/30 bg-emerald-400/10 text-emerald-100' },
                        { label: 'Close', status: 'closed', tone: 'border-white/10 bg-white/[0.03] text-slate-200' },
                        { label: 'Reopen', status: 'open', tone: 'border-amber-300/30 bg-amber-400/10 text-amber-100' },
                      ].map(action => (
                        <button
                          key={action.status}
                          type="button"
                          disabled={!canManageIncidents || updateIncidentMutation.isPending || incident.status === action.status}
                          onClick={() => updateIncidentMutation.mutate({ incidentId: incident.id, status: action.status as 'investigating' | 'resolved' | 'closed' | 'open' })}
                          className={`rounded-lg border px-3 py-2 text-xs disabled:cursor-not-allowed disabled:opacity-60 ${action.tone}`}
                        >
                          {action.label}
                        </button>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-slate-400">
                No incidents are open right now. This is an empty queue, not a fabricated all-clear.
              </p>
            )}
          </section>

          <section className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
            <div className="mb-3 flex items-center justify-between">
              <h4 className="text-sm font-semibold text-white">SLA And Escalation Posture</h4>
              <AlertTriangle className="h-4 w-4 text-cyan-300" />
            </div>
            {slaQuery.isError ? (
              <p className="text-sm text-amber-200">
                {messageFromError(slaQuery.error, 'SLA metrics are unavailable.')}
              </p>
            ) : (
              <div className="space-y-3">
                <div className="rounded-lg border border-white/10 bg-[#08111f] p-3">
                  <p className="text-xs uppercase tracking-[0.16em] text-slate-500">Median Time To Acknowledge</p>
                  <p className="mt-2 text-lg font-semibold text-white">{formatMinutes(sla?.avg_time_to_ack_minutes)}</p>
                </div>
                <div className="rounded-lg border border-white/10 bg-[#08111f] p-3">
                  <p className="text-xs uppercase tracking-[0.16em] text-slate-500">Median Time To Resolve</p>
                  <p className="mt-2 text-lg font-semibold text-white">{formatMinutes(sla?.avg_time_to_resolve_minutes)}</p>
                </div>
                <div className="rounded-lg border border-white/10 bg-[#08111f] p-3 text-sm text-slate-300">
                  Critical {sla?.critical_sla_breached ?? 0} | High {sla?.high_sla_breached ?? 0} | Medium {sla?.medium_sla_breached ?? 0} | Low {sla?.low_sla_breached ?? 0}
                </div>
              </div>
            )}
          </section>
        </div>
      ) : null}

      {activeTab === 'alerts' ? <SiemAlertsPanel tenant={tenant} role={role} /> : null}

      {activeTab === 'attackmap' ? <AttackMapPanel tenant={tenant} /> : null}

      {activeTab === 'intel' ? (
        <div className="grid gap-4 xl:grid-cols-[1.1fr_0.9fr]">
          <div className="space-y-4">
            <section className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
              <div className="mb-3 flex items-center justify-between">
                <h4 className="text-sm font-semibold text-white">AI Runtime</h4>
                <Radar className="h-4 w-4 text-cyan-300" />
              </div>
              {llmRuntimeQuery.isError ? (
                <p className="text-sm text-amber-200">
                  {messageFromError(llmRuntimeQuery.error, 'Threat AI runtime is unavailable.')}
                </p>
              ) : llmRuntime && !aiUnavailable ? (
                <div className="space-y-3">
                  <div className="rounded-lg border border-white/10 bg-[#08111f] p-3">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div>
                        <p className="text-sm font-medium text-white">{formatDeployment(llmRuntime.deployment)}</p>
                        <p className="mt-1 text-xs text-slate-400">
                          Provider {llmRuntime.provider} | Model {llmRuntime.model || 'not selected'}
                        </p>
                      </div>
                      <span className={`rounded-full border px-2 py-1 text-[10px] uppercase tracking-[0.16em] ${
                        llmRuntime.reachable
                          ? 'border-emerald-400/30 bg-emerald-400/10 text-emerald-100'
                          : 'border-amber-400/30 bg-amber-400/10 text-amber-100'
                      }`}>
                        {llmRuntime.reachable ? 'reachable' : 'fallback'}
                      </span>
                    </div>
                    <div className="mt-3 grid gap-2 text-xs text-slate-400 md:grid-cols-2">
                      <p>Endpoint: <span className="text-slate-200">{llmRuntime.endpoint || 'not configured'}</span></p>
                      <p>Latency: <span className="text-slate-200">{formatLatency(llmRuntime.latencyMs)}</span></p>
                      <p>Feature flag: <span className="text-slate-200">{llmRuntime.featureFlags?.llmFeaturesEnabled ? 'enabled' : 'disabled'}</span></p>
                      <p>Checked: <span className="text-slate-200">{new Date(llmRuntime.checkedAt).toLocaleString()}</span></p>
                    </div>
                    {llmRuntime.availableModels.length ? (
                      <p className="mt-3 text-xs text-slate-400">
                        Available models: <span className="text-slate-200">{llmRuntime.availableModels.slice(0, 3).join(', ')}</span>
                      </p>
                    ) : null}
                    {llmRuntime.reason ? <p className="mt-3 text-xs text-amber-200">{llmRuntime.reason}</p> : null}
                    {llmRuntime.sshTunnelSuggested ? (
                      <p className="mt-3 text-xs text-cyan-200">
                        This runtime looks local or tunnel-backed, which matches a Lightning AI SSH tunnel or local vLLM deployment.
                      </p>
                    ) : null}
                  </div>
                </div>
              ) : (
                <div className="rounded-lg border border-dashed border-white/10 bg-[#08111f] p-5 text-center">
                  <Radar className="mx-auto mb-2 h-8 w-8 text-slate-600" />
                  <p className="text-sm font-medium text-white">AI runtime not configured</p>
                  <p className="mt-2 text-xs text-slate-400">
                    {aiUnavailableMessage || 'Set LLM_PROVIDER to openai, ollama, or vllm in your environment to enable AI-powered threat analysis.'}
                  </p>
                </div>
              )}
            </section>

            <section className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
              <div className="mb-3 flex items-center justify-between">
                <h4 className="text-sm font-semibold text-white">Latest CVE Feed</h4>
                <MapPinned className="h-4 w-4 text-cyan-300" />
              </div>
              {cveQuery.isError ? (
                <p className="text-sm text-amber-200">
                  {messageFromError(cveQuery.error, 'Threat intel feed is unavailable.')}
                </p>
              ) : cveQuery.data?.data.length ? (
                <div className="space-y-3">
                  {cveQuery.data.data.map(item => (
                    <div
                      key={item.id}
                      className={`rounded-lg border p-3 ${
                        selectedCveId === item.cveId ? 'border-cyan-300/30 bg-cyan-400/5' : 'border-white/10 bg-[#08111f]'
                      }`}
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <p className="text-sm font-medium text-white">{item.cveId}</p>
                          <p className="mt-1 line-clamp-2 text-xs leading-relaxed text-slate-300">{item.description}</p>
                        </div>
                        <span className={`rounded-full border px-2 py-1 text-[10px] uppercase tracking-[0.16em] ${severityTone(item.severity)}`}>
                          {item.severity}
                        </span>
                      </div>
                      <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
                        <p className="text-xs text-slate-500">
                          Relevance {item.relevanceScore} | Published {item.publishedAt ? new Date(item.publishedAt).toLocaleDateString() : 'unknown'}
                        </p>
                        <button
                          type="button"
                          disabled={summarizeMutation.isPending || aiUnavailable}
                          onClick={() => summarizeMutation.mutate(item.cveId)}
                          className="rounded-lg border border-cyan-300/30 bg-cyan-400/10 px-3 py-2 text-xs text-cyan-100 disabled:cursor-not-allowed disabled:opacity-60"
                        >
                          {aiUnavailable
                            ? 'AI unavailable'
                            : summarizeMutation.isPending && selectedCveId === item.cveId
                              ? 'Summarizing...'
                              : 'Summarize'}
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="rounded-lg border border-dashed border-white/10 bg-[#08111f] p-5 text-center">
                  <MapPinned className="mx-auto mb-2 h-8 w-8 text-slate-600" />
                  <p className="text-sm font-medium text-white">No CVE entries ingested yet</p>
                  <p className="mt-1 text-xs text-slate-400">
                    Run a CVE sync or connect an NVD feed to start populating threat intelligence.
                  </p>
                </div>
              )}
            </section>
          </div>

          <div className="space-y-4">
            <section className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
              <div className="mb-3 flex items-center justify-between">
                <h4 className="text-sm font-semibold text-white">Analyst Summary Output</h4>
                <Siren className="h-4 w-4 text-cyan-300" />
              </div>
              {selectedCveSummary ? (
                <div className="space-y-3">
                  <div className="rounded-lg border border-white/10 bg-[#08111f] p-3">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div>
                        <p className="text-sm font-medium text-white">{selectedCveSummary.summary.cveId}</p>
                        <p className="mt-1 text-xs text-slate-400">
                          {selectedCveSummary.llm.provider} / {selectedCveSummary.llm.model}
                        </p>
                      </div>
                      <span className={`rounded-full border px-2 py-1 text-[10px] uppercase tracking-[0.16em] ${
                        selectedCveSummary.llm.aiGenerated
                          ? 'border-cyan-300/30 bg-cyan-400/10 text-cyan-100'
                          : 'border-white/10 bg-white/[0.03] text-slate-300'
                      }`}>
                        {selectedCveSummary.llm.aiGenerated ? 'AI assisted' : 'rule based'}
                      </span>
                    </div>
                    <p className="mt-3 whitespace-pre-wrap text-sm leading-relaxed text-slate-200">
                      {selectedCveSummary.summary.summaryText}
                    </p>
                    <div className="mt-3 grid gap-2 text-xs text-slate-400 md:grid-cols-2">
                      <p>Grounding: <span className="text-slate-200">{Number.isFinite(selectedCveSummary.llm.groundingScore) ? selectedCveSummary.llm.groundingScore : 'n/a'}</span></p>
                      <p>Quality gate: <span className="text-slate-200">{selectedCveSummary.llm.qualityGate?.accepted ? 'accepted' : 'not reported'}</span></p>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="rounded-lg border border-dashed border-white/10 bg-[#08111f] p-4">
                  <p className="text-sm text-white">
                    {aiUnavailable
                      ? 'AI provider not configured'
                      : 'Select a CVE and run Summarize to verify the live threat-analysis path, provider, and grounding details.'}
                  </p>
                  {aiUnavailable ? (
                    <p className="mt-2 text-xs text-slate-400">{aiUnavailableMessage}</p>
                  ) : null}
                </div>
              )}
            </section>

            <section className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
              <div className="mb-3 flex items-center justify-between">
                <h4 className="text-sm font-semibold text-white">Playbook Readiness</h4>
                <BookOpenCheck className="h-4 w-4 text-cyan-300" />
              </div>
              {playbooksQuery.isError ? (
                <p className="text-sm text-amber-200">
                  {messageFromError(playbooksQuery.error, 'Playbook catalog is unavailable.')}
                </p>
              ) : playbooksQuery.data?.data.length ? (
                <div className="space-y-3">
                  {playbooksQuery.data.data.map(playbook => (
                    <div key={playbook.id} className="rounded-lg border border-white/10 bg-[#08111f] p-3">
                      <div className="flex items-center justify-between gap-3">
                        <div>
                          <p className="text-sm font-medium text-white">{playbook.name}</p>
                          <p className="mt-1 text-xs text-slate-400">
                            {playbook.category} | {playbook.is_active ? 'active' : 'inactive'}
                          </p>
                        </div>
                        <span className="rounded-full border border-white/10 px-2 py-1 text-[10px] uppercase tracking-[0.16em] text-slate-300">
                          {playbook.auto_trigger ? 'auto' : 'manual'}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-slate-400">
                  No playbooks are configured yet. Automation stays off until a real playbook exists.
                </p>
              )}
            </section>
          </div>
        </div>
      ) : null}
    </div>
  );
}
