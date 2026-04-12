import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, ChevronsUpDown, ShieldAlert, Siren } from 'lucide-react';
import { pushToast } from '@/components/ui/toaster';
import { ApiError } from '@/lib/api';
import {
  assignAlertToUser,
  bulkUpdateAlertStatus,
  escalateAlert,
  fetchAlertSlaMetrics,
  fetchAlertTriageSuggestion,
  fetchSiemAlerts,
  fetchTenantAnalysts,
  uploadSiemLogs,
  updateAlertNotes,
  updateAlertStatus,
  type SiemAlert,
} from '@/lib/backend';
import { hasRoleAccess, type PlatformRole } from '@/lib/platform-registry';

type SortField = 'event_time' | 'severity' | 'status';
type SortDir = 'asc' | 'desc';

function errorMessage(error: unknown, fallback: string) {
  return error instanceof ApiError ? error.message : fallback;
}

function SortButton({
  active,
  direction,
  label,
  onClick,
}: {
  active: boolean;
  direction: SortDir;
  label: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs ${
        active
          ? 'border-cyan-300/30 bg-cyan-400/10 text-cyan-100'
          : 'border-white/10 bg-white/[0.03] text-slate-300'
      }`}
    >
      {label}
      <ChevronsUpDown className="h-3.5 w-3.5" />
      {active ? direction.toUpperCase() : null}
    </button>
  );
}

function severityRank(severity: SiemAlert['severity']) {
  switch (severity) {
    case 'critical':
      return 5;
    case 'high':
      return 4;
    case 'medium':
      return 3;
    case 'low':
      return 2;
    default:
      return 1;
  }
}

function severityTone(severity: SiemAlert['severity']) {
  switch (severity) {
    case 'critical':
      return 'border-rose-400/30 bg-rose-400/10 text-rose-100';
    case 'high':
      return 'border-amber-400/30 bg-amber-400/10 text-amber-100';
    case 'medium':
      return 'border-cyan-400/30 bg-cyan-400/10 text-cyan-100';
    case 'low':
      return 'border-emerald-400/30 bg-emerald-400/10 text-emerald-100';
    default:
      return 'border-white/10 bg-white/[0.03] text-slate-200';
  }
}

export default function SiemAlertsPanel({
  tenant,
  role,
}: {
  tenant: string;
  role: PlatformRole;
}) {
  const queryClient = useQueryClient();
  const canManage = hasRoleAccess(role, 'security_analyst');
  const [statusFilter, setStatusFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [sortField, setSortField] = useState<SortField>('event_time');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [bulkMode, setBulkMode] = useState(false);
  const [selectedAlertIds, setSelectedAlertIds] = useState<number[]>([]);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadSource, setUploadSource] = useState('');
  const [runCorrelationOnUpload, setRunCorrelationOnUpload] = useState(true);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [editingNotesId, setEditingNotesId] = useState<number | null>(null);
  const [notesDrafts, setNotesDrafts] = useState<Record<number, string>>({});
  const [triageSuggestion, setTriageSuggestion] = useState<Awaited<ReturnType<typeof fetchAlertTriageSuggestion>> | null>(null);
  const [triageAlertId, setTriageAlertId] = useState<number | null>(null);

  const alertsQuery = useQuery({
    queryKey: ['siem-alerts-panel', tenant, statusFilter, searchQuery],
    queryFn: () =>
      fetchSiemAlerts(tenant, {
        limit: 18,
        offset: 0,
        status: statusFilter === 'all' ? undefined : statusFilter,
        search: searchQuery || undefined,
      }),
    staleTime: 20_000,
  });
  const analystsQuery = useQuery({
    queryKey: ['siem-analysts-panel', tenant],
    queryFn: () => fetchTenantAnalysts(tenant),
    staleTime: 60_000,
  });
  const slaQuery = useQuery({
    queryKey: ['siem-sla-panel', tenant],
    queryFn: () => fetchAlertSlaMetrics(tenant),
    staleTime: 60_000,
  });

  const invalidateSocQueries = () => {
    queryClient.invalidateQueries({ queryKey: ['siem-alerts-panel', tenant] });
    queryClient.invalidateQueries({ queryKey: ['threat-command-alerts', tenant] });
    queryClient.invalidateQueries({ queryKey: ['threat-command-alert-stats', tenant] });
    queryClient.invalidateQueries({ queryKey: ['siem-sla-panel', tenant] });
    queryClient.invalidateQueries({ queryKey: ['threat-command-sla', tenant] });
    queryClient.invalidateQueries({ queryKey: ['threat-command-incidents', tenant] });
  };

  const statusMutation = useMutation({
    mutationFn: ({ alertId, status }: { alertId: number; status: string }) =>
      updateAlertStatus(tenant, alertId, status),
    onSuccess: (_, variables) => {
      invalidateSocQueries();
      pushToast({
        title: 'Alert updated',
        description: `Alert ${variables.alertId} moved to ${variables.status}.`,
      });
    },
    onError: error => {
      pushToast({
        title: 'Alert update failed',
        description: errorMessage(error, 'Unable to update alert status.'),
        variant: 'destructive',
      });
    },
  });

  const assignMutation = useMutation({
    mutationFn: ({ alertId, assignedTo }: { alertId: number; assignedTo: number | null }) =>
      assignAlertToUser(tenant, alertId, assignedTo),
    onSuccess: () => {
      invalidateSocQueries();
      pushToast({
        title: 'Alert assignment updated',
        description: 'The analyst assignment has been saved.',
      });
    },
    onError: error => {
      pushToast({
        title: 'Assignment failed',
        description: errorMessage(error, 'Unable to assign this alert.'),
        variant: 'destructive',
      });
    },
  });

  const bulkMutation = useMutation({
    mutationFn: ({ ids, status }: { ids: number[]; status: string }) =>
      bulkUpdateAlertStatus(tenant, ids, status),
    onSuccess: result => {
      invalidateSocQueries();
      setSelectedAlertIds([]);
      pushToast({
        title: 'Bulk alert update complete',
        description: `${result.updated} alerts updated.`,
      });
    },
    onError: error => {
      pushToast({
        title: 'Bulk update failed',
        description: errorMessage(error, 'Unable to perform the bulk action.'),
        variant: 'destructive',
      });
    },
  });

  const notesMutation = useMutation({
    mutationFn: ({ alertId, notes }: { alertId: number; notes: string }) =>
      updateAlertNotes(tenant, alertId, notes),
    onSuccess: (_, variables) => {
      invalidateSocQueries();
      setEditingNotesId(null);
      pushToast({
        title: 'Notes saved',
        description: `Notes for alert ${variables.alertId} were updated.`,
      });
    },
    onError: error => {
      pushToast({
        title: 'Notes update failed',
        description: errorMessage(error, 'Unable to save alert notes.'),
        variant: 'destructive',
      });
    },
  });

  const triageMutation = useMutation({
    mutationFn: (alertId: number) => fetchAlertTriageSuggestion(tenant, alertId),
    onSuccess: (result, alertId) => {
      setTriageAlertId(alertId);
      setTriageSuggestion(result);
    },
    onError: error => {
      pushToast({
        title: 'Triage suggestion failed',
        description: errorMessage(error, 'Unable to fetch triage guidance.'),
        variant: 'destructive',
      });
    },
  });

  const escalateMutation = useMutation({
    mutationFn: (alertId: number) => escalateAlert(tenant, alertId),
    onSuccess: result => {
      invalidateSocQueries();
      pushToast({
        title: 'Alert escalated',
        description: `Incident ${result.incidentId} was created from alert ${result.alertId}.`,
      });
    },
    onError: error => {
      pushToast({
        title: 'Escalation failed',
        description: errorMessage(error, 'Unable to escalate this alert to an incident.'),
        variant: 'destructive',
      });
    },
  });

  const uploadMutation = useMutation({
    mutationFn: ({ file, source, runCorrelation }: { file: File; source?: string; runCorrelation?: boolean }) =>
      uploadSiemLogs(tenant, file, {
        source,
        runCorrelation,
        onProgress: progress => setUploadProgress(progress),
      }),
    onSuccess: result => {
      invalidateSocQueries();
      setSelectedFile(null);
      setUploadSource('');
      setUploadProgress(0);
      pushToast({
        title: 'SIEM file ingested',
        description: `${result.ingestedAlerts} alerts ingested from ${result.uploadedRecords} uploaded records.`,
      });
    },
    onError: error => {
      setUploadProgress(0);
      pushToast({
        title: 'SIEM upload failed',
        description: errorMessage(error, 'Unable to ingest the uploaded SOC file.'),
        variant: 'destructive',
      });
    },
  });

  const alerts = [...(alertsQuery.data?.data || [])].sort((left, right) => {
    const direction = sortDir === 'asc' ? 1 : -1;
    if (sortField === 'severity') {
      return (severityRank(left.severity) - severityRank(right.severity)) * direction;
    }
    if (sortField === 'status') {
      return left.status.localeCompare(right.status) * direction;
    }
    const leftTime = left.event_time ? Date.parse(left.event_time) : 0;
    const rightTime = right.event_time ? Date.parse(right.event_time) : 0;
    return (leftTime - rightTime) * direction;
  });

  const selectedCount = selectedAlertIds.length;
  const allVisibleIds = alerts.map(alert => alert.id);

  function toggleSort(nextField: SortField) {
    if (sortField === nextField) {
      setSortDir(current => (current === 'asc' ? 'desc' : 'asc'));
      return;
    }
    setSortField(nextField);
    setSortDir(nextField === 'severity' ? 'desc' : 'asc');
  }

  function selectAll() {
    if (selectedAlertIds.length === allVisibleIds.length) {
      setSelectedAlertIds([]);
      return;
    }
    setSelectedAlertIds(allVisibleIds);
  }

  function toggleSelected(alertId: number) {
    setSelectedAlertIds(current =>
      current.includes(alertId)
        ? current.filter(id => id !== alertId)
        : [...current, alertId]
    );
  }

  return (
    <div className="space-y-4">
      <section className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
        <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
          <div>
            <h4 className="text-sm font-semibold text-white">SIEM Alerts</h4>
            <p className="mt-1 text-xs text-slate-400">
              Real alert data only. Search, assignment, bulk triage, and escalation all act on live tenant records.
            </p>
          </div>
          <button
            type="button"
            onClick={() => setBulkMode(current => !current)}
            className="rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-xs text-slate-200"
          >
            {bulkMode ? 'Exit Bulk Mode' : 'Enable Bulk Mode'}
          </button>
        </div>

        <div className="grid gap-3 lg:grid-cols-[1fr_0.8fr]">
          <div className="space-y-3">
            <div className="rounded-lg border border-white/10 bg-[#08111f] p-3">
              <div className="mb-3 flex items-center gap-2">
                <Siren className="h-4 w-4 text-cyan-300" />
                <p className="text-sm font-medium text-white">Upload SOC Logs</p>
              </div>
              <div className="grid gap-3 md:grid-cols-[1fr_0.8fr_auto]">
                <input
                  type="file"
                  accept=".json,.ndjson,.log,.txt,application/json,text/plain"
                  onChange={event => setSelectedFile(event.target.files?.[0] || null)}
                  className="rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-xs text-slate-200"
                />
                <input
                  value={uploadSource}
                  onChange={event => setUploadSource(event.target.value)}
                  placeholder="Source override"
                  className="rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-xs text-white"
                />
                <button
                  type="button"
                  disabled={!canManage || !selectedFile || uploadMutation.isPending}
                  onClick={() => {
                    if (!selectedFile) {
                      return;
                    }
                    uploadMutation.mutate({
                      file: selectedFile,
                      source: uploadSource || undefined,
                      runCorrelation: runCorrelationOnUpload,
                    });
                  }}
                  className="rounded-lg border border-cyan-300/30 bg-cyan-400/10 px-3 py-2 text-xs text-cyan-100 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {uploadMutation.isPending ? 'Uploading...' : 'Upload Logs'}
                </button>
              </div>
              <label className="mt-3 flex items-center gap-2 text-xs text-slate-400">
                <input
                  type="checkbox"
                  checked={runCorrelationOnUpload}
                  onChange={event => setRunCorrelationOnUpload(event.target.checked)}
                  className="h-4 w-4 rounded border-white/10 bg-[#08111f]"
                />
                Run correlation after upload
              </label>
              <p className="mt-2 text-xs text-slate-500">
                Upload JSON or NDJSON telemetry and convert it into real SIEM alerts for this tenant.
              </p>
              {uploadMutation.isPending ? (
                <p className="mt-2 text-xs text-cyan-200">Upload progress: {uploadProgress}%</p>
              ) : null}
            </div>

            <div className="grid gap-3 md:grid-cols-[0.9fr_1.1fr]">
              <label className="text-xs text-slate-400">
                Status
                <select
                  value={statusFilter}
                  onChange={event => setStatusFilter(event.target.value)}
                  className="mt-1 w-full rounded-lg border border-white/10 bg-[#08111f] px-3 py-2 text-sm text-white"
                >
                  <option value="all">All statuses</option>
                  <option value="new">New</option>
                  <option value="acknowledged">Acknowledged</option>
                  <option value="in_triage">In Triage</option>
                  <option value="escalated">Escalated</option>
                  <option value="resolved">Resolved</option>
                  <option value="dismissed">Dismissed</option>
                </select>
              </label>

              <label className="text-xs text-slate-400">
                Search
                <input
                  value={searchQuery}
                  onChange={event => setSearchQuery(event.target.value)}
                  placeholder="Search by rule name, alert ID, IP, or hostname"
                  className="mt-1 w-full rounded-lg border border-white/10 bg-[#08111f] px-3 py-2 text-sm text-white"
                />
              </label>
            </div>

            <div className="flex flex-wrap gap-2">
              <SortButton
                active={sortField === 'event_time'}
                direction={sortDir}
                label="Event Time"
                onClick={() => toggleSort('event_time')}
              />
              <SortButton
                active={sortField === 'severity'}
                direction={sortDir}
                label="Severity"
                onClick={() => toggleSort('severity')}
              />
              <SortButton
                active={sortField === 'status'}
                direction={sortDir}
                label="Status"
                onClick={() => toggleSort('status')}
              />
            </div>
          </div>

          <div className="rounded-lg border border-white/10 bg-[#08111f] p-3">
            <div className="mb-3 flex items-center justify-between gap-3">
              <p className="text-sm font-medium text-white">SLA Metrics</p>
              <Siren className="h-4 w-4 text-cyan-300" />
            </div>
            {slaQuery.isError ? (
              <p className="text-sm text-amber-200">
                {errorMessage(slaQuery.error, 'SLA metrics are unavailable.')}
              </p>
            ) : (
              <div className="grid gap-2 sm:grid-cols-3">
                <div className="rounded-lg border border-white/10 bg-white/[0.03] p-3">
                  <p className="text-xs uppercase tracking-[0.16em] text-slate-500">SLA Breached</p>
                  <p className="mt-2 text-lg font-semibold text-white">{slaQuery.data?.metrics.total_sla_breached ?? 0}</p>
                </div>
                <div className="rounded-lg border border-white/10 bg-white/[0.03] p-3">
                  <p className="text-xs uppercase tracking-[0.16em] text-slate-500">Avg ACK Time</p>
                  <p className="mt-2 text-lg font-semibold text-white">
                    {slaQuery.data?.metrics.avg_time_to_ack_minutes ?? 0}m
                  </p>
                </div>
                <div className="rounded-lg border border-white/10 bg-white/[0.03] p-3">
                  <p className="text-xs uppercase tracking-[0.16em] text-slate-500">Avg Resolve</p>
                  <p className="mt-2 text-lg font-semibold text-white">
                    {slaQuery.data?.metrics.avg_time_to_resolve_minutes ?? 0}m
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>

        {bulkMode ? (
          <div className="mt-4 rounded-lg border border-white/10 bg-[#08111f] p-3">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
              <p className="text-sm font-medium text-white">{selectedCount} selected</p>
              <button
                type="button"
                onClick={selectAll}
                className="rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-xs text-slate-200"
              >
                {selectedAlertIds.length === allVisibleIds.length && allVisibleIds.length > 0 ? 'Clear Selection' : 'Select All'}
              </button>
            </div>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                disabled={!canManage || !selectedCount || bulkMutation.isPending}
                onClick={() => bulkMutation.mutate({ ids: selectedAlertIds, status: 'acknowledged' })}
                className="rounded-lg border border-cyan-300/30 bg-cyan-400/10 px-3 py-2 text-xs text-cyan-100 disabled:cursor-not-allowed disabled:opacity-60"
              >
                Bulk ACK
              </button>
              <button
                type="button"
                disabled={!canManage || !selectedCount || bulkMutation.isPending}
                onClick={() => bulkMutation.mutate({ ids: selectedAlertIds, status: 'dismissed' })}
                className="rounded-lg border border-amber-300/30 bg-amber-400/10 px-3 py-2 text-xs text-amber-100 disabled:cursor-not-allowed disabled:opacity-60"
              >
                Bulk Dismiss
              </button>
            </div>
          </div>
        ) : null}
      </section>

      {alertsQuery.isError ? (
        <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4 text-sm text-amber-200">
          {errorMessage(alertsQuery.error, 'Alerts are unavailable.')}
        </div>
      ) : alerts.length ? (
        <div className="space-y-3">
          {alerts.map(alert => (
            <article key={alert.id} className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="flex items-start gap-3">
                  {bulkMode ? (
                    <input
                      type="checkbox"
                      checked={selectedAlertIds.includes(alert.id)}
                      onChange={() => toggleSelected(alert.id)}
                      className="mt-1 h-4 w-4 rounded border-white/10 bg-[#08111f]"
                    />
                  ) : null}
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <p className="text-sm font-medium text-white">{alert.rule_name || alert.alert_id || `Alert #${alert.id}`}</p>
                      <span className={`rounded-full border px-2 py-1 text-[10px] uppercase tracking-[0.16em] ${severityTone(alert.severity)}`}>
                        {alert.severity}
                      </span>
                    </div>
                    <p className="mt-1 text-xs text-slate-400">
                      {alert.source} · {alert.status.replace(/_/g, ' ')} · {alert.hostname || alert.source_ip || 'asset unknown'}
                    </p>
                    <p className="mt-1 text-xs text-slate-500">
                      {alert.event_time ? new Date(alert.event_time).toLocaleString() : 'Event time unavailable'}
                    </p>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <select
                    value={alert.assigned_to ?? ''}
                    disabled={!canManage || assignMutation.isPending}
                    onChange={event =>
                      assignMutation.mutate({
                        alertId: alert.id,
                        assignedTo: event.target.value ? Number(event.target.value) : null,
                      })
                    }
                    className="rounded-lg border border-white/10 bg-[#08111f] px-3 py-2 text-xs text-white disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    <option value="">Unassigned</option>
                    {(analystsQuery.data?.data || []).map(analyst => (
                      <option key={analyst.id} value={analyst.id}>
                        {analyst.displayName}
                      </option>
                    ))}
                  </select>
                  <button
                    type="button"
                    disabled={!canManage || statusMutation.isPending || alert.status !== 'new'}
                    onClick={() => statusMutation.mutate({ alertId: alert.id, status: 'acknowledged' })}
                    className="rounded-lg border border-cyan-300/30 bg-cyan-400/10 px-3 py-2 text-xs text-cyan-100 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    ACK
                  </button>
                  <button
                    type="button"
                    disabled={!canManage || statusMutation.isPending}
                    onClick={() => statusMutation.mutate({ alertId: alert.id, status: 'dismissed' })}
                    className="rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-xs text-slate-200 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    Dismiss
                  </button>
                  <button
                    type="button"
                    disabled={!canManage || escalateMutation.isPending}
                    onClick={() => escalateMutation.mutate(alert.id)}
                    className="rounded-lg border border-rose-300/30 bg-rose-400/10 px-3 py-2 text-xs text-rose-100 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    Escalate
                  </button>
                  <button
                    type="button"
                    disabled={triageMutation.isPending}
                    onClick={() => triageMutation.mutate(alert.id)}
                    className="rounded-lg border border-emerald-300/30 bg-emerald-400/10 px-3 py-2 text-xs text-emerald-100 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    Triage Suggestion
                  </button>
                </div>
              </div>

              <div className="mt-4 grid gap-4 xl:grid-cols-[1.2fr_0.8fr]">
                <div className="space-y-3">
                  <div className="rounded-lg border border-white/10 bg-[#08111f] p-3">
                    <div className="mb-2 flex items-center gap-2">
                      <ShieldAlert className="h-4 w-4 text-cyan-300" />
                      <p className="text-sm font-medium text-white">Analyst Notes</p>
                    </div>
                    {editingNotesId === alert.id ? (
                      <div className="space-y-3">
                        <textarea
                          value={notesDrafts[alert.id] ?? alert.notes ?? ''}
                          onChange={event =>
                            setNotesDrafts(current => ({
                              ...current,
                              [alert.id]: event.target.value,
                            }))
                          }
                          rows={4}
                          className="w-full rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-sm text-white"
                        />
                        <div className="flex gap-2">
                          <button
                            type="button"
                            disabled={notesMutation.isPending}
                            onClick={() =>
                              notesMutation.mutate({
                                alertId: alert.id,
                                notes: notesDrafts[alert.id] ?? alert.notes ?? '',
                              })
                            }
                            className="rounded-lg border border-cyan-300/30 bg-cyan-400/10 px-3 py-2 text-xs text-cyan-100 disabled:cursor-not-allowed disabled:opacity-60"
                          >
                            Save Notes
                          </button>
                          <button
                            type="button"
                            onClick={() => setEditingNotesId(null)}
                            className="rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-xs text-slate-200"
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    ) : (
                      <div className="space-y-3">
                        <p className="text-sm text-slate-300">{alert.notes || 'No analyst notes recorded yet.'}</p>
                        <button
                          type="button"
                          disabled={!canManage}
                          onClick={() => {
                            setEditingNotesId(alert.id);
                            setNotesDrafts(current => ({
                              ...current,
                              [alert.id]: current[alert.id] ?? alert.notes ?? '',
                            }));
                          }}
                          className="rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-xs text-slate-200 disabled:cursor-not-allowed disabled:opacity-60"
                        >
                          Edit Notes
                        </button>
                      </div>
                    )}
                  </div>

                  <details className="rounded-lg border border-white/10 bg-[#08111f] p-3">
                    <summary className="cursor-pointer text-sm font-medium text-white">Raw Payload</summary>
                    <pre className="mt-3 overflow-x-auto rounded-lg border border-white/10 bg-black/20 p-3 text-xs text-slate-300">
                      {JSON.stringify(alert.raw_payload, null, 2)}
                    </pre>
                  </details>
                </div>

                <div className="space-y-3">
                  {triageAlertId === alert.id && triageSuggestion ? (
                    <div className="rounded-lg border border-emerald-300/20 bg-emerald-400/5 p-3">
                      <div className="mb-2 flex items-center gap-2">
                        <AlertTriangle className="h-4 w-4 text-emerald-300" />
                        <p className="text-sm font-medium text-white">Triage Suggestion</p>
                      </div>
                      <p className="text-sm text-slate-200">
                        {'summary' in triageSuggestion && typeof triageSuggestion.summary === 'string'
                          ? triageSuggestion.summary
                          : `Suggested priority ${triageSuggestion.suggestedPriority}.`}
                      </p>
                      <div className="mt-3 space-y-2">
                        {triageSuggestion.suggestions.map(item => (
                          <div key={`${item.action}-${item.reason}`} className="rounded-lg border border-white/10 bg-black/10 p-3">
                            <p className="text-xs font-medium uppercase tracking-[0.16em] text-emerald-200">{item.action}</p>
                            <p className="mt-1 text-sm text-slate-200">{item.reason}</p>
                          </div>
                        ))}
                      </div>
                      {Array.isArray(triageSuggestion.evidence) && triageSuggestion.evidence.length ? (
                        <div className="mt-3 rounded-lg border border-white/10 bg-black/10 p-3">
                          <p className="text-xs font-medium uppercase tracking-[0.16em] text-slate-400">Evidence</p>
                          <div className="mt-2 space-y-1 text-xs text-slate-300">
                            {triageSuggestion.evidence.map(item => (
                              <p key={item}>{item}</p>
                            ))}
                          </div>
                        </div>
                      ) : null}
                      {triageSuggestion.llm ? (
                        <div className="mt-3 grid gap-2 rounded-lg border border-white/10 bg-black/10 p-3 text-xs text-slate-400 md:grid-cols-2">
                          <p>Provider: <span className="text-slate-200">{triageSuggestion.llm.provider}</span></p>
                          <p>Model: <span className="text-slate-200">{triageSuggestion.llm.model}</span></p>
                          <p>AI generated: <span className="text-slate-200">{triageSuggestion.llm.aiGenerated ? 'yes' : 'no'}</span></p>
                          <p>Grounding: <span className="text-slate-200">{Number.isFinite(triageSuggestion.llm.groundingScore) ? triageSuggestion.llm.groundingScore : 'n/a'}</span></p>
                        </div>
                      ) : null}
                      <p className="mt-3 text-xs text-slate-400">{triageSuggestion.disclaimer}</p>
                    </div>
                  ) : (
                    <div className="rounded-lg border border-white/10 bg-[#08111f] p-3 text-sm text-slate-400">
                      Run Triage Suggestion to retrieve grounded guidance for this alert.
                    </div>
                  )}

                  <div className="rounded-lg border border-white/10 bg-[#08111f] p-3">
                    <p className="text-sm font-medium text-white">Alert Context</p>
                    <div className="mt-3 space-y-2 text-xs text-slate-400">
                      <p>Category: {alert.category}</p>
                      <p>Source IP: {alert.source_ip || 'Unavailable'}</p>
                      <p>Destination IP: {alert.dest_ip || 'Unavailable'}</p>
                      <p>Correlated: {alert.correlated ? 'Yes' : 'No'}</p>
                    </div>
                  </div>
                </div>
              </div>
            </article>
          ))}
        </div>
      ) : (
        <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4 text-sm text-slate-400">
          No SIEM alerts match the current filters for this tenant.
        </div>
      )}
    </div>
  );
}
