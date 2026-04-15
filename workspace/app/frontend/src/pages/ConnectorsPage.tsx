/**
 * P1-10: Connector Configuration Page
 * Route: /platform/connectors
 * Manage Wazuh, MISP, OpenCTI, TheHive connector settings.
 */
import { useState, useEffect, FormEvent } from 'react';
import { Link } from 'react-router-dom';
import {
  ArrowLeft,
  Plug,
  CheckCircle2,
  XCircle,
  Loader2,
  TestTube2,
  Save,
  AlertCircle,
} from 'lucide-react';
import { api } from '@/lib/api';

interface ConnectorConfig {
  id: string;
  connector: string;
  apiUrl: string;
  apiTokenMasked: string;
  enabled: boolean;
  lastSyncAt: string | null;
  lastSyncStatus: string;
}

interface ConnectorTestResult {
  connector: string;
  reachable: boolean;
  statusCode: number | null;
  latencyMs: number;
  error?: string;
}

const CONNECTORS = [
  { key: 'wazuh', name: 'Wazuh', description: 'SIEM & XDR agent manager' },
  { key: 'misp', name: 'MISP', description: 'Malware information sharing platform' },
  { key: 'opencti', name: 'OpenCTI', description: 'Cyber threat intelligence platform' },
  { key: 'thehive', name: 'TheHive', description: 'Security incident response platform' },
];

export default function ConnectorsPage() {
  const [configs, setConfigs] = useState<ConnectorConfig[]>([]);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState<string | null>(null);
  const [editUrl, setEditUrl] = useState('');
  const [editToken, setEditToken] = useState('');
  const [editEnabled, setEditEnabled] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<ConnectorTestResult | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    loadConfigs();
  }, []);

  async function loadConfigs() {
    setLoading(true);
    try {
      const result = await api.get<ConnectorConfig[]>('/v1/admin/connectors', { auth: true });
      setConfigs(result || []);
    } catch {
      // User may not have access
    } finally {
      setLoading(false);
    }
  }

  function startEdit(key: string) {
    const existing = configs.find((c) => c.connector === key);
    setEditing(key);
    setEditUrl(existing?.apiUrl || '');
    setEditToken('');
    setEditEnabled(existing?.enabled ?? true);
    setError('');
    setTestResult(null);
  }

  async function handleSave(e: FormEvent) {
    e.preventDefault();
    if (!editing) return;
    setError('');
    setSaving(true);
    try {
      await api.put(`/v1/admin/connectors/${editing}`, {
        apiUrl: editUrl,
        apiToken: editToken || undefined,
        enabled: editEnabled,
      }, { auth: true });
      setEditing(null);
      await loadConfigs();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to save.');
    } finally {
      setSaving(false);
    }
  }

  async function handleTest(key: string) {
    setTesting(key);
    setTestResult(null);
    try {
      const result = await api.post<ConnectorTestResult>(`/v1/admin/connectors/${key}/test`, undefined, { auth: true });
      setTestResult(result);
    } catch (err: unknown) {
      setTestResult({
        connector: key,
        reachable: false,
        statusCode: null,
        latencyMs: 0,
        error: err instanceof Error ? err.message : 'Test failed',
      });
    } finally {
      setTesting(null);
    }
  }

  function getStatus(key: string) {
    return configs.find((c) => c.connector === key);
  }

  return (
    <div className="min-h-screen bg-[#04070f] text-white">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 py-8">
        <Link
          to="/admin"
          className="inline-flex items-center gap-2 text-sm text-slate-400 hover:text-cyan-300 transition-colors mb-6"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Admin
        </Link>

        <div className="flex items-center gap-3 mb-8">
          <div className="p-2.5 rounded-xl bg-gradient-to-br from-amber-500/10 to-orange-500/10 border border-white/10">
            <Plug className="w-6 h-6 text-amber-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Connector Configuration</h1>
            <p className="text-sm text-slate-500">Manage your external security tool integrations</p>
          </div>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="w-6 h-6 text-cyan-400 animate-spin" />
          </div>
        ) : (
          <div className="space-y-4">
            {CONNECTORS.map((conn) => {
              const status = getStatus(conn.key);
              const isEditing = editing === conn.key;

              return (
                <div
                  key={conn.key}
                  className={`rounded-2xl border ${
                    isEditing ? 'border-cyan-500/30 bg-cyan-500/[0.03]' : 'border-white/5 bg-white/[0.02]'
                  } transition-colors`}
                >
                  <div className="p-5">
                    <div className="flex items-center justify-between mb-1">
                      <div className="flex items-center gap-3">
                        <h3 className="text-base font-semibold text-white">{conn.name}</h3>
                        {status && (
                          <span className={`text-xs px-2 py-0.5 rounded ${
                            status.enabled
                              ? status.lastSyncStatus === 'ok'
                                ? 'bg-emerald-500/10 text-emerald-400'
                                : 'bg-amber-500/10 text-amber-400'
                              : 'bg-white/5 text-slate-500'
                          }`}>
                            {status.enabled ? (status.lastSyncStatus === 'ok' ? 'Connected' : status.lastSyncStatus || 'Configured') : 'Disabled'}
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-2">
                        {status && (
                          <button
                            onClick={() => handleTest(conn.key)}
                            disabled={testing === conn.key}
                            className="px-3 py-1.5 rounded-lg text-xs bg-white/5 text-slate-400 hover:text-white hover:bg-white/10 transition-colors flex items-center gap-1.5 border border-white/10"
                          >
                            {testing === conn.key ? <Loader2 className="w-3 h-3 animate-spin" /> : <TestTube2 className="w-3 h-3" />}
                            Test
                          </button>
                        )}
                        <button
                          onClick={() => isEditing ? setEditing(null) : startEdit(conn.key)}
                          className="px-3 py-1.5 rounded-lg text-xs bg-cyan-500/10 text-cyan-300 hover:bg-cyan-500/20 transition-colors border border-cyan-500/20"
                        >
                          {isEditing ? 'Cancel' : status ? 'Edit' : 'Configure'}
                        </button>
                      </div>
                    </div>
                    <p className="text-xs text-slate-500">{conn.description}</p>
                    {status?.apiUrl && !isEditing && (
                      <p className="text-xs text-slate-600 mt-1 font-mono">{status.apiUrl}</p>
                    )}
                  </div>

                  {/* Test result */}
                  {testResult && testResult.connector === conn.key && (
                    <div className={`mx-5 mb-4 p-3 rounded-lg text-sm flex items-start gap-2 ${
                      testResult.reachable ? 'bg-emerald-500/10 border border-emerald-500/20' : 'bg-red-500/10 border border-red-500/20'
                    }`}>
                      {testResult.reachable ? (
                        <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                      ) : (
                        <XCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                      )}
                      <span className={testResult.reachable ? 'text-emerald-300' : 'text-red-300'}>
                        {testResult.reachable
                          ? `Connected (${testResult.latencyMs}ms, HTTP ${testResult.statusCode})`
                          : `Failed: ${testResult.error || `HTTP ${testResult.statusCode}`}`}
                      </span>
                    </div>
                  )}

                  {/* Edit form */}
                  {isEditing && (
                    <form onSubmit={handleSave} className="px-5 pb-5 border-t border-white/5 pt-4 space-y-3">
                      {error && (
                        <div className="rounded-lg bg-red-500/10 border border-red-500/20 p-3 flex items-start gap-2">
                          <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                          <span className="text-sm text-red-300">{error}</span>
                        </div>
                      )}
                      <div>
                        <label className="block text-xs text-slate-400 mb-1">API URL</label>
                        <input
                          type="url"
                          value={editUrl}
                          onChange={(e) => setEditUrl(e.target.value)}
                          required
                          className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-lg text-white text-sm placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-cyan-500/40 transition"
                          placeholder="https://wazuh.internal:55000"
                        />
                      </div>
                      <div>
                        <label className="block text-xs text-slate-400 mb-1">API Token / Key</label>
                        <input
                          type="password"
                          value={editToken}
                          onChange={(e) => setEditToken(e.target.value)}
                          className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-lg text-white text-sm placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-cyan-500/40 transition"
                          placeholder={status?.apiTokenMasked || 'Enter API token'}
                        />
                        <p className="text-xs text-slate-600 mt-1">Leave blank to keep existing token</p>
                      </div>
                      <label className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={editEnabled}
                          onChange={(e) => setEditEnabled(e.target.checked)}
                          className="rounded border-white/20 bg-white/5"
                        />
                        <span className="text-sm text-slate-300">Enabled</span>
                      </label>
                      <div className="flex justify-end">
                        <button
                          type="submit"
                          disabled={saving}
                          className="px-4 py-2 rounded-lg bg-cyan-600 text-white text-sm font-medium hover:bg-cyan-500 transition-colors flex items-center gap-2 disabled:opacity-50"
                        >
                          {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
                          Save
                        </button>
                      </div>
                    </form>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
