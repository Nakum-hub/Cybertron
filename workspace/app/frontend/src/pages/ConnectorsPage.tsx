import { useEffect, useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import {
  AlertCircle,
  ArrowLeft,
  CheckCircle2,
  Loader2,
  Plug,
  Save,
  TestTube2,
  XCircle,
} from 'lucide-react';
import { useAuthStatus } from '@/hooks/use-auth-status';
import {
  listConnectorConfigs,
  testConnectorConnection,
  upsertConnectorConfig,
  type ConnectorConfig,
  type ConnectorTestResult,
} from '@/lib/backend';

const CONNECTORS = [
  { key: 'wazuh', name: 'Wazuh', description: 'SIEM and XDR agent manager' },
  { key: 'misp', name: 'MISP', description: 'Malware information sharing platform' },
  { key: 'opencti', name: 'OpenCTI', description: 'Cyber threat intelligence platform' },
  { key: 'thehive', name: 'TheHive', description: 'Security incident response platform' },
];

export default function ConnectorsPage() {
  const { status, profile } = useAuthStatus();
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

  const resolvedTenant = String(profile?.tenant || 'global').trim() || 'global';

  async function loadConfigs() {
    setLoading(true);
    setError('');

    try {
      const result = await listConnectorConfigs(resolvedTenant);
      setConfigs(result || []);
    } catch (loadError) {
      setConfigs([]);
      setError(loadError instanceof Error ? loadError.message : 'Unable to load connector configuration.');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (status === 'loading') {
      return;
    }
    void loadConfigs();
  }, [resolvedTenant, status]);

  function startEdit(key: string) {
    const existing = configs.find(config => config.connector === key);
    setEditing(key);
    setEditUrl(existing?.apiUrl || '');
    setEditToken('');
    setEditEnabled(existing?.enabled ?? true);
    setError('');
    setTestResult(null);
  }

  async function handleSave(event: FormEvent) {
    event.preventDefault();
    if (!editing) {
      return;
    }

    setSaving(true);
    setError('');

    try {
      await upsertConnectorConfig(resolvedTenant, editing, {
        apiUrl: editUrl,
        apiToken: editToken || undefined,
        enabled: editEnabled,
      });
      setEditing(null);
      await loadConfigs();
    } catch (saveError) {
      setError(saveError instanceof Error ? saveError.message : 'Failed to save connector settings.');
    } finally {
      setSaving(false);
    }
  }

  async function handleTest(key: string) {
    setTesting(key);
    setTestResult(null);
    setError('');

    try {
      const result = await testConnectorConnection(resolvedTenant, key);
      setTestResult(result);
    } catch (testError) {
      setTestResult({
        connector: key,
        reachable: false,
        statusCode: null,
        latencyMs: 0,
        error: testError instanceof Error ? testError.message : 'Test failed',
      });
    } finally {
      setTesting(null);
    }
  }

  function getStatus(key: string) {
    return configs.find(config => config.connector === key);
  }

  return (
    <div className="min-h-screen bg-[#04070f] text-white">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 py-8">
        <Link
          to="/account"
          className="inline-flex items-center gap-2 text-sm text-slate-400 hover:text-cyan-300 transition-colors mb-6"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Account
        </Link>

        <div className="flex items-center gap-3 mb-8">
          <div className="p-2.5 rounded-xl bg-gradient-to-br from-amber-500/10 to-orange-500/10 border border-white/10">
            <Plug className="w-6 h-6 text-amber-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Connector Configuration</h1>
            <p className="text-sm text-slate-500">Manage external security tool integrations for {resolvedTenant}</p>
          </div>
        </div>

        {error && (
          <div className="rounded-lg bg-red-500/10 border border-red-500/20 p-3 mb-6 flex items-start gap-2">
            <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
            <span className="text-sm text-red-300">{error}</span>
          </div>
        )}

        {loading ? (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="w-6 h-6 text-cyan-400 animate-spin" />
          </div>
        ) : (
          <div className="space-y-4">
            {CONNECTORS.map(connector => {
              const status = getStatus(connector.key);
              const isEditing = editing === connector.key;

              return (
                <div
                  key={connector.key}
                  className={`rounded-2xl border ${
                    isEditing ? 'border-cyan-500/30 bg-cyan-500/[0.03]' : 'border-white/5 bg-white/[0.02]'
                  } transition-colors`}
                >
                  <div className="p-5">
                    <div className="flex items-center justify-between mb-1">
                      <div className="flex items-center gap-3">
                        <h3 className="text-base font-semibold text-white">{connector.name}</h3>
                        {status && (
                          <span
                            className={`text-xs px-2 py-0.5 rounded ${
                              status.enabled
                                ? status.lastSyncStatus === 'ok'
                                  ? 'bg-emerald-500/10 text-emerald-400'
                                  : 'bg-amber-500/10 text-amber-400'
                                : 'bg-white/5 text-slate-500'
                            }`}
                          >
                            {status.enabled
                              ? status.lastSyncStatus === 'ok'
                                ? 'Connected'
                                : status.lastSyncStatus || 'Configured'
                              : 'Disabled'}
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-2">
                        {status && (
                          <button
                            onClick={() => void handleTest(connector.key)}
                            disabled={testing === connector.key}
                            className="px-3 py-1.5 rounded-lg text-xs bg-white/5 text-slate-400 hover:text-white hover:bg-white/10 transition-colors flex items-center gap-1.5 border border-white/10"
                          >
                            {testing === connector.key ? <Loader2 className="w-3 h-3 animate-spin" /> : <TestTube2 className="w-3 h-3" />}
                            Test
                          </button>
                        )}
                        <button
                          onClick={() => (isEditing ? setEditing(null) : startEdit(connector.key))}
                          className="px-3 py-1.5 rounded-lg text-xs bg-cyan-500/10 text-cyan-300 hover:bg-cyan-500/20 transition-colors border border-cyan-500/20"
                        >
                          {isEditing ? 'Cancel' : status ? 'Edit' : 'Configure'}
                        </button>
                      </div>
                    </div>
                    <p className="text-xs text-slate-500">{connector.description}</p>
                    {status?.apiUrl && !isEditing && (
                      <p className="text-xs text-slate-600 mt-1 font-mono">{status.apiUrl}</p>
                    )}
                  </div>

                  {testResult && testResult.connector === connector.key && (
                    <div
                      className={`mx-5 mb-4 p-3 rounded-lg text-sm flex items-start gap-2 ${
                        testResult.reachable ? 'bg-emerald-500/10 border border-emerald-500/20' : 'bg-red-500/10 border border-red-500/20'
                      }`}
                    >
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

                  {isEditing && (
                    <form onSubmit={handleSave} className="px-5 pb-5 border-t border-white/5 pt-4 space-y-3">
                      <div>
                        <label className="block text-xs text-slate-400 mb-1">API URL</label>
                        <input
                          type="url"
                          value={editUrl}
                          onChange={event => setEditUrl(event.target.value)}
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
                          onChange={event => setEditToken(event.target.value)}
                          className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-lg text-white text-sm placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-cyan-500/40 transition"
                          placeholder={status?.apiTokenMasked || 'Enter API token'}
                        />
                        <p className="text-xs text-slate-600 mt-1">Leave blank to keep the existing token.</p>
                      </div>
                      <label className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={editEnabled}
                          onChange={event => setEditEnabled(event.target.checked)}
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
