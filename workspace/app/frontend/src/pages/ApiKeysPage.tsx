import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Key, Plus, Trash2, Copy, Shield, ArrowLeft, AlertTriangle } from 'lucide-react';

interface ApiKeyRecord {
  id: string;
  name: string;
  keyPrefix: string;
  scopes: string[];
  lastUsedAt: string | null;
  expiresAt: string | null;
  createdAt: string;
}

export default function ApiKeysPage() {
  const navigate = useNavigate();
  const [keys, setKeys] = useState<ApiKeyRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [newKeyName, setNewKeyName] = useState('');
  const [createdKey, setCreatedKey] = useState('');
  const [creating, setCreating] = useState(false);
  const [copied, setCopied] = useState(false);

  const fetchKeys = async () => {
    try {
      const res = await fetch('/api/v1/admin/api-keys', { credentials: 'include' });
      if (res.ok) {
        const data = await res.json();
        setKeys(data.data || []);
      }
    } catch {
      // Silent fail
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchKeys(); }, []);

  const handleCreate = async () => {
    if (!newKeyName.trim()) return;
    setCreating(true);
    try {
      const res = await fetch('/api/v1/admin/api-keys', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newKeyName.trim(), scopes: ['read', 'write'] }),
      });
      if (res.ok) {
        const data = await res.json();
        setCreatedKey(data.rawKey || '');
        setNewKeyName('');
        fetchKeys();
      }
    } catch {
      // Error handling
    } finally {
      setCreating(false);
    }
  };

  const handleRevoke = async (keyId: string) => {
    try {
      await fetch(`/api/v1/admin/api-keys/${keyId}`, {
        method: 'DELETE',
        credentials: 'include',
      });
      fetchKeys();
    } catch {
      // Silent
    }
  };

  const copyKey = () => {
    navigator.clipboard.writeText(createdKey);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="min-h-screen bg-[#04070f] text-white">
      <div className="max-w-3xl mx-auto px-6 py-12">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-3">
            <button
              onClick={() => navigate('/account')}
              className="p-2 rounded-lg bg-slate-800/50 border border-slate-700/50 hover:bg-slate-700/50 transition-colors"
            >
              <ArrowLeft className="w-4 h-4 text-slate-400" />
            </button>
            <div>
              <h1 className="text-2xl font-bold">API Keys</h1>
              <p className="text-sm text-slate-500">Manage programmatic access to the platform</p>
            </div>
          </div>
          <button
            onClick={() => { setShowCreate(true); setCreatedKey(''); }}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-500 transition-colors text-sm font-medium"
          >
            <Plus className="w-4 h-4" />
            Create Key
          </button>
        </div>

        {/* Created Key Modal */}
        {createdKey && (
          <div className="mb-6 p-5 bg-amber-500/10 border border-amber-500/30 rounded-xl">
            <div className="flex items-center gap-2 mb-3">
              <AlertTriangle className="w-5 h-5 text-amber-400" />
              <span className="font-semibold text-amber-400">Copy your API key now — it won't be shown again</span>
            </div>
            <div className="flex items-center gap-2">
              <code className="flex-1 px-4 py-3 bg-slate-900 rounded-lg text-sm text-emerald-400 font-mono break-all">
                {createdKey}
              </code>
              <button
                onClick={copyKey}
                className="p-3 bg-slate-800 rounded-lg hover:bg-slate-700 transition-colors"
              >
                <Copy className="w-4 h-4 text-slate-400" />
              </button>
            </div>
            {copied && <p className="mt-2 text-sm text-emerald-400">Copied to clipboard!</p>}
          </div>
        )}

        {/* Create Form */}
        {showCreate && !createdKey && (
          <div className="mb-6 p-5 bg-slate-900/60 border border-slate-800/60 rounded-xl">
            <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4">New API Key</h3>
            <div className="flex gap-3">
              <input
                type="text"
                value={newKeyName}
                onChange={(e) => setNewKeyName(e.target.value)}
                placeholder="Key name (e.g., CI Pipeline)"
                className="flex-1 px-4 py-2.5 bg-slate-800 border border-slate-700 rounded-lg text-white placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              />
              <button
                onClick={handleCreate}
                disabled={creating || !newKeyName.trim()}
                className="px-5 py-2.5 bg-cyan-600 rounded-lg text-white font-medium hover:bg-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {creating ? 'Creating...' : 'Create'}
              </button>
              <button
                onClick={() => setShowCreate(false)}
                className="px-4 py-2.5 bg-slate-800 border border-slate-700 rounded-lg text-slate-400 hover:bg-slate-700 transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {/* Keys List */}
        {loading ? (
          <div className="flex justify-center py-12">
            <div className="h-8 w-8 border-2 border-cyan-500/30 border-t-cyan-400 rounded-full animate-spin" />
          </div>
        ) : keys.length === 0 ? (
          <div className="text-center py-16 bg-slate-900/30 border border-slate-800/40 rounded-xl">
            <Key className="w-12 h-12 text-slate-700 mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-slate-400">No API Keys</h3>
            <p className="text-sm text-slate-600 mt-1">Create an API key to access the platform programmatically.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {keys.map((key) => (
              <div key={key.id} className="flex items-center justify-between p-4 bg-slate-900/60 border border-slate-800/60 rounded-xl hover:border-slate-700/60 transition-colors">
                <div className="flex items-center gap-4">
                  <div className="p-2 rounded-lg bg-slate-800 border border-slate-700/50">
                    <Shield className="w-5 h-5 text-cyan-400" />
                  </div>
                  <div>
                    <p className="font-medium">{key.name}</p>
                    <p className="text-sm text-slate-500 font-mono">{key.keyPrefix}••••••••</p>
                  </div>
                </div>
                <div className="flex items-center gap-4">
                  <div className="text-right text-sm">
                    <p className="text-slate-500">{key.lastUsedAt ? `Last used ${new Date(key.lastUsedAt).toLocaleDateString()}` : 'Never used'}</p>
                    <p className="text-slate-600">{key.expiresAt ? `Expires ${new Date(key.expiresAt).toLocaleDateString()}` : 'No expiry'}</p>
                  </div>
                  <button
                    onClick={() => handleRevoke(key.id)}
                    className="p-2 rounded-lg hover:bg-red-500/10 text-slate-500 hover:text-red-400 transition-colors"
                    title="Revoke key"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
