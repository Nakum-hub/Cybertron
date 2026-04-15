import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Bell, Mail, Shield, AlertTriangle, CheckCircle, ArrowLeft, Save } from 'lucide-react';

interface NotificationPrefs {
  emailOnCritical: boolean;
  emailOnHigh: boolean;
  emailOnResolved: boolean;
  inAppAll: boolean;
}

const defaultPrefs: NotificationPrefs = {
  emailOnCritical: true,
  emailOnHigh: false,
  emailOnResolved: false,
  inAppAll: true,
};

export default function NotificationsPage() {
  const navigate = useNavigate();
  const [prefs, setPrefs] = useState<NotificationPrefs>(defaultPrefs);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    fetch('/api/v1/notifications/preferences', { credentials: 'include' })
      .then((res) => {
        if (res.ok) return res.json();
        throw new Error('Failed to load');
      })
      .then((data) => {
        if (data) setPrefs(data);
      })
      .catch(() => {
        // Use defaults silently
      });
  }, []);

  const handleSave = async () => {
    setSaving(true);
    setError('');
    setSaved(false);
    try {
      const res = await fetch('/api/v1/notifications/preferences', {
        method: 'PATCH',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(prefs),
      });
      if (!res.ok) throw new Error('Save failed');
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch {
      setError('Failed to save preferences. Please try again.');
    } finally {
      setSaving(false);
    }
  };

  const togglePref = (key: keyof NotificationPrefs) => {
    setPrefs((prev) => ({ ...prev, [key]: !prev[key] }));
    setSaved(false);
  };

  const Toggle = ({ checked, onChange }: { checked: boolean; onChange: () => void }) => (
    <button
      onClick={onChange}
      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 ${
        checked ? 'bg-cyan-600' : 'bg-slate-700'
      }`}
    >
      <span
        className={`inline-block h-4 w-4 rounded-full bg-white transition-transform duration-200 ${
          checked ? 'translate-x-6' : 'translate-x-1'
        }`}
      />
    </button>
  );

  return (
    <div className="min-h-screen bg-[#04070f] text-white">
      <div className="max-w-2xl mx-auto px-6 py-12">
        {/* Header */}
        <div className="flex items-center gap-3 mb-8">
          <button
            onClick={() => navigate('/account')}
            className="p-2 rounded-lg bg-slate-800/50 border border-slate-700/50 hover:bg-slate-700/50 transition-colors"
          >
            <ArrowLeft className="w-4 h-4 text-slate-400" />
          </button>
          <div>
            <h1 className="text-2xl font-bold">Notification Preferences</h1>
            <p className="text-sm text-slate-500">Control when and how you receive alerts</p>
          </div>
        </div>

        {/* Email Notifications */}
        <div className="bg-slate-900/60 border border-slate-800/60 rounded-xl p-6 mb-6">
          <div className="flex items-center gap-3 mb-5">
            <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20">
              <Mail className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <h2 className="text-lg font-semibold">Email Notifications</h2>
              <p className="text-sm text-slate-500">Receive alerts directly to your email</p>
            </div>
          </div>

          <div className="space-y-4">
            <div className="flex items-center justify-between py-3 border-b border-slate-800/50">
              <div className="flex items-center gap-3">
                <AlertTriangle className="w-4 h-4 text-red-400" />
                <div>
                  <p className="font-medium">Critical Severity Alerts</p>
                  <p className="text-sm text-slate-500">Immediate email for critical incidents</p>
                </div>
              </div>
              <Toggle checked={prefs.emailOnCritical} onChange={() => togglePref('emailOnCritical')} />
            </div>

            <div className="flex items-center justify-between py-3 border-b border-slate-800/50">
              <div className="flex items-center gap-3">
                <Shield className="w-4 h-4 text-orange-400" />
                <div>
                  <p className="font-medium">High Severity Alerts</p>
                  <p className="text-sm text-slate-500">Email notifications for high-severity incidents</p>
                </div>
              </div>
              <Toggle checked={prefs.emailOnHigh} onChange={() => togglePref('emailOnHigh')} />
            </div>

            <div className="flex items-center justify-between py-3">
              <div className="flex items-center gap-3">
                <CheckCircle className="w-4 h-4 text-emerald-400" />
                <div>
                  <p className="font-medium">Resolved Incidents</p>
                  <p className="text-sm text-slate-500">Email when incidents are resolved</p>
                </div>
              </div>
              <Toggle checked={prefs.emailOnResolved} onChange={() => togglePref('emailOnResolved')} />
            </div>
          </div>
        </div>

        {/* In-App Notifications */}
        <div className="bg-slate-900/60 border border-slate-800/60 rounded-xl p-6 mb-8">
          <div className="flex items-center gap-3 mb-5">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20">
              <Bell className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <h2 className="text-lg font-semibold">In-App Notifications</h2>
              <p className="text-sm text-slate-500">Real-time alerts within the platform</p>
            </div>
          </div>

          <div className="flex items-center justify-between py-3">
            <div>
              <p className="font-medium">All Events</p>
              <p className="text-sm text-slate-500">Receive all in-app notifications via the bell icon</p>
            </div>
            <Toggle checked={prefs.inAppAll} onChange={() => togglePref('inAppAll')} />
          </div>
        </div>

        {/* Save */}
        {error && (
          <div className="mb-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
            {error}
          </div>
        )}

        <button
          onClick={handleSave}
          disabled={saving}
          className="w-full flex items-center justify-center gap-2 px-6 py-3 bg-gradient-to-r from-cyan-600 to-blue-600 text-white font-semibold rounded-lg hover:from-cyan-500 hover:to-blue-500 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {saving ? (
            <div className="h-5 w-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
          ) : saved ? (
            <>
              <CheckCircle className="w-5 h-5" />
              Saved
            </>
          ) : (
            <>
              <Save className="w-5 h-5" />
              Save Preferences
            </>
          )}
        </button>
      </div>
    </div>
  );
}
