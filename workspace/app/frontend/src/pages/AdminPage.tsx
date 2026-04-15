/**
 * P1-6: Admin Dashboard Page
 * Route: /admin
 * Shows tenant-level admin tools: users, billing, invites, settings.
 */
import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  ArrowLeft,
  Users,
  CreditCard,
  Shield,
  Settings,
  UserPlus,
  Activity,
  Loader2,
} from 'lucide-react';
import { api } from '@/lib/api';

interface AdminUser {
  email: string;
  displayName: string;
  role: string;
  active: boolean;
  createdAt: string;
}

interface AdminInvite {
  id: string;
  email: string;
  role: string;
  expiresAt: string;
  acceptedAt: string | null;
}

type AdminTab = 'users' | 'invites' | 'billing' | 'settings';

export default function AdminPage() {
  const [activeTab, setActiveTab] = useState<AdminTab>('users');
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [invites, setInvites] = useState<AdminInvite[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadData();
  }, [activeTab]);

  async function loadData() {
    setLoading(true);
    try {
      if (activeTab === 'users') {
        const result = await api.get<{ data: AdminUser[] }>('/v1/admin/users', { auth: true });
        setUsers(result.data || []);
      } else if (activeTab === 'invites') {
        const result = await api.get<AdminInvite[]>('/v1/admin/invites', { auth: true });
        setInvites(result || []);
      }
    } catch {
      // Silently handle — user may not have admin access
    } finally {
      setLoading(false);
    }
  }

  const tabs: { key: AdminTab; label: string; icon: typeof Users }[] = [
    { key: 'users', label: 'Users', icon: Users },
    { key: 'invites', label: 'Invites', icon: UserPlus },
    { key: 'billing', label: 'Billing', icon: CreditCard },
    { key: 'settings', label: 'Settings', icon: Settings },
  ];

  return (
    <div className="min-h-screen bg-[#04070f] text-white">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 py-8">
        <Link
          to="/platform"
          className="inline-flex items-center gap-2 text-sm text-slate-400 hover:text-cyan-300 transition-colors mb-6"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Platform
        </Link>

        <div className="flex items-center gap-3 mb-8">
          <div className="p-2.5 rounded-xl bg-gradient-to-br from-cyan-500/10 to-violet-500/10 border border-white/10">
            <Shield className="w-6 h-6 text-cyan-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Admin Dashboard</h1>
            <p className="text-sm text-slate-500">Manage your workspace settings and team</p>
          </div>
        </div>

        {/* Tab Bar */}
        <div className="flex gap-1 mb-8 p-1 rounded-xl bg-white/[0.03] border border-white/5 w-fit">
          {tabs.map((tab) => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                activeTab === tab.key
                  ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/20'
                  : 'text-slate-400 hover:text-white hover:bg-white/5'
              }`}
            >
              <tab.icon className="w-4 h-4" />
              {tab.label}
            </button>
          ))}
        </div>

        {/* Content */}
        {loading ? (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="w-6 h-6 text-cyan-400 animate-spin" />
          </div>
        ) : (
          <>
            {activeTab === 'users' && (
              <div className="space-y-3">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-lg font-semibold">Team Members ({users.length})</h2>
                </div>
                {users.length === 0 ? (
                  <div className="rounded-xl border border-white/5 bg-white/[0.02] p-10 text-center text-slate-500">
                    <Users className="w-8 h-8 mx-auto mb-3 opacity-40" />
                    <p>No team members found.</p>
                  </div>
                ) : (
                  <div className="rounded-xl border border-white/5 overflow-hidden">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="bg-white/[0.03]">
                          <th className="text-left px-4 py-3 text-xs text-slate-400 font-medium uppercase tracking-wider">User</th>
                          <th className="text-left px-4 py-3 text-xs text-slate-400 font-medium uppercase tracking-wider">Role</th>
                          <th className="text-left px-4 py-3 text-xs text-slate-400 font-medium uppercase tracking-wider">Status</th>
                          <th className="text-left px-4 py-3 text-xs text-slate-400 font-medium uppercase tracking-wider">Joined</th>
                        </tr>
                      </thead>
                      <tbody>
                        {users.map((u, i) => (
                          <tr key={i} className="border-t border-white/5 hover:bg-white/[0.02] transition-colors">
                            <td className="px-4 py-3">
                              <p className="text-white font-medium">{u.displayName || u.email}</p>
                              <p className="text-xs text-slate-500">{u.email}</p>
                            </td>
                            <td className="px-4 py-3">
                              <span className="px-2 py-0.5 rounded text-xs bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
                                {u.role}
                              </span>
                            </td>
                            <td className="px-4 py-3">
                              <span className={`text-xs ${u.active ? 'text-emerald-400' : 'text-red-400'}`}>
                                {u.active ? '● Active' : '● Inactive'}
                              </span>
                            </td>
                            <td className="px-4 py-3 text-xs text-slate-500">
                              {new Date(u.createdAt).toLocaleDateString()}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {activeTab === 'invites' && (
              <div className="space-y-3">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-lg font-semibold">Pending Invites ({invites.length})</h2>
                  <Link
                    to="/account/team"
                    className="px-4 py-2 rounded-lg bg-cyan-600 text-white text-sm font-medium hover:bg-cyan-500 transition-colors flex items-center gap-2"
                  >
                    <UserPlus className="w-4 h-4" />
                    Invite Member
                  </Link>
                </div>
                {invites.length === 0 ? (
                  <div className="rounded-xl border border-white/5 bg-white/[0.02] p-10 text-center text-slate-500">
                    <UserPlus className="w-8 h-8 mx-auto mb-3 opacity-40" />
                    <p>No pending invitations.</p>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {invites.map((inv) => (
                      <div key={inv.id} className="flex items-center justify-between p-4 rounded-xl border border-white/5 bg-white/[0.02]">
                        <div>
                          <p className="text-white font-medium">{inv.email}</p>
                          <p className="text-xs text-slate-500">Role: {inv.role} · Expires: {new Date(inv.expiresAt).toLocaleDateString()}</p>
                        </div>
                        <span className={`text-xs px-2 py-0.5 rounded ${inv.acceptedAt ? 'bg-emerald-500/10 text-emerald-400' : 'bg-amber-500/10 text-amber-400'}`}>
                          {inv.acceptedAt ? 'Accepted' : 'Pending'}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {activeTab === 'billing' && (
              <div className="rounded-xl border border-white/5 bg-white/[0.02] p-10 text-center">
                <CreditCard className="w-10 h-10 text-slate-600 mx-auto mb-4" />
                <h2 className="text-lg font-semibold text-white mb-2">Billing & Subscription</h2>
                <p className="text-sm text-slate-500 mb-4">
                  Manage your plan, payment method, and invoices.
                </p>
                <Link
                  to="/pricing"
                  className="inline-flex px-6 py-2.5 rounded-lg bg-gradient-to-r from-cyan-600 to-cyan-500 text-white text-sm font-medium hover:from-cyan-500 hover:to-cyan-400 transition-all"
                >
                  View Plans
                </Link>
              </div>
            )}

            {activeTab === 'settings' && (
              <div className="space-y-6">
                <div className="rounded-xl border border-white/5 bg-white/[0.02] p-6">
                  <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                    <Activity className="w-5 h-5 text-cyan-400" />
                    Workspace Settings
                  </h2>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between py-3 border-b border-white/5">
                      <div>
                        <p className="text-sm text-white font-medium">Workspace Name</p>
                        <p className="text-xs text-slate-500">Displayed throughout your workspace</p>
                      </div>
                      <span className="text-sm text-slate-400">Cybertron</span>
                    </div>
                    <div className="flex items-center justify-between py-3 border-b border-white/5">
                      <div>
                        <p className="text-sm text-white font-medium">Auth Mode</p>
                        <p className="text-xs text-slate-500">Current authentication method</p>
                      </div>
                      <span className="text-sm text-slate-400">JWT HS256</span>
                    </div>
                    <div className="flex items-center justify-between py-3">
                      <div>
                        <p className="text-sm text-white font-medium">Connectors</p>
                        <p className="text-xs text-slate-500">Manage third-party integrations</p>
                      </div>
                      <Link
                        to="/platform/connectors"
                        className="px-3 py-1.5 rounded-lg bg-white/5 text-xs text-cyan-300 hover:bg-white/10 transition-colors border border-white/10"
                      >
                        Configure →
                      </Link>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
