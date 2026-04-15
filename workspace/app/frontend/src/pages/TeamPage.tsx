/**
 * P1-9: Team Management Page
 * Route: /account/team
 * Invite members, view current team, manage roles.
 */
import { useState, useEffect, FormEvent } from 'react';
import { Link } from 'react-router-dom';
import {
  ArrowLeft,
  UserPlus,
  Users,
  Mail,
  Trash2,
  Loader2,
  AlertCircle,
  CheckCircle2,
} from 'lucide-react';
import { api } from '@/lib/api';

interface TeamMember {
  email: string;
  displayName: string;
  role: string;
  active: boolean;
  createdAt: string;
}

interface Invite {
  id: string;
  email: string;
  role: string;
  expiresAt: string;
  acceptedAt: string | null;
  createdAt: string;
}

const AVAILABLE_ROLES = [
  'executive_viewer',
  'security_analyst',
  'analyst',
  'tenant_admin',
  'super_admin',
];

export default function TeamPage() {
  const [members, setMembers] = useState<TeamMember[]>([]);
  const [invites, setInvites] = useState<Invite[]>([]);
  const [loading, setLoading] = useState(true);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState('executive_viewer');
  const [sending, setSending] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  useEffect(() => {
    load();
  }, []);

  async function load() {
    setLoading(true);
    try {
      const [usersRes, invitesRes] = await Promise.allSettled([
        api.get<{ data: TeamMember[] }>('/v1/admin/users', { auth: true }),
        api.get<Invite[]>('/v1/admin/invites', { auth: true }),
      ]);
      if (usersRes.status === 'fulfilled') setMembers(usersRes.value.data || []);
      if (invitesRes.status === 'fulfilled') setInvites(invitesRes.value || []);
    } catch {
      // pass
    } finally {
      setLoading(false);
    }
  }

  async function handleInvite(e: FormEvent) {
    e.preventDefault();
    setError('');
    setSuccess('');
    if (!inviteEmail.includes('@')) {
      setError('Enter a valid email address.');
      return;
    }
    setSending(true);
    try {
      await api.post('/v1/admin/invites', { email: inviteEmail, role: inviteRole }, { auth: true });
      setSuccess(`Invitation sent to ${inviteEmail}`);
      setInviteEmail('');
      await load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to send invitation.');
    } finally {
      setSending(false);
    }
  }

  async function handleRevoke(inviteId: string) {
    try {
      await api.delete(`/v1/admin/invites/${inviteId}`, { auth: true });
      await load();
    } catch {
      // pass
    }
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
          <div className="p-2.5 rounded-xl bg-gradient-to-br from-violet-500/10 to-cyan-500/10 border border-white/10">
            <Users className="w-6 h-6 text-violet-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Team Management</h1>
            <p className="text-sm text-slate-500">Invite members and manage roles</p>
          </div>
        </div>

        {/* Invite Form */}
        <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-6 mb-8">
          <h2 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
            <Mail className="w-4 h-4 text-cyan-400" />
            Send Invitation
          </h2>

          {error && (
            <div className="rounded-lg bg-red-500/10 border border-red-500/20 p-3 mb-4 flex items-start gap-2">
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <span className="text-sm text-red-300">{error}</span>
            </div>
          )}

          {success && (
            <div className="rounded-lg bg-emerald-500/10 border border-emerald-500/20 p-3 mb-4 flex items-start gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <span className="text-sm text-emerald-300">{success}</span>
            </div>
          )}

          <form onSubmit={handleInvite} className="flex gap-3 items-end">
            <div className="flex-1">
              <label htmlFor="invite-email" className="block text-xs text-slate-400 mb-1">Email</label>
              <input
                id="invite-email"
                type="email"
                value={inviteEmail}
                onChange={(e) => setInviteEmail(e.target.value)}
                required
                className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-lg text-white text-sm placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-cyan-500/40 transition"
                placeholder="colleague@company.com"
              />
            </div>
            <div className="w-44">
              <label htmlFor="invite-role" className="block text-xs text-slate-400 mb-1">Role</label>
              <select
                id="invite-role"
                value={inviteRole}
                onChange={(e) => setInviteRole(e.target.value)}
                className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-lg text-white text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500/40 transition"
              >
                {AVAILABLE_ROLES.map((r) => (
                  <option key={r} value={r}>{r.replace(/_/g, ' ')}</option>
                ))}
              </select>
            </div>
            <button
              type="submit"
              disabled={sending}
              className="px-4 py-2 rounded-lg bg-cyan-600 text-white text-sm font-medium hover:bg-cyan-500 transition-colors flex items-center gap-2 disabled:opacity-50"
            >
              {sending ? <Loader2 className="w-4 h-4 animate-spin" /> : <UserPlus className="w-4 h-4" />}
              Invite
            </button>
          </form>
        </div>

        {/* Pending Invites */}
        {invites.filter((i) => !i.acceptedAt).length > 0 && (
          <div className="mb-8">
            <h2 className="text-sm font-semibold text-white mb-3">Pending Invites</h2>
            <div className="space-y-2">
              {invites
                .filter((i) => !i.acceptedAt)
                .map((inv) => (
                  <div key={inv.id} className="flex items-center justify-between p-3 rounded-xl border border-white/5 bg-white/[0.02]">
                    <div>
                      <p className="text-sm text-white">{inv.email}</p>
                      <p className="text-xs text-slate-500">{inv.role} · Expires {new Date(inv.expiresAt).toLocaleDateString()}</p>
                    </div>
                    <button
                      onClick={() => handleRevoke(inv.id)}
                      className="p-1.5 rounded-lg hover:bg-red-500/10 text-slate-500 hover:text-red-400 transition-colors"
                      title="Revoke invite"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                ))}
            </div>
          </div>
        )}

        {/* Current Members */}
        <div>
          <h2 className="text-sm font-semibold text-white mb-3">Current Members ({members.length})</h2>
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-5 h-5 text-cyan-400 animate-spin" />
            </div>
          ) : members.length === 0 ? (
            <div className="rounded-xl border border-white/5 bg-white/[0.02] p-10 text-center text-slate-500">
              <Users className="w-8 h-8 mx-auto mb-3 opacity-40" />
              <p>No members yet.</p>
            </div>
          ) : (
            <div className="rounded-xl border border-white/5 overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="bg-white/[0.03]">
                    <th className="text-left px-4 py-3 text-xs text-slate-400 font-medium uppercase tracking-wider">Member</th>
                    <th className="text-left px-4 py-3 text-xs text-slate-400 font-medium uppercase tracking-wider">Role</th>
                    <th className="text-left px-4 py-3 text-xs text-slate-400 font-medium uppercase tracking-wider">Joined</th>
                  </tr>
                </thead>
                <tbody>
                  {members.map((m, i) => (
                    <tr key={i} className="border-t border-white/5">
                      <td className="px-4 py-3">
                        <p className="font-medium text-white">{m.displayName || m.email}</p>
                        <p className="text-xs text-slate-500">{m.email}</p>
                      </td>
                      <td className="px-4 py-3">
                        <span className="px-2 py-0.5 rounded text-xs bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
                          {m.role}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-500">
                        {new Date(m.createdAt).toLocaleDateString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
