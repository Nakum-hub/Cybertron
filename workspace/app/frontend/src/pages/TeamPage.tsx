import { useEffect, useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import {
  AlertCircle,
  ArrowLeft,
  CheckCircle2,
  Loader2,
  Mail,
  Trash2,
  UserPlus,
  Users,
} from 'lucide-react';
import { useAuthStatus } from '@/hooks/use-auth-status';
import {
  createWorkspaceInvite,
  fetchUsers,
  listWorkspaceInvites,
  revokeWorkspaceInvite,
  type InviteRecord,
  type UserRecord,
} from '@/lib/backend';

const AVAILABLE_ROLES = [
  'executive_viewer',
  'security_analyst',
  'analyst',
  'tenant_admin',
  'super_admin',
];

export default function TeamPage() {
  const { status, profile } = useAuthStatus();
  const [members, setMembers] = useState<UserRecord[]>([]);
  const [invites, setInvites] = useState<InviteRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState('executive_viewer');
  const [sending, setSending] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const resolvedTenant = String(profile?.tenant || 'global').trim() || 'global';

  async function load() {
    setLoading(true);
    setError('');

    try {
      const [users, inviteList] = await Promise.all([
        fetchUsers(resolvedTenant, 100),
        listWorkspaceInvites(resolvedTenant),
      ]);
      setMembers(users || []);
      setInvites(inviteList || []);
    } catch (loadError) {
      setMembers([]);
      setInvites([]);
      setError(loadError instanceof Error ? loadError.message : 'Unable to load team data.');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (status === 'loading') {
      return;
    }
    void load();
  }, [resolvedTenant, status]);

  async function handleInvite(event: FormEvent) {
    event.preventDefault();
    setError('');
    setSuccess('');

    if (!inviteEmail.includes('@')) {
      setError('Enter a valid email address.');
      return;
    }

    setSending(true);

    try {
      await createWorkspaceInvite(resolvedTenant, { email: inviteEmail, role: inviteRole });
      setSuccess(`Invitation sent to ${inviteEmail}`);
      setInviteEmail('');
      await load();
    } catch (inviteError) {
      setError(inviteError instanceof Error ? inviteError.message : 'Failed to send invitation.');
    } finally {
      setSending(false);
    }
  }

  async function handleRevoke(inviteId: string) {
    setError('');

    try {
      await revokeWorkspaceInvite(resolvedTenant, inviteId);
      await load();
    } catch (revokeError) {
      setError(revokeError instanceof Error ? revokeError.message : 'Failed to revoke invitation.');
    }
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
          <div className="p-2.5 rounded-xl bg-gradient-to-br from-violet-500/10 to-cyan-500/10 border border-white/10">
            <Users className="w-6 h-6 text-violet-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Team Management</h1>
            <p className="text-sm text-slate-500">Invite members and manage roles for {resolvedTenant}</p>
          </div>
        </div>

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
              <label htmlFor="invite-email" className="block text-xs text-slate-400 mb-1">
                Email
              </label>
              <input
                id="invite-email"
                type="email"
                value={inviteEmail}
                onChange={event => setInviteEmail(event.target.value)}
                required
                className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-lg text-white text-sm placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-cyan-500/40 transition"
                placeholder="colleague@company.com"
              />
            </div>
            <div className="w-44">
              <label htmlFor="invite-role" className="block text-xs text-slate-400 mb-1">
                Role
              </label>
              <select
                id="invite-role"
                value={inviteRole}
                onChange={event => setInviteRole(event.target.value)}
                className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-lg text-white text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500/40 transition"
              >
                {AVAILABLE_ROLES.map(role => (
                  <option key={role} value={role}>
                    {role.replace(/_/g, ' ')}
                  </option>
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

        {invites.filter(invite => !invite.acceptedAt).length > 0 && (
          <div className="mb-8">
            <h2 className="text-sm font-semibold text-white mb-3">Pending Invites</h2>
            <div className="space-y-2">
              {invites
                .filter(invite => !invite.acceptedAt)
                .map(invite => (
                  <div
                    key={invite.id}
                    className="flex items-center justify-between p-3 rounded-xl border border-white/5 bg-white/[0.02]"
                  >
                    <div>
                      <p className="text-sm text-white">{invite.email}</p>
                      <p className="text-xs text-slate-500">
                        {invite.role} | Expires {new Date(invite.expiresAt).toLocaleDateString()}
                      </p>
                    </div>
                    <button
                      onClick={() => void handleRevoke(invite.id)}
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
                  {members.map(member => (
                    <tr key={`${member.email}-${member.createdAt}`} className="border-t border-white/5">
                      <td className="px-4 py-3">
                        <p className="font-medium text-white">{member.displayName || member.email}</p>
                        <p className="text-xs text-slate-500">{member.email}</p>
                      </td>
                      <td className="px-4 py-3">
                        <span className="px-2 py-0.5 rounded text-xs bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
                          {member.role}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-500">
                        {new Date(member.createdAt).toLocaleDateString()}
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
