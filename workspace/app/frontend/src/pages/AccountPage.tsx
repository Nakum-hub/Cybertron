import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Activity, ArrowRight, BadgeCheck, Building2, CreditCard, Github, LayoutDashboard, LogOut, Settings, Shield, ShieldCheck, UserRound, Users } from 'lucide-react';
import { Link, useSearchParams } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { useAuthStatus } from '@/hooks/use-auth-status';
import { usePlatformApps } from '@/hooks/use-platform-apps';
import { ApiError } from '@/lib/api';
import { setAuthTokens } from '@/lib/auth';
import {
  fetchBillingCredits,
  fetchTenantProducts,
  fetchUsers,
  loginWithPassword,
  registerAccount,
  requestPasswordReset,
} from '@/lib/backend';
import { hasRoleAccess, normalizeRole, roleLabels } from '@/lib/platform-registry';
import { buildWorkspaceTarget } from '@/lib/workspace-access';

type AccountMode = 'login' | 'register' | 'forgot';

function resolveMode(value: string | null): AccountMode {
  if (value === 'register' || value === 'forgot') {
    return value;
  }
  return 'login';
}

function sanitizeReturnTo(value: string | null): string {
  const input = String(value || '').trim();
  if (!input || !input.startsWith('/') || input.startsWith('//')) {
    return '/account';
  }
  return input;
}

function describeAuthError(error: unknown): string {
  if (!(error instanceof ApiError)) {
    return 'Unable to complete the request right now. Please try again.';
  }

  switch (error.code) {
    case 'invalid_credentials':
      return 'The email, password, or workspace slug is incorrect.';
    case 'workspace_slug_required':
      return 'Add a workspace slug before continuing.';
    case 'reserved_workspace_slug':
      return 'That workspace slug is reserved. Choose a different one.';
    case 'email_already_registered':
      return 'That email is already registered. Sign in instead.';
    case 'duplicate_email':
      return 'That email already exists in another Cybertron workspace.';
    case 'tenant_scope_denied':
      return 'This account does not have access to the workspace you entered.';
    case 'rate_limit_exceeded':
      return 'Too many attempts were detected. Please wait and try again.';
    default:
      return error.message || 'Unable to complete the request right now. Please try again.';
  }
}

function formatDate(value: string | null | undefined): string {
  if (!value) {
    return 'Not available';
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return 'Not available';
  }

  return parsed.toLocaleString();
}

export default function AccountPage() {
  const [searchParams] = useSearchParams();
  const { status, profile, logout } = useAuthStatus();
  const [mode, setMode] = useState<AccountMode>(() => resolveMode(searchParams.get('mode')));
  const [tenant, setTenant] = useState(() => (searchParams.get('tenant') || '').trim().toLowerCase());
  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const [successMessage, setSuccessMessage] = useState('');

  const returnTo = sanitizeReturnTo(searchParams.get('returnTo'));
  const planFromUrl = searchParams.get('plan') || '';
  const isAuthenticated = status === 'authenticated' && Boolean(profile);
  const resolvedRole = normalizeRole(profile?.role || 'executive_viewer');
  const resolvedTenant = String(profile?.tenant || 'global').trim() || 'global';
  const accountDisplayName = profile?.displayName || profile?.name || profile?.email || 'Cybertron User';
  const workspaceHome = buildWorkspaceTarget('/platform', resolvedTenant, resolvedRole);
  const showTeamInsights = isAuthenticated && hasRoleAccess(resolvedRole, 'tenant_admin');

  const appsQuery = usePlatformApps(resolvedRole, resolvedTenant, isAuthenticated);
  const billingQuery = useQuery({
    queryKey: ['account-billing', resolvedTenant],
    queryFn: () => fetchBillingCredits(resolvedTenant),
    enabled: isAuthenticated,
    staleTime: 30_000,
  });
  const productsQuery = useQuery({
    queryKey: ['account-products', resolvedTenant, resolvedRole],
    queryFn: () => fetchTenantProducts(resolvedTenant, resolvedRole),
    enabled: isAuthenticated,
    staleTime: 30_000,
  });
  const usersQuery = useQuery({
    queryKey: ['account-users', resolvedTenant],
    queryFn: () => fetchUsers(resolvedTenant, 100),
    enabled: showTeamInsights,
    staleTime: 30_000,
  });

  const accessibleApps = useMemo(
    () => (Array.isArray(appsQuery.data) ? appsQuery.data.filter(app => app.path.startsWith('/platform/')) : []),
    [appsQuery.data]
  );
  const enabledProducts = useMemo(
    () => (productsQuery.data || []).filter(product => product.visible !== false && product.effectiveEnabled !== false),
    [productsQuery.data]
  );

  const resetFeedback = () => {
    setErrorMessage('');
    setSuccessMessage('');
  };

  const redirectAfterAuth = (target: string) => {
    const safeTarget = sanitizeReturnTo(target);
    window.location.assign(safeTarget);
  };

  const handleLogin = async () => {
    resetFeedback();
    setIsSubmitting(true);

    try {
      const result = await loginWithPassword({
        tenant: tenant || undefined,
        email: email.trim(),
        password,
      });
      setAuthTokens(result.tokens.accessToken, result.tokens.refreshToken);
      redirectAfterAuth(returnTo);
    } catch (error) {
      setErrorMessage(describeAuthError(error));
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRegister = async () => {
    resetFeedback();
    setIsSubmitting(true);

    try {
      const createdUser = await registerAccount({
        tenant: tenant || undefined,
        email: email.trim(),
        password,
        displayName: displayName.trim() || undefined,
      });
      const result = await loginWithPassword({
        tenant: createdUser.tenant || tenant || undefined,
        email: email.trim(),
        password,
      });
      setAuthTokens(result.tokens.accessToken, result.tokens.refreshToken);
      redirectAfterAuth(returnTo);
    } catch (error) {
      setErrorMessage(describeAuthError(error));
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleForgotPassword = async () => {
    resetFeedback();
    setIsSubmitting(true);

    try {
      const result = await requestPasswordReset({
        tenant: tenant || undefined,
        email: email.trim(),
      });
      setSuccessMessage(result.message || 'Password reset instructions were generated.');
    } catch (error) {
      setErrorMessage(describeAuthError(error));
    } finally {
      setIsSubmitting(false);
    }
  };

  if (status === 'loading') {
    return (
      <div className="min-h-screen bg-[#04070f] text-white">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_left,rgba(34,211,238,0.12),transparent_26%),linear-gradient(180deg,#04070f_0%,#07111d_48%,#04070f_100%)]" />
        <div className="relative z-10 flex min-h-screen items-center justify-center px-6">
          <div className="rounded-3xl border border-white/10 bg-white/[0.04] px-8 py-10 text-center shadow-[0_24px_90px_rgba(2,12,25,0.45)]">
            <div className="mx-auto h-10 w-10 animate-spin rounded-full border-2 border-cyan-500/30 border-t-cyan-300" />
            <p className="mt-4 text-sm font-medium text-slate-300">Checking your Cybertron session...</p>
          </div>
        </div>
      </div>
    );
  }

  if (isAuthenticated) {
    return (
      <div className="min-h-screen bg-[#04070f] text-white">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_left,rgba(34,211,238,0.14),transparent_28%),radial-gradient(circle_at_top_right,rgba(56,189,248,0.12),transparent_24%),linear-gradient(180deg,#04070f_0%,#07111d_46%,#04070f_100%)]" />
        <div className="relative z-10">
          <header className="border-b border-white/10 bg-[#04070f]/80 backdrop-blur-xl">
            <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
              <Link to="/" className="flex items-center gap-3">
                <img
                  src="/assets/cybertron-logo.jpeg"
                  alt="Cybertron"
                  className="h-10 w-10 rounded-xl border border-cyan-400/20 object-cover shadow-[0_0_24px_rgba(34,211,238,0.2)]"
                />
                <div>
                  <p className="text-xs uppercase tracking-[0.22em] text-cyan-200/70">Cybertron</p>
                  <h1 className="text-lg font-semibold text-white">Account Center</h1>
                </div>
              </Link>
              <div className="flex items-center gap-3">
                <Link
                  to={workspaceHome}
                  className="inline-flex items-center gap-2 rounded-full border border-cyan-400/20 bg-cyan-500/10 px-4 py-2 text-sm font-medium text-cyan-100 transition hover:border-cyan-300/40 hover:bg-cyan-500/15"
                >
                  <LayoutDashboard className="h-4 w-4" />
                  Open Workspace
                </Link>
                <Button variant="outline" size="sm" onClick={() => void logout()}>
                  <LogOut className="h-4 w-4" />
                  Logout
                </Button>
              </div>
            </div>
          </header>

          <main className="mx-auto max-w-6xl px-6 py-10">
            <section className="grid gap-6 lg:grid-cols-[1.15fr_0.85fr]">
              <div className="rounded-3xl border border-cyan-400/15 bg-[#081321]/85 p-8 shadow-[0_24px_90px_rgba(2,12,25,0.45)]">
                <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-cyan-400/20 bg-cyan-500/10 px-4 py-1.5 text-xs font-semibold uppercase tracking-[0.18em] text-cyan-100">
                  <BadgeCheck className="h-4 w-4" />
                  Profile Active
                </div>
                <h2 className="text-3xl font-semibold text-white">{accountDisplayName}</h2>
                <p className="mt-3 max-w-2xl text-base leading-7 text-slate-300">
                  This is the client-facing profile and workspace hub for Cybertron. It shows who the user is,
                  which tenant they belong to, what plan is active, and which platform modules they can open.
                </p>

                <div className="mt-8 grid gap-4 sm:grid-cols-3">
                  <div className="rounded-2xl border border-white/10 bg-white/[0.04] p-4">
                    <p className="text-xs uppercase tracking-[0.18em] text-slate-400">Role</p>
                    <p className="mt-2 text-lg font-semibold text-white">{roleLabels[resolvedRole]}</p>
                  </div>
                  <div className="rounded-2xl border border-white/10 bg-white/[0.04] p-4">
                    <p className="text-xs uppercase tracking-[0.18em] text-slate-400">Workspace</p>
                    <p className="mt-2 text-lg font-semibold text-white">{resolvedTenant}</p>
                  </div>
                  <div className="rounded-2xl border border-white/10 bg-white/[0.04] p-4">
                    <p className="text-xs uppercase tracking-[0.18em] text-slate-400">Session</p>
                    <p className="mt-2 text-lg font-semibold text-white">{formatDate(profile?.expiresAt)}</p>
                  </div>
                </div>

                {returnTo !== '/account' && (
                  <div className="mt-6 flex flex-wrap items-center gap-3 rounded-2xl border border-emerald-400/20 bg-emerald-500/10 p-4 text-sm text-emerald-100">
                    <ShieldCheck className="h-4 w-4 flex-none" />
                    A workspace requested sign-in. Continue when you are ready.
                    <Link
                      to={returnTo}
                      className="inline-flex items-center gap-2 rounded-full border border-emerald-300/30 px-3 py-1.5 font-medium transition hover:border-emerald-200/50 hover:bg-emerald-400/10"
                    >
                      Continue
                      <ArrowRight className="h-4 w-4" />
                    </Link>
                  </div>
                )}
              </div>

              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-1">
                <div className="rounded-3xl border border-white/10 bg-white/[0.04] p-6">
                  <div className="flex items-center gap-3">
                    <UserRound className="h-5 w-5 text-cyan-300" />
                    <h3 className="text-lg font-semibold text-white">Identity</h3>
                  </div>
                  <dl className="mt-5 space-y-4 text-sm text-slate-300">
                    <div>
                      <dt className="text-slate-500">Email</dt>
                      <dd className="mt-1 font-medium text-white">{profile?.email || 'Not available'}</dd>
                    </div>
                    <div>
                      <dt className="text-slate-500">User ID</dt>
                      <dd className="mt-1 font-medium text-white">{profile?.id}</dd>
                    </div>
                  </dl>
                </div>

                <div className="rounded-3xl border border-white/10 bg-white/[0.04] p-6">
                  <div className="flex items-center gap-3">
                    <CreditCard className="h-5 w-5 text-cyan-300" />
                    <h3 className="text-lg font-semibold text-white">Plan</h3>
                  </div>
                  <dl className="mt-5 space-y-4 text-sm text-slate-300">
                    <div>
                      <dt className="text-slate-500">Tier</dt>
                      <dd className="mt-1 font-medium text-white">
                        {billingQuery.data?.planLabel || billingQuery.data?.planTier || 'Loading'}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-slate-500">Credits</dt>
                      <dd className="mt-1 font-medium text-white">
                        {billingQuery.data
                          ? billingQuery.data.quotaEnforced
                            ? `${billingQuery.data.quotaRemainingUnits ?? 0} remaining`
                            : `${billingQuery.data.balanceUnits} balance`
                          : billingQuery.isError
                            ? 'Unavailable'
                            : 'Loading'}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-slate-500">Billing window</dt>
                      <dd className="mt-1 font-medium text-white">{formatDate(billingQuery.data?.periodEndsAt)}</dd>
                    </div>
                  </dl>
                </div>

                <div className="rounded-3xl border border-white/10 bg-white/[0.04] p-6">
                  <div className="flex items-center gap-3">
                    <Building2 className="h-5 w-5 text-cyan-300" />
                    <h3 className="text-lg font-semibold text-white">Workspace Access</h3>
                  </div>
                  <div className="mt-5 grid grid-cols-2 gap-4 text-sm">
                    <div className="rounded-2xl border border-white/10 bg-[#09111d] p-4">
                      <p className="text-slate-500">Apps</p>
                      <p className="mt-2 text-2xl font-semibold text-white">{accessibleApps.length}</p>
                    </div>
                    <div className="rounded-2xl border border-white/10 bg-[#09111d] p-4">
                      <p className="text-slate-500">Products</p>
                      <p className="mt-2 text-2xl font-semibold text-white">{enabledProducts.length}</p>
                    </div>
                  </div>
                </div>

                {showTeamInsights && (
                  <div className="rounded-3xl border border-white/10 bg-white/[0.04] p-6">
                    <div className="flex items-center gap-3">
                      <Users className="h-5 w-5 text-cyan-300" />
                      <h3 className="text-lg font-semibold text-white">Tenant Team</h3>
                    </div>
                    <p className="mt-5 text-3xl font-semibold text-white">
                      {usersQuery.data ? usersQuery.data.length : usersQuery.isError ? 'Unavailable' : '...'}
                    </p>
                    <p className="mt-2 text-sm text-slate-400">
                      Tenant admins can see the user directory count for the current workspace.
                    </p>
                  </div>
                )}
              </div>
            </section>

            <section className="mt-8 grid gap-6 lg:grid-cols-2">
              <div className="rounded-3xl border border-white/10 bg-[#07111d]/90 p-6">
                <div className="mb-5 flex items-center justify-between gap-3">
                  <div>
                    <p className="text-xs uppercase tracking-[0.18em] text-cyan-200/70">Workspace Modules</p>
                    <h3 className="mt-1 text-xl font-semibold text-white">Available Apps</h3>
                  </div>
                  <LayoutDashboard className="h-5 w-5 text-cyan-300" />
                </div>
                <div className="space-y-4">
                  {accessibleApps.map(app => (
                    <Link
                      key={app.id}
                      to={buildWorkspaceTarget(app.path, resolvedTenant, resolvedRole)}
                      className="block rounded-2xl border border-white/10 bg-white/[0.04] p-4 transition hover:border-cyan-300/30 hover:bg-white/[0.06]"
                    >
                      <div className="flex items-center justify-between gap-3">
                        <div>
                          <h4 className="text-base font-semibold text-white">{app.name}</h4>
                          <p className="mt-1 text-sm text-slate-400">{app.tagline}</p>
                        </div>
                        <ArrowRight className="h-4 w-4 text-cyan-300" />
                      </div>
                    </Link>
                  ))}
                  {!appsQuery.isLoading && accessibleApps.length === 0 && (
                    <div className="rounded-2xl border border-dashed border-white/15 bg-white/[0.02] p-4 text-sm text-slate-400">
                      No platform apps are currently visible for this account.
                    </div>
                  )}
                </div>
              </div>

              <div className="rounded-3xl border border-white/10 bg-[#07111d]/90 p-6">
                <div className="mb-5 flex items-center justify-between gap-3">
                  <div>
                    <p className="text-xs uppercase tracking-[0.18em] text-cyan-200/70">Tenant Coverage</p>
                    <h3 className="mt-1 text-xl font-semibold text-white">Enabled Products</h3>
                  </div>
                  <ShieldCheck className="h-5 w-5 text-cyan-300" />
                </div>
                <div className="space-y-4">
                  {enabledProducts.map(product => (
                    <div key={product.productKey} className="rounded-2xl border border-white/10 bg-white/[0.04] p-4">
                      <div className="flex items-center justify-between gap-3">
                        <div>
                          <h4 className="text-base font-semibold text-white">{product.name}</h4>
                          <p className="mt-1 text-sm text-slate-400">
                            {product.planLabel || product.planTier || 'Plan assigned'} · minimum role {product.roleMin}
                          </p>
                        </div>
                        <span className="rounded-full border border-emerald-400/20 bg-emerald-500/10 px-3 py-1 text-xs font-medium text-emerald-200">
                          Active
                        </span>
                      </div>
                    </div>
                  ))}
                  {!productsQuery.isLoading && enabledProducts.length === 0 && (
                    <div className="rounded-2xl border border-dashed border-white/15 bg-white/[0.02] p-4 text-sm text-slate-400">
                      No tenant products are enabled yet.
                    </div>
                  )}
                </div>
              </div>
            </section>

            {/* Quick Actions */}
            <section className="mt-8">
              <h3 className="text-lg font-semibold text-white mb-4">Quick Actions</h3>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <Link
                  to="/account/team"
                  className="flex items-center gap-3 rounded-2xl border border-white/10 bg-white/[0.04] p-4 transition hover:border-cyan-300/30 hover:bg-white/[0.06]"
                >
                  <Users className="h-5 w-5 text-cyan-300 flex-none" />
                  <div>
                    <p className="text-sm font-medium text-white">Team Management</p>
                    <p className="text-xs text-slate-500">Invite &amp; manage members</p>
                  </div>
                </Link>
                <Link
                  to="/account/api-keys"
                  className="flex items-center gap-3 rounded-2xl border border-white/10 bg-white/[0.04] p-4 transition hover:border-cyan-300/30 hover:bg-white/[0.06]"
                >
                  <Shield className="h-5 w-5 text-cyan-300 flex-none" />
                  <div>
                    <p className="text-sm font-medium text-white">API Keys</p>
                    <p className="text-xs text-slate-500">Create &amp; revoke keys</p>
                  </div>
                </Link>
                <Link
                  to="/account/notifications"
                  className="flex items-center gap-3 rounded-2xl border border-white/10 bg-white/[0.04] p-4 transition hover:border-cyan-300/30 hover:bg-white/[0.06]"
                >
                  <Activity className="h-5 w-5 text-cyan-300 flex-none" />
                  <div>
                    <p className="text-sm font-medium text-white">Notifications</p>
                    <p className="text-xs text-slate-500">Alert preferences</p>
                  </div>
                </Link>
                {showTeamInsights && (
                  <Link
                    to="/admin"
                    className="flex items-center gap-3 rounded-2xl border border-white/10 bg-white/[0.04] p-4 transition hover:border-cyan-300/30 hover:bg-white/[0.06]"
                  >
                    <Settings className="h-5 w-5 text-cyan-300 flex-none" />
                    <div>
                      <p className="text-sm font-medium text-white">Admin Dashboard</p>
                      <p className="text-xs text-slate-500">Workspace settings</p>
                    </div>
                  </Link>
                )}
              </div>
            </section>
          </main>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#04070f] text-white">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_left,rgba(34,211,238,0.12),transparent_26%),radial-gradient(circle_at_bottom_right,rgba(14,165,233,0.12),transparent_24%),linear-gradient(180deg,#04070f_0%,#07111d_48%,#04070f_100%)]" />
      <div className="relative z-10">
        <header className="border-b border-white/10 bg-[#04070f]/80 backdrop-blur-xl">
          <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
            <Link to="/" className="flex items-center gap-3">
              <img
                src="/assets/cybertron-logo.jpeg"
                alt="Cybertron"
                className="h-10 w-10 rounded-xl border border-cyan-400/20 object-cover shadow-[0_0_24px_rgba(34,211,238,0.2)]"
              />
              <div>
                <p className="text-xs uppercase tracking-[0.22em] text-cyan-200/70">Cybertron</p>
                <h1 className="text-lg font-semibold text-white">Account Center</h1>
              </div>
            </Link>
            <Link
              to="/"
              className="rounded-full border border-white/10 px-4 py-2 text-sm font-medium text-slate-300 transition hover:border-white/20 hover:text-white"
            >
              Back to landing
            </Link>
          </div>
        </header>

        <main className="mx-auto grid max-w-6xl gap-8 px-6 py-10 lg:grid-cols-[0.95fr_1.05fr]">
          <section className="rounded-3xl border border-cyan-400/15 bg-[#081321]/85 p-8 shadow-[0_24px_90px_rgba(2,12,25,0.45)]">
            <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-cyan-400/20 bg-cyan-500/10 px-4 py-1.5 text-xs font-semibold uppercase tracking-[0.18em] text-cyan-100">
              <ShieldCheck className="h-4 w-4" />
              Secure Login
            </div>
            <h2 className="text-3xl font-semibold text-white">Account Center</h2>
            <p className="mt-3 text-base leading-7 text-slate-300">
              This page gives registered clients a proper place to sign in, create a workspace, and later review
              their profile, plan, and account access.
            </p>

            {returnTo !== '/account' && (
              <div className="mt-6 rounded-2xl border border-emerald-400/20 bg-emerald-500/10 p-4 text-sm text-emerald-100">
                Sign in first, then Cybertron will continue to your requested workspace automatically.
              </div>
            )}

            <div className="mt-8 grid gap-4 sm:grid-cols-3">
              <button
                type="button"
                onClick={() => {
                  resetFeedback();
                  setMode('login');
                }}
                className={`rounded-2xl border px-4 py-3 text-sm font-medium transition ${
                  mode === 'login'
                    ? 'border-cyan-300/40 bg-cyan-500/15 text-white'
                    : 'border-white/10 bg-white/[0.03] text-slate-300 hover:border-white/20 hover:text-white'
                }`}
              >
                Login
              </button>
              <button
                type="button"
                onClick={() => {
                  resetFeedback();
                  setMode('register');
                }}
                className={`rounded-2xl border px-4 py-3 text-sm font-medium transition ${
                  mode === 'register'
                    ? 'border-cyan-300/40 bg-cyan-500/15 text-white'
                    : 'border-white/10 bg-white/[0.03] text-slate-300 hover:border-white/20 hover:text-white'
                }`}
              >
                Create Account
              </button>
              <button
                type="button"
                onClick={() => {
                  resetFeedback();
                  setMode('forgot');
                }}
                className={`rounded-2xl border px-4 py-3 text-sm font-medium transition ${
                  mode === 'forgot'
                    ? 'border-cyan-300/40 bg-cyan-500/15 text-white'
                    : 'border-white/10 bg-white/[0.03] text-slate-300 hover:border-white/20 hover:text-white'
                }`}
              >
                Reset Access
              </button>
            </div>

            <div className="mt-8 space-y-4">
              {(mode === 'login' || mode === 'register' || mode === 'forgot') && (
                <label className="block">
                  <span className="mb-2 block text-sm font-medium text-slate-300">Workspace slug</span>
                  <input
                    value={tenant}
                    onChange={event => setTenant(event.target.value.trim().toLowerCase())}
                    placeholder="acme-security"
                    className="w-full rounded-2xl border border-white/10 bg-white/[0.04] px-4 py-3 text-white outline-none transition placeholder:text-slate-500 focus:border-cyan-300/40 focus:bg-white/[0.06]"
                  />
                </label>
              )}

              {mode === 'register' && (
                <label className="block">
                  <span className="mb-2 block text-sm font-medium text-slate-300">Display name</span>
                  <input
                    value={displayName}
                    onChange={event => setDisplayName(event.target.value)}
                    placeholder="Alex Morgan"
                    className="w-full rounded-2xl border border-white/10 bg-white/[0.04] px-4 py-3 text-white outline-none transition placeholder:text-slate-500 focus:border-cyan-300/40 focus:bg-white/[0.06]"
                  />
                </label>
              )}

              <label className="block">
                <span className="mb-2 block text-sm font-medium text-slate-300">Email</span>
                <input
                  value={email}
                  onChange={event => setEmail(event.target.value)}
                  type="email"
                  placeholder="name@company.com"
                  className="w-full rounded-2xl border border-white/10 bg-white/[0.04] px-4 py-3 text-white outline-none transition placeholder:text-slate-500 focus:border-cyan-300/40 focus:bg-white/[0.06]"
                />
              </label>

              {mode !== 'forgot' && (
                <label className="block">
                  <span className="mb-2 block text-sm font-medium text-slate-300">Password</span>
                  <input
                    value={password}
                    onChange={event => setPassword(event.target.value)}
                    type="password"
                    placeholder="Enter a strong password"
                    className="w-full rounded-2xl border border-white/10 bg-white/[0.04] px-4 py-3 text-white outline-none transition placeholder:text-slate-500 focus:border-cyan-300/40 focus:bg-white/[0.06]"
                  />
                </label>
              )}

              {errorMessage && (
                <div className="rounded-2xl border border-red-400/20 bg-red-500/10 px-4 py-3 text-sm text-red-100">
                  {errorMessage}
                </div>
              )}

              {successMessage && (
                <div className="rounded-2xl border border-emerald-400/20 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-100">
                  {successMessage}
                </div>
              )}

              {mode === 'login' && (
                <Button className="w-full" size="lg" onClick={() => void handleLogin()} disabled={isSubmitting}>
                  {isSubmitting ? 'Signing in...' : 'Secure Login'}
                </Button>
              )}
              {mode === 'register' && (
                <Button className="w-full" size="lg" onClick={() => void handleRegister()} disabled={isSubmitting}>
                  {isSubmitting ? 'Creating account...' : 'Create Workspace Account'}
                </Button>
              )}
              {mode === 'forgot' && (
                <Button className="w-full" size="lg" onClick={() => void handleForgotPassword()} disabled={isSubmitting}>
                  {isSubmitting ? 'Sending reset instructions...' : 'Send Reset Instructions'}
                </Button>
              )}

              {/* OAuth Divider */}
              {mode !== 'forgot' && (
                <>
                  <div className="relative my-2">
                    <div className="absolute inset-0 flex items-center">
                      <div className="w-full border-t border-white/10" />
                    </div>
                    <div className="relative flex justify-center">
                      <span className="bg-[#081321] px-4 text-xs text-slate-500">or continue with</span>
                    </div>
                  </div>

                  <div className="grid grid-cols-3 gap-3">
                    <button
                      type="button"
                      onClick={() => {
                        if (!tenant.trim()) {
                          setErrorMessage('Enter a workspace slug before using social sign-in.');
                          return;
                        }
                        window.location.assign(`/api/v1/auth/oauth/google?tenant=${encodeURIComponent(tenant)}`);
                      }}
                      className="flex items-center justify-center gap-2 rounded-2xl border border-white/10 bg-white/[0.04] px-4 py-3 text-sm font-medium text-slate-300 transition hover:border-white/20 hover:bg-white/[0.08] hover:text-white"
                    >
                      <svg className="h-4 w-4" viewBox="0 0 24 24">
                        <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" />
                        <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                        <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
                        <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
                      </svg>
                      Google
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        if (!tenant.trim()) {
                          setErrorMessage('Enter a workspace slug before using social sign-in.');
                          return;
                        }
                        window.location.assign(`/api/v1/auth/oauth/microsoft?tenant=${encodeURIComponent(tenant)}`);
                      }}
                      className="flex items-center justify-center gap-2 rounded-2xl border border-white/10 bg-white/[0.04] px-4 py-3 text-sm font-medium text-slate-300 transition hover:border-white/20 hover:bg-white/[0.08] hover:text-white"
                    >
                      <svg className="h-4 w-4" viewBox="0 0 23 23">
                        <path fill="#f35325" d="M1 1h10v10H1z" />
                        <path fill="#81bc06" d="M12 1h10v10H12z" />
                        <path fill="#05a6f0" d="M1 12h10v10H1z" />
                        <path fill="#ffba08" d="M12 12h10v10H12z" />
                      </svg>
                      Microsoft
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        if (!tenant.trim()) {
                          setErrorMessage('Enter a workspace slug before using social sign-in.');
                          return;
                        }
                        window.location.assign(`/api/v1/auth/oauth/github?tenant=${encodeURIComponent(tenant)}`);
                      }}
                      className="flex items-center justify-center gap-2 rounded-2xl border border-white/10 bg-white/[0.04] px-4 py-3 text-sm font-medium text-slate-300 transition hover:border-white/20 hover:bg-white/[0.08] hover:text-white"
                    >
                      <Github className="h-4 w-4" />
                      GitHub
                    </button>
                  </div>
                </>
              )}

              {planFromUrl && (
                <div className="rounded-2xl border border-cyan-400/20 bg-cyan-500/10 px-4 py-3 text-sm text-cyan-100">
                  Selected plan: <span className="font-semibold capitalize">{planFromUrl}</span>. Your workspace will be created on this tier.
                </div>
              )}
            </div>
          </section>

          <section className="grid gap-5 sm:grid-cols-2">
            <div className="rounded-3xl border border-white/10 bg-white/[0.04] p-6">
              <UserRound className="h-6 w-6 text-cyan-300" />
              <h3 className="mt-5 text-xl font-semibold text-white">Profile Hub</h3>
              <p className="mt-3 text-sm leading-6 text-slate-400">
                After sign-in, clients can see their identity details, active workspace, role, and session status in one place.
              </p>
            </div>
            <div className="rounded-3xl border border-white/10 bg-white/[0.04] p-6">
              <CreditCard className="h-6 w-6 text-cyan-300" />
              <h3 className="mt-5 text-xl font-semibold text-white">Plan Visibility</h3>
              <p className="mt-3 text-sm leading-6 text-slate-400">
                The account center exposes plan tier, credits, and enabled products so the client journey feels complete.
              </p>
            </div>
            <div className="rounded-3xl border border-white/10 bg-white/[0.04] p-6">
              <LayoutDashboard className="h-6 w-6 text-cyan-300" />
              <h3 className="mt-5 text-xl font-semibold text-white">Workspace Access</h3>
              <p className="mt-3 text-sm leading-6 text-slate-400">
                Users can jump directly into the modules they are allowed to open instead of guessing where to go next.
              </p>
            </div>
            <div className="rounded-3xl border border-white/10 bg-white/[0.04] p-6">
              <Building2 className="h-6 w-6 text-cyan-300" />
              <h3 className="mt-5 text-xl font-semibold text-white">Tenant-Aware</h3>
              <p className="mt-3 text-sm leading-6 text-slate-400">
                Workspace slug, access scope, and plan state stay tied to the real tenant session instead of mock data.
              </p>
            </div>
          </section>
        </main>
      </div>
    </div>
  );
}
