import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { AlertCircle, Home, Info } from 'lucide-react';
import { Button } from '@/components/ui/button';

const REDIRECT_SECONDS = 12;

const PROVIDER_SETUP: Record<string, { label: string; vars: string[]; guide: string }> = {
  google: {
    label: 'Google',
    vars: ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET'],
    guide: 'https://console.cloud.google.com/apis/credentials',
  },
  microsoft: {
    label: 'Microsoft',
    vars: ['MICROSOFT_CLIENT_ID', 'MICROSOFT_CLIENT_SECRET'],
    guide: 'https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps',
  },
  github: {
    label: 'GitHub',
    vars: ['GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET'],
    guide: 'https://github.com/settings/developers',
  },
};

function resolveMessage(searchParams: URLSearchParams): string {
  const message = (searchParams.get('message') || '').trim();
  if (message) {
    return message;
  }

  const msg = (searchParams.get('msg') || '').trim();
  if (msg) {
    return msg;
  }

  const error = (searchParams.get('error') || '').trim();
  if (error === 'oauth_not_configured') {
    return 'OAuth provider is not configured. Set the required environment variables.';
  }
  if (error === 'oidc_not_configured') {
    return 'OIDC provider is not configured. Set OIDC_ISSUER_URL, OIDC_CLIENT_ID, and OIDC_CLIENT_SECRET.';
  }
  if (error === 'oauth_state_mismatch') {
    return 'OAuth state verification failed. This may be caused by an expired session or a CSRF attempt. Please try again.';
  }
  if (error === 'no_email_from_provider') {
    return 'The OAuth provider did not return an email address. Ensure your account has a verified email.';
  }
  if (error === 'oauth_token_exchange_failed') {
    return 'Failed to exchange authorization code for tokens. Please try signing in again.';
  }
  if (error === 'oauth_profile_failed') {
    return 'Failed to retrieve your profile from the OAuth provider. Please try again.';
  }
  if (error === 'oauth_token_exchange_timeout' || error === 'oauth_profile_timeout') {
    return 'The OAuth provider took too long to respond. Please try signing in again.';
  }
  if (error === 'registration_disabled') {
    return 'Public registration is disabled. An administrator must create your account before you can sign in.';
  }
  if (error === 'disposable_email') {
    return 'Disposable or temporary email addresses are not allowed. Please use a permanent email address.';
  }
  if (error === 'tenant_join_invite_required') {
    return 'This workspace already exists. Public self-service sign-in cannot join an existing customer tenant. Ask your administrator for an invite.';
  }
  if (error === 'self_service_workspace_limit_reached') {
    return 'This email already belongs to another Cybertron workspace. Sign in there or contact support to consolidate billing.';
  }
  if (error === 'external_identity_workspace_limit_reached') {
    return 'This social account is already linked to another Cybertron workspace. Sign in to the original workspace or contact support to consolidate billing.';
  }
  if (error === 'oauth_email_not_verified') {
    return 'The external identity provider did not confirm a verified email address. Use a verified provider email before signing in.';
  }
  if (error === 'workspace_slug_required') {
    return 'Workspace slug is required before continuing with this authentication flow.';
  }
  if (error === 'reserved_workspace_slug') {
    return 'This workspace slug is reserved for internal operations. Choose a different workspace slug.';
  }
  if (error === 'workspace_creation_device_limit_reached') {
    return 'This browser already created a free Cybertron workspace recently. Sign in to the existing workspace or wait before creating another workspace.';
  }
  if (error === 'workspace_creation_network_limit_reached') {
    return 'Too many free Cybertron workspaces were created from this network recently. Sign in to an existing workspace or contact support.';
  }
  if (error === 'account_deactivated') {
    return 'Your account has been deactivated. Contact your administrator.';
  }
  if (error) {
    return `Authentication error: ${error}`;
  }

  return 'Authentication failed or session callback was invalid.';
}

export default function AuthErrorPage() {
  const [searchParams] = useSearchParams();
  const [countdown, setCountdown] = useState(REDIRECT_SECONDS);
  const message = useMemo(() => resolveMessage(searchParams), [searchParams]);

  const errorCode = (searchParams.get('error') || '').trim();
  const provider = (searchParams.get('provider') || '').trim().toLowerCase();
  const tenant = (searchParams.get('tenant') || '').trim();
  const isNotConfigured = errorCode === 'oauth_not_configured' || errorCode === 'oidc_not_configured';
  const setup = provider ? PROVIDER_SETUP[provider] : undefined;

  useEffect(() => {
    const timer = window.setInterval(() => {
      setCountdown(prev => {
        if (prev <= 1) {
          window.clearInterval(timer);
          window.location.assign('/');
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => window.clearInterval(timer);
  }, []);

  return (
    <div className="min-h-screen bg-[#07080D] text-white px-4 py-10 sm:px-6 sm:py-16">
      <div className="max-w-xl mx-auto rounded-2xl border border-white/10 bg-white/[0.03] p-6 sm:p-8">
        <div className="flex items-start gap-4">
          <div className="rounded-xl border border-red-300/25 bg-red-400/10 p-3">
            <AlertCircle className="w-6 h-6 text-red-300" />
          </div>
          <div>
            <p className="text-xs uppercase tracking-[0.16em] text-red-200 mb-2">Authentication Error</p>
            <h1 className="text-2xl font-bold mb-2">Unable to complete sign in</h1>
            <p className="text-sm text-slate-300">{message}</p>
          </div>
        </div>

        {isNotConfigured && setup && (
          <div className="mt-6 rounded-xl border border-amber-500/20 bg-amber-500/5 p-4">
            <div className="flex items-start gap-3">
              <Info className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-semibold text-amber-200 mb-2">
                  {setup.label} OAuth Setup Required
                </p>
                <p className="text-xs text-slate-300 mb-3">
                  To enable {setup.label} sign-in, register an OAuth app and set these environment variables:
                </p>
                <div className="space-y-1 mb-3">
                  {setup.vars.map(v => (
                    <code key={v} className="block text-xs font-mono text-cyan-300 bg-white/[0.04] px-2 py-1 rounded">
                      {v}
                    </code>
                  ))}
                </div>
                <p className="text-xs text-slate-400 mb-1">
                  Callback URL to register:
                </p>
                <code className="block text-xs font-mono text-cyan-300 bg-white/[0.04] px-2 py-1 rounded break-all">
                  {window.location.origin}/api/v1/auth/oauth/{provider}/callback
                </code>
                <a
                  href={setup.guide}
                  target="_blank"
                  rel="noreferrer"
                  className="mt-3 inline-flex text-xs text-cyan-400 hover:text-cyan-300 underline"
                >
                  Open {setup.label} developer console
                </a>
              </div>
            </div>
          </div>
        )}

        <div className="mt-6 rounded-xl border border-white/10 bg-white/[0.02] p-4">
          <p className="text-sm text-slate-300">
            Redirecting to home in <span className="font-semibold text-cyan-300">{countdown}</span> second
            {countdown === 1 ? '' : 's'}.
          </p>
        </div>

        <div className="mt-6 flex items-center gap-3">
          <Button
            type="button"
            className="magnetic-btn inline-flex items-center gap-2 bg-cyan-600 hover:bg-cyan-500 text-white"
            onClick={() => window.location.assign('/')}
          >
            <Home className="w-4 h-4" />
            Return Home
          </Button>
          {provider && !isNotConfigured && ['google', 'microsoft', 'github', 'oidc'].includes(provider) && (
            <Button
              type="button"
              variant="outline"
              className="inline-flex items-center gap-2 border-white/20 text-slate-300 hover:text-white hover:border-white/40"
              onClick={() => {
                if (!tenant) {
                  window.location.assign('/');
                  return;
                }
                window.location.assign(
                  `/api/v1/auth/oauth/${provider}?tenant=${encodeURIComponent(tenant)}`
                );
              }}
            >
              Try Again
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}
