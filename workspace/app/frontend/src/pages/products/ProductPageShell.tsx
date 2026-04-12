import type { ComponentType } from 'react';
import { Link } from 'react-router-dom';
import { ArrowRight, Lock } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useAuthStatus } from '@/hooks/use-auth-status';
import { normalizeRole, type PlatformRole } from '@/lib/platform-registry';

export default function ProductPageShell({
  eyebrow,
  title,
  description,
  workspacePath,
  fallbackRole,
  Console,
}: {
  eyebrow: string;
  title: string;
  description: string;
  workspacePath: string;
  fallbackRole: PlatformRole;
  Console: ComponentType<{ tenant: string; role: string }>;
}) {
  const { status, profile, loginUrl } = useAuthStatus();
  const tenant = profile?.tenant || 'global';
  const role = normalizeRole(profile?.role || fallbackRole);

  return (
    <div className="min-h-screen bg-[#07080D] px-4 py-10 text-white sm:px-6">
      <div className="mx-auto max-w-6xl space-y-6">
        <header className="rounded-2xl border border-white/10 bg-white/[0.03] p-6">
          <p className="text-xs uppercase tracking-[0.2em] text-cyan-300">{eyebrow}</p>
          <div className="mt-3 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
            <div className="max-w-3xl">
              <h1 className="text-3xl font-bold">{title}</h1>
              <p className="mt-3 text-sm leading-relaxed text-slate-300">{description}</p>
            </div>
            <div className="flex flex-wrap gap-3">
              {status === 'authenticated' ? (
                <Link
                  to={`${workspacePath}?tenant=${encodeURIComponent(tenant)}&role=${encodeURIComponent(role)}`}
                  className="inline-flex items-center gap-2 rounded-lg border border-cyan-300/20 bg-cyan-400/10 px-4 py-2 text-sm text-cyan-100 hover:bg-cyan-400/15"
                >
                  Open Workspace
                  <ArrowRight className="h-4 w-4" />
                </Link>
              ) : (
                <Button onClick={() => window.location.assign(loginUrl)}>
                  <Lock className="h-4 w-4" />
                  Continue To Secure Login
                </Button>
              )}
            </div>
          </div>
        </header>

        {status !== 'authenticated' ? (
          <section className="rounded-2xl border border-white/10 bg-white/[0.03] p-6">
            <p className="text-sm text-slate-300">
              Sign in to access the live console. Until then, this page avoids fabricating tenant data.
            </p>
          </section>
        ) : (
          <section className="rounded-2xl border border-white/10 bg-white/[0.03] p-6">
            <Console tenant={tenant} role={role} />
          </section>
        )}
      </div>
    </div>
  );
}
