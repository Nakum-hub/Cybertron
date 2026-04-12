import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { useAuthStatus } from '@/hooks/use-auth-status';
import { canAccessInternalOperations } from '@/lib/internal-access';

type InternalRouteGateProps = {
  children: ReactNode;
  title?: string;
};

export default function InternalRouteGate({
  children,
  title = 'Internal Operations Access',
}: InternalRouteGateProps) {
  const { status, profile, loginUrl } = useAuthStatus();

  if (status === 'loading') {
    return (
      <div className="min-h-screen bg-[#07080D] px-4 py-16 text-white sm:px-6">
        <div className="mx-auto max-w-3xl rounded-2xl border border-white/10 bg-white/[0.03] p-8">
          <h1 className="mb-3 text-3xl font-bold">{title}</h1>
          <p className="text-slate-300">Checking internal operations access...</p>
        </div>
      </div>
    );
  }

  if (status === 'authenticated' && canAccessInternalOperations(profile?.role)) {
    return <>{children}</>;
  }

  const isAnonymous = status === 'anonymous';

  return (
    <div className="min-h-screen bg-[#07080D] px-4 py-16 text-white sm:px-6">
      <div className="mx-auto max-w-3xl space-y-5 rounded-2xl border border-white/10 bg-white/[0.03] p-8">
        <div>
          <p className="mb-2 text-xs uppercase tracking-[0.2em] text-cyan-300">Restricted Surface</p>
          <h1 className="mb-3 text-3xl font-bold">{title}</h1>
          <p className="text-slate-300">
            This route is reserved for internal tenant-admin operations. Customer and lower-privilege roles are intentionally blocked.
          </p>
        </div>

        {isAnonymous ? (
          <div className="flex flex-wrap gap-3">
            <a
              href={loginUrl}
              className="inline-flex rounded-lg bg-cyan-600 px-5 py-2.5 font-medium hover:bg-cyan-500"
            >
              Continue To Secure Login
            </a>
            <Link
              to="/status"
              className="inline-flex rounded-lg border border-white/20 bg-white/[0.04] px-5 py-2.5 text-sm hover:bg-white/[0.08]"
            >
              Open Runtime Status
            </Link>
          </div>
        ) : (
          <div className="flex flex-wrap gap-3">
            <Link
              to="/status"
              className="inline-flex rounded-lg border border-amber-300/30 bg-amber-400/10 px-5 py-2.5 text-sm hover:bg-amber-400/15"
            >
              Open Runtime Status
            </Link>
            <Link
              to="/"
              className="inline-flex rounded-lg border border-white/20 bg-white/[0.04] px-5 py-2.5 text-sm hover:bg-white/[0.08]"
            >
              Back To Corporate Site
            </Link>
          </div>
        )}
      </div>
    </div>
  );
}
