import { AlertTriangle, ArrowRight, ShieldAlert, XCircle } from 'lucide-react';
import { Link } from 'react-router-dom';
import type { WorkspaceNavigationResolution } from '@/lib/workspace-access';

type NoticeProps = {
  notice: WorkspaceNavigationResolution | null;
  onClose: () => void;
};

function resolveIcon(kind: WorkspaceNavigationResolution['kind']) {
  if (kind === 'blocked') {
    return ShieldAlert;
  }

  return XCircle;
}

export default function WorkspaceAccessNotice({ notice, onClose }: NoticeProps) {
  if (!notice || (notice.kind !== 'blocked' && notice.kind !== 'error')) {
    return null;
  }

  const Icon = resolveIcon(notice.kind);
  const title = notice.kind === 'blocked' ? notice.title : 'Action Failed';
  const message = notice.message;
  const actionPath = notice.kind === 'blocked' ? notice.actionPath : undefined;
  const actionLabel = notice.kind === 'blocked' ? notice.actionLabel : undefined;

  return (
    <div className="fixed inset-0 z-[80] flex items-center justify-center bg-[#03050b]/85 px-4" role="dialog" aria-modal="true" aria-labelledby="workspace-access-notice-title">
      <div className="w-full max-w-lg rounded-2xl border border-amber-300/30 bg-[#0a0f1e] shadow-[0_24px_90px_rgba(0,0,0,0.55)]">
        <div className="flex items-start gap-3 border-b border-white/10 px-6 py-4">
          <div className="mt-0.5 rounded-lg border border-amber-300/35 bg-amber-400/10 p-2">
            <Icon className="h-5 w-5 text-amber-200" />
          </div>
          <div>
            <p id="workspace-access-notice-title" className="text-base font-semibold text-white">{title}</p>
            <p className="text-xs text-slate-400">Code: {notice.code || 'unknown'}</p>
          </div>
        </div>

        <div className="space-y-4 px-6 py-5">
          <p className="text-sm text-slate-200">{message}</p>
          <p className="rounded-lg border border-cyan-300/20 bg-cyan-400/10 px-3 py-2 text-xs text-cyan-100">
            Backend enforcement is active. Access checks are validated server-side before navigation.
          </p>

          <div className="flex flex-wrap items-center gap-3">
            {actionPath && actionLabel && (
              <Link
                to={actionPath}
                onClick={onClose}
                className="inline-flex items-center gap-2 rounded-lg border border-cyan-300/30 bg-cyan-400/12 px-3 py-2 text-sm text-cyan-100 hover:bg-cyan-400/18"
              >
                {actionLabel}
                <ArrowRight className="h-4 w-4" />
              </Link>
            )}
            <button
              type="button"
              onClick={onClose}
              className="inline-flex items-center gap-2 rounded-lg border border-white/20 bg-white/[0.05] px-3 py-2 text-sm text-slate-100 hover:bg-white/[0.1]"
            >
              Close
            </button>
          </div>
        </div>
      </div>

      <button
        type="button"
        className="absolute right-5 top-5 inline-flex items-center gap-1 rounded-full border border-white/20 bg-[#0a1020]/80 px-3 py-1.5 text-xs text-slate-200 hover:bg-[#101a32]"
        onClick={onClose}
      >
        <AlertTriangle className="h-3.5 w-3.5" />
        Dismiss
      </button>
    </div>
  );
}
