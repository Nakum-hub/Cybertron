import { ArrowLeft, SearchX } from 'lucide-react';
import { Link } from 'react-router-dom';

export default function NotFoundPage() {
  return (
    <div className="min-h-screen bg-[#07080D] text-white px-4 sm:px-6 py-16">
      <div className="max-w-3xl mx-auto rounded-2xl border border-white/10 bg-white/[0.03] p-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-cyan-300/25 bg-cyan-400/10 text-cyan-200 text-xs uppercase tracking-[0.16em]">
          <SearchX className="w-3.5 h-3.5" />
          Route Not Found
        </div>
        <h1 className="text-3xl font-bold mt-4 mb-3">404</h1>
        <p className="text-slate-300 mb-6">
          This route is not registered in the frontend router. Use the links below to continue.
        </p>
        <div className="flex flex-wrap gap-3">
          <Link
            to="/"
            className="inline-flex items-center gap-2 rounded-lg border border-cyan-300/30 bg-cyan-400/10 px-4 py-2 text-sm hover:bg-cyan-400/15"
          >
            <ArrowLeft className="w-4 h-4" />
            Back To Home
          </Link>
          <Link
            to="/status"
            className="inline-flex rounded-lg border border-white/20 bg-white/[0.04] px-4 py-2 text-sm hover:bg-white/[0.08]"
          >
            Open Runtime Status
          </Link>
        </div>
      </div>
    </div>
  );
}
