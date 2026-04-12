import { Link } from 'react-router-dom';

export default function CookiePolicy() {
  return (
    <main className="min-h-screen bg-[#07080D] text-white px-4 sm:px-6 py-10">
      <div className="max-w-4xl mx-auto rounded-2xl border border-white/10 bg-white/[0.03] p-6 sm:p-8">
        <p className="text-xs uppercase tracking-[0.2em] text-cyan-300 mb-3">Legal</p>
        <h1 className="text-3xl sm:text-4xl font-bold mb-4">Cookie Policy</h1>
        <p className="text-sm text-slate-400 mb-8">Effective date: February 22, 2026</p>

        <div className="space-y-5 text-sm text-slate-200 leading-relaxed">
          <section>
            <h2 className="text-lg font-semibold mb-2">1. Essential Storage</h2>
            <p>
              Cybertron uses secure cookies for authenticated sessions. Access and refresh cookies
              are configured server-side and used for protected API access.
            </p>
          </section>
          <section>
            <h2 className="text-lg font-semibold mb-2">2. Functional Preferences</h2>
            <p>
              The client stores only minimal local browser state for logout continuity in supported
              environments. Role and tenant authorization are enforced server-side.
            </p>
          </section>
          <section>
            <h2 className="text-lg font-semibold mb-2">3. Analytics</h2>
            <p>
              Analytics behavior is controlled by runtime configuration. Disable analytics in
              sensitive environments using public environment settings.
            </p>
          </section>
          <section>
            <h2 className="text-lg font-semibold mb-2">4. Control</h2>
            <p>
              You can clear browser storage and cookies at any time. This logs you out and removes
              local session continuity markers.
            </p>
          </section>
        </div>

        <div className="mt-8 pt-6 border-t border-white/10">
          <Link to="/" className="text-sm text-cyan-300 hover:text-cyan-200">
            Back to Cybertron
          </Link>
        </div>
      </div>
    </main>
  );
}
