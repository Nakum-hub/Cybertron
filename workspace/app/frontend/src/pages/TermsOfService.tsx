import { Link } from 'react-router-dom';

export default function TermsOfService() {
  return (
    <main className="min-h-screen bg-[#07080D] text-white px-4 sm:px-6 py-10">
      <div className="max-w-4xl mx-auto rounded-2xl border border-white/10 bg-white/[0.03] p-6 sm:p-8">
        <p className="text-xs uppercase tracking-[0.2em] text-cyan-300 mb-3">Legal</p>
        <h1 className="text-3xl sm:text-4xl font-bold mb-4">Terms of Service</h1>
        <p className="text-sm text-slate-400 mb-8">Effective date: February 22, 2026</p>

        <div className="space-y-5 text-sm text-slate-200 leading-relaxed">
          <section>
            <h2 className="text-lg font-semibold mb-2">1. Use of Service</h2>
            <p>
              You may use Cybertron only for lawful security operations and authorized analysis.
              You are responsible for activities performed by users within your tenant.
            </p>
          </section>
          <section>
            <h2 className="text-lg font-semibold mb-2">2. Account Security</h2>
            <p>
              You must protect credentials, enforce least privilege, and promptly report suspected
              account compromise. Cybertron supports role-based access and audit monitoring.
            </p>
          </section>
          <section>
            <h2 className="text-lg font-semibold mb-2">3. Acceptable Conduct</h2>
            <p>
              You must not use the platform to attack systems without authorization, bypass tenant
              controls, or attempt to disrupt service availability.
            </p>
          </section>
          <section>
            <h2 className="text-lg font-semibold mb-2">4. Availability</h2>
            <p>
              Service levels depend on deployment architecture, infrastructure provider
              capabilities, and configuration quality. Production guidance is documented in the
              Cybertron runbooks.
            </p>
          </section>
          <section>
            <h2 className="text-lg font-semibold mb-2">5. Liability and Contact</h2>
            <p>
              Terms inquiries should be sent to{' '}
              <a className="text-cyan-300 hover:text-cyan-200" href="mailto:legal@cybertron.io">
                legal@cybertron.io
              </a>
              .
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

