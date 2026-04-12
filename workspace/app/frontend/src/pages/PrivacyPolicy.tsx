import { Link } from 'react-router-dom';

export default function PrivacyPolicy() {
  return (
    <main className="min-h-screen bg-[#07080D] text-white px-4 sm:px-6 py-10">
      <div className="max-w-4xl mx-auto rounded-2xl border border-white/10 bg-white/[0.03] p-6 sm:p-8">
        <p className="text-xs uppercase tracking-[0.2em] text-cyan-300 mb-3">Legal</p>
        <h1 className="text-3xl sm:text-4xl font-bold mb-4">Privacy Policy</h1>
        <p className="text-sm text-slate-400 mb-8">Effective date: February 22, 2026</p>

        <div className="space-y-5 text-sm text-slate-200 leading-relaxed">
          <section>
            <h2 className="text-lg font-semibold mb-2">1. Data We Process</h2>
            <p>
              Cybertron processes account profile information, authentication metadata, security
              events, audit logs, incident records, and service workflow records needed to operate
              the platform.
            </p>
          </section>
          <section>
            <h2 className="text-lg font-semibold mb-2">2. Purpose</h2>
            <p>
              Data is used to provide security operations capabilities, maintain tenant isolation,
              enforce access control, investigate incidents, and satisfy compliance and audit
              requirements.
            </p>
          </section>
          <section>
            <h2 className="text-lg font-semibold mb-2">3. Retention</h2>
            <p>
              Operational logs and security records are retained according to deployment
              configuration and legal obligations. Data can be deleted by authorized administrators
              following tenant policy.
            </p>
          </section>
          <section>
            <h2 className="text-lg font-semibold mb-2">4. Security Controls</h2>
            <p>
              Cybertron applies authentication controls, role-based access, request validation,
              rate limits, audit trails, and transport security as configured in deployment
              runbooks.
            </p>
          </section>
          <section>
            <h2 className="text-lg font-semibold mb-2">5. Contact</h2>
            <p>
              For privacy requests, contact{' '}
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

