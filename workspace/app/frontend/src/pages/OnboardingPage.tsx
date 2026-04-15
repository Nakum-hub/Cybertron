/**
 * P1-7: Onboarding Wizard Page
 * Route: /onboarding
 * Step-by-step setup: workspace → connectors → team invites → complete.
 */
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Rocket,
  Building2,
  Link2,
  UserPlus,
  CheckCircle2,
  ArrowRight,
  ArrowLeft,
  Loader2,
} from 'lucide-react';

const STEPS = [
  {
    key: 'workspace',
    title: 'Create Workspace',
    description: 'Set up your organization workspace',
    icon: Building2,
  },
  {
    key: 'connectors',
    title: 'Connect Sources',
    description: 'Integrate your security tools',
    icon: Link2,
  },
  {
    key: 'team',
    title: 'Invite Team',
    description: 'Add your team members',
    icon: UserPlus,
  },
  {
    key: 'complete',
    title: 'All Set!',
    description: 'Your workspace is ready',
    icon: CheckCircle2,
  },
];

export default function OnboardingPage() {
  const navigate = useNavigate();
  const [step, setStep] = useState(0);
  const [workspaceName, setWorkspaceName] = useState('');
  const [inviteEmails, setInviteEmails] = useState('');
  const [loading, setLoading] = useState(false);

  function next() {
    if (step < STEPS.length - 1) {
      setStep(step + 1);
    }
  }

  function prev() {
    if (step > 0) {
      setStep(step - 1);
    }
  }

  async function handleFinish() {
    setLoading(true);
    try {
      // Simulate setup completion
      await new Promise((r) => setTimeout(r, 1000));
      navigate('/platform');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-[#04070f] flex items-center justify-center px-4">
      <div className="w-full max-w-2xl">
        {/* Header */}
        <div className="text-center mb-10">
          <div className="inline-flex p-3 rounded-2xl bg-gradient-to-br from-cyan-500/10 to-violet-500/10 border border-white/10 mb-4">
            <Rocket className="w-8 h-8 text-cyan-400" />
          </div>
          <h1 className="text-3xl font-bold text-white tracking-tight">Welcome to Cybertron</h1>
          <p className="text-slate-500 text-sm mt-2">Let's get your security workspace ready in 3 steps</p>
        </div>

        {/* Progress */}
        <div className="flex items-center justify-center gap-2 mb-10">
          {STEPS.map((s, i) => (
            <div key={s.key} className="flex items-center gap-2">
              <div
                className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold transition-all ${
                  i < step
                    ? 'bg-cyan-500 text-white'
                    : i === step
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                      : 'bg-white/5 text-slate-600 border border-white/10'
                }`}
              >
                {i < step ? '✓' : i + 1}
              </div>
              {i < STEPS.length - 1 && (
                <div
                  className={`w-12 h-0.5 rounded ${
                    i < step ? 'bg-cyan-500' : 'bg-white/10'
                  }`}
                />
              )}
            </div>
          ))}
        </div>

        {/* Step Content */}
        <div className="rounded-2xl border border-white/10 bg-white/[0.03] backdrop-blur-xl p-8">
          <div className="flex items-center gap-3 mb-6">
            {(() => {
              const StepIcon = STEPS[step].icon;
              return (
                <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20">
                  <StepIcon className="w-5 h-5 text-cyan-400" />
                </div>
              );
            })()}
            <div>
              <h2 className="text-lg font-semibold text-white">{STEPS[step].title}</h2>
              <p className="text-xs text-slate-500">{STEPS[step].description}</p>
            </div>
          </div>

          {step === 0 && (
            <div className="space-y-4">
              <div>
                <label htmlFor="workspace-name" className="block text-xs font-medium text-slate-400 mb-1.5">
                  Workspace Name
                </label>
                <input
                  id="workspace-name"
                  type="text"
                  value={workspaceName}
                  onChange={(e) => setWorkspaceName(e.target.value)}
                  className="w-full px-3 py-2.5 bg-white/5 border border-white/10 rounded-lg text-white text-sm placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-cyan-500/40 transition"
                  placeholder="e.g., acme-security"
                />
                <p className="text-xs text-slate-600 mt-1">This becomes your workspace URL slug</p>
              </div>
            </div>
          )}

          {step === 1 && (
            <div className="space-y-4">
              <p className="text-sm text-slate-400">
                Connect your existing security tools. You can do this later from Settings → Connectors.
              </p>
              <div className="grid grid-cols-2 gap-3">
                {['Wazuh', 'MISP', 'OpenCTI', 'TheHive'].map((name) => (
                  <button
                    key={name}
                    className="p-4 rounded-xl border border-white/5 bg-white/[0.02] text-left hover:border-cyan-500/30 hover:bg-cyan-500/5 transition-all group"
                  >
                    <p className="text-sm font-medium text-white group-hover:text-cyan-300 transition-colors">{name}</p>
                    <p className="text-xs text-slate-600 mt-0.5">Click to configure</p>
                  </button>
                ))}
              </div>
            </div>
          )}

          {step === 2 && (
            <div className="space-y-4">
              <div>
                <label htmlFor="invite-emails" className="block text-xs font-medium text-slate-400 mb-1.5">
                  Email Addresses (one per line)
                </label>
                <textarea
                  id="invite-emails"
                  value={inviteEmails}
                  onChange={(e) => setInviteEmails(e.target.value)}
                  rows={4}
                  className="w-full px-3 py-2.5 bg-white/5 border border-white/10 rounded-lg text-white text-sm placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-cyan-500/40 transition resize-none"
                  placeholder="colleague@company.com"
                />
                <p className="text-xs text-slate-600 mt-1">Invitations will be sent via email. You can skip this step.</p>
              </div>
            </div>
          )}

          {step === 3 && (
            <div className="text-center py-6">
              <CheckCircle2 className="w-16 h-16 text-emerald-400 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-white mb-2">You're all set!</h3>
              <p className="text-sm text-slate-400">
                Your Cybertron workspace is ready. Head to the platform to get started.
              </p>
            </div>
          )}

          {/* Navigation */}
          <div className="flex items-center justify-between mt-8 pt-6 border-t border-white/5">
            {step > 0 ? (
              <button
                onClick={prev}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm text-slate-400 hover:text-white hover:bg-white/5 transition-colors"
              >
                <ArrowLeft className="w-4 h-4" />
                Back
              </button>
            ) : (
              <div />
            )}

            {step < STEPS.length - 1 ? (
              <button
                onClick={next}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-gradient-to-r from-cyan-600 to-cyan-500 text-white text-sm font-medium hover:from-cyan-500 hover:to-cyan-400 transition-all"
              >
                {step === 1 ? 'Skip / Continue' : 'Continue'}
                <ArrowRight className="w-4 h-4" />
              </button>
            ) : (
              <button
                onClick={handleFinish}
                disabled={loading}
                className="inline-flex items-center gap-2 px-6 py-2.5 rounded-lg bg-gradient-to-r from-emerald-600 to-emerald-500 text-white text-sm font-medium hover:from-emerald-500 hover:to-emerald-400 transition-all disabled:opacity-50"
              >
                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
                Go to Platform
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
