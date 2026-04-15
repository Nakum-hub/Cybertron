import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { CheckCircle, ArrowRight, Sparkles } from 'lucide-react';

export default function BillingSuccessPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [countdown, setCountdown] = useState(5);

  useEffect(() => {
    const timer = setInterval(() => {
      setCountdown((c) => {
        if (c <= 1) {
          clearInterval(timer);
          navigate('/platform');
          return 0;
        }
        return c - 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [navigate]);

  return (
    <div className="min-h-screen bg-[#04070f] flex items-center justify-center px-4">
      <div className="max-w-lg w-full text-center">
        <div className="relative mx-auto w-20 h-20 mb-8">
          <div className="absolute inset-0 bg-emerald-500/20 rounded-full animate-ping" />
          <div className="relative flex items-center justify-center w-20 h-20 bg-gradient-to-br from-emerald-500/30 to-cyan-500/30 rounded-full border border-emerald-500/40">
            <CheckCircle className="w-10 h-10 text-emerald-400" />
          </div>
        </div>

        <div className="flex items-center justify-center gap-2 mb-3">
          <Sparkles className="w-5 h-5 text-amber-400" />
          <span className="text-sm font-medium text-amber-400 tracking-wider uppercase">Plan Activated</span>
        </div>

        <h1 className="text-3xl font-bold text-white mb-4">
          Subscription Activated!
        </h1>
        <p className="text-slate-400 mb-8 leading-relaxed">
          Your workspace has been upgraded successfully. All premium features are now
          available across your platform.
        </p>

        <button
          onClick={() => navigate('/platform')}
          className="inline-flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-cyan-600 to-blue-600 text-white font-semibold rounded-lg hover:from-cyan-500 hover:to-blue-500 transition-all duration-200 shadow-lg shadow-cyan-500/20"
        >
          Open Platform
          <ArrowRight className="w-4 h-4" />
        </button>

        <p className="mt-6 text-sm text-slate-600">
          Redirecting in {countdown}s...
        </p>
      </div>
    </div>
  );
}
