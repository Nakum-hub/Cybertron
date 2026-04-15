import { useNavigate } from 'react-router-dom';
import { XCircle, ArrowLeft } from 'lucide-react';

export default function BillingCancelPage() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-[#04070f] flex items-center justify-center px-4">
      <div className="max-w-lg w-full text-center">
        <div className="mx-auto w-20 h-20 mb-8 flex items-center justify-center bg-slate-800/50 rounded-full border border-slate-700/60">
          <XCircle className="w-10 h-10 text-slate-500" />
        </div>

        <h1 className="text-3xl font-bold text-white mb-4">
          Checkout Cancelled
        </h1>
        <p className="text-slate-400 mb-8 leading-relaxed">
          Your checkout session was cancelled. No charges were made.
          You can return to the pricing page to try again at any time.
        </p>

        <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
          <button
            onClick={() => navigate('/pricing')}
            className="inline-flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-cyan-600 to-blue-600 text-white font-semibold rounded-lg hover:from-cyan-500 hover:to-blue-500 transition-all duration-200"
          >
            View Plans
          </button>
          <button
            onClick={() => navigate('/platform')}
            className="inline-flex items-center gap-2 px-6 py-3 bg-slate-800 text-slate-300 font-medium rounded-lg border border-slate-700 hover:bg-slate-700 transition-all duration-200"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to Platform
          </button>
        </div>
      </div>
    </div>
  );
}
