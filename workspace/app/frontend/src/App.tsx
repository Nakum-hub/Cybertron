import { Suspense, lazy } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Route, Routes } from 'react-router-dom';
import InternalRouteGate from './components/InternalRouteGate';
import SystemStatusBanner from './components/SystemStatusBanner';
import { Toaster } from './components/ui/toaster';

const Index = lazy(() => import('./pages/Index'));
const Platform = lazy(() => import('./pages/Platform'));
const AuthCallback = lazy(() => import('./pages/AuthCallback'));
const AuthError = lazy(() => import('./pages/AuthError'));
const AccountPage = lazy(() => import('./pages/AccountPage'));
const PrivacyPolicy = lazy(() => import('./pages/PrivacyPolicy'));
const TermsOfService = lazy(() => import('./pages/TermsOfService'));
const CookiePolicy = lazy(() => import('./pages/CookiePolicy'));
const StatusPage = lazy(() => import('./pages/StatusPage'));
const DocsPage = lazy(() => import('./pages/DocsPage'));
const UiChecklistPage = lazy(() => import('./pages/UiChecklistPage'));
const UiWiringPage = lazy(() => import('./pages/UiWiringPage'));
const RiskCopilotPage = lazy(() => import('./pages/RiskCopilotPage'));
const ComplianceEnginePage = lazy(() => import('./pages/ComplianceEnginePage'));
const ThreatIntelPage = lazy(() => import('./pages/ThreatIntelPage'));
const AboutPage = lazy(() => import('./pages/AboutPage'));
const BlogPage = lazy(() => import('./pages/BlogPage'));
const PricingPage = lazy(() => import('./pages/PricingPage'));
const NotFoundPage = lazy(() => import('./pages/NotFoundPage'));

// P1 new pages
const PasswordResetPage = lazy(() => import('./pages/PasswordResetPage'));
const AdminPage = lazy(() => import('./pages/AdminPage'));
const OnboardingPage = lazy(() => import('./pages/OnboardingPage'));
const TeamPage = lazy(() => import('./pages/TeamPage'));
const ConnectorsPage = lazy(() => import('./pages/ConnectorsPage'));
const BillingSuccessPage = lazy(() => import('./pages/BillingSuccessPage'));
const BillingCancelPage = lazy(() => import('./pages/BillingCancelPage'));
const NotificationsPage = lazy(() => import('./pages/NotificationsPage'));
const ApiKeysPage = lazy(() => import('./pages/ApiKeysPage'));

const stableQueryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

export default function App() {
  return (
    <QueryClientProvider client={stableQueryClient}>
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-[9999] focus:px-4 focus:py-2 focus:rounded focus:bg-cyan-600 focus:text-white focus:text-sm focus:font-medium focus:outline-none focus:ring-2 focus:ring-cyan-400"
      >
        Skip to main content
      </a>
      <SystemStatusBanner />
      <Suspense
        fallback={
          <div className="min-h-screen bg-[#04070f] flex items-center justify-center">
            <div className="flex flex-col items-center gap-3">
              <div className="h-8 w-8 border-2 border-cyan-500/30 border-t-cyan-400 rounded-full animate-spin" />
              <span className="text-sm text-slate-500 tracking-wide">Loading...</span>
            </div>
          </div>
        }
      >
        <Routes>
          <Route path="/" element={<Index />} />
          <Route path="/account" element={<AccountPage />} />
          <Route path="/platform" element={<Platform />} />
          <Route path="/platform/:appId" element={<Platform />} />
          <Route path="/auth/callback" element={<AuthCallback />} />
          <Route path="/auth/error" element={<AuthError />} />
          <Route path="/auth/reset-password" element={<PasswordResetPage />} />
          <Route path="/onboarding" element={<OnboardingPage />} />
          <Route path="/admin" element={<AdminPage />} />
          <Route path="/account/team" element={<TeamPage />} />
          <Route path="/account/api-keys" element={<ApiKeysPage />} />
          <Route path="/account/notifications" element={<NotificationsPage />} />
          <Route path="/platform/connectors" element={<ConnectorsPage />} />
          <Route path="/billing/success" element={<BillingSuccessPage />} />
          <Route path="/billing/cancel" element={<BillingCancelPage />} />
          <Route path="/status" element={<StatusPage />} />
          <Route path="/diagnostics" element={<InternalRouteGate title="Platform Diagnostics"><StatusPage /></InternalRouteGate>} />
          <Route path="/docs" element={<InternalRouteGate title="Developer Documentation"><DocsPage /></InternalRouteGate>} />
          <Route path="/qa/ui-checklist" element={<InternalRouteGate title="UI Checklist"><UiChecklistPage /></InternalRouteGate>} />
          <Route path="/qa/ui-wiring" element={<InternalRouteGate title="UI Wiring QA"><UiWiringPage /></InternalRouteGate>} />
          <Route path="/products/risk-copilot" element={<RiskCopilotPage />} />
          <Route path="/products/compliance-engine" element={<ComplianceEnginePage />} />
          <Route path="/products/threat-intel" element={<ThreatIntelPage />} />
          <Route path="/legal/privacy" element={<PrivacyPolicy />} />
          <Route path="/legal/terms" element={<TermsOfService />} />
          <Route path="/legal/cookies" element={<CookiePolicy />} />
          <Route path="/about" element={<AboutPage />} />
          <Route path="/blog" element={<BlogPage />} />
          <Route path="/pricing" element={<PricingPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
      </Suspense>
      <Toaster />
    </QueryClientProvider>
  );
}
