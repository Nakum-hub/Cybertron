import ResilienceHQConsole from '@/components/platform/ResilienceHQConsole';
import ProductPageShell from './ProductPageShell';

export default function ComplianceEngineProductPage() {
  return (
    <ProductPageShell
      eyebrow="Resilience HQ"
      title="Compliance and resilience oversight with live framework and policy state"
      description="Resilience HQ rolls up framework readiness, policy lifecycle, and report inventory for the current tenant. It stays truthful when frameworks, policies, or evidence have not been configured yet."
      workspacePath="/platform/resilience-hq"
      fallbackRole="executive_viewer"
      Console={ResilienceHQConsole}
    />
  );
}
