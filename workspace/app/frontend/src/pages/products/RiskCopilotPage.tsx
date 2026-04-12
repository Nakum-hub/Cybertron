import RiskCopilotConsole from '@/components/platform/RiskCopilotConsole';
import ProductPageShell from './ProductPageShell';

export default function RiskCopilotProductPage() {
  return (
    <ProductPageShell
      eyebrow="Risk Copilot"
      title="AI-assisted risk prioritization backed by live tenant findings"
      description="Risk Copilot turns ingested evidence into ranked findings, treatment workflows, and report generation. If no risk evidence has been ingested yet, the console shows that honestly instead of inventing posture."
      workspacePath="/platform/risk-copilot"
      fallbackRole="executive_viewer"
      Console={RiskCopilotConsole}
    />
  );
}
