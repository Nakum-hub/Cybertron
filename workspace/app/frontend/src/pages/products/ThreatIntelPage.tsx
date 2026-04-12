import ThreatCommandConsole from '@/components/platform/ThreatCommandConsole';
import ProductPageShell from './ProductPageShell';

export default function ThreatIntelProductPage() {
  return (
    <ProductPageShell
      eyebrow="Threat Command"
      title="Threat intelligence and SOC workflows driven by real feeds and playbooks"
      description="Threat Command surfaces CVE feed activity, playbook readiness, and tenant-specific threat posture. When NVD or connector data is not configured, the console remains explicit about missing inputs."
      workspacePath="/platform/threat-command"
      fallbackRole="security_analyst"
      Console={ThreatCommandConsole}
    />
  );
}
