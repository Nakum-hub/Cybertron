import { useMemo, useState } from 'react';
import { CheckCircle2, Loader2, Play, XCircle } from 'lucide-react';
import { Link, useSearchParams } from 'react-router-dom';
import { ApiError } from '@/lib/api';
import { useAuthStatus } from '@/hooks/use-auth-status';
import {
  computeRiskScores,
  fetchAuditPackagePdfBinary,
  fetchAppStatus,
  fetchAuditLogs,
  fetchBillingCredits,
  fetchBillingUsage,
  fetchConnectorStatus,
  fetchModuleRegistry,
  fetchModuleStatus,
  fetchRiskReportPdfBinary,
  fetchIncidents,
  fetchRiskFindings,
  fetchSoc2Controls,
  fetchSoc2Status,
  fetchPlatformApps,
  fetchReports,
  fetchServiceRequests,
  fetchTenantFeatureFlags,
  fetchTenantProducts,
  fetchThreatIntelCveFeed,
  fetchThreatIntelDashboard,
  fetchThreatIncidents,
  fetchThreatSummary,
  fetchUsers,
  generateAuditPackage,
  generateCompliancePolicy,
  generateRiskReport,
  summarizeCve,
  syncThreatIntelCves,
  updateSoc2Status,
  uploadAwsLogs,
  uploadSoc2Evidence,
} from '@/lib/backend';
import { normalizeRole, roleLabels, type PlatformRole } from '@/lib/platform-registry';
import awsLogsFixtureRaw from '@/fixtures/aws-logs.sample.json?raw';
import evidenceFixtureRaw from '@/fixtures/evidence.sample.pdf?raw';

type RunStatus = 'idle' | 'running' | 'pass' | 'fail';

type TestResult = {
  status: RunStatus;
  detail: string;
};

type RouteProbeCase = {
  id: string;
  label: string;
  path: string;
  expectedSnippets: string[];
  requirements: string;
};

type ApiProbeCase = {
  id: string;
  label: string;
  endpoint: string;
  requirements: string;
  run: () => Promise<TestResult>;
};

type TransactionProbeCase = ApiProbeCase;

const MIN_PDF_BYTES = 5 * 1024;

function toFailureResult(error: unknown): TestResult {
  if (error instanceof ApiError) {
    return {
      status: 'fail',
      detail: `${error.status} ${error.code || 'api_error'}: ${error.message}`,
    };
  }

  if (error instanceof Error) {
    return {
      status: 'fail',
      detail: error.message,
    };
  }

  return {
    status: 'fail',
    detail: 'Unknown UI wiring failure.',
  };
}

function isExpectedGuardError(error: unknown): boolean {
  return (
    error instanceof ApiError &&
    (error.status === 401 ||
      error.status === 403 ||
      error.code === 'feature_disabled' ||
      error.code === 'LLM_NOT_CONFIGURED')
  );
}

function hasPdfSignature(bytes: Uint8Array): boolean {
  if (!bytes || bytes.length < 4) {
    return false;
  }
  return bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46;
}

function buildFixtureFile(raw: string, fileName: string, mimeType: string): File {
  return new File([raw], fileName, { type: mimeType });
}

function remediationForApiError(error: ApiError): string {
  if (error.code === 'LLM_NOT_CONFIGURED') {
    return 'Configure LLM_PROVIDER and provider credentials, then enable llm_features_enabled.';
  }
  if (error.code === 'feature_disabled') {
    return 'Enable tenant product flag and required feature flags in Platform governance.';
  }
  if (error.status === 403) {
    return 'Use a role with sufficient scope for this action (Tenant Admin/Compliance Officer/Security Analyst).';
  }
  if (error.status === 401) {
    return 'Authenticate first and retry the transaction.';
  }
  if (error.status === 503) {
    return 'Open /diagnostics and configure missing dependencies (DB/Redis/storage/LLM).';
  }
  return 'Review backend logs and diagnostics, then retry.';
}

async function probeRoute(caseItem: RouteProbeCase): Promise<TestResult> {
  if (typeof window === 'undefined') {
    return {
      status: 'fail',
      detail: 'Route probe requires browser runtime.',
    };
  }

  return new Promise(resolve => {
    const iframe = document.createElement('iframe');
    iframe.setAttribute('aria-hidden', 'true');
    iframe.style.position = 'fixed';
    iframe.style.left = '-9999px';
    iframe.style.top = '-9999px';
    iframe.style.width = '1200px';
    iframe.style.height = '900px';
    iframe.style.opacity = '0';
    iframe.style.pointerEvents = 'none';

    const startedAt = Date.now();
    const timeoutMs = 12_000;
    let finished = false;

    const finish = (result: TestResult) => {
      if (finished) {
        return;
      }
      finished = true;
      iframe.remove();
      resolve(result);
    };

    const inspect = () => {
      if (finished) {
        return;
      }

      if (Date.now() - startedAt > timeoutMs) {
        finish({
          status: 'fail',
          detail: `Route probe timed out for ${caseItem.path}.`,
        });
        return;
      }

      try {
        const bodyText = (iframe.contentDocument?.body?.innerText || '').toLowerCase();
        const matched = caseItem.expectedSnippets.find(snippet =>
          bodyText.includes(snippet.toLowerCase())
        );

        if (matched) {
          const routePath = iframe.contentWindow?.location?.pathname || caseItem.path;
          finish({
            status: 'pass',
            detail: `Loaded ${routePath} and found "${matched}".`,
          });
          return;
        }
      } catch {
        // Keep polling until timeout.
      }

      window.setTimeout(inspect, 250);
    };

    iframe.onload = () => {
      window.setTimeout(inspect, 150);
    };

    document.body.appendChild(iframe);
    iframe.src = caseItem.path;
  });
}

export default function UiWiringPage() {
  const { status: authStatus, profile, loginUrl } = useAuthStatus();
  const [searchParams] = useSearchParams();
  const [results, setResults] = useState<Record<string, TestResult>>({});
  const [runningAll, setRunningAll] = useState(false);

  const tenant = profile?.tenant || searchParams.get('tenant') || 'global';
  const role: PlatformRole = normalizeRole(profile?.role || searchParams.get('role') || 'executive_viewer');

  const routeCases = useMemo<RouteProbeCase[]>(
    () => [
      {
        id: 'route-home',
        label: '[Landing] Root Route',
        path: '/',
        expectedSnippets: ['enterprise cyber operations platform', 'cybertron'],
        requirements: 'public',
      },
      {
        id: 'route-status',
        label: '[Landing] Status Page Link',
        path: '/status',
        expectedSnippets: ['system status', 'dependency status'],
        requirements: 'public',
      },
      {
        id: 'route-docs',
        label: '[Landing] Docs Page Link',
        path: '/docs',
        expectedSnippets: ['api documentation', 'endpoint catalog'],
        requirements: 'public',
      },
      {
        id: 'route-pricing-page',
        label: '[Landing] Pricing Page Link',
        path: '/pricing',
        expectedSnippets: ['affordable cyber defense', 'get started free'],
        requirements: 'public',
      },
      {
        id: 'route-about-page',
        label: '[Footer] About Page Link',
        path: '/about',
        expectedSnippets: ['about us', 'cyber operations'],
        requirements: 'public',
      },
      {
        id: 'route-blog-page',
        label: '[Footer] Blog Page Link',
        path: '/blog',
        expectedSnippets: ['security insights', 'blog'],
        requirements: 'public',
      },
      {
        id: 'route-footer-features-anchor',
        label: '[Footer] Features Anchor Link',
        path: '/#features',
        expectedSnippets: ['core capabilities', 'defense systems'],
        requirements: 'public',
      },
      {
        id: 'route-platform',
        label: '[Shell] Platform Route',
        path: `/platform?tenant=${encodeURIComponent(tenant)}&role=${role}`,
        expectedSnippets: ['multi-app operations shell', 'platform workspace'],
        requirements: 'auth + tenant scope',
      },
      {
        id: 'route-nav-get-started-desktop',
        label: '[Index Nav] Create Account CTA (desktop)',
        path: '/account?mode=register',
        expectedSnippets: ['account center', 'secure login'],
        requirements: 'public',
      },
      {
        id: 'route-nav-get-started-mobile',
        label: '[Index Nav] Create Account CTA (mobile)',
        path: '/account?mode=register',
        expectedSnippets: ['account center', 'secure login'],
        requirements: 'public',
      },
      {
        id: 'route-hero-start-free-trial',
        label: '[Hero] Create Account CTA',
        path: '/account?mode=register',
        expectedSnippets: ['account center', 'secure login'],
        requirements: 'public',
      },
      {
        id: 'route-hero-view-live-demo',
        label: '[Hero] Login CTA',
        path: '/account?mode=login',
        expectedSnippets: ['account center', 'secure login'],
        requirements: 'public',
      },
      {
        id: 'route-features-threat-command',
        label: '[Features] Open Threat Command CTA',
        path: '/products/threat-intel?tenant=global&role=security_analyst',
        expectedSnippets: ['threat intel product workspace', 'continue to secure login'],
        requirements: 'auth + product enabled + role gate',
      },
      {
        id: 'route-features-identity-guardian',
        label: '[Features] Open Identity Guardian CTA',
        path: '/platform/identity-guardian?tenant=global&role=security_analyst',
        expectedSnippets: ['identity guardian', 'continue to secure login', 'multi-app operations shell'],
        requirements: 'auth + tenant scope + role gate',
      },
      {
        id: 'route-features-governance',
        label: '[Features] Open Governance Console CTA',
        path: '/products/compliance-engine?tenant=global&role=tenant_admin',
        expectedSnippets: ['compliance engine product workspace', 'continue to secure login'],
        requirements: 'auth + tenant admin role + product/feature gate',
      },
      {
        id: 'route-features-risk-copilot',
        label: '[Features] Open Risk Copilot CTA',
        path: '/products/risk-copilot?tenant=global&role=security_analyst',
        expectedSnippets: ['risk copilot product workspace', 'continue to secure login'],
        requirements: 'auth + product enabled + role gate',
      },
      {
        id: 'route-pricing-starter',
        label: '[Pricing] Starter CTA',
        path: '/products/threat-intel?tenant=global&role=security_analyst',
        expectedSnippets: ['threat intel product workspace', 'continue to secure login'],
        requirements: 'auth + product enabled + role gate',
      },
      {
        id: 'route-pricing-pro',
        label: '[Pricing] Pro CTA',
        path: '/products/compliance-engine?tenant=global&role=tenant_admin',
        expectedSnippets: ['compliance engine product workspace', 'continue to secure login'],
        requirements: 'auth + tenant admin role + product/feature gate',
      },
      {
        id: 'route-auth-open-identity',
        label: '[Auth Showcase] Open Identity Console CTA',
        path: '/platform/identity-guardian?tenant=global&role=security_analyst',
        expectedSnippets: ['identity guardian', 'continue to secure login', 'multi-app operations shell'],
        requirements: 'auth + tenant scope + role gate',
      },
      {
        id: 'route-auth-open-governance',
        label: '[Auth Showcase] Open Tenant Governance CTA',
        path: '/platform/resilience-hq?tenant=global&role=tenant_admin',
        expectedSnippets: ['resilience', 'continue to secure login', 'multi-app operations shell'],
        requirements: 'auth + tenant admin role',
      },
      {
        id: 'route-auth-open-role-scope',
        label: '[Auth Showcase] Open Role Scope View CTA',
        path: '/platform/identity-guardian?tenant=global&role=executive_viewer',
        expectedSnippets: ['identity guardian', 'continue to secure login', 'multi-app operations shell'],
        requirements: 'auth + tenant scope + role gate',
      },
      {
        id: 'route-auth-open-status',
        label: '[Auth Showcase] Open Status CTA',
        path: '/status',
        expectedSnippets: ['system status', 'dependency status'],
        requirements: 'public',
      },
      {
        id: 'route-auth-open-wiring-qa',
        label: '[Auth Showcase] Open UI Wiring QA CTA',
        path: '/qa/ui-wiring',
        expectedSnippets: ['ui wiring checklist', 'continue to secure login'],
        requirements: 'auth recommended',
      },
      {
        id: 'route-threat-intel',
        label: '[Products] Threat Intel Route',
        path: `/products/threat-intel?tenant=${encodeURIComponent(tenant)}&role=${role}`,
        expectedSnippets: ['threat intel product workspace', 'continue to secure login'],
        requirements: 'auth + product enabled + role gate',
      },
      {
        id: 'route-compliance',
        label: '[Products] Compliance Route',
        path: `/products/compliance-engine?tenant=${encodeURIComponent(tenant)}&role=${role}`,
        expectedSnippets: ['compliance engine product workspace', 'continue to secure login'],
        requirements: 'auth + product enabled + role gate',
      },
      {
        id: 'route-risk',
        label: '[Products] Risk Copilot Route',
        path: `/products/risk-copilot?tenant=${encodeURIComponent(tenant)}&role=${role}`,
        expectedSnippets: ['risk copilot product workspace', 'continue to secure login'],
        requirements: 'auth + product enabled + role gate',
      },
      {
        id: 'route-legal-privacy',
        label: '[Footer] Privacy Link',
        path: '/legal/privacy',
        expectedSnippets: ['privacy policy', 'privacy'],
        requirements: 'public',
      },
      {
        id: 'route-legal-terms',
        label: '[Footer] Terms Link',
        path: '/legal/terms',
        expectedSnippets: ['terms of service', 'terms'],
        requirements: 'public',
      },
      {
        id: 'route-legal-cookies',
        label: '[Footer] Cookie Policy Link',
        path: '/legal/cookies',
        expectedSnippets: ['cookie policy', 'cookies'],
        requirements: 'public',
      },
    ],
    [role, tenant]
  );

  const apiCases = useMemo<ApiProbeCase[]>(
    () => [
      {
        id: 'api-threat-summary',
        label: '[Threat Dashboard] Threat Summary API',
        endpoint: 'GET /v1/threats/summary',
        requirements: 'auth in strict mode',
        run: async () => {
          const payload = await fetchThreatSummary();
          return {
            status: 'pass',
            detail: `Summary loaded: activeThreats=${payload.activeThreats}`,
          };
        },
      },
      {
        id: 'api-threat-incidents',
        label: '[Threat Dashboard] Threat Incidents API',
        endpoint: 'GET /v1/threats/incidents',
        requirements: 'auth in strict mode',
        run: async () => {
          const payload = await fetchThreatIncidents();
          return {
            status: 'pass',
            detail: `Incidents payload length=${payload.length}`,
          };
        },
      },
      {
        id: 'api-risk-findings',
        label: '[Risk Copilot] Risk Findings API',
        endpoint: 'GET /v1/risk/findings',
        requirements: 'auth + product_risk_copilot_enabled',
        run: async () => {
          try {
            const payload = await fetchRiskFindings(tenant, { limit: 5 });
            return {
              status: 'pass',
              detail: `Risk findings=${payload.data.length}.`,
            };
          } catch (error) {
            if (isExpectedGuardError(error)) {
              return {
                status: 'pass',
                detail: `Risk findings guarded correctly: ${
                  error instanceof ApiError ? `${error.status} ${error.code || ''}`.trim() : 'access denied'
                }.`,
              };
            }
            return toFailureResult(error);
          }
        },
      },
      {
        id: 'api-risk-compute',
        label: '[Risk Copilot] Score Compute API',
        endpoint: 'POST /v1/risk/score/compute',
        requirements: 'security_analyst+ + feature gates',
        run: async () => {
          try {
            const payload = await computeRiskScores(tenant, { includeAi: false, limit: 20 });
            return {
              status: 'pass',
              detail: `Risk compute completed: totalFindings=${payload.portfolio.totalFindings}.`,
            };
          } catch (error) {
            if (isExpectedGuardError(error)) {
              return {
                status: 'pass',
                detail: `Risk compute guarded correctly: ${
                  error instanceof ApiError ? `${error.status} ${error.code || ''}`.trim() : 'access denied'
                }.`,
              };
            }
            return toFailureResult(error);
          }
        },
      },
      {
        id: 'api-compliance-status',
        label: '[Compliance Engine] SOC2 Status API',
        endpoint: 'GET /v1/compliance/soc2/status',
        requirements: 'auth + product_compliance_engine_enabled',
        run: async () => {
          try {
            const payload = await fetchSoc2Status(tenant);
            return {
              status: 'pass',
              detail: `SOC2 controls=${payload.controls.length}, readiness=${payload.gap.readinessScore.toFixed(1)}%.`,
            };
          } catch (error) {
            if (isExpectedGuardError(error)) {
              return {
                status: 'pass',
                detail: `SOC2 status guarded correctly: ${
                  error instanceof ApiError ? `${error.status} ${error.code || ''}`.trim() : 'access denied'
                }.`,
              };
            }
            return toFailureResult(error);
          }
        },
      },
      {
        id: 'api-compliance-policy-generate',
        label: '[Compliance Engine] Policy Generate API',
        endpoint: 'POST /v1/compliance/policy/generate',
        requirements: 'compliance_officer+ + llm_features_enabled',
        run: async () => {
          try {
            const payload = await generateCompliancePolicy(tenant, {
              policyKey: 'ui-wiring-smoke-policy',
              organization: 'Cybertron',
            });
            return {
              status: 'pass',
              detail: `Policy generated via ${payload.llm.provider}/${payload.llm.model}.`,
            };
          } catch (error) {
            if (isExpectedGuardError(error)) {
              return {
                status: 'pass',
                detail: `Policy generation guarded correctly: ${
                  error instanceof ApiError ? `${error.status} ${error.code || ''}`.trim() : 'access denied'
                }.`,
              };
            }
            return toFailureResult(error);
          }
        },
      },
      {
        id: 'api-threat-intel-dashboard',
        label: '[Threat Intel] Dashboard API',
        endpoint: 'GET /v1/threat-intel/dashboard',
        requirements: 'auth + product_threat_intel_enabled',
        run: async () => {
          try {
            const payload = await fetchThreatIntelDashboard(tenant, 30);
            return {
              status: 'pass',
              detail: `Threat dashboard loaded with ${payload.trend.length} trend point(s).`,
            };
          } catch (error) {
            if (isExpectedGuardError(error)) {
              return {
                status: 'pass',
                detail: `Threat dashboard guarded correctly: ${
                  error instanceof ApiError ? `${error.status} ${error.code || ''}`.trim() : 'access denied'
                }.`,
              };
            }
            return toFailureResult(error);
          }
        },
      },
      {
        id: 'api-threat-intel-feed',
        label: '[Threat Intel] CVE Feed API',
        endpoint: 'GET /v1/threat-intel/cve/feed',
        requirements: 'auth + product_threat_intel_enabled',
        run: async () => {
          try {
            const payload = await fetchThreatIntelCveFeed(tenant, { limit: 5 });
            return {
              status: 'pass',
              detail: `CVE feed entries=${payload.data.length}.`,
            };
          } catch (error) {
            if (isExpectedGuardError(error)) {
              return {
                status: 'pass',
                detail: `CVE feed guarded correctly: ${
                  error instanceof ApiError ? `${error.status} ${error.code || ''}`.trim() : 'access denied'
                }.`,
              };
            }
            return toFailureResult(error);
          }
        },
      },
      {
        id: 'api-platform-apps',
        label: '[Platform Shell] Apps Catalog API',
        endpoint: 'GET /v1/platform/apps',
        requirements: 'auth + tenant scope + role scope',
        run: async () => {
          const payload = await fetchPlatformApps(role, tenant);
          return {
            status: 'pass',
            detail: `Loaded ${payload.length} app(s).`,
          };
        },
      },
      {
        id: 'api-module-registry',
        label: '[Platform Shell] Module Registry API',
        endpoint: 'GET /v1/modules',
        requirements: 'auth + tenant scope + role scope',
        run: async () => {
          const payload = await fetchModuleRegistry(tenant, role);
          return {
            status: 'pass',
            detail: `Registry modules=${payload.modules.length}, accessibleApps=${payload.apps.length}.`,
          };
        },
      },
      {
        id: 'api-module-status-risk-copilot',
        label: '[Platform Shell] Module Status API',
        endpoint: 'GET /v1/modules/risk-copilot/status',
        requirements: 'auth + tenant scope + module access',
        run: async () => {
          try {
            const payload = await fetchModuleStatus('risk-copilot', tenant, role);
            return {
              status: 'pass',
              detail: `Risk Copilot status=${payload.status}, latency=${payload.latencyMs}ms.`,
            };
          } catch (error) {
            if (isExpectedGuardError(error)) {
              return {
                status: 'pass',
                detail: `Module status guarded correctly: ${
                  error instanceof ApiError ? `${error.status} ${error.code || ''}`.trim() : 'access denied'
                }.`,
              };
            }
            return toFailureResult(error);
          }
        },
      },
      {
        id: 'api-identity-status',
        label: '[Identity Guardian] App Status API',
        endpoint: 'GET /v1/apps/identity-guardian/status',
        requirements: 'auth + product enabled + role scope',
        run: async () => {
          const payload = await fetchAppStatus('identity-guardian', tenant, role);
          return {
            status: 'pass',
            detail: `Status=${payload.status}, latency=${payload.latencyMs}ms.`,
          };
        },
      },
      {
        id: 'api-users',
        label: '[Identity Guardian] Users Directory API',
        endpoint: 'GET /v1/users',
        requirements: 'auth + security_analyst+',
        run: async () => {
          try {
            const payload = await fetchUsers(tenant, 5);
            return {
              status: 'pass',
              detail: `Loaded ${payload.length} user record(s).`,
            };
          } catch (error) {
            if (error instanceof ApiError && (error.status === 401 || error.status === 403)) {
              return {
                status: 'pass',
                detail: `Denied as expected for role ${roleLabels[role]}.`,
              };
            }
            return toFailureResult(error);
          }
        },
      },
      {
        id: 'api-service-requests',
        label: '[Identity Guardian] Service Requests API',
        endpoint: 'GET /v1/service-requests',
        requirements: 'auth + tenant scope',
        run: async () => {
          const payload = await fetchServiceRequests(tenant, 5);
          return {
            status: 'pass',
            detail: `Loaded ${payload.length} service request(s).`,
          };
        },
      },
      {
        id: 'api-incidents',
        label: '[Threat Command] Incidents API',
        endpoint: 'GET /v1/incidents',
        requirements: 'auth + tenant scope',
        run: async () => {
          const payload = await fetchIncidents(tenant, { limit: 5 });
          return {
            status: 'pass',
            detail: `Loaded ${payload.data.length} incident(s).`,
          };
        },
      },
      {
        id: 'api-reports',
        label: '[Resilience HQ] Reports API',
        endpoint: 'GET /v1/reports',
        requirements: 'auth + tenant scope + role gate',
        run: async () => {
          try {
            const payload = await fetchReports(tenant, 5);
            return {
              status: 'pass',
              detail: `Loaded ${payload.length} report row(s).`,
            };
          } catch (error) {
            if (error instanceof ApiError && (error.status === 401 || error.status === 403)) {
              return {
                status: 'pass',
                detail: `Report access denied as expected for role ${roleLabels[role]}.`,
              };
            }
            return toFailureResult(error);
          }
        },
      },
      {
        id: 'api-connectors-status',
        label: '[Identity Guardian] Connector Status API',
        endpoint: 'GET /v1/connectors/status',
        requirements: 'auth + security_analyst+',
        run: async () => {
          try {
            const payload = await fetchConnectorStatus();
            return {
              status: 'pass',
              detail: `Connector entries=${payload.connectors?.length || 0}.`,
            };
          } catch (error) {
            if (error instanceof ApiError && (error.status === 401 || error.status === 403)) {
              return {
                status: 'pass',
                detail: `Connector visibility denied as expected for role ${roleLabels[role]}.`,
              };
            }
            return toFailureResult(error);
          }
        },
      },
      {
        id: 'api-tenant-products',
        label: '[Governance] Tenant Products API',
        endpoint: `GET /v1/tenants/${tenant}/products`,
        requirements: 'auth + tenant scope',
        run: async () => {
          const payload = await fetchTenantProducts(tenant, role);
          return {
            status: 'pass',
            detail: `Product records=${payload.length}.`,
          };
        },
      },
      {
        id: 'api-tenant-feature-flags',
        label: '[Governance] Tenant Feature Flags API',
        endpoint: `GET /v1/tenants/${tenant}/feature-flags`,
        requirements: 'auth + tenant scope',
        run: async () => {
          const payload = await fetchTenantFeatureFlags(tenant);
          return {
            status: 'pass',
            detail: `Feature flags=${payload.length}.`,
          };
        },
      },
      {
        id: 'api-billing-usage',
        label: '[Billing Stub] Usage API',
        endpoint: 'GET /v1/billing/usage',
        requirements: 'auth + tenant scope + security_analyst+',
        run: async () => {
          try {
            const payload = await fetchBillingUsage(tenant, { limit: 5 });
            return {
              status: 'pass',
              detail: `Usage events=${payload.data.length}.`,
            };
          } catch (error) {
            if (error instanceof ApiError && (error.status === 401 || error.status === 403)) {
              return {
                status: 'pass',
                detail: `Billing usage denied as expected for role ${roleLabels[role]}.`,
              };
            }
            return toFailureResult(error);
          }
        },
      },
      {
        id: 'api-billing-credits',
        label: '[Billing Stub] Credits API',
        endpoint: 'GET /v1/billing/credits',
        requirements: 'auth + tenant scope',
        run: async () => {
          const payload = await fetchBillingCredits(tenant);
          return {
            status: 'pass',
            detail: `Credit balance=${payload.balanceUnits}.`,
          };
        },
      },
      {
        id: 'api-audit-logs',
        label: '[Resilience HQ] Audit Logs API',
        endpoint: 'GET /v1/audit-logs',
        requirements: 'auth + tenant_admin+',
        run: async () => {
          try {
            const payload = await fetchAuditLogs(tenant, { limit: 10 });
            return {
              status: 'pass',
              detail: `Audit events=${payload.data?.length ?? 0}.`,
            };
          } catch (error) {
            if (error instanceof ApiError && (error.status === 401 || error.status === 403)) {
              return {
                status: 'pass',
                detail: `Audit logs denied as expected for role ${roleLabels[role]}.`,
              };
            }
            return toFailureResult(error);
          }
        },
      },
    ],
    [role, tenant]
  );

  const transactionCases = useMemo<TransactionProbeCase[]>(
    () => [
      {
        id: 'txn-risk-copilot-e2e',
        label: '[Transaction] Risk Copilot: upload -> score -> generate PDF -> verify bytes',
        endpoint:
          'POST /v1/risk/ingest/aws-logs -> POST /v1/risk/score/compute -> POST /v1/risk/report/generate -> GET /v1/risk/report/:id/download',
        requirements: 'security_analyst+ + product_risk_copilot_enabled (+ llm_features_enabled for report)',
        run: async () => {
          try {
            const awsFixture = buildFixtureFile(
              awsLogsFixtureRaw,
              'aws-logs.sample.json',
              'application/json'
            );
            const ingest = await uploadAwsLogs(tenant, awsFixture);
            const scored = await computeRiskScores(tenant, { includeAi: false, limit: 100 });
            const report = await generateRiskReport(tenant);
            const downloaded = await fetchRiskReportPdfBinary(tenant, report.report.id);

            if (!hasPdfSignature(downloaded.bytes)) {
              return {
                status: 'fail',
                detail:
                  'Risk report download did not start with %PDF signature. Remediation: verify backend PDF generation and storage stream integrity.',
              };
            }
            if (downloaded.bytes.length <= MIN_PDF_BYTES) {
              return {
                status: 'fail',
                detail: `Risk report PDF too small (${downloaded.bytes.length} bytes). Remediation: ensure board report generator includes full executive summary/heatmap content.`,
              };
            }

            return {
              status: 'pass',
              detail: `Risk transaction passed. Findings=${scored.portfolio.totalFindings}, uploaded=${ingest.insertedFindings}, pdfBytes=${downloaded.bytes.length}.`,
            };
          } catch (error) {
            if (error instanceof ApiError) {
              return {
                status: 'fail',
                detail: `${error.status} ${error.code || 'api_error'}: ${error.message}. Remediation: ${remediationForApiError(error)}`,
              };
            }
            return toFailureResult(error);
          }
        },
      },
      {
        id: 'txn-compliance-e2e',
        label: '[Transaction] Compliance: controls -> status update -> evidence upload -> policy -> audit PDF',
        endpoint:
          'GET /v1/compliance/soc2/controls -> PATCH /v1/compliance/soc2/status/:id -> POST /v1/compliance/soc2/evidence/upload -> POST /v1/compliance/policy/generate -> POST+GET /v1/compliance/audit-package/*',
        requirements: 'compliance_officer+ + product_compliance_engine_enabled',
        run: async () => {
          try {
            const controls = await fetchSoc2Controls(tenant);
            if (!controls.length) {
              return {
                status: 'fail',
                detail: 'No SOC2 controls available. Remediation: run migrations and verify soc2_controls seed data.',
              };
            }

            const controlId = controls[0].controlId;
            await updateSoc2Status(tenant, controlId, {
              status: 'implemented',
              notes: 'UI wiring transaction validation',
            });

            const evidenceFixture = buildFixtureFile(
              evidenceFixtureRaw,
              'evidence.sample.pdf',
              'application/pdf'
            );
            await uploadSoc2Evidence(tenant, controlId, evidenceFixture);

            let policyState = 'generated';
            try {
              await generateCompliancePolicy(tenant, {
                policyKey: 'ui-wiring-transaction-policy',
                organization: 'Cybertron',
              });
            } catch (error) {
              if (error instanceof ApiError && error.code === 'LLM_NOT_CONFIGURED') {
                policyState = 'llm_not_configured';
              } else if (error instanceof ApiError && error.code === 'feature_disabled') {
                policyState = 'llm_feature_disabled';
              } else {
                throw error;
              }
            }

            const auditPackage = await generateAuditPackage(tenant);
            const downloaded = await fetchAuditPackagePdfBinary(tenant, auditPackage.id);
            if (!hasPdfSignature(downloaded.bytes)) {
              return {
                status: 'fail',
                detail:
                  'Audit package download did not start with %PDF signature. Remediation: verify backend audit package PDF stream.',
              };
            }
            if (downloaded.bytes.length <= MIN_PDF_BYTES) {
              return {
                status: 'fail',
                detail: `Audit package PDF too small (${downloaded.bytes.length} bytes). Remediation: ensure control/evidence manifest content is rendered in PDF.`,
              };
            }

            return {
              status: 'pass',
              detail: `Compliance transaction passed. control=${controlId}, policy=${policyState}, auditPdfBytes=${downloaded.bytes.length}.`,
            };
          } catch (error) {
            if (error instanceof ApiError) {
              return {
                status: 'fail',
                detail: `${error.status} ${error.code || 'api_error'}: ${error.message}. Remediation: ${remediationForApiError(error)}`,
              };
            }
            return toFailureResult(error);
          }
        },
      },
      {
        id: 'txn-threat-intel-e2e',
        label: '[Transaction] Threat Intel: sync -> feed -> summarize -> dashboard',
        endpoint:
          'POST /v1/threat-intel/cve/sync -> GET /v1/threat-intel/cve/feed -> POST /v1/threat-intel/cve/:id/summarize -> GET /v1/threat-intel/dashboard',
        requirements: 'tenant_admin+ for sync, security_analyst+ for summarize, product_threat_intel_enabled',
        run: async () => {
          try {
            const sync = await syncThreatIntelCves(tenant);
            const feed = await fetchThreatIntelCveFeed(tenant, { limit: 10 });
            const dashboard = await fetchThreatIntelDashboard(tenant, 30);

            let summarizeState = 'skipped_no_cve';
            const firstCve = feed.data[0];
            if (firstCve?.cveId) {
              try {
                await summarizeCve(tenant, firstCve.cveId);
                summarizeState = 'generated';
              } catch (error) {
                if (error instanceof ApiError && error.code === 'LLM_NOT_CONFIGURED') {
                  summarizeState = 'llm_not_configured';
                } else if (error instanceof ApiError && error.code === 'feature_disabled') {
                  summarizeState = 'llm_feature_disabled';
                } else {
                  throw error;
                }
              }
            }

            return {
              status: 'pass',
              detail: `Threat intel transaction passed. synced=${sync.synced ? 'yes' : 'no'} notModified=${sync.notModified ? 'yes' : 'no'} feedCount=${feed.data.length} summarize=${summarizeState} trendPoints=${dashboard.trend.length}.`,
            };
          } catch (error) {
            if (error instanceof ApiError) {
              return {
                status: 'fail',
                detail: `${error.status} ${error.code || 'api_error'}: ${error.message}. Remediation: ${remediationForApiError(error)}`,
              };
            }
            return toFailureResult(error);
          }
        },
      },
    ],
    [tenant]
  );

  const checks = useMemo(
    () => [
      ...routeCases.map(item => ({
        id: item.id,
        label: item.label,
        target: item.path,
        requirements: item.requirements,
        type: 'route' as const,
        run: () => probeRoute(item),
      })),
      ...apiCases.map(item => ({
        id: item.id,
        label: item.label,
        target: item.endpoint,
        requirements: item.requirements,
        type: 'api' as const,
        run: item.run,
      })),
      ...transactionCases.map(item => ({
        id: item.id,
        label: item.label,
        target: item.endpoint,
        requirements: item.requirements,
        type: 'transaction' as const,
        run: item.run,
      })),
    ],
    [apiCases, routeCases, transactionCases]
  );

  const totals = useMemo(() => {
    const values = Object.values(results);
    return {
      pass: values.filter(item => item.status === 'pass').length,
      fail: values.filter(item => item.status === 'fail').length,
      running: values.filter(item => item.status === 'running').length,
      total: checks.length,
    };
  }, [checks.length, results]);

  async function runSingle(checkId: string) {
    const target = checks.find(item => item.id === checkId);
    if (!target) {
      return;
    }

    setResults(current => ({
      ...current,
      [checkId]: {
        status: 'running',
        detail: `Running ${target.type} check...`,
      },
    }));

    try {
      const result = await target.run();
      setResults(current => ({
        ...current,
        [checkId]: result,
      }));
    } catch (error) {
      setResults(current => ({
        ...current,
        [checkId]: toFailureResult(error),
      }));
    }
  }

  async function runAll() {
    setRunningAll(true);
    for (const item of checks) {
      // Sequential checks prevent auth/rate-limit skew.
      // eslint-disable-next-line no-await-in-loop
      await runSingle(item.id);
    }
    setRunningAll(false);
  }

  if (authStatus === 'anonymous') {
    return (
      <div className="min-h-screen bg-[#07080D] px-6 py-16 text-white">
        <div className="mx-auto max-w-3xl rounded-2xl border border-white/10 bg-white/[0.03] p-8">
          <h1 className="mb-3 text-3xl font-bold">UI Wiring Checklist</h1>
          <p className="mb-6 text-slate-300">
            Sign in to validate protected route and API wiring with tenant and role context.
          </p>
          <a
            href={loginUrl}
            className="inline-flex rounded-lg bg-cyan-600 px-5 py-2.5 font-medium hover:bg-cyan-500"
          >
            Continue To Secure Login
          </a>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#07080D] px-4 py-8 text-white sm:px-6">
      <div className="mx-auto max-w-7xl space-y-6">
        <header className="rounded-2xl border border-white/10 bg-white/[0.03] p-5 sm:p-6">
          <p className="mb-2 text-xs uppercase tracking-[0.2em] text-cyan-300">Pre-Phase-3 QA</p>
          <h1 className="mb-2 text-3xl font-bold">UI Wiring Checklist</h1>
          <p className="text-sm text-slate-300">
            Button-by-button route and API parity verification for homepage and platform modules.
          </p>
          <p className="mt-3 text-sm text-slate-200">
            Tenant <span className="font-semibold">{tenant}</span> | Role{' '}
            <span className="font-semibold">{roleLabels[role]}</span>
          </p>
        </header>

        <section className="grid gap-4 sm:grid-cols-4">
          <article className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
            <p className="mb-1 text-xs text-slate-400">Total Checks</p>
            <p className="text-2xl font-bold">{totals.total}</p>
          </article>
          <article className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
            <p className="mb-1 text-xs text-slate-400">Passing</p>
            <p className="text-2xl font-bold text-emerald-300">{totals.pass}</p>
          </article>
          <article className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
            <p className="mb-1 text-xs text-slate-400">Failing</p>
            <p className="text-2xl font-bold text-red-300">{totals.fail}</p>
          </article>
          <article className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
            <p className="mb-1 text-xs text-slate-400">Running</p>
            <p className="text-2xl font-bold text-cyan-200">{totals.running}</p>
          </article>
        </section>

        <div className="flex flex-wrap gap-3">
          <button
            type="button"
            onClick={() => void runAll()}
            disabled={runningAll}
            className="inline-flex items-center gap-2 rounded-lg border border-cyan-300/30 bg-cyan-400/10 px-4 py-2 text-sm hover:bg-cyan-400/15 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {runningAll ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
            Run All Checks
          </button>
          <Link to="/diagnostics" className="inline-flex rounded-lg border border-amber-300/30 bg-amber-400/10 px-4 py-2 text-sm hover:bg-amber-400/15">
            Diagnostics
          </Link>
          <Link to="/status" className="inline-flex rounded-lg border border-white/20 bg-white/[0.04] px-4 py-2 text-sm hover:bg-white/[0.08]">
            Status
          </Link>
          <Link to="/qa/ui-checklist" className="inline-flex rounded-lg border border-white/20 bg-white/[0.04] px-4 py-2 text-sm hover:bg-white/[0.08]">
            Legacy UI Checklist
          </Link>
          <Link to="/" className="inline-flex rounded-lg border border-white/20 bg-white/[0.04] px-4 py-2 text-sm hover:bg-white/[0.08]">
            Back To Landing
          </Link>
        </div>

        <section className="space-y-3">
          {checks.map(item => {
            const result = results[item.id] || { status: 'idle' as const, detail: 'Not run yet.' };
            const icon =
              result.status === 'pass' ? (
                <CheckCircle2 className="h-4 w-4 text-emerald-300" />
              ) : result.status === 'fail' ? (
                <XCircle className="h-4 w-4 text-red-300" />
              ) : result.status === 'running' ? (
                <Loader2 className="h-4 w-4 animate-spin text-cyan-200" />
              ) : null;

            return (
              <article key={item.id} className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
                <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                  <div className="space-y-1.5">
                    <p className="font-semibold">{item.label}</p>
                    <p className="text-xs text-slate-400">Target: {item.target}</p>
                    <p className="text-xs text-slate-400">Requirements: {item.requirements}</p>
                    <p className="flex items-center gap-2 text-sm text-slate-200">
                      {icon}
                      {result.detail}
                    </p>
                  </div>

                  <button
                    type="button"
                    onClick={() => void runSingle(item.id)}
                    disabled={result.status === 'running' || runningAll}
                    className="inline-flex items-center gap-2 rounded-lg border border-cyan-300/30 bg-cyan-400/10 px-3 py-2 text-sm hover:bg-cyan-400/15 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {result.status === 'running' ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Play className="h-4 w-4" />
                    )}
                    Run Check
                  </button>
                </div>
              </article>
            );
          })}
        </section>
      </div>
    </div>
  );
}
