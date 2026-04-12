-- Phase 3 access alignment:
-- Executive Viewer can open each AI product workspace in read-only mode.
-- Write actions remain enforced per-route by role guards.

UPDATE products
SET role_min = 'executive_viewer'
WHERE COALESCE(product_key, product_id) IN (
  'risk-copilot',
  'resilience-hq',
  'threat-command'
);

UPDATE tenant_products
SET role_min = 'executive_viewer',
    updated_at = NOW()
WHERE product_id IN (
  'risk-copilot',
  'resilience-hq',
  'threat-command'
)
  AND role_min IN ('security_analyst', 'compliance_officer');

UPDATE products
SET enabled = TRUE,
    is_active = TRUE
WHERE COALESCE(product_key, product_id) = 'risk-copilot';
