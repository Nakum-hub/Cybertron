-- Enable Risk Copilot globally now that Phase 3 product implementation is active.
-- Phase 2 kept this product behind a beta gate; Phase 3 promotes it to enabled-by-default.

UPDATE products
SET
  enabled = TRUE,
  is_active = TRUE
WHERE product_id = 'risk-copilot'
   OR product_key = 'risk-copilot';

UPDATE product_feature_flags
SET enabled_by_default = TRUE
WHERE product_key = 'risk-copilot'
  AND flag_key = 'risk_copilot_beta';

INSERT INTO feature_flags (flag_key, description)
VALUES
  ('risk_copilot_beta', 'Enable risk copilot module access')
ON CONFLICT (flag_key) DO NOTHING;
