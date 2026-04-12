-- LLM feature flags must gate only LLM-powered endpoints, not entire product access.
-- Product routing/access remains controlled by product_* flags and product enablement.

DELETE FROM product_feature_flags
WHERE flag_key = 'llm_features_enabled'
  AND product_key IN ('risk-copilot', 'resilience-hq', 'threat-command');
