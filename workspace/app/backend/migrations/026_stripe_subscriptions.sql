-- P1-4: Stripe subscription tracking columns on tenants table
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS
  stripe_customer_id VARCHAR(64);
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS
  stripe_subscription_id VARCHAR(64);
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS
  stripe_subscription_status VARCHAR(32) DEFAULT 'none';
