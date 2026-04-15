/**
 * P1-4: Stripe Billing Service
 *
 * Handles Stripe Checkout sessions, webhook processing,
 * and subscription status tracking.
 */

const { ServiceError } = require('./auth-service');
const { query } = require('./database');

function getStripeClient(config) {
  const key = String(config.stripeSecretKey || '').trim();
  if (!key) {
    return null;
  }

  let stripe;
  try {
    stripe = require('stripe');
  } catch {
    console.warn('[stripe] stripe package not installed. Run: npm install stripe');
    return null;
  }

  return stripe(key, { apiVersion: '2024-06-20' });
}

function resolvePriceId(config, planKey, billingCycle) {
  if (planKey === 'pro' && billingCycle === 'annual') {
    return config.stripePriceIdProAnnual;
  }
  if (planKey === 'pro') {
    return config.stripePriceIdProMonthly;
  }
  if (planKey === 'enterprise') {
    return config.stripePriceIdEnterpriseMonthly;
  }
  return '';
}

async function createCheckoutSession(config, { tenant, priceId, successUrl, cancelUrl }) {
  const stripe = getStripeClient(config);
  if (!stripe) {
    throw new ServiceError(503, 'stripe_not_configured', 'Stripe is not configured. Set STRIPE_SECRET_KEY.');
  }

  if (!priceId) {
    throw new ServiceError(400, 'invalid_price_id', 'A valid Stripe price ID is required.');
  }

  // Look up or create the Stripe customer for this tenant
  const tenantResult = await query(config, 'SELECT stripe_customer_id, slug, name FROM tenants WHERE slug = $1', [tenant]);
  const tenantRow = tenantResult?.rows?.[0];
  if (!tenantRow) {
    throw new ServiceError(404, 'tenant_not_found', 'Tenant not found.');
  }

  let customerId = tenantRow.stripe_customer_id;
  if (!customerId) {
    const customer = await stripe.customers.create({
      metadata: { tenant_slug: tenant },
      name: tenantRow.name || tenant,
    });
    customerId = customer.id;
    await query(config, 'UPDATE tenants SET stripe_customer_id = $1 WHERE slug = $2', [customerId, tenant]);
  }

  const session = await stripe.checkout.sessions.create({
    customer: customerId,
    mode: 'subscription',
    line_items: [{ price: priceId, quantity: 1 }],
    success_url: successUrl || `${config.frontendOrigin}/billing/success?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: cancelUrl || `${config.frontendOrigin}/billing/cancel`,
    metadata: { tenant_slug: tenant },
  });

  return { sessionId: session.id, url: session.url };
}

async function handleWebhookEvent(config, rawBody, signature) {
  const stripe = getStripeClient(config);
  if (!stripe) {
    throw new ServiceError(503, 'stripe_not_configured', 'Stripe is not configured.');
  }

  const webhookSecret = String(config.stripeWebhookSecret || '').trim();
  if (!webhookSecret) {
    throw new ServiceError(500, 'webhook_secret_missing', 'STRIPE_WEBHOOK_SECRET is not set.');
  }

  let event;
  try {
    event = stripe.webhooks.constructEvent(rawBody, signature, webhookSecret);
  } catch (err) {
    throw new ServiceError(400, 'webhook_signature_invalid', `Webhook signature verification failed: ${err.message}`);
  }

  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object;
      const tenantSlug = session.metadata?.tenant_slug;
      if (tenantSlug && session.subscription) {
        await query(
          config,
          `UPDATE tenants SET stripe_subscription_id = $1, stripe_subscription_status = 'active' WHERE slug = $2`,
          [String(session.subscription), tenantSlug]
        );
        // Upgrade tenant plan to pro
        await query(
          config,
          `UPDATE tenant_plans SET tier = 'pro', active_since = NOW() WHERE tenant_slug = $1`,
          [tenantSlug]
        );
      }
      break;
    }

    case 'customer.subscription.updated': {
      const subscription = event.data.object;
      const customerId = subscription.customer;
      await query(
        config,
        `UPDATE tenants SET stripe_subscription_status = $1 WHERE stripe_customer_id = $2`,
        [subscription.status, customerId]
      );
      break;
    }

    case 'customer.subscription.deleted': {
      const subscription = event.data.object;
      const customerId = subscription.customer;
      await query(
        config,
        `UPDATE tenants SET stripe_subscription_status = 'canceled', stripe_subscription_id = NULL WHERE stripe_customer_id = $1`,
        [customerId]
      );
      // Revert to free plan
      const tenantResult = await query(config, 'SELECT slug FROM tenants WHERE stripe_customer_id = $1', [customerId]);
      const slug = tenantResult?.rows?.[0]?.slug;
      if (slug) {
        await query(config, `UPDATE tenant_plans SET tier = 'free', active_since = NOW() WHERE tenant_slug = $1`, [slug]);
      }
      break;
    }

    case 'invoice.payment_failed': {
      const invoice = event.data.object;
      const customerId = invoice.customer;
      await query(
        config,
        `UPDATE tenants SET stripe_subscription_status = 'past_due' WHERE stripe_customer_id = $1`,
        [customerId]
      );
      break;
    }

    default:
      // Unhandled event type — log but do not error
      break;
  }

  return { received: true, type: event.type };
}

async function getSubscriptionStatus(config, tenant) {
  const result = await query(
    config,
    `SELECT stripe_customer_id, stripe_subscription_id, stripe_subscription_status FROM tenants WHERE slug = $1`,
    [tenant]
  );
  const row = result?.rows?.[0];
  if (!row) {
    return { status: 'none', customerId: null, subscriptionId: null };
  }
  return {
    status: row.stripe_subscription_status || 'none',
    customerId: row.stripe_customer_id || null,
    subscriptionId: row.stripe_subscription_id || null,
  };
}

module.exports = {
  createCheckoutSession,
  handleWebhookEvent,
  getSubscriptionStatus,
  resolvePriceId,
};
