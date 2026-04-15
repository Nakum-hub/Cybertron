/**
 * P1-1: Email Transport Service
 *
 * Provides email sending via multiple providers:
 * - console: Logs emails to stdout (development)
 * - resend: Resend SDK (production recommended)
 * - smtp: Nodemailer SMTP transport (self-hosted deployments)
 *
 * Usage:
 *   const { sendPasswordResetEmail, sendWelcomeEmail } = require('./email-service');
 *   await sendPasswordResetEmail(config, { to, resetUrl, tenantName });
 */

const { ServiceError } = require('./auth-service');

/**
 * Resolve the active email transport based on config.emailProvider.
 * Returns an object with a `send(options)` method.
 */
function resolveTransport(config) {
  const provider = String(config.emailProvider || 'console').toLowerCase().trim();

  if (provider === 'resend') {
    return createResendTransport(config);
  }

  if (provider === 'smtp') {
    return createSmtpTransport(config);
  }

  // Default: console transport for development
  return createConsoleTransport();
}

function createConsoleTransport() {
  return {
    name: 'console',
    async send({ to, subject, html, text }) {
      console.log('[email:console] ════════════════════════════════════════');
      console.log(`  To:      ${to}`);
      console.log(`  Subject: ${subject}`);
      if (text) {
        console.log(`  Body:    ${text.slice(0, 500)}`);
      }
      console.log('[email:console] ════════════════════════════════════════');
      return { provider: 'console', messageId: `console-${Date.now()}` };
    },
  };
}

function createResendTransport(config) {
  let Resend;
  try {
    Resend = require('resend').Resend;
  } catch {
    console.warn('[email] resend package not installed. Run: npm install resend');
    return createConsoleTransport();
  }

  const apiKey = String(config.resendApiKey || '').trim();
  if (!apiKey) {
    console.warn('[email] RESEND_API_KEY is not set. Falling back to console transport.');
    return createConsoleTransport();
  }

  const client = new Resend(apiKey);
  const fromAddress = config.emailFromAddress || 'noreply@cybertron.io';
  const fromName = config.emailFromName || 'Cybertron';

  return {
    name: 'resend',
    async send({ to, subject, html, text }) {
      const result = await client.emails.send({
        from: `${fromName} <${fromAddress}>`,
        to: [to],
        subject,
        html: html || undefined,
        text: text || undefined,
      });

      if (result.error) {
        throw new Error(`Resend error: ${result.error.message || JSON.stringify(result.error)}`);
      }

      return { provider: 'resend', messageId: result.data?.id || 'unknown' };
    },
  };
}

function createSmtpTransport(config) {
  let nodemailer;
  try {
    nodemailer = require('nodemailer');
  } catch {
    console.warn('[email] nodemailer package not installed. Run: npm install nodemailer');
    return createConsoleTransport();
  }

  const host = String(config.smtpHost || '').trim();
  if (!host) {
    console.warn('[email] SMTP_HOST is not set. Falling back to console transport.');
    return createConsoleTransport();
  }

  const transporter = nodemailer.createTransport({
    host,
    port: Number(config.smtpPort) || 587,
    secure: Boolean(config.smtpSecure),
    auth: config.smtpUser
      ? { user: config.smtpUser, pass: config.smtpPass || '' }
      : undefined,
  });

  const fromAddress = config.emailFromAddress || 'noreply@cybertron.io';
  const fromName = config.emailFromName || 'Cybertron';

  return {
    name: 'smtp',
    async send({ to, subject, html, text }) {
      const info = await transporter.sendMail({
        from: `"${fromName}" <${fromAddress}>`,
        to,
        subject,
        html: html || undefined,
        text: text || undefined,
      });

      return { provider: 'smtp', messageId: info.messageId || 'unknown' };
    },
  };
}

/**
 * Send with retry logic (2 retries on failure).
 */
async function sendWithRetry(transport, options, maxRetries = 2) {
  let lastError;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await transport.send(options);
    } catch (error) {
      lastError = error;
      if (attempt < maxRetries) {
        await new Promise(resolve => setTimeout(resolve, 500 * (attempt + 1)));
      }
    }
  }

  throw new ServiceError(
    503,
    'email_unavailable',
    `Email send failed after ${maxRetries + 1} attempts: ${lastError?.message || 'unknown error'}`
  );
}

// ─── Public Email Functions ────────────────────────────────────────────

async function sendPasswordResetEmail(config, { to, resetUrl, tenantName }) {
  const transport = resolveTransport(config);

  if (transport.name === 'console' && config.emailProvider !== 'console') {
    console.warn('[email] Password reset email not sent — email provider not configured.');
    return;
  }

  const subject = `Reset your ${tenantName || 'Cybertron'} password`;
  const html = `
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 520px; margin: 0 auto;">
      <h2 style="color: #0f172a;">Password Reset</h2>
      <p>You requested a password reset for your <strong>${tenantName || 'Cybertron'}</strong> account.</p>
      <p>Click the link below to set a new password. This link expires in 30 minutes.</p>
      <p style="margin: 24px 0;">
        <a href="${resetUrl}" style="background: #0891b2; color: white; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: 600;">
          Reset Password
        </a>
      </p>
      <p style="color: #64748b; font-size: 13px;">If you did not request this, you can safely ignore this email.</p>
      <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 24px 0;" />
      <p style="color: #94a3b8; font-size: 12px;">Cybertron Security Platform</p>
    </div>
  `;
  const text = `Password Reset\n\nYou requested a password reset for your ${tenantName || 'Cybertron'} account.\n\nReset your password: ${resetUrl}\n\nThis link expires in 30 minutes. If you did not request this, ignore this email.`;

  await sendWithRetry(transport, { to, subject, html, text });
}

async function sendWelcomeEmail(config, { to, displayName, loginUrl }) {
  const transport = resolveTransport(config);

  if (transport.name === 'console' && config.emailProvider !== 'console') {
    return;
  }

  const subject = 'Welcome to Cybertron';
  const html = `
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 520px; margin: 0 auto;">
      <h2 style="color: #0f172a;">Welcome, ${displayName || 'there'}!</h2>
      <p>Your Cybertron workspace is ready. Sign in to get started:</p>
      <p style="margin: 24px 0;">
        <a href="${loginUrl}" style="background: #0891b2; color: white; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: 600;">
          Open Cybertron
        </a>
      </p>
      <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 24px 0;" />
      <p style="color: #94a3b8; font-size: 12px;">Cybertron Security Platform</p>
    </div>
  `;
  const text = `Welcome to Cybertron, ${displayName || 'there'}!\n\nYour workspace is ready. Sign in: ${loginUrl}`;

  await sendWithRetry(transport, { to, subject, html, text });
}

async function sendWorkspaceInviteEmail(config, { to, inviterName, workspaceName, inviteUrl }) {
  const transport = resolveTransport(config);

  if (transport.name === 'console' && config.emailProvider !== 'console') {
    return;
  }

  const subject = `You're invited to join ${workspaceName} on Cybertron`;
  const html = `
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 520px; margin: 0 auto;">
      <h2 style="color: #0f172a;">Workspace Invitation</h2>
      <p><strong>${inviterName}</strong> has invited you to join the <strong>${workspaceName}</strong> workspace on Cybertron.</p>
      <p style="margin: 24px 0;">
        <a href="${inviteUrl}" style="background: #0891b2; color: white; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: 600;">
          Accept Invitation
        </a>
      </p>
      <p style="color: #64748b; font-size: 13px;">This invitation will expire in 7 days.</p>
      <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 24px 0;" />
      <p style="color: #94a3b8; font-size: 12px;">Cybertron Security Platform</p>
    </div>
  `;
  const text = `${inviterName} has invited you to join ${workspaceName} on Cybertron.\n\nAccept invitation: ${inviteUrl}\n\nThis invitation expires in 7 days.`;

  await sendWithRetry(transport, { to, subject, html, text });
}

async function sendAlertEscalationEmail(config, { to, alertTitle, severity, alertUrl }) {
  const transport = resolveTransport(config);

  if (transport.name === 'console' && config.emailProvider !== 'console') {
    return;
  }

  const subject = `[${severity?.toUpperCase() || 'ALERT'}] Escalated: ${alertTitle}`;
  const html = `
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 520px; margin: 0 auto;">
      <h2 style="color: #dc2626;">Alert Escalation</h2>
      <p>The following alert has been escalated and requires your attention:</p>
      <div style="background: #fef2f2; border-left: 4px solid #dc2626; padding: 12px 16px; margin: 16px 0; border-radius: 4px;">
        <p style="margin: 0; font-weight: 600;">${alertTitle}</p>
        <p style="margin: 4px 0 0; color: #991b1b; font-size: 13px;">Severity: ${severity || 'unknown'}</p>
      </div>
      <p style="margin: 24px 0;">
        <a href="${alertUrl}" style="background: #dc2626; color: white; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: 600;">
          View Alert
        </a>
      </p>
      <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 24px 0;" />
      <p style="color: #94a3b8; font-size: 12px;">Cybertron Security Platform</p>
    </div>
  `;
  const text = `ALERT ESCALATION\n\n${alertTitle}\nSeverity: ${severity || 'unknown'}\n\nView alert: ${alertUrl}`;

  await sendWithRetry(transport, { to, subject, html, text });
}

module.exports = {
  sendPasswordResetEmail,
  sendWelcomeEmail,
  sendWorkspaceInviteEmail,
  sendAlertEscalationEmail,
};
