/**
 * P1-8: Workspace Invite Service
 *
 * Handles creating, accepting, listing, and revoking workspace invites.
 */

const crypto = require('node:crypto');
const { ServiceError } = require('./auth-service');
const { query } = require('./database');
const { sendWorkspaceInviteEmail } = require('./email-service');

function hashToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

async function createInvite(config, { tenant, email, role, invitedByUserId }) {
  if (!email || !email.includes('@')) {
    throw new ServiceError(400, 'invalid_email', 'A valid email address is required.');
  }

  const normalizedEmail = email.trim().toLowerCase();
  const normalizedRole = role || 'executive_viewer';

  // Check for existing pending invite
  const existing = await query(
    config,
    `SELECT id FROM workspace_invites WHERE tenant_slug = $1 AND email = $2 AND accepted_at IS NULL AND expires_at > NOW()`,
    [tenant, normalizedEmail]
  );
  if (existing?.rows?.length) {
    throw new ServiceError(409, 'invite_already_pending', 'An invite is already pending for this email.');
  }

  const rawToken = crypto.randomBytes(32).toString('base64url');
  const tokenHash = hashToken(rawToken);
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

  const result = await query(
    config,
    `INSERT INTO workspace_invites (tenant_slug, email, role, token_hash, invited_by, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING id, created_at`,
    [tenant, normalizedEmail, normalizedRole, tokenHash, invitedByUserId || null, expiresAt.toISOString()]
  );

  const invite = result?.rows?.[0];

  // Send invite email
  const inviteUrl = `${config.frontendOrigin}/invites/${rawToken}/accept`;
  try {
    await sendWorkspaceInviteEmail(config, {
      to: normalizedEmail,
      inviterName: 'Your teammate',
      workspaceName: tenant,
      inviteUrl,
    });
  } catch (emailError) {
    console.warn('[invite] Failed to send invite email:', emailError.message);
  }

  return {
    inviteId: String(invite?.id),
    expiresAt: expiresAt.toISOString(),
  };
}

async function acceptInvite(config, { token, acceptingUserId }) {
  const tokenHash = hashToken(token);

  const result = await query(
    config,
    `SELECT id, tenant_slug, email, role, expires_at, accepted_at
     FROM workspace_invites
     WHERE token_hash = $1`,
    [tokenHash]
  );

  const invite = result?.rows?.[0];
  if (!invite) {
    throw new ServiceError(404, 'invite_not_found', 'Invitation not found or invalid.');
  }

  if (invite.accepted_at) {
    throw new ServiceError(410, 'invite_already_accepted', 'This invitation has already been accepted.');
  }

  if (new Date(invite.expires_at) < new Date()) {
    throw new ServiceError(410, 'invite_expired', 'This invitation has expired.');
  }

  // Mark as accepted
  await query(
    config,
    `UPDATE workspace_invites SET accepted_at = NOW() WHERE id = $1`,
    [invite.id]
  );

  return {
    tenantSlug: invite.tenant_slug,
    email: invite.email,
    role: invite.role,
  };
}

async function listInvites(config, tenant) {
  const result = await query(
    config,
    `SELECT id, email, role, expires_at, accepted_at, created_at
     FROM workspace_invites
     WHERE tenant_slug = $1
     ORDER BY created_at DESC
     LIMIT 100`,
    [tenant]
  );

  return result?.rows || [];
}

async function revokeInvite(config, tenant, inviteId) {
  const result = await query(
    config,
    `DELETE FROM workspace_invites WHERE id = $1 AND tenant_slug = $2 AND accepted_at IS NULL RETURNING id`,
    [Number(inviteId), tenant]
  );

  if (!result?.rows?.length) {
    throw new ServiceError(404, 'invite_not_found', 'Invite not found or already accepted.');
  }

  return { revoked: true };
}

module.exports = {
  createInvite,
  acceptInvite,
  listInvites,
  revokeInvite,
};
