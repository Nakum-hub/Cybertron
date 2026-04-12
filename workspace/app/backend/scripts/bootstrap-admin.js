#!/usr/bin/env node

const bcrypt = require('bcryptjs');

const { config } = require('../src/config');
const { withClient, closeDatabase } = require('../src/database');
const { appendAuditLog } = require('../src/audit-log');
const { sanitizeTenant } = require('../src/validators');
const { normalizeRole, listRoles } = require('../src/security-policy');

const LEGACY_ROLE_ALIASES = new Set([
  'client',
  'viewer',
  'analyst',
  'operator',
  'admin',
  'executive',
]);

function parseArgs(argv) {
  const args = {};

  for (let index = 0; index < argv.length; index += 1) {
    const token = String(argv[index] || '');
    if (!token.startsWith('--')) {
      continue;
    }

    const key = token.slice(2);
    const next = argv[index + 1];
    if (next && !String(next).startsWith('--')) {
      args[key] = String(next);
      index += 1;
      continue;
    }

    args[key] = 'true';
  }

  return args;
}

function usage() {
  return [
    'Usage:',
    '  node scripts/bootstrap-admin.js --password <strong-password> [options]',
    '',
    'Options:',
    '  --email <value>        Admin email (default: admin@cybertron.local)',
    '  --tenant <value>       Tenant slug (default: global)',
    '  --display-name <value> Display name (default: existing value or Cybertron Admin)',
    '  --role <value>         Role (default: existing value or tenant_admin)',
    '',
    'Environment fallbacks:',
    '  BOOTSTRAP_ADMIN_PASSWORD, BOOTSTRAP_ADMIN_EMAIL, BOOTSTRAP_ADMIN_TENANT,',
    '  BOOTSTRAP_ADMIN_DISPLAY_NAME, BOOTSTRAP_ADMIN_ROLE',
  ].join('\n');
}

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function resolveRole(input, existingRole) {
  const rawValue = String(input || '').trim().toLowerCase();
  if (!rawValue) {
    return normalizeRole(existingRole || 'tenant_admin');
  }

  const normalized = normalizeRole(rawValue);
  const acceptedRole =
    listRoles().includes(rawValue) ||
    LEGACY_ROLE_ALIASES.has(rawValue) ||
    listRoles().includes(normalized);

  if (!acceptedRole) {
    throw new Error(
      `Invalid role "${rawValue}". Expected one of: ${[...listRoles(), ...LEGACY_ROLE_ALIASES].join(', ')}`
    );
  }

  return normalized;
}

async function run() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help === 'true') {
    process.stdout.write(`${usage()}\n`);
    return;
  }

  if (!config.databaseUrl) {
    throw new Error('DATABASE_URL is not configured. Admin bootstrap requires a real database.');
  }

  const email = normalizeEmail(args.email || process.env.BOOTSTRAP_ADMIN_EMAIL || 'admin@cybertron.local');
  const password = String(args.password || process.env.BOOTSTRAP_ADMIN_PASSWORD || '');
  const tenant = sanitizeTenant(args.tenant || process.env.BOOTSTRAP_ADMIN_TENANT || 'global');

  if (!email || !email.includes('@')) {
    throw new Error('A valid admin email is required.');
  }

  if (password.length < 10) {
    throw new Error('Admin password must be at least 10 characters long.');
  }

  const passwordHash = await bcrypt.hash(password, Math.max(10, Number(config.passwordHashRounds || 12)));
  const traceId = `bootstrap-admin-${Date.now()}`;

  const result = await withClient(config, async client => {
    await client.query('BEGIN');

    try {
      await client.query(
        `
          INSERT INTO tenants (slug, name)
          VALUES ($1, $2)
          ON CONFLICT (slug) DO NOTHING
        `,
        [tenant, tenant === 'global' ? 'Global Tenant' : `Tenant ${tenant}`]
      );

      const existingResult = await client.query(
        `
          SELECT id, tenant_slug, email, display_name, role, is_active, password_hash
          FROM users
          WHERE tenant_slug = $1 AND email = $2
          LIMIT 1
        `,
        [tenant, email]
      );

      const existingUser = existingResult.rows[0] || null;
      const resolvedRole = resolveRole(args.role || process.env.BOOTSTRAP_ADMIN_ROLE, existingUser?.role);
      const displayName = String(
        args['display-name'] ||
        process.env.BOOTSTRAP_ADMIN_DISPLAY_NAME ||
        existingUser?.display_name ||
        'Cybertron Admin'
      ).trim().slice(0, 191);

      let user;
      let action;

      if (existingUser) {
        const updated = await client.query(
          `
            UPDATE users
            SET
              display_name = $2,
              role = $3,
              is_active = TRUE,
              password_hash = $4,
              failed_login_count = 0,
              locked_until = NULL
            WHERE id = $1
            RETURNING id, tenant_slug, email, display_name, role, is_active
          `,
          [existingUser.id, displayName, resolvedRole, passwordHash]
        );
        user = updated.rows[0];
        action = existingUser.password_hash ? 'rotated_existing_admin_password' : 'initialized_existing_admin_password';
      } else {
        const inserted = await client.query(
          `
            INSERT INTO users (
              tenant_slug,
              email,
              display_name,
              role,
              is_active,
              password_hash
            )
            VALUES ($1,$2,$3,$4,TRUE,$5)
            RETURNING id, tenant_slug, email, display_name, role, is_active
          `,
          [tenant, email, displayName || email, resolvedRole, passwordHash]
        );
        user = inserted.rows[0];
        action = 'created_admin_user';
      }

      await client.query('COMMIT');

      return {
        user,
        action,
      };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    }
  });

  await appendAuditLog(config, {
    tenantSlug: tenant,
    actorId: 'bootstrap-admin-cli',
    actorEmail: email,
    action: 'auth.admin_bootstrap',
    targetType: 'user',
    targetId: String(result.user.id),
    traceId,
    payload: {
      bootstrapAction: result.action,
      role: result.user.role,
      cli: true,
    },
  });

  process.stdout.write(
    [
      'Admin bootstrap completed.',
      `tenant=${result.user.tenant_slug}`,
      `email=${result.user.email}`,
      `role=${result.user.role}`,
      `userId=${result.user.id}`,
      `action=${result.action}`,
    ].join('\n') + '\n'
  );
}

run()
  .catch(error => {
    process.stderr.write(`${error instanceof Error ? error.message : 'Admin bootstrap failed.'}\n`);
    process.stderr.write(`${usage()}\n`);
    process.exitCode = 1;
  })
  .finally(async () => {
    try {
      await closeDatabase();
    } catch {
      // ignore close errors in CLI
    }
  });
