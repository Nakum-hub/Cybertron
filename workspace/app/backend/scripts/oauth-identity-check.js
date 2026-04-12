#!/usr/bin/env node

const { config } = require('../src/config');
const { closeDatabase } = require('../src/database');
const { findOrCreateOAuthUser, registerUser, ServiceError } = require('../src/auth-service');

function assertCondition(condition, label) {
  if (!condition) {
    throw new Error(`Assertion failed: ${label}`);
  }

  process.stdout.write(`PASS: ${label}\n`);
}

function buildTenantSlug(prefix = 'oauth') {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, '-');
}

async function main() {
  if (!config.databaseUrl) {
    throw new Error('DATABASE_URL is required for oauth identity checks.');
  }

  const providerSubject = `github-oauth-${Date.now()}`;
  const tenantA = buildTenantSlug('oauth-a');
  const tenantB = buildTenantSlug('oauth-b');

  const first = await findOrCreateOAuthUser(
    config,
    {
      tenant: tenantA,
      email: `oauth.owner.${Date.now()}@cybertron.local`,
      displayName: 'OAuth Owner',
      provider: 'github',
      providerId: providerSubject,
      emailVerified: true,
    },
    { isAdmin: false }
  );
  assertCondition(first.created === true, 'oauth external identity can create its first workspace');

  const repeat = await findOrCreateOAuthUser(
    config,
    {
      tenant: tenantA,
      email: `oauth.alias.${Date.now()}@cybertron.local`,
      displayName: 'OAuth Alias',
      provider: 'github',
      providerId: providerSubject,
      emailVerified: true,
    },
    { isAdmin: false }
  );
  assertCondition(repeat.created === false, 'oauth repeat login reuses linked external identity');
  assertCondition(repeat.user.id === first.user.id, 'oauth repeat login resolves to the original linked user');

  let blocked = false;
  try {
    await findOrCreateOAuthUser(
      config,
      {
        tenant: tenantB,
        email: `oauth.other.${Date.now()}@cybertron.local`,
        displayName: 'OAuth Other Workspace',
        provider: 'github',
        providerId: providerSubject,
        emailVerified: true,
      },
      { isAdmin: false }
    );
  } catch (error) {
    assertCondition(error instanceof ServiceError, 'oauth second-workspace conflict throws service error');
    assertCondition(
      error.code === 'external_identity_workspace_limit_reached',
      'oauth external identity cannot bootstrap a second workspace'
    );
    blocked = true;
  }
  assertCondition(blocked, 'oauth external identity second-workspace attempt is blocked');

  let unverifiedBlocked = false;
  try {
    await findOrCreateOAuthUser(
      config,
      {
        tenant: buildTenantSlug('oauth-unverified'),
        email: `oauth.unverified.${Date.now()}@cybertron.local`,
        displayName: 'OAuth Unverified',
        provider: 'github',
        providerId: `github-unverified-${Date.now()}`,
        emailVerified: false,
      },
      { isAdmin: false }
    );
  } catch (error) {
    assertCondition(error instanceof ServiceError, 'oauth unverified email throws service error');
    assertCondition(
      error.code === 'oauth_email_not_verified',
      'oauth unverified email is rejected'
    );
    unverifiedBlocked = true;
  }
  assertCondition(unverifiedBlocked, 'oauth provider accounts require verified email');

  const sharedFingerprint = `fp-${Date.now()}-shared-bootstrap-device`;
  const fingerprintTenantA = buildTenantSlug('fingerprint-a');
  const fingerprintTenantB = buildTenantSlug('fingerprint-b');

  const passwordBootstrap = await registerUser(
    config,
    {
      tenant: fingerprintTenantA,
      email: `fingerprint.password.${Date.now()}@cybertron.local`,
      password: `StrongPass!${Date.now()}`,
      displayName: 'Fingerprint Password Bootstrap',
    },
    {
      isAdmin: false,
      publicFingerprint: sharedFingerprint,
      ipAddress: '198.51.100.21',
    }
  );
  assertCondition(
    passwordBootstrap.tenant === fingerprintTenantA,
    'password bootstrap succeeds with a new device fingerprint'
  );

  let fingerprintBlocked = false;
  try {
    await findOrCreateOAuthUser(
      config,
      {
        tenant: fingerprintTenantB,
        email: `fingerprint.oauth.${Date.now()}@cybertron.local`,
        displayName: 'Fingerprint OAuth Bootstrap',
        provider: 'google',
        providerId: `google-fingerprint-${Date.now()}`,
        emailVerified: true,
      },
      {
        isAdmin: false,
        publicFingerprint: sharedFingerprint,
        ipAddress: '198.51.100.21',
      }
    );
  } catch (error) {
    assertCondition(error instanceof ServiceError, 'fingerprint limit throws service error');
    assertCondition(
      error.code === 'workspace_creation_device_limit_reached',
      'same browser fingerprint cannot bootstrap a second free workspace across auth methods'
    );
    fingerprintBlocked = true;
  }
  assertCondition(fingerprintBlocked, 'device fingerprint workspace bootstrap limit is enforced');

  const networkIp = '198.51.100.88';
  for (let index = 0; index < Math.max(1, Number(config.maxWorkspaceBootstrapsPerNetwork || 3)); index += 1) {
    const fingerprint = `fp-${Date.now()}-network-${index}`;
    await registerUser(
      config,
      {
        tenant: buildTenantSlug(`network-${index}`),
        email: `network.${index}.${Date.now()}@cybertron.local`,
        password: `StrongPass!${Date.now()}${index}`,
        displayName: `Network Bootstrap ${index}`,
      },
      {
        isAdmin: false,
        publicFingerprint: fingerprint,
        ipAddress: networkIp,
      }
    );
  }

  let networkBlocked = false;
  try {
    await registerUser(
      config,
      {
        tenant: buildTenantSlug('network-overflow'),
        email: `network.overflow.${Date.now()}@cybertron.local`,
        password: `StrongPass!${Date.now()}overflow`,
        displayName: 'Network Overflow',
      },
      {
        isAdmin: false,
        publicFingerprint: `fp-${Date.now()}-network-overflow`,
        ipAddress: networkIp,
      }
    );
  } catch (error) {
    assertCondition(error instanceof ServiceError, 'network limit throws service error');
    assertCondition(
      error.code === 'workspace_creation_network_limit_reached',
      'same network cannot bootstrap unlimited free workspaces'
    );
    networkBlocked = true;
  }
  assertCondition(networkBlocked, 'network workspace bootstrap limit is enforced');
}

main()
  .then(async () => {
    await closeDatabase();
  })
  .catch(async error => {
    await closeDatabase().catch(() => {});
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
