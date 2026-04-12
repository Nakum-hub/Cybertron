import { ApiError } from './api';
import { fetchAppStatus, fetchAuthProfile, type AuthUser } from './backend';
import { getConfig } from './config';
import { normalizeRole, roleLabels, type PlatformRole } from './platform-registry';

type AccessDetails = {
  requiredRole?: string;
  effectiveRole?: string;
};

export type WorkspaceNavigationIntent = {
  appId?: string;
  path: string;
  role: PlatformRole;
  tenant: string;
};

export type WorkspaceNavigationResolution =
  | {
      kind: 'navigate';
      target: string;
    }
  | {
      kind: 'login_redirect';
      target: string;
      returnTo: string;
    }
  | {
      kind: 'blocked';
      code: string;
      title: string;
      message: string;
      actionPath?: string;
      actionLabel?: string;
      details?: AccessDetails;
    }
  | {
      kind: 'error';
      code: string;
      message: string;
    };

function sanitizeInternalPath(value: string, fallback = '/platform'): string {
  const input = String(value || '').trim();
  if (!input || !input.startsWith('/') || input.startsWith('//')) {
    return fallback;
  }
  return input;
}

function safeTenant(value: string): string {
  const tenant = String(value || '').trim().toLowerCase();
  return tenant || 'global';
}

function toAccessDetails(value: unknown): AccessDetails {
  if (!value || typeof value !== 'object') {
    return {};
  }

  const details = value as Record<string, unknown>;
  const requiredRole = typeof details.requiredRole === 'string' ? details.requiredRole : undefined;
  const effectiveRole = typeof details.effectiveRole === 'string' ? details.effectiveRole : undefined;
  return {
    requiredRole,
    effectiveRole,
  };
}

function asRoleLabel(value: string | undefined): string {
  if (!value) {
    return 'Unknown role';
  }

  const normalized = normalizeRole(value);
  return roleLabels[normalized];
}

export function buildWorkspaceTarget(path: string, tenant: string, role: string): string {
  const safePath = sanitizeInternalPath(path);
  const url = new URL(safePath, window.location.origin);
  url.searchParams.set('tenant', safeTenant(tenant));
  url.searchParams.set('role', normalizeRole(role));
  return `${url.pathname}${url.search}`;
}

export function buildLoginEntryUrl(returnTo: string, tenant: string, role: string): string {
  const cfg = getConfig();
  const normalizedReturnTo = sanitizeInternalPath(returnTo, '/platform/threat-command');
  const normalizedRole = normalizeRole(role);
  const normalizedTenant = safeTenant(tenant);
  const directLoginEnabled = Boolean(cfg.authLoginUrl) || (cfg.authMode === 'demo' && cfg.demoAuthEnabled);

  if (directLoginEnabled) {
    const base = cfg.authLoginUrl || `${cfg.apiBaseUrl}${cfg.authLoginPath}`;
    const loginUrl = new URL(base, window.location.origin);
    loginUrl.searchParams.set('role', normalizedRole);
    loginUrl.searchParams.set('tenant', normalizedTenant);
    loginUrl.searchParams.set('redirect', normalizedReturnTo);
    return loginUrl.toString();
  }

  const localLogin = new URL('/', window.location.origin);
  localLogin.searchParams.set('returnTo', normalizedReturnTo);
  localLogin.searchParams.set('tenant', normalizedTenant);
  localLogin.searchParams.set('role', normalizedRole);
  return `${localLogin.pathname}${localLogin.search}#auth`;
}

export function resolveReturnToFromLocation(defaultPath: string): string {
  if (typeof window === 'undefined') {
    return sanitizeInternalPath(defaultPath, '/platform/threat-command');
  }

  const params = new URLSearchParams(window.location.search);
  const requested = params.get('returnTo');
  return sanitizeInternalPath(requested || defaultPath, '/platform/threat-command');
}

async function fetchSessionProfile(): Promise<AuthUser | null> {
  try {
    return await fetchAuthProfile();
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      return null;
    }
    throw error;
  }
}

function resolveBlockedOutcome(error: ApiError): WorkspaceNavigationResolution {
  const details = toAccessDetails(error.details);

  if (error.code === 'module_not_accessible') {
    return {
      kind: 'blocked',
      code: error.code,
      title: 'Product Disabled For Tenant',
      message:
        'This module is disabled, feature-gated, or not included in the selected plan for this tenant. Tenant Admin or Super Admin can resolve it through governance or billing controls.',
      actionPath: '/platform/resilience-hq',
      actionLabel: 'Open Product Governance',
      details,
    };
  }

  if (error.code === 'plan_upgrade_required') {
    return {
      kind: 'blocked',
      code: error.code,
      title: 'Plan Upgrade Required',
      message: error.message || 'The selected tenant plan does not include this module.',
      actionPath: '/pricing',
      actionLabel: 'Review Plans',
      details,
    };
  }

  if (error.code === 'billing_quota_exhausted') {
    return {
      kind: 'blocked',
      code: error.code,
      title: 'Free Plan Quota Exhausted',
      message:
        error.message ||
        'The current plan quota is exhausted for this billing window. Upgrade to continue using Cybertron.',
      actionPath: '/pricing',
      actionLabel: 'Upgrade Plan',
      details,
    };
  }

  if (error.code === 'access_denied' || error.code === 'role_scope_denied') {
    return {
      kind: 'blocked',
      code: error.code || 'access_denied',
      title: 'Insufficient Role',
      message: `Current role ${asRoleLabel(details.effectiveRole)} cannot access this module. Required role is ${asRoleLabel(details.requiredRole)}.`,
      actionPath: '/platform',
      actionLabel: 'Open Platform Workspace',
      details,
    };
  }

  if (error.code === 'tenant_scope_denied') {
    return {
      kind: 'blocked',
      code: error.code,
      title: 'Tenant Scope Denied',
      message:
        'Requested tenant does not match your authenticated tenant scope. Switch tenant in workspace or request elevated access.',
      actionPath: '/platform',
      actionLabel: 'Open Platform Workspace',
      details,
    };
  }

  if (error.code === 'database_not_configured' || error.code === 'redis_not_configured') {
    return {
      kind: 'blocked',
      code: error.code,
      title: 'Platform Not Configured',
      message: 'Required backend dependencies are not configured. Open runtime status for exact setup steps.',
      actionPath: '/status',
      actionLabel: 'Open Status',
      details,
    };
  }

  return {
    kind: 'error',
    code: error.code || 'access_check_failed',
    message: error.message || 'Unable to validate workspace access.',
  };
}

export async function resolveWorkspaceNavigation(
  intent: WorkspaceNavigationIntent
): Promise<WorkspaceNavigationResolution> {
  if (typeof window === 'undefined') {
    return {
      kind: 'error',
      code: 'window_unavailable',
      message: 'Browser window is not available.',
    };
  }

  const target = buildWorkspaceTarget(intent.path, intent.tenant, intent.role);
  const normalizedPath = sanitizeInternalPath(intent.path);
  const targetsProtectedWorkspace =
    normalizedPath.startsWith('/platform') || normalizedPath.startsWith('/products');

  if (!intent.appId && !targetsProtectedWorkspace) {
    return {
      kind: 'navigate',
      target,
    };
  }

  let profile: AuthUser | null;

  try {
    profile = await fetchSessionProfile();
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unable to validate authentication state.';
    return {
      kind: 'error',
      code: 'auth_state_error',
      message,
    };
  }

  if (!profile) {
    if (normalizedPath.startsWith('/products')) {
      return {
        kind: 'navigate',
        target,
      };
    }

    return {
      kind: 'login_redirect',
      target: buildLoginEntryUrl(target, intent.tenant, intent.role),
      returnTo: target,
    };
  }

  if (!intent.appId) {
    return {
      kind: 'navigate',
      target,
    };
  }

  const effectiveRole = normalizeRole(profile.role || intent.role);
  const effectiveTenant = safeTenant(profile.tenant || intent.tenant);

  try {
    await fetchAppStatus(intent.appId, effectiveTenant, effectiveRole);
    return {
      kind: 'navigate',
      target,
    };
  } catch (error) {
    if (error instanceof ApiError) {
      if (error.status === 401) {
        return {
          kind: 'login_redirect',
          target: buildLoginEntryUrl(target, intent.tenant, intent.role),
          returnTo: target,
        };
      }

      if (error.status === 403 || error.status === 404 || error.status === 503) {
        return resolveBlockedOutcome(error);
      }

      return {
        kind: 'error',
        code: error.code || 'access_check_failed',
        message: error.message,
      };
    }

    return {
      kind: 'error',
      code: 'access_check_failed',
      message: error instanceof Error ? error.message : 'Unable to verify workspace access.',
    };
  }
}
