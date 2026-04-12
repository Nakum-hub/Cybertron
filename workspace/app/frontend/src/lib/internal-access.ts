import { hasRoleAccess, normalizeRole, type PlatformRole } from './platform-registry';

export const INTERNAL_OPERATIONS_ROLE: PlatformRole = 'tenant_admin';

export function canAccessInternalOperations(role: string | null | undefined): boolean {
  return hasRoleAccess(normalizeRole(role), INTERNAL_OPERATIONS_ROLE);
}

export function getInternalOperationsPath(role: string | null | undefined): '/diagnostics' | '/status' {
  return canAccessInternalOperations(role) ? '/diagnostics' : '/status';
}
