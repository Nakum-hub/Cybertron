import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  clearAccessToken,
  getRefreshToken,
  hasAccessToken,
  hasSessionHint,
  isManualLogout,
  markSessionHintActive,
} from '@/lib/auth';
import { ApiError } from '@/lib/api';
import { fetchAuthProfile, logoutAuthSession, type AuthUser } from '@/lib/backend';
import { getConfig } from '@/lib/config';

function sanitizeReturnTo(value: string): string {
  const input = String(value || '').trim();
  if (!input || !input.startsWith('/') || input.startsWith('//')) {
    return '/platform';
  }
  return input;
}

function getLoginUrl(returnTo?: string): string {
  const { apiBaseUrl, authLoginPath, authLoginUrl, authMode, demoAuthEnabled } = getConfig();
  const requestedReturnTo = sanitizeReturnTo(returnTo || '/platform');

  if (authLoginUrl) {
    const url = new URL(authLoginUrl, window.location.origin);
    url.searchParams.set('redirect', requestedReturnTo);
    return url.toString();
  }

  if (authMode === 'demo' && demoAuthEnabled) {
    const url = new URL(`${apiBaseUrl}${authLoginPath}`, window.location.origin);
    url.searchParams.set('redirect', requestedReturnTo);
    return url.toString();
  }

  // Password auth happens in the landing auth section when external login redirect is not configured.
  const next = new URL('/', window.location.origin);
  next.searchParams.set('returnTo', requestedReturnTo);
  return `${next.pathname}${next.search}#auth`;
}

function navigateToLogin(url: string): void {
  if (typeof window === 'undefined') {
    return;
  }

  window.location.assign(url);
}

export function useAuthStatus() {
  const manualLogout = isManualLogout();
  const shouldProbeSession = !manualLogout && (hasAccessToken() || Boolean(getRefreshToken()) || hasSessionHint());

  const profileQuery = useQuery({
    queryKey: ['auth-profile', manualLogout ? 'manual-logout' : shouldProbeSession ? 'session-probe' : 'anonymous'],
    enabled: shouldProbeSession,
    queryFn: async () => {
      try {
        const profile = await fetchAuthProfile();
        markSessionHintActive();
        return profile;
      } catch (error) {
        if (error instanceof ApiError && error.status === 401) {
          clearAccessToken();
        }

        throw error;
      }
    },
    retry: false,
  });

  const status = useMemo(() => {
    if (manualLogout || !shouldProbeSession) {
      return 'anonymous' as const;
    }

    if (profileQuery.isLoading) {
      return 'loading' as const;
    }

    if (profileQuery.isError) {
      if (profileQuery.error instanceof ApiError && profileQuery.error.status === 401) {
        return 'anonymous' as const;
      }
      return 'session-error' as const;
    }

    return 'authenticated' as const;
  }, [manualLogout, profileQuery.error, profileQuery.isError, profileQuery.isLoading, shouldProbeSession]);

  return {
    status,
    profile: profileQuery.data as AuthUser | undefined,
    loginUrl: getLoginUrl(typeof window !== 'undefined' ? window.location.pathname + window.location.search : '/platform'),
    async logout() {
      await logoutAuthSession();
      clearAccessToken(true);
      window.location.reload();
    },
    navigateToLogin(returnTo?: string) {
      navigateToLogin(getLoginUrl(returnTo));
    },
  };
}
