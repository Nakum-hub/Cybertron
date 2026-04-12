import { useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { markSessionHintActive, setAuthTokens } from '@/lib/auth';
import { getConfig } from '@/lib/config';

function sanitizeRedirect(value: string | null): string {
  if (!value) {
    return '/platform/threat-command';
  }

  if (!value.startsWith('/')) {
    return '/platform/threat-command';
  }

  if (value.startsWith('//')) {
    return '/platform/threat-command';
  }

  return value;
}

export default function AuthCallback() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  useEffect(() => {
    const error = searchParams.get('error');
    const errorDescription = searchParams.get('error_description');

    if (error) {
      const message = errorDescription || error || 'Authentication failed';
      navigate(`/auth/error?msg=${encodeURIComponent(message)}`, { replace: true });
      return;
    }

    const config = getConfig();
    const redirect = sanitizeRedirect(searchParams.get('redirect'));

    // Cookie-based auth: the backend already set HttpOnly auth cookies
    // during the OAuth callback redirect. No token in the URL is expected.
    // Mark a session hint so downstream routes know a session probe is warranted.
    if (config.authTransport === 'cookie') {
      markSessionHintActive();
      navigate(redirect, { replace: true });
      return;
    }

    // Bearer-token auth: token may arrive as a query parameter (legacy) or
    // in the URL fragment (preferred). In either case, strip them from the
    // browser address bar / history immediately to avoid leaking credentials
    // into server logs, Referer headers, and browser history.
    const hashParams = new URLSearchParams(window.location.hash.slice(1));
    const token = hashParams.get('token') || searchParams.get('token');
    const refreshToken = hashParams.get('refreshToken') || searchParams.get('refreshToken');

    // Immediately clear fragment and query string containing tokens.
    if (token) {
      window.history.replaceState(null, '', window.location.pathname);
    }

    if (!token) {
      navigate(
        `/auth/error?msg=${encodeURIComponent('Authentication callback received no token. Try logging in again.')}`,
        { replace: true }
      );
      return;
    }

    setAuthTokens(token, refreshToken || undefined);
    navigate(redirect, { replace: true });
  }, [navigate, searchParams]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#07080D] text-white">
      <div className="text-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-400 mx-auto mb-4" />
        <p className="text-slate-300">Finalizing secure authentication...</p>
      </div>
    </div>
  );
}
