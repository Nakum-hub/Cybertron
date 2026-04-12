import { getConfig } from './config';

export type AnalyticsEventName =
  | 'nav_click'
  | 'cta_click'
  | 'auth_action'
  | 'threat_view'
  | 'pricing_view'
  | 'platform_app_open'
  | 'tenant_switch'
  | 'role_switch'
  | 'backend_health';

export interface AnalyticsPayload {
  [key: string]: string | number | boolean | undefined;
}

declare global {
  interface Window {
    dataLayer?: Array<Record<string, unknown>>;
  }
}

export function trackEvent(event: AnalyticsEventName, payload: AnalyticsPayload = {}) {
  const { analyticsEnabled, environment } = getConfig();

  if (!analyticsEnabled) {
    return;
  }

  const entry = {
    event,
    environment,
    timestamp: new Date().toISOString(),
    ...payload,
  };

  if (typeof window !== 'undefined') {
    window.dataLayer = window.dataLayer ?? [];
    window.dataLayer.push(entry);
  }

  if (environment !== 'production') {
    // Intentional debug visibility in non-prod environments.
    console.info('[analytics]', entry);
  }
}
