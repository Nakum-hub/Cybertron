export interface ApiObservation {
  path: string;
  method: string;
  status: number;
  durationMs: number;
  ok: boolean;
  requestId?: string;
  attempt: number;
  timestamp: string;
}

declare global {
  interface Window {
    __cybertronApiObservations?: ApiObservation[];
  }
}

export function recordApiObservation(observation: ApiObservation) {
  if (typeof window !== 'undefined') {
    window.__cybertronApiObservations = window.__cybertronApiObservations ?? [];
    window.__cybertronApiObservations.push(observation);

    if (window.__cybertronApiObservations.length > 200) {
      window.__cybertronApiObservations.shift();
    }
  }

  if (!observation.ok) {
    console.warn('[api-observation]', observation);
    return;
  }

  if (observation.durationMs > 1200) {
    console.info('[api-observation:slow]', observation);
  }
}

export function getApiObservations(): ApiObservation[] {
  if (typeof window === 'undefined') {
    return [];
  }

  return window.__cybertronApiObservations ?? [];
}
