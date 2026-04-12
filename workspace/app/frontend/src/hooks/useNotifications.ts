import { useCallback, useEffect, useRef, useState } from 'react';
import { buildApiUrl } from '@/lib/backend';

export interface NotificationEvent {
  id: string;
  type: string;
  payload: Record<string, unknown>;
  timestamp: string;
}

interface UseNotificationsOptions {
  tenant: string;
  enabled?: boolean;
  maxEvents?: number;
}

export function useNotifications({ tenant, enabled = true, maxEvents = 50 }: UseNotificationsOptions) {
  const [events, setEvents] = useState<NotificationEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);
  const sourceRef = useRef<EventSource | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const clearEvents = useCallback(() => {
    setEvents([]);
    setUnreadCount(0);
  }, []);

  const markRead = useCallback(() => {
    setUnreadCount(0);
  }, []);

  useEffect(() => {
    if (!enabled || !tenant) {
      return;
    }

    let cancelled = false;

    function connect() {
      if (cancelled) return;

      const url = buildApiUrl('/v1/notifications/stream', { tenant });
      const es = new EventSource(url, { withCredentials: true });
      sourceRef.current = es;

      es.onopen = () => {
        if (!cancelled) setConnected(true);
      };

      es.onerror = () => {
        if (cancelled) return;
        setConnected(false);
        es.close();
        sourceRef.current = null;
        // Reconnect after 5 seconds
        reconnectTimerRef.current = setTimeout(connect, 5000);
      };

      // Listen for typed events
      const eventTypes = [
        'incident.created',
        'incident.updated',
        'alert.ingested',
        'compliance.status_changed',
        'playbook.executed',
        'audit.event',
      ];

      for (const eventType of eventTypes) {
        es.addEventListener(eventType, (event: MessageEvent) => {
          if (cancelled) return;
          try {
            const data = JSON.parse(event.data);
            const notification: NotificationEvent = {
              id: event.lastEventId || String(Date.now()),
              type: data.type || eventType,
              payload: data.payload || {},
              timestamp: data.timestamp || new Date().toISOString(),
            };
            setEvents(prev => {
              const next = [notification, ...prev];
              return next.length > maxEvents ? next.slice(0, maxEvents) : next;
            });
            setUnreadCount(prev => prev + 1);
          } catch {
            // ignore malformed events
          }
        });
      }
    }

    connect();

    return () => {
      cancelled = true;
      if (sourceRef.current) {
        sourceRef.current.close();
        sourceRef.current = null;
      }
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
      setConnected(false);
    };
  }, [tenant, enabled, maxEvents]);

  return {
    events,
    connected,
    unreadCount,
    clearEvents,
    markRead,
  };
}
