export interface ThreatSummary {
  activeThreats: number;
  blockedToday: number;
  mttrMinutes: number;
  trustScore: number;
}

export type ThreatSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface ThreatIncident {
  id: string;
  title: string;
  severity: ThreatSeverity;
  detectedAt: string;
  status: 'open' | 'investigating' | 'resolved';
}

export const emptyThreatSummary: ThreatSummary = {
  activeThreats: 0,
  blockedToday: 0,
  mttrMinutes: 0,
  trustScore: 0,
};

export const emptyThreatIncidents: ThreatIncident[] = [];

export function hasThreatData(summary: ThreatSummary, incidents: ThreatIncident[]): boolean {
  return (
    incidents.length > 0 ||
    summary.activeThreats > 0 ||
    summary.blockedToday > 0 ||
    summary.mttrMinutes > 0 ||
    summary.trustScore > 0
  );
}