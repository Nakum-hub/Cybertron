import { api, ApiError } from './api';
import { getConfig } from './config';
import { getAccessToken, getCsrfToken } from './auth';
import {
  emptyThreatIncidents,
  emptyThreatSummary,
  hasThreatData,
  type ThreatIncident,
  type ThreatSummary,
} from './contracts';
import { normalizeRole, type PlatformApp } from './platform-registry';

export interface AuthUser {
  id: string;
  name?: string;
  displayName?: string;
  email?: string;
  role?: string;
  tenant?: string;
  expiresAt?: string;
}

export interface AuthTokenPair {
  accessToken: string;
  accessTokenExpiresAt: string;
  accessTokenExpiresInSeconds: number;
  refreshToken: string;
  refreshTokenExpiresAt: string;
  tokenType: 'Bearer';
}

export interface AuthLoginResponse {
  user: AuthUser;
  tokens: AuthTokenPair;
}

export interface AuthResetRequestResponse {
  accepted: boolean;
  message: string;
  resetToken?: string;
  expiresAt?: string;
}

export interface AuthResetResponse {
  success: boolean;
  message: string;
}

export interface SystemHealth {
  status: 'ok' | 'degraded' | 'down';
  uptimeSeconds: number;
  region: string;
  version: string;
  authMode?: string;
  checkedAt: string;
  memoryRssMb?: number;
  heapUsedMb?: number;
  inFlightRequests?: number;
  dependencies?: {
    database?: {
      configured: boolean;
      status: string;
      latencyMs: number;
    };
    storage?: {
      configured: boolean;
      status: string;
      latencyMs: number;
    };
    redis?: {
      configured: boolean;
      status: string;
      latencyMs: number;
    };
  };
}

export interface SystemReadiness {
  status: 'ready' | 'not_ready';
  ready: boolean;
  environment: string;
  checkedAt: string;
  errors: string[];
  warnings: string[];
  dependencies?: SystemHealth['dependencies'];
}

export interface OpenApiSpec {
  openapi: string;
  info?: {
    title?: string;
    version?: string;
    description?: string;
  };
  paths: Record<string, unknown>;
  components?: Record<string, unknown>;
}

export interface ThreatBundle {
  summary: ThreatSummary;
  incidents: ThreatIncident[];
  dataSource: 'live' | 'empty' | 'unavailable';
  dataAvailable: boolean;
  usingFallbackData: boolean;
}

export interface PaginationMeta {
  limit: number;
  offset: number;
  total: number;
  hasMore: boolean;
}

export interface ListResponse<T> {
  data: T[];
  pagination?: PaginationMeta;
  /** Flat total/limit/offset returned by some endpoints (e.g. audit-logs) */
  total?: number;
  limit?: number;
  offset?: number;
  message?: string;
}

export interface AppModuleStatus {
  appId: string;
  tenant: string;
  checkedAt: string;
  status: 'operational' | 'degraded' | 'no_data' | 'unavailable';
  latencyMs: number;
  message?: string;
  evidence?: Record<string, unknown>;
}

export interface ModuleDescriptorRecord {
  moduleId: string;
  productKey: string;
  name: string;
  tagline: string;
  description: string;
  requiredRole: string;
  path: string;
  capabilities: string[];
}

export interface ModuleRegistryResponse {
  modules: ModuleDescriptorRecord[];
  apps: PlatformApp[];
}

export type IncidentSeverity = 'critical' | 'high' | 'medium' | 'low';
export type IncidentStatus = 'open' | 'investigating' | 'resolved' | 'closed';

export interface IncidentRecord {
  id: string;
  tenant: string;
  title: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  priority: string;
  blocked: boolean;
  source: string | null;
  assignedTo: string | null;
  assignedAt: string | null;
  escalatedFromAlertId: string | null;
  detectedAt: string;
  resolvedAt: string | null;
  responseTimeMinutes: number | null;
  createdAt: string | null;
}

export interface IncidentTimelineEvent {
  id: string;
  incidentId: string;
  eventType: string;
  message: string;
  actorUserId: string | null;
  createdAt: string;
}

export interface IncidentTimelineResponse {
  incidentId: string;
  data: IncidentTimelineEvent[];
}

export interface CreateIncidentPayload {
  title: string;
  severity: IncidentSeverity;
  status?: IncidentStatus;
  blocked?: boolean;
  source?: string;
  detectedAt?: string;
  resolvedAt?: string | null;
  responseTimeMinutes?: number | null;
  timelineMessage?: string;
}

export interface UpdateIncidentPayload extends Partial<CreateIncidentPayload> {
  timelineMessage?: string;
  priority?: IncidentSeverity;
  assignedTo?: number | null;
}

export type IocType = 'ip' | 'domain' | 'url' | 'hash';

export type IocSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface IocRecord {
  id: string;
  tenant: string;
  type: IocType;
  value: string;
  source: string | null;
  confidence: number;
  severity: IocSeverity;
  firstSeenAt: string | null;
  lastSeenAt: string | null;
  tags: string[];
  createdAt: string | null;
}

export interface CreateIocPayload {
  iocType: IocType;
  value: string;
  source?: string;
  confidence?: number;
  firstSeenAt?: string;
  lastSeenAt?: string | null;
  tags?: string[];
}

export type ServiceRequestPriority = 'critical' | 'high' | 'medium' | 'low';
export type ServiceRequestStatus = 'open' | 'triaged' | 'in_progress' | 'resolved' | 'closed';

export interface ServiceRequestRecord {
  id: string;
  tenant: string;
  requesterEmail: string;
  category: string;
  priority: ServiceRequestPriority;
  status: ServiceRequestStatus;
  subject: string;
  description: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface ServiceRequestComment {
  id: string;
  requestId: string;
  authorUserId: string | null;
  authorEmail: string | null;
  body: string;
  createdAt: string;
}

export interface ServiceRequestCommentsResponse {
  requestId: string;
  data: ServiceRequestComment[];
}

export interface CreateServiceRequestPayload {
  requesterEmail?: string;
  category: string;
  priority?: ServiceRequestPriority;
  subject: string;
  description?: string;
  comment?: string;
}

export interface UpdateServiceRequestPayload {
  category?: string;
  priority?: ServiceRequestPriority;
  status?: ServiceRequestStatus;
  subject?: string;
  description?: string | null;
  comment?: string;
}

export interface ReportListItem {
  id: string;
  type: string;
  reportDate: string;
  storagePath: string | null;
  storageProvider?: string | null;
  fileName?: string | null;
  mimeType?: string | null;
  sizeBytes?: number | null;
  checksumSha256: string | null;
  createdAt: string;
}

export interface ReportRecord {
  id: string;
  tenant: string;
  reportType: string;
  reportDate: string;
  storagePath: string | null;
  checksumSha256: string | null;
  fileName: string | null;
  mimeType: string | null;
  sizeBytes: number | null;
  storageProvider?: string | null;
  idempotencyKey?: string | null;
  uploadedAt?: string | null;
  metadata: Record<string, unknown>;
  createdAt: string;
}

export interface CreateReportPayload {
  reportType: string;
  reportDate: string;
  storagePath?: string;
  checksumSha256?: string;
  fileName?: string;
  mimeType?: string;
  sizeBytes?: number;
  metadata?: Record<string, unknown>;
  idempotencyKey?: string;
  storageProvider?: string;
}

export interface UploadReportPayload {
  reportType: string;
  reportDate: string;
  file: File;
  metadata?: Record<string, unknown>;
  idempotencyKey?: string;
}

export interface UploadReportResult {
  report: ReportRecord;
  idempotent: boolean;
  message?: string;
}

export interface ConnectorStatus {
  name: string;
  configured: boolean;
  status: 'healthy' | 'unreachable' | 'not_configured';
  checkedAt: string;
  latencyMs?: number;
  message?: string;
}

export interface ConnectorsStatusResponse {
  checkedAt: string;
  connectors: ConnectorStatus[];
}

export interface TenantRecord {
  slug: string;
  name: string;
  createdAt: string;
}

export interface ProductFeatureFlagState {
  flagKey: string;
  enabled: boolean;
  source: 'default' | 'tenant_override';
}

export interface ProductFeatureGate {
  allowed: boolean;
  flags: ProductFeatureFlagState[];
}

export interface TenantProductRecord {
  productId: string;
  productKey: string;
  name: string;
  description: string | null;
  modulePath: string | null;
  active: boolean;
  enabled: boolean;
  roleMin: string;
  tenantEnabled: boolean | null;
  tenantRoleMin: string | null;
  updatedAt: string | null;
  createdAt: string | null;
  effectiveEnabled?: boolean;
  allowedForRole?: boolean;
  visible?: boolean;
  planAllowed?: boolean;
  planTier?: string;
  planLabel?: string | null;
  quotaEnforced?: boolean;
  quotaAllowed?: boolean;
  quotaRemainingUnits?: number | null;
  quotaLimitUnits?: number | null;
  quotaPeriodEndsAt?: string | null;
  quotaExhausted?: boolean;
  featureGate?: ProductFeatureGate;
}

export interface TenantFeatureFlagRecord {
  flagKey: string;
  description: string | null;
  enabled: boolean;
  updatedAt: string | null;
}

export interface BillingUsageEvent {
  id: string;
  tenant: string;
  userId: string | null;
  productKey: string;
  actionKey: string;
  units: number;
  meta: Record<string, unknown>;
  createdAt: string;
}

export interface BillingCreditsRecord {
  tenant: string;
  balanceUnits: number;
  updatedAt: string | null;
  topUpUnits?: number;
  includedUnits?: number;
  usedUnits?: number;
  quotaLimitUnits?: number | null;
  quotaRemainingUnits?: number | null;
  quotaEnforced?: boolean;
  exhausted?: boolean;
  periodStart?: string | null;
  periodEndsAt?: string | null;
  planTier?: string;
  planLabel?: string | null;
}

export interface UserRecord {
  tenant: string;
  email: string;
  displayName: string;
  role: string;
  active: boolean;
  createdAt: string;
}

export interface AuditLogRecord {
  id: string;
  action: string;
  actorId: string | null;
  actorEmail: string | null;
  targetType: string | null;
  targetId: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  traceId: string | null;
  payload: Record<string, unknown>;
  createdAt: string;
}

function resolveTenantTemplate(pathTemplate: string, tenant: string): string {
  const safeTenant = encodeURIComponent(String(tenant || 'global').trim() || 'global');
  if (pathTemplate.includes('{tenant}')) {
    return pathTemplate.replace('{tenant}', safeTenant);
  }

  return `${pathTemplate.replace(/\/+$/, '')}/${safeTenant}`;
}

export async function fetchAuthProfile(): Promise<AuthUser> {
  const { authMePath } = getConfig();
  return api.get<AuthUser>(authMePath);
}

export async function loginWithPassword(payload: {
  tenant?: string;
  email: string;
  password: string;
}): Promise<AuthLoginResponse> {
  const { authLoginPath } = getConfig();
  return api.post<AuthLoginResponse>(authLoginPath, payload, { auth: false, retryCount: 0 });
}

export async function registerAccount(payload: {
  tenant?: string;
  email: string;
  password: string;
  displayName?: string;
  role?: string;
}): Promise<AuthUser> {
  return api.post<AuthUser>('/v1/auth/register', payload, { auth: false, retryCount: 0 });
}

export async function requestPasswordReset(payload: {
  tenant?: string;
  email: string;
}): Promise<AuthResetRequestResponse> {
  return api.post<AuthResetRequestResponse>('/v1/auth/password/forgot', payload, {
    auth: false,
    retryCount: 0,
  });
}

export async function resetPassword(payload: {
  tenant: string;
  resetToken: string;
  newPassword: string;
}): Promise<AuthResetResponse> {
  return api.post<AuthResetResponse>('/v1/auth/password/reset', payload, {
    auth: false,
    retryCount: 0,
  });
}

export async function refreshAccessToken(payload?: { refreshToken?: string }): Promise<AuthLoginResponse> {
  const body: Record<string, string> = {
    grantType: 'refresh_token',
  };

  if (payload?.refreshToken) {
    body.refreshToken = payload.refreshToken;
  }

  return api.post<AuthLoginResponse>(
    '/v1/auth/token',
    body,
    { auth: false, retryCount: 0 }
  );
}

export async function logoutAuthSession(refreshToken?: string): Promise<void> {
  const { authLogoutPath } = getConfig();

  try {
    await api.post(authLogoutPath, refreshToken ? { refreshToken } : undefined, { retryCount: 0 });
  } catch {
    // Best-effort logout for local/dev compatibility.
  }
}

export async function fetchThreatSummary(): Promise<ThreatSummary> {
  const { threatSummaryPath } = getConfig();

  try {
    return await api.get<ThreatSummary>(threatSummaryPath);
  } catch {
    return emptyThreatSummary;
  }
}

export async function fetchThreatIncidents(): Promise<ThreatIncident[]> {
  const { threatIncidentsPath } = getConfig();

  try {
    return await api.get<ThreatIncident[]>(threatIncidentsPath);
  } catch {
    return emptyThreatIncidents;
  }
}

export async function fetchThreatBundle(): Promise<ThreatBundle> {
  const { threatSummaryPath, threatIncidentsPath } = getConfig();

  const [summaryResult, incidentsResult] = await Promise.allSettled([
    api.get<ThreatSummary>(threatSummaryPath),
    api.get<ThreatIncident[]>(threatIncidentsPath),
  ]);

  const summary = summaryResult.status === 'fulfilled' ? summaryResult.value : emptyThreatSummary;
  const incidents = incidentsResult.status === 'fulfilled' ? incidentsResult.value : emptyThreatIncidents;

  const hasLiveData = hasThreatData(summary, incidents);
  const hasTransportErrors = summaryResult.status === 'rejected' || incidentsResult.status === 'rejected';

  return {
    summary,
    incidents,
    dataSource: hasTransportErrors ? 'unavailable' : hasLiveData ? 'live' : 'empty',
    dataAvailable: hasLiveData,
    usingFallbackData: hasTransportErrors,
  };
}

export async function fetchSystemHealth(): Promise<SystemHealth> {
  const { systemHealthPath } = getConfig();
  return api.get<SystemHealth>(systemHealthPath, { auth: false });
}

export async function fetchSystemReadiness(): Promise<SystemReadiness> {
  return api.get<SystemReadiness>('/v1/system/readiness', { auth: false });
}

export async function fetchOpenApiSpec(): Promise<OpenApiSpec> {
  return api.get<OpenApiSpec>('/v1/system/openapi', { auth: true });
}

export async function fetchPlatformApps(roleHint?: string, tenantHint?: string): Promise<PlatformApp[]> {
  const { platformAppsPath } = getConfig();
  const role = normalizeRole(roleHint);
  const tenant = (tenantHint ?? '').trim() || 'global';

  return api.get<PlatformApp[]>(platformAppsPath, {
    auth: true,
    query: {
      role,
      tenant,
    },
  });
}

export async function fetchAppStatus(
  appId: string,
  tenant: string,
  role: string
): Promise<AppModuleStatus> {
  return api.get<AppModuleStatus>(`/v1/apps/${encodeURIComponent(appId)}/status`, {
    auth: true,
    query: {
      tenant,
      role,
    },
  });
}

export async function fetchIncidents(
  tenant: string,
  options: {
    limit?: number;
    offset?: number;
    search?: string;
    severity?: IncidentSeverity;
    status?: IncidentStatus;
  } = {}
): Promise<ListResponse<IncidentRecord>> {
  return api.get<ListResponse<IncidentRecord>>('/v1/incidents', {
    auth: true,
    query: {
      tenant,
      limit: options.limit,
      offset: options.offset,
      search: options.search,
      severity: options.severity,
      status: options.status,
    },
  });
}

export async function createIncident(tenant: string, payload: CreateIncidentPayload): Promise<IncidentRecord> {
  return api.post<IncidentRecord>('/v1/incidents', payload, {
    auth: true,
    query: { tenant },
  });
}

export async function updateIncident(
  tenant: string,
  incidentId: string,
  payload: UpdateIncidentPayload
): Promise<IncidentRecord> {
  return api.patch<IncidentRecord>(`/v1/incidents/${encodeURIComponent(incidentId)}`, payload, {
    auth: true,
    query: { tenant },
  });
}

export async function fetchIncidentTimeline(
  tenant: string,
  incidentId: string
): Promise<IncidentTimelineResponse> {
  return api.get<IncidentTimelineResponse>(`/v1/incidents/${encodeURIComponent(incidentId)}/timeline`, {
    auth: true,
    query: { tenant },
  });
}

export async function fetchIocs(
  tenant: string,
  options: {
    limit?: number;
    offset?: number;
    search?: string;
    iocType?: IocType;
    minConfidence?: number;
  } = {}
): Promise<ListResponse<IocRecord>> {
  return api.get<ListResponse<IocRecord>>('/v1/iocs', {
    auth: true,
    query: {
      tenant,
      limit: options.limit,
      offset: options.offset,
      search: options.search,
      iocType: options.iocType,
      minConfidence: options.minConfidence,
    },
  });
}

export async function createIoc(tenant: string, payload: CreateIocPayload): Promise<IocRecord> {
  return api.post<IocRecord>('/v1/iocs', payload, {
    auth: true,
    query: { tenant },
  });
}

export async function linkIocToIncident(tenant: string, incidentId: string, iocId: string): Promise<void> {
  await api.post<void>(
    `/v1/incidents/${encodeURIComponent(incidentId)}/iocs/${encodeURIComponent(iocId)}`,
    undefined,
    {
      auth: true,
      query: { tenant },
    }
  );
}

export async function fetchServiceRequests(tenant: string, limit = 25): Promise<ServiceRequestRecord[]> {
  return api.get<ServiceRequestRecord[]>('/v1/service-requests', {
    auth: true,
    query: { tenant, limit },
  });
}

export async function createServiceRequest(
  tenant: string,
  payload: CreateServiceRequestPayload
): Promise<ServiceRequestRecord> {
  return api.post<ServiceRequestRecord>('/v1/service-requests', payload, {
    auth: true,
    query: { tenant },
  });
}

export async function updateServiceRequest(
  tenant: string,
  requestId: string,
  payload: UpdateServiceRequestPayload
): Promise<ServiceRequestRecord> {
  return api.patch<ServiceRequestRecord>(
    `/v1/service-requests/${encodeURIComponent(requestId)}`,
    payload,
    {
      auth: true,
      query: { tenant },
    }
  );
}

export async function fetchServiceRequestComments(
  tenant: string,
  requestId: string
): Promise<ServiceRequestCommentsResponse> {
  return api.get<ServiceRequestCommentsResponse>(
    `/v1/service-requests/${encodeURIComponent(requestId)}/comments`,
    {
      auth: true,
      query: { tenant },
    }
  );
}

export async function addServiceRequestComment(
  tenant: string,
  requestId: string,
  comment: string
): Promise<ServiceRequestRecord> {
  const result = await api.post<{ request: ServiceRequestRecord }>(
    `/v1/service-requests/${encodeURIComponent(requestId)}/comments`,
    { comment },
    {
      auth: true,
      query: { tenant },
    }
  );

  return result.request;
}

function normalizePath(path: string): string {
  const cleaned = String(path || '').trim();
  if (!cleaned) {
    return '/';
  }

  return cleaned.startsWith('/') ? cleaned : `/${cleaned}`;
}

function isAbsoluteUrl(value: string): boolean {
  return /^https?:\/\//i.test(value);
}

export function buildApiUrl(path: string, query?: Record<string, string | number | boolean>): string {
  const cfg = getConfig();
  const normalizedPath = normalizePath(path);
  let base = cfg.apiBaseUrl === '/' ? '' : cfg.apiBaseUrl;
  if (base.endsWith('/')) {
    base = base.slice(0, -1);
  }

  const combined = isAbsoluteUrl(normalizedPath) ? normalizedPath : `${base}${normalizedPath}`;
  const url = new URL(combined, window.location.origin);
  Object.entries(query || {}).forEach(([key, value]) => {
    if (value === undefined || value === null || value === '') {
      return;
    }
    url.searchParams.set(key, String(value));
  });

  return isAbsoluteUrl(combined) ? url.toString() : `${url.pathname}${url.search}`;
}

function extractApiErrorMessage(payload: unknown, fallback: string): string {
  if (payload && typeof payload === 'object' && 'error' in payload) {
    const error = (payload as { error?: { message?: string } }).error;
    if (error?.message) {
      return error.message;
    }
  }

  return fallback;
}

export async function fetchReports(tenant: string, limit = 25): Promise<ReportListItem[]> {
  return api.get<ReportListItem[]>('/v1/reports', {
    auth: true,
    query: { tenant, limit },
  });
}

export async function createReport(tenant: string, payload: CreateReportPayload): Promise<ReportRecord> {
  return api.post<ReportRecord>('/v1/reports', payload, {
    auth: true,
    query: { tenant },
  });
}

export async function fetchReportById(tenant: string, reportId: string): Promise<ReportRecord> {
  return api.get<ReportRecord>(`/v1/reports/${encodeURIComponent(reportId)}`, {
    auth: true,
    query: { tenant },
  });
}

export function uploadReportFile(
  tenant: string,
  payload: UploadReportPayload,
  onProgress?: (progressPercent: number) => void
): Promise<UploadReportResult> {
  const cfg = getConfig();
  const url = buildApiUrl(cfg.reportUploadPath || '/v1/reports/upload', { tenant });

  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', url, true);
    xhr.responseType = 'json';
    xhr.timeout = Math.max(1, cfg.requestTimeoutMs);
    xhr.withCredentials = true;
    xhr.setRequestHeader('Accept', 'application/json');
    const bearerToken = getAccessToken();
    if (bearerToken) {
      xhr.setRequestHeader('Authorization', `Bearer ${bearerToken}`);
    }
    if (cfg.csrfEnabled) {
      const csrfToken = getCsrfToken(cfg.csrfCookieName || 'ct_csrf');
      if (csrfToken) {
        xhr.setRequestHeader(cfg.csrfHeaderName || 'x-csrf-token', csrfToken);
      }
    }

    if (payload.idempotencyKey) {
      xhr.setRequestHeader('Idempotency-Key', payload.idempotencyKey);
    }

    xhr.upload.onprogress = event => {
      if (!onProgress || !event.lengthComputable || event.total <= 0) {
        return;
      }

      const next = Math.max(0, Math.min(100, Math.round((event.loaded / event.total) * 100)));
      onProgress(next);
    };

    xhr.onerror = () => {
      reject(
        new ApiError('Network request failed during report upload.', {
          status: 0,
          path: cfg.reportUploadPath || '/v1/reports/upload',
        })
      );
    };

    xhr.ontimeout = () => {
      reject(
        new ApiError('Report upload timed out.', {
          status: 408,
          path: cfg.reportUploadPath || '/v1/reports/upload',
        })
      );
    };

    xhr.onload = () => {
      const body = xhr.response || null;
      if (xhr.status >= 200 && xhr.status < 300) {
        const typed = body as UploadReportResult;
        resolve(typed);
        return;
      }

      reject(
        new ApiError(
          extractApiErrorMessage(body, `Report upload failed with status ${xhr.status}.`),
          {
            status: xhr.status,
            path: cfg.reportUploadPath || '/v1/reports/upload',
            code:
              body && typeof body === 'object' && 'error' in body
                ? (body as { error?: { code?: string } }).error?.code
                : undefined,
            requestId:
              body && typeof body === 'object' && 'error' in body
                ? (body as { error?: { requestId?: string } }).error?.requestId
                : undefined,
            details:
              body && typeof body === 'object' && 'error' in body
                ? (body as { error?: { details?: unknown } }).error?.details
                : undefined,
          }
        )
      );
    };

    const formData = new FormData();
    formData.append('reportType', payload.reportType);
    formData.append('reportDate', payload.reportDate);
    formData.append('file', payload.file, payload.file.name);
    if (payload.metadata && Object.keys(payload.metadata).length > 0) {
      formData.append('metadata', JSON.stringify(payload.metadata));
    }
    if (payload.idempotencyKey) {
      formData.append('idempotencyKey', payload.idempotencyKey);
    }

    xhr.send(formData);
  });
}

function inferDownloadName(report: ReportRecord): string {
  if (report.fileName && report.fileName.trim()) {
    return report.fileName.trim();
  }

  return `${report.reportType || 'report'}-${report.id}`;
}

function parseContentDispositionFileName(contentDispositionHeader: string | null): string | null {
  if (!contentDispositionHeader) {
    return null;
  }

  const utf8Match = /filename\*=UTF-8''([^;]+)/i.exec(contentDispositionHeader);
  if (utf8Match?.[1]) {
    try {
      return decodeURIComponent(utf8Match[1]);
    } catch {
      return utf8Match[1];
    }
  }

  const asciiMatch = /filename="?([^";]+)"?/i.exec(contentDispositionHeader);
  return asciiMatch?.[1] || null;
}

export async function downloadReportFile(tenant: string, report: ReportRecord): Promise<void> {
  const cfg = getConfig();
  const downloadPath = (cfg.reportDownloadPathTemplate || '/v1/reports/{reportId}/download').replace(
    '{reportId}',
    encodeURIComponent(report.id)
  );
  const url = buildApiUrl(downloadPath, { tenant });

  const headers: Record<string, string> = {};
  const token = getAccessToken();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(url, {
    method: 'GET',
    credentials: 'include',
    headers,
  });

  if (!response.ok) {
    let payload: unknown = null;
    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      try {
        payload = await response.json();
      } catch {
        payload = null;
      }
    }

    throw new ApiError(
      extractApiErrorMessage(payload, `Report download failed with status ${response.status}.`),
      {
        status: response.status,
        path: downloadPath,
        code:
          payload && typeof payload === 'object' && 'error' in payload
            ? (payload as { error?: { code?: string } }).error?.code
            : undefined,
        requestId:
          payload && typeof payload === 'object' && 'error' in payload
            ? (payload as { error?: { requestId?: string } }).error?.requestId
            : undefined,
      }
    );
  }

  const blob = await response.blob();
  const objectUrl = window.URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  const headerFileName = parseContentDispositionFileName(response.headers.get('content-disposition'));
  anchor.href = objectUrl;
  anchor.download = headerFileName || inferDownloadName(report);
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.URL.revokeObjectURL(objectUrl);
}

export async function fetchConnectorStatus(): Promise<ConnectorsStatusResponse> {
  return api.get<ConnectorsStatusResponse>('/v1/connectors/status', { auth: true });
}

export async function fetchTenants(limit = 25): Promise<TenantRecord[]> {
  const { tenantsPath } = getConfig();
  return api.get<TenantRecord[]>(tenantsPath || '/v1/tenants', {
    auth: true,
    query: { limit },
  });
}

export async function fetchProducts(tenant: string, role?: string): Promise<TenantProductRecord[]> {
  const { productsPath } = getConfig();
  return api.get<TenantProductRecord[]>(productsPath || '/v1/products', {
    auth: true,
    query: {
      tenant,
      role: role ? normalizeRole(role) : undefined,
    },
  });
}

export async function fetchTenantProducts(tenant: string, role?: string): Promise<TenantProductRecord[]> {
  const { tenantProductsPathTemplate } = getConfig();
  const path = resolveTenantTemplate(tenantProductsPathTemplate || '/v1/tenants/{tenant}/products', tenant);
  return api.get<TenantProductRecord[]>(path, {
    auth: true,
    query: {
      role: role ? normalizeRole(role) : undefined,
    },
  });
}

export async function fetchModuleRegistry(
  tenant: string,
  role?: string
): Promise<ModuleRegistryResponse> {
  const { modulesPath } = getConfig();
  return api.get<ModuleRegistryResponse>(modulesPath || '/v1/modules', {
    auth: true,
    query: {
      tenant,
      role: role ? normalizeRole(role) : undefined,
    },
  });
}

export async function fetchModuleStatus(
  moduleId: string,
  tenant: string,
  role?: string
): Promise<AppModuleStatus> {
  return api.get<AppModuleStatus>(`/v1/modules/${encodeURIComponent(moduleId)}/status`, {
    auth: true,
    query: {
      tenant,
      role: role ? normalizeRole(role) : undefined,
    },
  });
}

export async function updateTenantProductState(
  tenant: string,
  productKey: string,
  payload: {
    enabled: boolean;
    roleMin?: string;
  }
): Promise<TenantProductRecord> {
  const path = `/v1/tenants/${encodeURIComponent(tenant)}/products/${encodeURIComponent(productKey)}`;
  return api.patch<TenantProductRecord>(
    path,
    {
      enabled: payload.enabled,
      roleMin: payload.roleMin ? normalizeRole(payload.roleMin) : undefined,
    },
    { auth: true }
  );
}

export async function fetchTenantFeatureFlags(tenant: string): Promise<TenantFeatureFlagRecord[]> {
  const { tenantFeatureFlagsPathTemplate } = getConfig();
  const path = resolveTenantTemplate(
    tenantFeatureFlagsPathTemplate || '/v1/tenants/{tenant}/feature-flags',
    tenant
  );
  return api.get<TenantFeatureFlagRecord[]>(path, { auth: true });
}

export async function updateTenantFeatureFlag(
  tenant: string,
  flagKey: string,
  enabled: boolean
): Promise<{ tenant: string; flagKey: string; enabled: boolean; updatedAt: string }> {
  const path = `/v1/tenants/${encodeURIComponent(tenant)}/feature-flags/${encodeURIComponent(flagKey)}`;
  return api.patch<{ tenant: string; flagKey: string; enabled: boolean; updatedAt: string }>(
    path,
    { enabled },
    { auth: true }
  );
}

export async function fetchBillingUsage(
  tenant: string,
  options: {
    limit?: number;
    offset?: number;
    productKey?: string;
  } = {}
): Promise<ListResponse<BillingUsageEvent>> {
  const { billingUsagePath } = getConfig();
  return api.get<ListResponse<BillingUsageEvent>>(billingUsagePath || '/v1/billing/usage', {
    auth: true,
    query: {
      tenant,
      limit: options.limit,
      offset: options.offset,
      productKey: options.productKey,
    },
  });
}

export async function fetchBillingCredits(tenant: string): Promise<BillingCreditsRecord> {
  const { billingCreditsPath } = getConfig();
  return api.get<BillingCreditsRecord>(billingCreditsPath || '/v1/billing/credits', {
    auth: true,
    query: { tenant },
  });
}

export async function fetchUsers(tenant: string, limit = 25): Promise<UserRecord[]> {
  return api.get<UserRecord[]>('/v1/users', {
    auth: true,
    query: { tenant, limit },
  });
}

export async function fetchAuditLogs(
  tenant: string,
  options: { limit?: number; offset?: number; action?: string; actorEmail?: string; startDate?: string; endDate?: string } = {}
): Promise<ListResponse<AuditLogRecord>> {
  return api.get<ListResponse<AuditLogRecord>>('/v1/audit-logs', {
    auth: true,
    query: { tenant, ...options },
  });
}

export interface RiskIngestResult {
  jobId: string;
  tenant: string;
  recordCount: number;
  insertedFindings: number;
  severityCounts: Record<'critical' | 'high' | 'medium' | 'low', number>;
  message?: string;
}

export interface SiemFileUploadResult {
  uploadedRecords: number;
  ingestedAlerts: number;
  errorCount: number;
  sampleAlerts: SiemAlert[];
  errors: Array<{ ruleName: string; source: string; error: string }>;
  correlationRun: { evaluated: number; correlations: Array<Record<string, unknown>> } | null;
  message?: string;
}

export type RiskTreatmentStatus = 'open' | 'mitigating' | 'mitigated' | 'accepted' | 'transferred' | 'avoided';

export interface RiskFindingRecord {
  id: string;
  tenant: string;
  assetId: string | null;
  category: string;
  severity: IncidentSeverity;
  score: number;
  details: Record<string, unknown>;
  createdAt: string;
  treatmentStatus: RiskTreatmentStatus;
  ownerUserId: string | null;
  reviewedAt: string | null;
  reviewNotes: string | null;
  residualScore: number | null;
}

export interface RiskPortfolioSummary {
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  averageScore: number;
  highestScore: number;
  lastFindingAt: string | null;
  treatmentDistribution?: Record<string, number>;
}

export interface RiskScoringModel {
  formula: string;
  weights: { vulnerability: number; exposure: number; misconfiguration: number };
  severityThresholds: { critical: number; high: number; medium: number; low: number };
}

export interface RiskComputeResponse {
  tenant: string;
  portfolio: RiskPortfolioSummary;
  findings: RiskFindingRecord[];
  aiExplanation: {
    explanation: string;
    provider: string;
    model: string;
    aiGenerated?: boolean;
    mitigationSuggestions?: string[];
    groundingScore?: number;
    disclaimer?: string;
  } | null;
  scoringModel?: RiskScoringModel;
  message?: string;
}

export interface RiskReportRecord {
  id: string;
  tenant: string;
  createdBy: string | null;
  pdfStoragePath: string;
  summary: Record<string, unknown>;
  createdAt: string;
}

export interface Soc2ControlRecord {
  controlId: string;
  family: string;
  title: string;
  description: string;
  defaultWeight: number;
}

export type Soc2StatusValue =
  | 'not_started'
  | 'in_progress'
  | 'implemented'
  | 'validated'
  | 'not_applicable';

export interface Soc2StatusRecord extends Soc2ControlRecord {
  status: Soc2StatusValue;
  ownerUserId: string | null;
  evidenceCount: number;
  notes: string;
  updatedAt: string | null;
}

export interface Soc2EvidenceRecord {
  id: string;
  tenant: string;
  controlId: string;
  fileName: string;
  mimeType: string;
  sizeBytes: number;
  storageKey: string;
  checksumSha256: string;
  uploadedBy: string | null;
  createdAt: string;
}

export interface Soc2StatusResponse {
  controls: Soc2StatusRecord[];
  gap: {
    totalControls: number;
    validated: number;
    implemented: number;
    inProgress: number;
    notStarted: number;
    notApplicable: number;
    readinessScore: number;
    validatedWithoutEvidence: number;
    staleControls: number;
    gaps: Array<{
      controlId: string;
      family: string;
      title: string;
      status: string;
      evidenceCount: number;
      recommendedAction: string;
    }>;
  };
  evidencePreview: Soc2EvidenceRecord[];
}

export type PolicyStatus = 'draft' | 'pending_approval' | 'approved' | 'rejected' | 'archived';

export interface PolicyRecord {
  id: string;
  tenant: string;
  policyKey: string;
  content: string;
  createdBy: string | null;
  createdAt: string;
  status: PolicyStatus;
  approvedBy: string | null;
  approvedAt: string | null;
  rejectedBy: string | null;
  rejectedAt: string | null;
  rejectionReason: string | null;
}

export interface AuditPackageRecord {
  id: string;
  tenant: string;
  pdfStoragePath: string;
  manifest: Record<string, unknown>;
  createdAt: string;
}

export interface CveFeedRecord {
  id: string;
  tenant: string;
  cveId: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  cvssScore: number | null;
  description: string;
  relevanceScore: number;
  publishedAt: string | null;
  lastModifiedAt: string | null;
  viewedAt: string | null;
}

export interface CveSummaryRecord {
  id: string;
  tenant: string;
  cveId: string;
  summaryText: string;
  model: string;
  createdAt: string;
}

export interface LlmQualityGateMetadata {
  accepted: boolean;
  attempts: number;
  reasons?: string[];
  upstreamProvider?: string | null;
  upstreamModel?: string | null;
}

export interface LlmExecutionMetadata {
  provider: string;
  model: string;
  aiGenerated?: boolean;
  groundingScore?: number;
  promptVersion?: string;
  qualityGate?: LlmQualityGateMetadata;
}

export interface ThreatLlmRuntimeStatus {
  provider: string;
  deployment: string;
  configured: boolean;
  reachable: boolean;
  model: string | null;
  endpoint: string;
  checkedAt: string;
  latencyMs: number | null;
  availableModels: string[];
  sshTunnelSuggested: boolean;
  reason: string | null;
  featureFlags?: {
    llmFeaturesEnabled: boolean;
  };
}

export interface ThreatIntelDashboard {
  tenant: string;
  severityCounts: Record<'critical' | 'high' | 'medium' | 'low', number>;
  trend: Array<{ day: string; total: number }>;
  generatedAt: string;
  message?: string;
}

export function uploadAwsLogs(
  tenant: string,
  file: File,
  onProgress?: (progressPercent: number) => void
): Promise<RiskIngestResult> {
  const url = buildApiUrl('/v1/risk/ingest/aws-logs', { tenant });
  const cfg = getConfig();

  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', url, true);
    xhr.responseType = 'json';
    xhr.withCredentials = true;
    xhr.timeout = Math.max(1, cfg.requestTimeoutMs);
    xhr.setRequestHeader('Accept', 'application/json');
    const bearerToken2 = getAccessToken();
    if (bearerToken2) {
      xhr.setRequestHeader('Authorization', `Bearer ${bearerToken2}`);
    }
    if (cfg.csrfEnabled) {
      const csrfToken = getCsrfToken(cfg.csrfCookieName || 'ct_csrf');
      if (csrfToken) {
        xhr.setRequestHeader(cfg.csrfHeaderName || 'x-csrf-token', csrfToken);
      }
    }

    xhr.upload.onprogress = event => {
      if (!onProgress || !event.lengthComputable || event.total <= 0) {
        return;
      }
      onProgress(Math.max(0, Math.min(100, Math.round((event.loaded / event.total) * 100))));
    };

    xhr.onerror = () => {
      reject(new ApiError('AWS log upload failed due to network error.', { status: 0, path: '/v1/risk/ingest/aws-logs' }));
    };

    xhr.ontimeout = () => {
      reject(new ApiError('AWS log upload timed out.', { status: 408, path: '/v1/risk/ingest/aws-logs' }));
    };

    xhr.onload = () => {
      const body = xhr.response || null;
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(body as RiskIngestResult);
        return;
      }
      reject(
        new ApiError(
          extractApiErrorMessage(body, `AWS log upload failed with status ${xhr.status}.`),
          {
            status: xhr.status,
            path: '/v1/risk/ingest/aws-logs',
            code: body && typeof body === 'object' && 'error' in body
              ? (body as { error?: { code?: string } }).error?.code
              : undefined,
          }
        )
      );
    };

    const formData = new FormData();
    formData.append('file', file, file.name);
    xhr.send(formData);
  });
}

export function uploadSiemLogs(
  tenant: string,
  file: File,
  options: {
    runCorrelation?: boolean;
    source?: string;
    onProgress?: (progressPercent: number) => void;
  } = {}
): Promise<SiemFileUploadResult> {
  const url = buildApiUrl('/v1/threat-intel/siem/upload', {
    tenant,
    runCorrelation: options.runCorrelation === true,
  });
  const cfg = getConfig();

  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', url, true);
    xhr.responseType = 'json';
    xhr.withCredentials = true;
    xhr.timeout = Math.max(1, cfg.requestTimeoutMs);
    xhr.setRequestHeader('Accept', 'application/json');
    const bearerToken = getAccessToken();
    if (bearerToken) {
      xhr.setRequestHeader('Authorization', `Bearer ${bearerToken}`);
    }
    if (cfg.csrfEnabled) {
      const csrfToken = getCsrfToken(cfg.csrfCookieName || 'ct_csrf');
      if (csrfToken) {
        xhr.setRequestHeader(cfg.csrfHeaderName || 'x-csrf-token', csrfToken);
      }
    }

    xhr.upload.onprogress = event => {
      if (!options.onProgress || !event.lengthComputable || event.total <= 0) {
        return;
      }
      options.onProgress(Math.max(0, Math.min(100, Math.round((event.loaded / event.total) * 100))));
    };

    xhr.onerror = () => {
      reject(new ApiError('SIEM log upload failed due to network error.', { status: 0, path: '/v1/threat-intel/siem/upload' }));
    };

    xhr.ontimeout = () => {
      reject(new ApiError('SIEM log upload timed out.', { status: 408, path: '/v1/threat-intel/siem/upload' }));
    };

    xhr.onload = () => {
      const body = xhr.response || null;
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(body as SiemFileUploadResult);
        return;
      }
      reject(
        new ApiError(
          extractApiErrorMessage(body, `SIEM log upload failed with status ${xhr.status}.`),
          {
            status: xhr.status,
            path: '/v1/threat-intel/siem/upload',
            code: body && typeof body === 'object' && 'error' in body
              ? (body as { error?: { code?: string } }).error?.code
              : undefined,
          }
        )
      );
    };

    const formData = new FormData();
    formData.append('file', file, file.name);
    if (options.source) {
      formData.append('source', options.source);
    }
    if (options.runCorrelation === true) {
      formData.append('runCorrelation', 'true');
    }
    xhr.send(formData);
  });
}

export async function computeRiskScores(
  tenant: string,
  options: {
    limit?: number;
    includeAi?: boolean;
  } = {}
): Promise<RiskComputeResponse> {
  return api.post<RiskComputeResponse>(
    '/v1/risk/score/compute',
    {
      limit: options.limit,
      includeAi: options.includeAi,
    },
    {
      auth: true,
      query: { tenant },
    }
  );
}

export async function fetchRiskFindings(
  tenant: string,
  options: {
    limit?: number;
    offset?: number;
    severity?: IncidentSeverity;
    category?: string;
  } = {}
): Promise<ListResponse<RiskFindingRecord>> {
  return api.get<ListResponse<RiskFindingRecord>>('/v1/risk/findings', {
    auth: true,
    query: {
      tenant,
      limit: options.limit,
      offset: options.offset,
      severity: options.severity,
      category: options.category,
    },
  });
}

export async function updateRiskFindingTreatment(
  tenant: string,
  findingId: string,
  payload: {
    treatmentStatus: RiskTreatmentStatus;
    ownerUserId?: number;
    residualScore?: number;
    reviewNotes?: string;
  }
): Promise<RiskFindingRecord> {
  return api.patch(
    `/v1/risk/findings/${encodeURIComponent(findingId)}/treatment`,
    payload,
    { auth: true, query: { tenant } }
  );
}

export async function generateRiskReport(tenant: string): Promise<{
  report: RiskReportRecord;
  aiExplanation: {
    explanation: string;
    provider: string;
    model: string;
    aiGenerated?: boolean;
    mitigationSuggestions: string[];
    groundingScore?: number;
    disclaimer?: string;
  };
}> {
  return api.post(
    '/v1/risk/report/generate',
    undefined,
    {
      auth: true,
      query: { tenant },
    }
  );
}

export async function downloadRiskReportPdf(tenant: string, reportId: string): Promise<void> {
  const url = buildApiUrl(`/v1/risk/report/${encodeURIComponent(reportId)}/download`, { tenant });
  const response = await fetch(url, {
    method: 'GET',
    credentials: 'include',
  });
  if (!response.ok) {
    let payload: unknown = null;
    try {
      payload = await response.json();
    } catch {
      payload = null;
    }
    throw new ApiError(
      extractApiErrorMessage(payload, `Risk report download failed with status ${response.status}.`),
      {
        status: response.status,
        path: '/v1/risk/report/:id/download',
      }
    );
  }

  const blob = await response.blob();
  const objectUrl = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = objectUrl;
  link.download = `risk-report-${reportId}.pdf`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(objectUrl);
}

export async function fetchRiskReportPdfBinary(
  tenant: string,
  reportId: string
): Promise<{ bytes: Uint8Array; contentType: string }> {
  const url = buildApiUrl(`/v1/risk/report/${encodeURIComponent(reportId)}/download`, { tenant });
  const response = await fetch(url, {
    method: 'GET',
    credentials: 'include',
  });

  if (!response.ok) {
    let payload: unknown = null;
    try {
      payload = await response.json();
    } catch {
      payload = null;
    }
    throw new ApiError(
      extractApiErrorMessage(payload, `Risk report download failed with status ${response.status}.`),
      {
        status: response.status,
        path: '/v1/risk/report/:id/download',
      }
    );
  }

  const bytes = new Uint8Array(await response.arrayBuffer());
  return {
    bytes,
    contentType: String(response.headers.get('content-type') || ''),
  };
}

export async function fetchSoc2Controls(tenant: string): Promise<Soc2ControlRecord[]> {
  return api.get<Soc2ControlRecord[]>('/v1/compliance/soc2/controls', {
    auth: true,
    query: { tenant },
  });
}

export async function fetchSoc2Status(tenant: string): Promise<Soc2StatusResponse> {
  return api.get<Soc2StatusResponse>('/v1/compliance/soc2/status', {
    auth: true,
    query: { tenant },
  });
}

export async function updateSoc2Status(
  tenant: string,
  controlId: string,
  payload: {
    status: Soc2StatusValue;
    ownerUserId?: string;
    notes?: string;
  }
): Promise<Soc2StatusRecord> {
  return api.patch<Soc2StatusRecord>(
    `/v1/compliance/soc2/status/${encodeURIComponent(controlId)}`,
    payload,
    {
      auth: true,
      query: { tenant },
    }
  );
}

export function uploadSoc2Evidence(
  tenant: string,
  controlId: string,
  file: File,
  onProgress?: (progressPercent: number) => void
): Promise<Soc2EvidenceRecord> {
  const url = buildApiUrl('/v1/compliance/soc2/evidence/upload', { tenant });
  const cfg = getConfig();

  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', url, true);
    xhr.responseType = 'json';
    xhr.withCredentials = true;
    xhr.timeout = Math.max(1, cfg.requestTimeoutMs);
    xhr.setRequestHeader('Accept', 'application/json');
    const bearerToken2 = getAccessToken();
    if (bearerToken2) {
      xhr.setRequestHeader('Authorization', `Bearer ${bearerToken2}`);
    }
    if (cfg.csrfEnabled) {
      const csrfToken = getCsrfToken(cfg.csrfCookieName || 'ct_csrf');
      if (csrfToken) {
        xhr.setRequestHeader(cfg.csrfHeaderName || 'x-csrf-token', csrfToken);
      }
    }

    xhr.upload.onprogress = event => {
      if (!onProgress || !event.lengthComputable || event.total <= 0) {
        return;
      }
      onProgress(Math.max(0, Math.min(100, Math.round((event.loaded / event.total) * 100))));
    };

    xhr.onerror = () => {
      reject(new ApiError('SOC2 evidence upload failed due to network error.', { status: 0, path: '/v1/compliance/soc2/evidence/upload' }));
    };

    xhr.ontimeout = () => {
      reject(new ApiError('SOC2 evidence upload timed out.', { status: 408, path: '/v1/compliance/soc2/evidence/upload' }));
    };

    xhr.onload = () => {
      const body = xhr.response || null;
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(body as Soc2EvidenceRecord);
        return;
      }
      reject(
        new ApiError(
          extractApiErrorMessage(body, `SOC2 evidence upload failed with status ${xhr.status}.`),
          {
            status: xhr.status,
            path: '/v1/compliance/soc2/evidence/upload',
            code: body && typeof body === 'object' && 'error' in body
              ? (body as { error?: { code?: string } }).error?.code
              : undefined,
          }
        )
      );
    };

    const formData = new FormData();
    formData.append('controlId', controlId);
    formData.append('file', file, file.name);
    xhr.send(formData);
  });
}

export async function generateCompliancePolicy(
  tenant: string,
  payload: {
    policyKey: string;
    organization?: string;
  }
): Promise<{
  policy: PolicyRecord;
  llm: { provider: string; model: string };
}> {
  return api.post('/v1/compliance/policy/generate', payload, {
    auth: true,
    query: { tenant },
  });
}

export async function generateAuditPackage(tenant: string): Promise<AuditPackageRecord> {
  return api.post<AuditPackageRecord>('/v1/compliance/audit-package/generate', undefined, {
    auth: true,
    query: { tenant },
  });
}

export async function downloadAuditPackagePdf(tenant: string, packageId: string): Promise<void> {
  const url = buildApiUrl(`/v1/compliance/audit-package/${encodeURIComponent(packageId)}/download`, { tenant });
  const response = await fetch(url, {
    method: 'GET',
    credentials: 'include',
  });
  if (!response.ok) {
    let payload: unknown = null;
    try {
      payload = await response.json();
    } catch {
      payload = null;
    }
    throw new ApiError(
      extractApiErrorMessage(payload, `Audit package download failed with status ${response.status}.`),
      {
        status: response.status,
        path: '/v1/compliance/audit-package/:id/download',
      }
    );
  }

  const blob = await response.blob();
  const objectUrl = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = objectUrl;
  link.download = `audit-package-${packageId}.pdf`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(objectUrl);
}

export async function fetchAuditPackagePdfBinary(
  tenant: string,
  packageId: string
): Promise<{ bytes: Uint8Array; contentType: string }> {
  const url = buildApiUrl(`/v1/compliance/audit-package/${encodeURIComponent(packageId)}/download`, { tenant });
  const response = await fetch(url, {
    method: 'GET',
    credentials: 'include',
  });
  if (!response.ok) {
    let payload: unknown = null;
    try {
      payload = await response.json();
    } catch {
      payload = null;
    }
    throw new ApiError(
      extractApiErrorMessage(payload, `Audit package download failed with status ${response.status}.`),
      {
        status: response.status,
        path: '/v1/compliance/audit-package/:id/download',
      }
    );
  }

  const bytes = new Uint8Array(await response.arrayBuffer());
  return {
    bytes,
    contentType: String(response.headers.get('content-type') || ''),
  };
}

export async function syncThreatIntelCves(tenant: string): Promise<{
  synced: boolean;
  notModified: boolean;
  source: string;
  cveCount: number;
  tenant: string;
}> {
  return api.post('/v1/threat-intel/cve/sync', undefined, {
    auth: true,
    query: { tenant },
  });
}

export async function fetchThreatIntelCveFeed(
  tenant: string,
  options: {
    limit?: number;
    offset?: number;
    severity?: 'low' | 'medium' | 'high' | 'critical';
  } = {}
): Promise<ListResponse<CveFeedRecord>> {
  return api.get<ListResponse<CveFeedRecord>>('/v1/threat-intel/cve/feed', {
    auth: true,
    query: {
      tenant,
      limit: options.limit,
      offset: options.offset,
      severity: options.severity,
    },
  });
}

export async function summarizeCve(
  tenant: string,
  cveId: string
): Promise<{
  summary: CveSummaryRecord;
  llm: LlmExecutionMetadata;
}> {
  return api.post(
    `/v1/threat-intel/cve/${encodeURIComponent(cveId)}/summarize`,
    undefined,
    {
      auth: true,
      query: { tenant },
    }
  );
}

export async function fetchThreatLlmRuntime(
  tenant: string,
): Promise<ThreatLlmRuntimeStatus> {
  return api.get('/v1/threat-intel/ai/runtime', {
    auth: true,
    query: { tenant },
  });
}

export async function fetchThreatIntelDashboard(
  tenant: string,
  days = 30
): Promise<ThreatIntelDashboard> {
  return api.get<ThreatIntelDashboard>('/v1/threat-intel/dashboard', {
    auth: true,
    query: { tenant, days },
  });
}

// ─── MITRE ATT&CK ───────────────────────────────────────────────

export interface MitreTechnique {
  technique_id: string;
  name: string;
  tactic: string;
  description: string | null;
  url: string | null;
}

export interface MitreMapping {
  id: number;
  incident_id: number;
  technique_id: string;
  confidence: number;
  notes: string | null;
  created_by: number | null;
  created_at: string;
  technique_name: string;
  tactic: string;
  technique_description: string | null;
}

export interface MitreHeatmapTactic {
  tactic: string;
  unique_incidents: number;
  total_mappings: number;
}

export interface MitreHeatmapTechnique {
  technique_id: string;
  technique_name: string;
  tactic: string;
  incident_count: number;
  avg_confidence: number;
}

export interface MitreHeatmap {
  tactics: MitreHeatmapTactic[];
  techniques: MitreHeatmapTechnique[];
}

export async function fetchMitreTechniques(
  tenant: string,
  tactic?: string
): Promise<{ data: MitreTechnique[]; total?: number }> {
  return api.get('/v1/threat-intel/mitre/techniques', {
    auth: true,
    query: { tenant, tactic },
  });
}

export async function fetchMitreHeatmap(tenant: string): Promise<MitreHeatmap> {
  return api.get('/v1/threat-intel/mitre/heatmap', {
    auth: true,
    query: { tenant },
  });
}

export async function fetchIncidentMitreMappings(
  tenant: string,
  incidentId: number
): Promise<{ data: MitreMapping[] }> {
  return api.get(`/v1/threat-intel/mitre/incidents/${incidentId}`, {
    auth: true,
    query: { tenant },
  });
}

export async function addIncidentMitreMapping(
  tenant: string,
  incidentId: number,
  payload: { techniqueId: string; confidence?: number; notes?: string }
): Promise<MitreMapping> {
  return api.post(`/v1/threat-intel/mitre/incidents/${incidentId}`, payload, {
    auth: true,
    query: { tenant },
  });
}

export async function removeIncidentMitreMapping(
  tenant: string,
  mappingId: number
): Promise<{ removed: boolean }> {
  return api.delete(`/v1/threat-intel/mitre/mappings/${mappingId}`, {
    auth: true,
    query: { tenant },
  });
}

// ─── Playbooks ───────────────────────────────────────────────────

export interface PlaybookRecord {
  id: number;
  tenant_slug: string;
  name: string;
  description: string | null;
  severity_filter: string | null;
  category: string;
  is_active: boolean;
  auto_trigger: boolean;
  severity_trigger: string | null;
  category_trigger: string | null;
  created_by: number | null;
  created_at: string;
  updated_at: string;
}

export interface PlaybookStep {
  id: number;
  playbook_id: number;
  step_order: number;
  title: string;
  description: string | null;
  action_type: 'manual' | 'automated' | 'notification' | 'approval';
  assigned_role: string;
  timeout_minutes: number;
  created_at: string;
}

export interface PlaybookWithSteps extends PlaybookRecord {
  steps: PlaybookStep[];
}

export interface PlaybookExecution {
  id: number;
  tenant_slug: string;
  playbook_id: number;
  playbook_name?: string;
  incident_id: number | null;
  status: 'running' | 'completed' | 'failed' | 'cancelled';
  started_by: number | null;
  started_at: string;
  completed_at: string | null;
  result_summary: Record<string, unknown>;
  stepResults?: PlaybookStepResult[];
}

export interface PlaybookStepResult {
  id: number;
  execution_id: number;
  step_id: number;
  status: 'pending' | 'in_progress' | 'completed' | 'skipped' | 'failed';
  started_at: string | null;
  completed_at: string | null;
  notes: string | null;
  completed_by: number | null;
  step_title?: string;
  step_order?: number;
  action_type?: string;
  assigned_role?: string;
  timeout_minutes?: number;
}

export async function fetchPlaybooks(
  tenant: string,
  options: { limit?: number; offset?: number; category?: string } = {}
): Promise<ListResponse<PlaybookRecord>> {
  return api.get('/v1/threat-intel/playbooks', {
    auth: true,
    query: { tenant, ...options },
  });
}

export async function fetchPlaybookDetail(
  tenant: string,
  playbookId: number
): Promise<PlaybookWithSteps> {
  return api.get(`/v1/threat-intel/playbooks/${playbookId}`, {
    auth: true,
    query: { tenant },
  });
}

export async function createPlaybook(
  tenant: string,
  payload: { name: string; description?: string; severityFilter?: string; category?: string }
): Promise<PlaybookRecord> {
  return api.post('/v1/threat-intel/playbooks', payload, {
    auth: true,
    query: { tenant },
  });
}

export async function updatePlaybook(
  tenant: string,
  playbookId: number,
  payload: { name?: string; description?: string; severityFilter?: string; category?: string; isActive?: boolean }
): Promise<PlaybookRecord> {
  return api.put(`/v1/threat-intel/playbooks/${playbookId}`, payload, {
    auth: true,
    query: { tenant },
  });
}

export async function addPlaybookStep(
  tenant: string,
  playbookId: number,
  payload: { title: string; description?: string; actionType?: string; assignedRole?: string; timeoutMinutes?: number; stepOrder?: number }
): Promise<PlaybookStep> {
  return api.post(`/v1/threat-intel/playbooks/${playbookId}/steps`, payload, {
    auth: true,
    query: { tenant },
  });
}

export async function executePlaybook(
  tenant: string,
  playbookId: number,
  incidentId?: number
): Promise<PlaybookExecution> {
  return api.post(`/v1/threat-intel/playbooks/${playbookId}/execute`, { incidentId }, {
    auth: true,
    query: { tenant },
  });
}

export async function fetchPlaybookExecutions(
  tenant: string,
  options: { playbookId?: number; incidentId?: number; status?: string; limit?: number; offset?: number } = {}
): Promise<ListResponse<PlaybookExecution>> {
  return api.get('/v1/threat-intel/playbooks/executions', {
    auth: true,
    query: { tenant, ...options },
  });
}

export async function updatePlaybookStepResult(
  tenant: string,
  executionId: number,
  stepId: number,
  payload: { status: string; notes?: string }
): Promise<PlaybookStepResult> {
  return api.put(
    `/v1/threat-intel/playbooks/executions/${executionId}/steps/${stepId}`,
    payload,
    { auth: true, query: { tenant } }
  );
}

export async function fetchExecutionStepResults(
  tenant: string,
  executionId: number
): Promise<{ data: PlaybookStepResult[] }> {
  return api.get(`/v1/threat-intel/playbooks/executions/${executionId}/steps`, {
    auth: true,
    query: { tenant },
  });
}

// ─── SIEM Alerts ─────────────────────────────────────────────────

export interface SiemAlert {
  id: number;
  tenant_slug: string;
  source: string;
  alert_id: string | null;
  rule_name: string | null;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  raw_payload: Record<string, unknown>;
  source_ip: string | null;
  dest_ip: string | null;
  hostname: string | null;
  correlated: boolean;
  incident_id: number | null;
  status: 'new' | 'acknowledged' | 'in_triage' | 'escalated' | 'resolved' | 'dismissed';
  assigned_to: number | null;
  acknowledged_at: string | null;
  acknowledged_by: number | null;
  resolved_at: string | null;
  notes: string | null;
  ingested_at: string;
  event_time: string | null;
}

export interface SiemAlertStats {
  total_alerts: number;
  uncorrelated: number;
  new_count: number;
  acknowledged_count: number;
  in_triage_count: number;
  escalated_count: number;
  resolved_count: number;
  dismissed_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  source_count: number;
  assigned_analyst_count: number;
  latest_event_time: string | null;
}

export interface CorrelationRule {
  id: number;
  tenant_slug: string;
  name: string;
  description: string | null;
  rule_type: 'threshold' | 'sequence' | 'aggregation' | 'anomaly';
  conditions: Record<string, unknown>;
  severity_output: string;
  is_active: boolean;
  created_by: number | null;
  created_at: string;
}

export async function fetchSiemAlerts(
  tenant: string,
  options: { limit?: number; offset?: number; severity?: string; source?: string; correlated?: boolean; status?: string; assignedTo?: number; search?: string } = {}
): Promise<ListResponse<SiemAlert>> {
  return api.get('/v1/threat-intel/siem/alerts', {
    auth: true,
    query: { tenant, ...options },
  });
}

export async function ingestSiemAlert(
  tenant: string,
  payload: {
    source: string;
    alertId?: string;
    ruleName?: string;
    severity?: string;
    category?: string;
    rawPayload?: Record<string, unknown>;
    sourceIp?: string;
    destIp?: string;
    hostname?: string;
    eventTime?: string;
  }
): Promise<SiemAlert> {
  return api.post('/v1/threat-intel/siem/alerts', payload, {
    auth: true,
    query: { tenant },
  });
}

export async function fetchSiemAlertStats(tenant: string): Promise<{ stats: SiemAlertStats }> {
  return api.get('/v1/threat-intel/siem/alerts/stats', {
    auth: true,
    query: { tenant },
  });
}

export async function correlateSiemAlert(
  tenant: string,
  alertId: number,
  incidentId: number
): Promise<SiemAlert> {
  return api.post(`/v1/threat-intel/siem/alerts/${alertId}/correlate`, { incidentId }, {
    auth: true,
    query: { tenant },
  });
}

export async function fetchCorrelationRules(
  tenant: string
): Promise<{ data: CorrelationRule[] }> {
  return api.get('/v1/threat-intel/siem/correlation-rules', {
    auth: true,
    query: { tenant },
  });
}

export async function createCorrelationRule(
  tenant: string,
  payload: { name: string; description?: string; ruleType?: string; conditions?: Record<string, unknown>; severityOutput?: string }
): Promise<CorrelationRule> {
  return api.post('/v1/threat-intel/siem/correlation-rules', payload, {
    auth: true,
    query: { tenant },
  });
}

export async function updateCorrelationRule(
  tenant: string,
  ruleId: number,
  payload: { name?: string; description?: string; ruleType?: string; conditions?: Record<string, unknown>; isActive?: boolean }
): Promise<CorrelationRule> {
  return api.put(`/v1/threat-intel/siem/correlation-rules/${ruleId}`, payload, {
    auth: true,
    query: { tenant },
  });
}

export interface ConnectorSyncResult {
  fetched: number;
  ingested: number;
  errors: Array<{ alertId: string; source: string; error: string }>;
}

export async function syncSiemConnectors(
  tenant: string,
  limit = 50,
): Promise<ConnectorSyncResult> {
  return api.post('/v1/threat-intel/siem/sync-connectors', {}, {
    auth: true,
    query: { tenant, limit: String(limit) },
  });
}

export async function updateAlertStatus(
  tenant: string,
  alertId: number,
  status: string,
  notes?: string,
): Promise<{ id: number; status: string; assigned_to: number | null }> {
  return api.patch(`/v1/threat-intel/siem/alerts/${alertId}/status`, { status, notes }, {
    auth: true,
    query: { tenant },
  });
}

export async function assignAlertToUser(
  tenant: string,
  alertId: number,
  assignedTo: number | null,
): Promise<{ id: number; status: string; assigned_to: number | null }> {
  return api.patch(`/v1/threat-intel/siem/alerts/${alertId}/assign`, { assignedTo }, {
    auth: true,
    query: { tenant },
  });
}

export async function escalateAlert(
  tenant: string,
  alertId: number,
  title?: string,
  severity?: string,
): Promise<{ alertId: number; incidentId: number; title: string; severity: string; priority: string }> {
  return api.post(`/v1/threat-intel/siem/alerts/${alertId}/escalate`, { title, severity }, {
    auth: true,
    query: { tenant },
  });
}

// --- SOC Gaps: New API Functions ---

export interface AnalystRecord {
  id: number;
  email: string;
  displayName: string;
}

export async function fetchTenantAnalysts(
  tenant: string,
): Promise<{ data: AnalystRecord[] }> {
  return api.get('/v1/threat-intel/analysts', {
    auth: true,
    query: { tenant },
  });
}

export async function bulkUpdateAlertStatus(
  tenant: string,
  alertIds: number[],
  status: string,
  notes?: string,
): Promise<{ updated: number; failed: number; results: Array<{ id: number; status: string; reason?: string }> }> {
  return api.post('/v1/threat-intel/siem/alerts/bulk-status', { alertIds, status, notes }, {
    auth: true,
    query: { tenant },
  });
}

export interface SlaMetrics {
  open_alerts: number;
  avg_time_to_ack_minutes: number | null;
  avg_time_to_resolve_minutes: number | null;
  critical_sla_breached: number;
  high_sla_breached: number;
  medium_sla_breached: number;
  low_sla_breached: number;
  total_sla_breached: number;
  sla_thresholds: Record<string, { acknowledgeMinutes: number; resolveMinutes: number }>;
}

export async function fetchAlertSlaMetrics(
  tenant: string,
): Promise<{ metrics: SlaMetrics }> {
  return api.get('/v1/threat-intel/siem/alerts/sla-metrics', {
    auth: true,
    query: { tenant },
  });
}

export interface TriageSuggestion {
  alertId: number;
  severity: string;
  suggestedPriority: string;
  suggestions: Array<{ action: string; confidence: string; reason: string }>;
  automated: boolean;
  disclaimer: string;
  summary?: string;
  evidence?: string[];
  llm?: LlmExecutionMetadata;
}

export async function fetchAlertTriageSuggestion(
  tenant: string,
  alertId: number,
): Promise<TriageSuggestion> {
  return api.get(`/v1/threat-intel/siem/alerts/${alertId}/triage-suggestion`, {
    auth: true,
    query: { tenant },
  });
}

export async function updateAlertNotes(
  tenant: string,
  alertId: number,
  notes: string,
): Promise<{ id: number; status: string; notes: string | null }> {
  return api.patch(`/v1/threat-intel/siem/alerts/${alertId}/notes`, { notes }, {
    auth: true,
    query: { tenant },
  });
}

export interface AttackMapData {
  nodes: Array<{ ip: string; lat: number; lon: number; country: string; city: string; type: string; alertCount: number }>;
  edges: Array<{ source: string; destination: string; severity: string; alertCount: number; latestEvent: string }>;
  countrySummary: Array<{ country: string; attack_count: number; unique_ips: number }>;
  timeRange: string;
  generatedAt: string;
}

export async function fetchAttackMapData(
  tenant: string,
): Promise<AttackMapData> {
  return api.get('/v1/threat-intel/siem/attack-map', {
    auth: true,
    query: { tenant },
  });
}

// ─── Threat Hunting ──────────────────────────────────────────────

export interface ThreatHuntQuery {
  id: number;
  tenant_slug: string;
  name: string;
  description: string | null;
  query_type: 'kql' | 'sql' | 'regex' | 'yara';
  query_text: string;
  data_source: string;
  last_run_at: string | null;
  last_result_count: number;
  created_by: number | null;
  created_at: string;
  updated_at: string;
}

export interface ThreatHuntResult {
  queryId: number;
  queryType: string;
  dataSource: string;
  resultCount: number;
  results: Array<Record<string, unknown>>;
  executedAt: string;
}

export async function fetchThreatHuntQueries(
  tenant: string,
  options: { limit?: number; offset?: number; queryType?: string } = {}
): Promise<ListResponse<ThreatHuntQuery>> {
  return api.get('/v1/threat-intel/hunts', {
    auth: true,
    query: { tenant, ...options },
  });
}

export async function createThreatHuntQuery(
  tenant: string,
  payload: { name: string; queryText: string; description?: string; queryType?: string; dataSource?: string }
): Promise<ThreatHuntQuery> {
  return api.post('/v1/threat-intel/hunts', payload, {
    auth: true,
    query: { tenant },
  });
}

export async function updateThreatHuntQuery(
  tenant: string,
  queryId: number,
  payload: { name?: string; description?: string; queryType?: string; queryText?: string; dataSource?: string }
): Promise<ThreatHuntQuery> {
  return api.put(`/v1/threat-intel/hunts/${queryId}`, payload, {
    auth: true,
    query: { tenant },
  });
}

export async function deleteThreatHuntQuery(
  tenant: string,
  queryId: number
): Promise<{ deleted: boolean }> {
  return api.delete(`/v1/threat-intel/hunts/${queryId}`, {
    auth: true,
    query: { tenant },
  });
}

export async function executeThreatHuntQuery(
  tenant: string,
  queryId: number
): Promise<ThreatHuntResult> {
  return api.post(`/v1/threat-intel/hunts/${queryId}/execute`, undefined, {
    auth: true,
    query: { tenant },
  });
}

// ─── Multi-Framework Compliance ─────────────────────────────────

export interface ComplianceFramework {
  id: string;
  name: string;
  version: string;
  description: string | null;
  category: string;
  created_at: string;
}

export interface ComplianceControl {
  id: number;
  framework_id: string;
  control_id: string;
  family: string;
  title: string;
  description: string | null;
  default_weight: number;
  created_at: string;
}

export interface ComplianceControlStatus {
  controlId: string;
  family: string;
  title: string;
  description: string | null;
  defaultWeight: number;
  status: 'not_started' | 'in_progress' | 'implemented' | 'validated' | 'not_applicable';
  ownerUserId: number | null;
  notes: string | null;
  updatedAt: string | null;
  evidenceCount: number;
}

export interface ComplianceGap {
  totalControls: number;
  validated: number;
  implemented: number;
  inProgress: number;
  notStarted: number;
  notApplicable: number;
  readinessScore: number;
  gaps: Array<{
    controlId: string;
    family: string;
    title: string;
    status: string;
    recommendedAction: string;
  }>;
  validatedWithoutEvidence: number;
}

export interface ComplianceFrameworkSummary {
  frameworkId: string;
  name: string;
  version: string;
  category: string;
  totalControls: number;
  readinessScore: number;
  validated: number;
  implemented: number;
  inProgress: number;
  notStarted: number;
  notApplicable: number;
  gapCount: number;
}

export async function fetchComplianceFrameworks(
  tenant: string
): Promise<{ data: ComplianceFramework[] }> {
  return api.get('/v1/compliance/frameworks', {
    auth: true,
    query: { tenant },
  });
}

export async function fetchComplianceSummary(
  tenant: string
): Promise<{ frameworks: ComplianceFrameworkSummary[] }> {
  return api.get('/v1/compliance/summary', {
    auth: true,
    query: { tenant },
  });
}

export async function fetchFrameworkControls(
  tenant: string,
  frameworkId: string,
  options: { family?: string } = {}
): Promise<{ data: ComplianceControl[]; total: number }> {
  return api.get(`/v1/compliance/frameworks/${encodeURIComponent(frameworkId)}/controls`, {
    auth: true,
    query: { tenant, ...options },
  });
}

export async function fetchFrameworkStatus(
  tenant: string,
  frameworkId: string
): Promise<{ controls: ComplianceControlStatus[]; gap: ComplianceGap }> {
  return api.get(`/v1/compliance/frameworks/${encodeURIComponent(frameworkId)}/status`, {
    auth: true,
    query: { tenant },
  });
}

export async function updateFrameworkControlStatus(
  tenant: string,
  frameworkId: string,
  controlId: string,
  payload: { status: string; ownerUserId?: number; notes?: string }
): Promise<{
  tenantSlug: string;
  frameworkId: string;
  controlId: string;
  status: string;
  ownerUserId: number | null;
  notes: string | null;
  updatedAt: string;
}> {
  return api.patch(
    `/v1/compliance/frameworks/${encodeURIComponent(frameworkId)}/status/${encodeURIComponent(controlId)}`,
    payload,
    { auth: true, query: { tenant } }
  );
}

// ─── Policy Approval Workflow ───────────────────────────────────────

export async function fetchPolicies(tenant: string): Promise<{ data: PolicyRecord[] }> {
  return api.get('/v1/compliance/policies', { auth: true, query: { tenant } });
}

export async function updatePolicyApprovalStatus(
  tenant: string,
  policyId: string,
  payload: { status: PolicyStatus; rejectionReason?: string }
): Promise<PolicyRecord> {
  return api.patch(
    `/v1/compliance/policies/${encodeURIComponent(policyId)}/status`,
    payload,
    { auth: true, query: { tenant } }
  );
}

// ─── Billing / Stripe ───────────────────────────────────────────────

export async function createBillingCheckout(payload: {
  tenant: string;
  planKey: 'pro' | 'enterprise';
  billingCycle: 'monthly' | 'annual';
  returnTo?: string;
}): Promise<{ sessionUrl: string }> {
  const result = await api.post('/v1/billing/checkout', {
    plan: payload.planKey,
    billingCycle: payload.billingCycle,
    successUrl: `${window.location.origin}/billing/success`,
    cancelUrl: `${window.location.origin}/billing/cancel`,
  }, { auth: true, query: { tenant: payload.tenant } });
  return { sessionUrl: result.url || '' };
}

export async function fetchBillingStatus(tenant: string): Promise<{
  plan: string;
  status: string;
  currentPeriodEnd: string | null;
}> {
  return api.get('/v1/billing/status', { auth: true, query: { tenant } });
}

// ─── Workspace Invites ──────────────────────────────────────────────

export interface InviteRecord {
  id: string;
  email: string;
  role: string;
  expiresAt: string;
  acceptedAt: string | null;
  createdAt: string;
}

export async function createWorkspaceInvite(
  tenant: string,
  payload: { email: string; role: string }
): Promise<{ inviteId: string; expiresAt: string }> {
  return api.post('/v1/admin/invites', payload, { auth: true, query: { tenant } });
}

export async function listWorkspaceInvites(tenant: string): Promise<{ data: InviteRecord[] }> {
  return api.get('/v1/admin/invites', { auth: true, query: { tenant } });
}

export async function revokeWorkspaceInvite(tenant: string, inviteId: string): Promise<void> {
  return api.delete(`/v1/admin/invites/${encodeURIComponent(inviteId)}`, { auth: true, query: { tenant } });
}

// ─── Connector Configuration ────────────────────────────────────────

export interface ConnectorConfig {
  id: string;
  connector: string;
  apiUrl: string;
  enabled: boolean;
  lastSyncAt: string | null;
  lastSyncStatus: string | null;
}

export async function listConnectorConfigs(tenant: string): Promise<{ data: ConnectorConfig[] }> {
  return api.get('/v1/admin/connectors', { auth: true, query: { tenant } });
}

export async function upsertConnectorConfig(
  tenant: string,
  connector: string,
  payload: { apiUrl: string; apiToken?: string; enabled: boolean }
): Promise<ConnectorConfig> {
  return api.put(`/v1/admin/connectors/${encodeURIComponent(connector)}`, payload, {
    auth: true,
    query: { tenant },
  });
}

export async function testConnectorConnection(
  tenant: string,
  connector: string
): Promise<{ success: boolean; message: string; latencyMs?: number }> {
  return api.post(`/v1/admin/connectors/${encodeURIComponent(connector)}/test`, {}, {
    auth: true,
    query: { tenant },
  });
}

// ─── API Key Management ─────────────────────────────────────────────

export interface ApiKeyRecord {
  id: string;
  name: string;
  keyPrefix: string;
  scopes: string[];
  lastUsedAt: string | null;
  expiresAt: string | null;
  createdAt: string;
}

export async function listApiKeys(tenant: string): Promise<{ data: ApiKeyRecord[] }> {
  return api.get('/v1/admin/api-keys', { auth: true, query: { tenant } });
}

export async function createApiKey(
  tenant: string,
  payload: { name: string; scopes?: string[]; expiresIn?: string }
): Promise<{ id: string; rawKey: string; keyPrefix: string }> {
  return api.post('/v1/admin/api-keys', payload, { auth: true, query: { tenant } });
}

export async function revokeApiKey(tenant: string, keyId: string): Promise<void> {
  return api.delete(`/v1/admin/api-keys/${encodeURIComponent(keyId)}`, { auth: true, query: { tenant } });
}

// ─── Notification Preferences ───────────────────────────────────────

export interface NotificationPreferences {
  emailOnCritical: boolean;
  emailOnHigh: boolean;
  emailOnResolved: boolean;
  inAppAll: boolean;
}

export async function fetchNotificationPreferences(): Promise<NotificationPreferences> {
  return api.get('/v1/notifications/preferences', { auth: true });
}

export async function updateNotificationPreferences(
  prefs: Partial<NotificationPreferences>
): Promise<NotificationPreferences> {
  return api.patch('/v1/notifications/preferences', prefs, { auth: true });
}
