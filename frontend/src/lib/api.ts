import { apiUrl } from "@/lib/apiConfig";

export interface UserSummary {
  id: string;
  name: string;
  email: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface AuthTokenResponse {
  access_token?: string | null;
  token_type?: string;
  expires_in?: number | null;
  user?: AuthUserSummary | null;
  mfa_required?: boolean;
  mfa_challenge?: string | null;
}

export interface AuthUserSummary {
  id: string;
  name: string;
  email: string;
  is_active: boolean;
}

export class ApiError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message);
    this.name = "ApiError";
  }
}

export interface DashboardData {
  stats: {
    total_scans: number;
    high_risk: number;
    medium_risk: number;
    safe_scans: number;
  };

  threat_activity: {
    day: string;
    scans: number;
  }[];

  threat_distribution: {
    name: string;
    value: number;
  }[];

  recent_scans: {
    id: string;
    title: string;
    type: string;
    score: number | null;
    confidence: number | null;
    status: "critical" | "high" | "medium" | "safe";
    date: string;
  }[];
}

export interface SecurityActivity {
  id: string;
  event_type: string;
  category: "scan" | "security";
  severity: "info" | "warning" | "high" | "critical";
  message: string;
  created_at: string;
}
export interface MfaStatus { enabled: boolean; recovery_codes?: string[] | null; }
export interface MfaEnrollment { provisioning_uri: string; manual_key: string; }
export interface ManagedSession { id: string; created_at: string; last_activity_at: string; expires_at: string; user_agent: string | null; current: boolean; }
export type AppearanceMode = "dark" | "light" | "system";
export interface NotificationPreferences { high_risk: boolean; critical_risk: boolean; security_events: boolean; }
export interface PrivacyPreferences { store_scan_history: boolean; }
export interface UserNotification { id: string; event_type: string; title: string; message: string; link_path: string | null; created_at: string; read_at: string | null; }
export interface NotificationList { items: UserNotification[]; unread_count: number; }
export interface SandboxStatus {
  status: "available" | "runtime_unavailable";
  available: boolean;
  message: string;
  reason: string | null;
  capabilities: {
    url_browser_runtime: boolean;
    restricted_egress: boolean;
    file_static_analysis: boolean;
    file_detonation: boolean;
  };
}
export interface SandboxJob {
  id: string;
  scan_id: string;
  state: string;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  error_code: string | null;
  observations: Record<string, unknown> | null;
  report: {
    classification?: string;
    risk_score?: number;
    reachability?: "reachable" | "unreachable" | "timed_out" | "blocked" | "unknown";
    findings?: { id: string; rule: string; title: string; severity: string; observation_refs: string[]; count?: number }[];
    conclusion?: string;
    limitations?: string[];
  } | null;
}

export interface ReportSummary {
  total_scans: number;
  risk_distribution: { label: string; count: number }[];
  scan_type_distribution: { name: string; count: number }[];
  threat_type_distribution: { name: string; count: number }[];
  recent_trends: { day: string; scans: number }[];
  recent_scans: {
    id: string;
    input_type: string;
    threat_type: string | null;
    risk_score: number | null;
    created_at: string;
  }[];
}
export interface ScanIndicator {
  id: string;
  indicator_type: string;
  description: string;
  severity: string;
  evidence: Record<string, unknown> | null;
}

export interface ScanAnalysis {
  id: string;
  model_name: string;
  model_version: string;
  prediction: string;
  probability: number | null;
  features: Record<string, unknown> | null;
  explanation: Record<string, unknown> | null;
  created_at: string;
}

export interface ScanDetailData {
  id: string;
  input_type: string;
  status: "queued" | "analyzing" | "safe" | "medium" | "high" | "critical" | "runtime_unavailable";
  risk_score: number | null;
  confidence: number | null;
  threat_type: string | null;
  created_at: string;
  analysis: ScanAnalysis | null;
  indicators: ScanIndicator[];
}

export function getStoredAuthToken() {
  return sessionStorage.getItem("scamshield_access_token");
}

export function clearAuthSession() {
  sessionStorage.removeItem("scamshield_access_token");
  sessionStorage.removeItem("scamshield_user");
}

export async function logout() {
  const token = getStoredAuthToken();
  try {
    if (token) await fetch(apiUrl("/auth/logout"), { method: "POST", headers: { Authorization: `Bearer ${token}` } });
  } catch {
    // Clear local credentials even when the server cannot be reached.
  } finally {
    clearAuthSession();
    window.location.assign("/login");
  }
}

async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {},
): Promise<T> {
  const token = getStoredAuthToken();

  const headers = new Headers(options.headers ?? {});
  if (!(options.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }

  if (token) {
    headers.set("Authorization", "Bearer " + token);
  }

  let response: Response;
  try {
    response = await fetch(apiUrl(endpoint), {
      ...options,
      headers,
      cache: options.cache ?? "no-store",
    });
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("The backend API is not configured")) throw error;
    throw new ApiError("Unable to reach the ScamShield server. Check your connection and try again.");
  }

  const raw = await response.text().catch(() => "");
  let data: unknown = null;
  if (raw) {
    try {
      data = JSON.parse(raw);
    } catch {
      data = null;
    }
  }

  if (!response.ok) {
    // A route can return 401 for a verification failure while the bearer
    // session is still valid. Only clear auth after the identity endpoint
    // rejects the same token; ordinary 403 responses never invalidate it.
    if (response.status === 401) {
      if (endpoint === "/auth/me") {
        if (getStoredAuthToken() === token) clearAuthSession();
      } else if (token && getStoredAuthToken() === token) {
        try {
          const identityResponse = await fetch(apiUrl("/auth/me"), {
            headers: { Authorization: `Bearer ${token}` },
            cache: "no-store",
          });
          if (
            (identityResponse.status === 401 || identityResponse.status === 403) &&
            getStoredAuthToken() === token
          ) {
            clearAuthSession();
          }
        } catch {
          // A failed identity check is not evidence that the session is invalid.
        }
      }
    }
    const detail = data && typeof data === "object" ? (data as Record<string, unknown>).detail ?? (data as Record<string, unknown>).message : null;
    const message = typeof detail === "string" ? detail : Array.isArray(detail) ? "Please check the submitted information." : `Request failed with status ${response.status}.`;
    throw new ApiError(message, response.status);
  }

  return (data ?? undefined) as T;
}

export function registerAccount(name: string, email: string, password: string): Promise<AuthUserSummary> {
  return apiRequest<AuthUserSummary>("/auth/register", {
    method: "POST",
    body: JSON.stringify({ name, email, password }),
  });
}

export function loginWithPassword(email: string, password: string): Promise<AuthTokenResponse> {
  return apiRequest<AuthTokenResponse>("/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}

export function resetPasswordWithAuthenticator(payload: {
  email: string;
  code: string;
  new_password: string;
  confirm_password: string;
}) {
  return apiRequest<{ message: string }>("/auth/password-reset/authenticator", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function getCurrentUser(): Promise<UserSummary> {
  return apiRequest<UserSummary>("/auth/me");
}
export const getMfaStatus = () => apiRequest<MfaStatus>("/auth/mfa");
export const beginMfaEnrollment = () => apiRequest<MfaEnrollment>("/auth/mfa/enroll", { method: "POST" });
export const verifyMfaEnrollment = (code: string) => apiRequest<MfaStatus>("/auth/mfa/verify", { method: "POST", body: JSON.stringify({ code }) });
export const regenerateRecoveryCodes = () => apiRequest<MfaStatus>("/auth/mfa/recovery-codes", { method: "POST" });
export const disableMfa = (code: string, useRecoveryCode: boolean) => apiRequest<MfaStatus>("/auth/mfa/disable", { method: "POST", body: JSON.stringify({ code, use_recovery_code: useRecoveryCode }) });
export const getSessions = () => apiRequest<ManagedSession[]>("/auth/sessions");
export const revokeSession = (id: string) => apiRequest<void>(`/auth/sessions/${id}`, { method: "DELETE" });
export const revokeOtherSessions = () => apiRequest<void>("/auth/sessions/revoke-others", { method: "POST" });
export const getAppearancePreference = () => apiRequest<{ appearance: AppearanceMode }>("/preferences/appearance");
export const saveAppearancePreference = (appearance: AppearanceMode) => apiRequest<{ appearance: AppearanceMode }>("/preferences/appearance", { method: "PUT", body: JSON.stringify({ appearance }) });
export const getNotificationPreferences = () => apiRequest<NotificationPreferences>("/preferences/notifications");
export const saveNotificationPreferences = (preferences: NotificationPreferences) => apiRequest<NotificationPreferences>("/preferences/notifications", { method: "PUT", body: JSON.stringify(preferences) });
export const getPrivacyPreferences = () => apiRequest<PrivacyPreferences>("/preferences/privacy");
export const savePrivacyPreferences = (preferences: PrivacyPreferences) => apiRequest<PrivacyPreferences>("/preferences/privacy", { method: "PUT", body: JSON.stringify(preferences) });
export const getNotifications = () => apiRequest<NotificationList>("/notifications");
export const markNotificationRead = (id: string) => apiRequest<void>(`/notifications/${id}/read`, { method: "POST" });
export const markAllNotificationsRead = () => apiRequest<void>("/notifications/read-all", { method: "POST" });
export const deleteScanHistory = () => apiRequest<{ deleted_count: number }>("/scans/history", { method: "DELETE" });
export const exportScanData = () => apiRequest<{ exported_at: string; scans: unknown[] }>("/scans/export");
export const getSandboxStatus = () => apiRequest<SandboxStatus>("/sandbox/status");
export const submitSandboxUrl = (url: string) => apiRequest<SandboxJob>("/sandbox/url", { method: "POST", body: JSON.stringify({ url }) });
export const getSandboxJobs = () => apiRequest<SandboxJob[]>("/sandbox/jobs");
export const getSandboxJob = (id: string) => apiRequest<SandboxJob>(`/sandbox/jobs/${id}`);
export const cancelSandboxJob = (id: string) => apiRequest<{ id: string; state: string; cancel_requested: boolean }>(`/sandbox/jobs/${id}/cancel`, { method: "POST" });

export function getDashboard(): Promise<DashboardData> {
  return apiRequest<DashboardData>("/dashboard");
}
export function getSecurityActivity(): Promise<SecurityActivity[]> {
  return apiRequest<SecurityActivity[]>("/activity");
}
export function getReports(): Promise<ReportSummary> {
  return apiRequest<ReportSummary>("/reports");
}
export function getScanDetail(scanId: string): Promise<ScanDetailData> {
  return apiRequest<ScanDetailData>(`/scans/${scanId}`);
}

export interface MessageScanResponse {
  id: string;
  input_type: string;
  status:
    | "queued"
    | "analyzing"
    | "safe"
    | "medium"
    | "high"
    | "critical"
    | "runtime_unavailable";
  risk_score: number | null;
  confidence: number | null;
  threat_type: string | null;
  redacted_preview: string | null;
  created_at: string;
  analysis?: ScanAnalysis | null;
  indicators?: ScanIndicator[] | null;
}

export interface UrlDecisionResponse {
  outcome: "dataset_match" | "sandbox_queued" | "runtime_unavailable" | "sandbox_blocked";
  dataset_lookup: {
    status: "known_malicious" | "non_malicious_label" | "not_listed" | "ambiguous";
    match_type?: "exact_url" | "scheme_agnostic_path" | null;
    source_label?: string | null;
    dataset_name?: string | null;
    record_source?: string | null;
    dataset_fingerprint?: string | null;
    imported_at?: string | null;
    recorded_at?: string | null;
  };
  risk_assessment?: {
    verdict: "known_malicious" | "suspicious" | "unverified";
    risk_score?: number | null;
    method: string;
    explanation: string;
    indicators: string[];
    limitations: string[];
  } | null;
  reachability: "not_checked" | "pending" | "reachable" | "unreachable" | "timed_out" | "blocked" | "unknown" | "runtime_unavailable";
  reason?: string | null;
  scan?: MessageScanResponse | null;
  sandbox_job?: SandboxJob | null;
}

export function createMessageScan(message: string) {
  return apiRequest<MessageScanResponse>("/scans/message", {
    method: "POST",
    body: JSON.stringify({ message }),
  });
}

export function createUrlScan(url: string) {
  return apiRequest<MessageScanResponse>("/scans/url", {
    method: "POST",
    body: JSON.stringify({ url }),
  });
}

export function createUrlDecision(url: string) {
  return apiRequest<UrlDecisionResponse>("/scans/url/decision", {
    method: "POST",
    body: JSON.stringify({ url }),
  });
}

export function createQrScan(payload: string) {
  return apiRequest<MessageScanResponse>("/scans/qr", {
    method: "POST",
    body: JSON.stringify({ payload }),
  });
}

export function createScreenshotScan(file: File) {
  const formData = new FormData();
  formData.append("file", file);

  return fetch(apiUrl("/scans/screenshot"), {
    method: "POST",
    headers: {
      Authorization: `Bearer ${getStoredAuthToken() ?? ""}`,
    },
    body: formData,
  }).then(async (response) => {
    const data = await response.json().catch(() => null);

    if (!response.ok) {
      if (response.status === 401 || response.status === 403) {
        clearAuthSession();
      }
      throw new Error(data?.detail ?? `Request failed with status ${response.status}`);
    }

    return data as MessageScanResponse;
  });
}

export interface ScanHistoryItem {
  id: string;
  input_type: string;
  redacted_preview?: string | null;
  status:
    | "queued"
    | "analyzing"
    | "safe"
    | "medium"
    | "high"
    | "critical"
    | "runtime_unavailable";
  risk_score: number | null;
  confidence: number | null;
  threat_type: string | null;
  created_at: string;
}

export function getScanHistory() {
  return apiRequest<ScanHistoryItem[]>("/scans");
}
