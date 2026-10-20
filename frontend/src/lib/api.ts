const API_BASE_URL =
  (import.meta as ImportMeta & { env: { VITE_API_BASE_URL?: string } }).env
    .VITE_API_BASE_URL ?? "http://127.0.0.1:8000/api/v1";

export interface UserSummary {
  id: string;
  name: string;
  email: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
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
  status: "queued" | "analyzing" | "safe" | "medium" | "high" | "critical";
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

export function logout() {
  clearAuthSession();
  window.location.assign("/login");
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

  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers,
  });

  const data = await response.json().catch(() => null);

  if (!response.ok) {
    if (response.status === 401 || response.status === 403) {
      clearAuthSession();
    }
    throw new Error(
      data?.detail ?? `Request failed with status ${response.status}`,
    );
  }

  return data as T;
}

export function getCurrentUser(): Promise<UserSummary> {
  return apiRequest<UserSummary>("/auth/me");
}

export function getDashboard(): Promise<DashboardData> {
  return apiRequest<DashboardData>("/dashboard");
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
    | "critical";
  risk_score: number | null;
  confidence: number | null;
  threat_type: string | null;
  redacted_preview: string | null;
  created_at: string;
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

export function createQrScan(payload: string) {
  return apiRequest<MessageScanResponse>("/scans/qr", {
    method: "POST",
    body: JSON.stringify({ payload }),
  });
}

export function createScreenshotScan(file: File) {
  const formData = new FormData();
  formData.append("file", file);

  return fetch(`${API_BASE_URL}/scans/screenshot`, {
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
    | "critical";
  risk_score: number | null;
  confidence: number | null;
  threat_type: string | null;
  created_at: string;
}

export function getScanHistory() {
  return apiRequest<ScanHistoryItem[]>("/scans");
}
