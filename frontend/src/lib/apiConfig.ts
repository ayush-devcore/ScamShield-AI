import { resolveApiBaseUrl } from "@/lib/apiBase.mjs";

const apiBaseUrl = resolveApiBaseUrl(import.meta.env.VITE_API_BASE_URL, import.meta.env.DEV);

export function apiUrl(path: string): string {
  if (!apiBaseUrl) {
    throw new Error("The backend API is not configured for this build. Set VITE_API_BASE_URL to the reachable ScamShield API base URL.");
  }
  return `${apiBaseUrl}${path.startsWith("/") ? path : `/${path}`}`;
}
