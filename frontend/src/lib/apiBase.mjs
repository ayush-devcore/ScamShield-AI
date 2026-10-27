export function resolveApiBaseUrl(configuredUrl, isDevelopment) {
  const configured = configuredUrl?.trim();
  if (configured) return configured.replace(/\/+$/, "");
  if (isDevelopment) return "http://127.0.0.1:8000/api/v1";
  return "";
}
