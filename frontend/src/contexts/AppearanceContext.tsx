import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { getAppearancePreference, getCurrentUser, getStoredAuthToken, saveAppearancePreference, type AppearanceMode } from "@/lib/api";

type AppearanceStatus = "loading" | "saved" | "saving" | "fallback";
interface AppearanceContextValue {
  mode: AppearanceMode;
  setMode: (mode: AppearanceMode) => Promise<void>;
  status: AppearanceStatus;
  error: string;
}

const AppearanceContext = createContext<AppearanceContextValue | null>(null);
const cacheKey = (userId: string) => `scamshield_appearance:${userId}`;

function storedUserId(): string | null {
  try {
    const user = JSON.parse(sessionStorage.getItem("scamshield_user") ?? "null");
    return typeof user?.id === "string" ? user.id : null;
  } catch { return null; }
}

function readInitialMode(): AppearanceMode {
  const id = storedUserId();
  if (!id) return "dark";
  try {
    const value = localStorage.getItem(cacheKey(id));
    return value === "dark" || value === "light" || value === "system" ? value : "dark";
  } catch { return "dark"; }
}

function applyMode(mode: AppearanceMode) {
  const resolved = mode === "system"
    ? (window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark")
    : mode;
  document.documentElement.dataset.theme = resolved;
  document.documentElement.dataset.themeMode = mode;
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", resolved === "light" ? "#edf3f8" : "#0B1220");
}

export function AppearanceProvider({ children }: { children: ReactNode }) {
  const [mode, setModeState] = useState<AppearanceMode>(readInitialMode);
  const [status, setStatus] = useState<AppearanceStatus>(getStoredAuthToken() ? "loading" : "fallback");
  const [error, setError] = useState("");
  const userId = useRef<string | null>(storedUserId());
  const operation = useRef(0);

  useEffect(() => {
    applyMode(mode);
    const media = window.matchMedia("(prefers-color-scheme: light)");
    const updateSystemMode = () => { if (mode === "system") applyMode("system"); };
    media.addEventListener("change", updateSystemMode);
    return () => media.removeEventListener("change", updateSystemMode);
  }, [mode]);

  useEffect(() => {
    if (!getStoredAuthToken()) return;
    const request = ++operation.current;
    let active = true;
    void (async () => {
      try {
        const user = await getCurrentUser();
        if (!active || request !== operation.current) return;
        userId.current = user.id;
        try {
          const cached = localStorage.getItem(cacheKey(user.id));
          if (cached === "dark" || cached === "light" || cached === "system") setModeState(cached);
        } catch { /* Server preference remains available if browser storage is blocked. */ }
        const preference = await getAppearancePreference();
        if (!active || request !== operation.current) return;
        setModeState(preference.appearance);
        try { localStorage.setItem(cacheKey(user.id), preference.appearance); } catch { /* Server remains the source of truth. */ }
        setStatus("saved");
        setError("");
      } catch {
        if (!active || request !== operation.current) return;
        setStatus("fallback");
        setError("Account appearance sync is unavailable; this browser's saved theme is being used.");
      }
    })();
    return () => { active = false; };
  }, []);

  const setMode = useCallback(async (nextMode: AppearanceMode) => {
    const request = ++operation.current;
    setModeState(nextMode);
    setStatus("saving");
    setError("");
    let id = userId.current;
    try {
      if (!id) {
        const user = await getCurrentUser();
        id = user.id;
        userId.current = id;
      }
      try { localStorage.setItem(cacheKey(id), nextMode); } catch { /* Continue with account persistence. */ }
      await saveAppearancePreference(nextMode);
      if (request === operation.current) setStatus("saved");
    } catch {
      if (request === operation.current) {
        setStatus("fallback");
        setError("Theme changed in this browser, but account sync failed. Try again later.");
      }
    }
  }, []);

  return <AppearanceContext.Provider value={{ mode, setMode, status, error }}>{children}</AppearanceContext.Provider>;
}

export function useAppearance() {
  const context = useContext(AppearanceContext);
  if (!context) throw new Error("useAppearance must be used inside AppearanceProvider.");
  return context;
}
