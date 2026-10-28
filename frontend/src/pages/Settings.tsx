import { useEffect, useRef, useState } from "react";
import { Copy, KeyRound, Laptop, Monitor, Moon, RefreshCw, Sun } from "lucide-react";
import { beginMfaEnrollment, disableMfa, getMfaStatus, getSessions, regenerateRecoveryCodes, revokeOtherSessions, revokeSession, type ManagedSession, type MfaEnrollment, verifyMfaEnrollment } from "@/lib/api";
import { deleteScanHistory, exportScanData, getNotificationPreferences, getPrivacyPreferences, saveNotificationPreferences, savePrivacyPreferences, type NotificationPreferences, type PrivacyPreferences } from "@/lib/api";
import { useAppearance } from "@/contexts/AppearanceContext";

const fmt = (value: string) => new Date(value).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });

export default function Settings() {
  const [enabled, setEnabled] = useState(false), [sessions, setSessions] = useState<ManagedSession[]>([]), [enrollment, setEnrollment] = useState<MfaEnrollment | null>(null), [codes, setCodes] = useState<string[] | null>(null), [code, setCode] = useState(""), [recover, setRecover] = useState(false), [disableMode, setDisableMode] = useState(false), [message, setMessage] = useState(""), [error, setError] = useState(""), [loading, setLoading] = useState(true);
  const appearance = useAppearance();
  const [notificationPreferences, setNotificationPreferences] = useState<NotificationPreferences>({ high_risk: true, critical_risk: true, security_events: true });
  const [privacyPreferences, setPrivacyPreferences] = useState<PrivacyPreferences>({ store_scan_history: true });
  const [preferencesLoading, setPreferencesLoading] = useState(true), [preferencesLoaded, setPreferencesLoaded] = useState(false), [preferencesSaving, setPreferencesSaving] = useState(false), [preferencesError, setPreferencesError] = useState(""), [preferencesMessage, setPreferencesMessage] = useState("");
  const [privacyBusy, setPrivacyBusy] = useState(false), [privacyError, setPrivacyError] = useState(""), [privacyMessage, setPrivacyMessage] = useState("");
  const [browserPermission, setBrowserPermission] = useState<NotificationPermission | "unsupported">(() => typeof window !== "undefined" && "Notification" in window ? Notification.permission : "unsupported");
  const loadSequence = useRef(0), actionSequence = useRef(0);
  const load = async (fromAction = false) => {
    if (!fromAction) actionSequence.current += 1;
    const sequence = ++loadSequence.current;
    const actionAtStart = actionSequence.current;
    setLoading(true); setMessage("");
    try {
      const [mfa, active] = await Promise.all([getMfaStatus(), getSessions()]);
      const current = sequence === loadSequence.current && actionAtStart === actionSequence.current;
      if (current) { setEnabled(mfa.enabled); setSessions(active); setError(""); }
      return current;
    } catch (err) {
      if (sequence === loadSequence.current && actionAtStart === actionSequence.current) { setError(err instanceof Error ? err.message : "Unable to load security settings."); setMessage(""); }
      return false;
    } finally { if (sequence === loadSequence.current) setLoading(false); }
  };
  useEffect(() => { void load(); }, []);
  const loadPreferences = async () => {
    setPreferencesLoading(true); setPreferencesError(""); setPreferencesMessage("");
    try {
      const [notifications, privacy] = await Promise.all([getNotificationPreferences(), getPrivacyPreferences()]);
      setNotificationPreferences(notifications); setPrivacyPreferences(privacy); setPreferencesLoaded(true);
    } catch (err) {
      setPreferencesLoaded(false); setPreferencesError(err instanceof Error ? err.message : "Unable to load notification and privacy preferences.");
    } finally { setPreferencesLoading(false); }
  };
  useEffect(() => { void loadPreferences(); }, []);
  const execute = async (action: () => Promise<string | void>) => {
    const sequence = ++actionSequence.current;
    setError(""); setMessage("");
    try { const success = await action(); if (success && sequence === actionSequence.current) setMessage(success); }
    catch (err) { if (sequence === actionSequence.current) { setMessage(""); setError(err instanceof Error ? err.message : "Security action failed."); } }
  };
  const updateNotificationPreference = async (key: keyof NotificationPreferences, value: boolean) => {
    const previous = notificationPreferences;
    const next = { ...previous, [key]: value };
    setNotificationPreferences(next); setPreferencesSaving(true); setPreferencesError(""); setPreferencesMessage("");
    try { setNotificationPreferences(await saveNotificationPreferences(next)); setPreferencesMessage("Notification preferences saved."); }
    catch (err) { setNotificationPreferences(previous); setPreferencesError(err instanceof Error ? err.message : "Unable to save notification preferences."); }
    finally { setPreferencesSaving(false); }
  };
  const updateHistoryPreference = async (value: boolean) => {
    const previous = privacyPreferences;
    setPrivacyPreferences({ store_scan_history: value }); setPreferencesSaving(true); setPreferencesError(""); setPreferencesMessage("");
    try { setPrivacyPreferences(await savePrivacyPreferences({ store_scan_history: value })); setPreferencesMessage("Privacy preference saved."); }
    catch (err) { setPrivacyPreferences(previous); setPreferencesError(err instanceof Error ? err.message : "Unable to save privacy preference."); }
    finally { setPreferencesSaving(false); }
  };
  const requestBrowserPermission = async () => {
    if (!("Notification" in window)) { setBrowserPermission("unsupported"); return; }
    try { setBrowserPermission(await Notification.requestPermission()); }
    catch { setBrowserPermission("denied"); }
  };
  const downloadExport = async () => {
    setPrivacyBusy(true); setPrivacyError(""); setPrivacyMessage("");
    try {
      const data = await exportScanData();
      const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
      const anchor = document.createElement("a"); anchor.href = url; anchor.download = "scamshield-scan-export.json"; anchor.click(); URL.revokeObjectURL(url);
      setPrivacyMessage(`Exported ${data.scans.length} saved scans.`);
    } catch (err) { setPrivacyError(err instanceof Error ? err.message : "Unable to export scan data."); }
    finally { setPrivacyBusy(false); }
  };
  const deleteHistory = async () => {
    if (!window.confirm("Permanently delete all saved scans and their analysis and indicator records for this account? This cannot be undone. Account-security audit records will be retained.")) return;
    setPrivacyBusy(true); setPrivacyError(""); setPrivacyMessage("");
    try {
      const result = await deleteScanHistory();
      setPrivacyMessage(`Deleted ${result.deleted_count} saved scans.`);
      window.dispatchEvent(new Event("scamshield:scan-history-changed"));
    } catch (err) { setPrivacyError(err instanceof Error ? err.message : "Unable to delete scan history."); }
    finally { setPrivacyBusy(false); }
  };
  return <div className="settings-page space-y-6"><div><p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-cyan-300">Account security</p><h1 className="mt-3 text-3xl font-semibold text-white">Settings</h1><p className="mt-2 text-sm text-slate-400">Manage your appearance, privacy, notifications, recovery and active sessions.</p></div>
    <nav className="settings-jump flex gap-2 overflow-x-auto pb-1" aria-label="Settings sections">{[["appearance-title", "Appearance"], ["notifications-title", "Notifications"], ["privacy-title", "Privacy"], ["recovery-title", "Recovery"], ["sessions-title", "Sessions"]].map(([id, label]) => <a key={id} href={`#${id}`} className="shrink-0 rounded-full border border-slate-700/80 bg-slate-950/20 px-3 py-2 text-xs text-slate-300 transition hover:border-cyan-300/30 hover:text-cyan-100">{label}</a>)}</nav>
    {error && <p role="alert" className="rounded-xl border border-rose-400/30 bg-rose-400/10 p-3 text-sm text-rose-200">{error}</p>}{message && <p role="status" className="rounded-xl border border-teal-400/30 bg-teal-400/10 p-3 text-sm text-teal-100">{message}</p>}
    <section className="scam-card rounded-2xl p-5" aria-labelledby="appearance-title">
      <div className="flex items-start justify-between gap-4"><div><h2 id="appearance-title" className="text-sm font-semibold text-white">Appearance</h2><p className="mt-1 text-xs text-slate-400">Choose a theme for every ScamShield page and panel.</p></div><span className="rounded-full border border-cyan-400/20 px-2.5 py-1 text-[10px] font-medium text-cyan-200">{appearance.mode === "system" ? "Follows device" : `${appearance.mode[0].toUpperCase()}${appearance.mode.slice(1)} theme`}</span></div>
      <div className="mt-4 grid max-w-xl grid-cols-3 gap-2" role="group" aria-label="Appearance theme">
        {([ ["dark", "Dark", Moon], ["light", "Light", Sun], ["system", "System", Monitor] ] as const).map(([mode, label, Icon]) => <button key={mode} type="button" aria-pressed={appearance.mode === mode} disabled={appearance.status === "loading" || appearance.status === "saving"} onClick={() => void appearance.setMode(mode)} className={`flex min-h-16 flex-col items-center justify-center gap-1.5 rounded-xl border px-3 py-2 text-xs font-medium transition focus-visible:outline-none disabled:cursor-wait disabled:opacity-60 ${appearance.mode === mode ? "border-cyan-300/60 bg-cyan-400/10 text-cyan-100" : "border-slate-700 bg-slate-950/20 text-slate-300 hover:border-cyan-300/30"}`}><Icon className="h-4 w-4"/>{label}</button>)}
      </div>
      <p className="mt-3 text-xs text-slate-400" role="status">{appearance.status === "loading" ? "Loading your saved appearance…" : appearance.status === "saving" ? "Saving appearance to your account…" : appearance.status === "saved" ? "Appearance is synced to your account." : "Using this browser’s saved appearance; account sync is unavailable."}</p>
      {appearance.error && <p className="mt-2 text-xs text-amber-200" role="alert">{appearance.error}</p>}
    </section>
    <section className="scam-card rounded-2xl p-5" aria-labelledby="notifications-title">
      <div><h2 id="notifications-title" className="text-sm font-semibold text-white">Notifications</h2><p className="mt-1 text-xs text-slate-400">Choose which genuine scan and account-security events create an in-app notification.</p></div>
      {preferencesLoading ? <p className="mt-4 text-xs text-slate-400">Loading notification preferences…</p> : <div className="mt-4 space-y-3">
        {([ ["high_risk", "High-risk scan results", "Notify after a completed scan receives the existing high-risk classification."], ["critical_risk", "Critical-risk scan results", "Notify after a completed scan receives the existing critical-risk classification."], ["security_events", "Account-security events", "Notify for completed sign-ins, authenticator recovery changes, recovery-code regeneration, and session revocations."] ] as const).map(([key, title, description]) => <label key={key} className="flex items-start gap-3 rounded-xl border border-slate-700/70 bg-slate-950/20 p-3"><input className="mt-0.5 accent-cyan-400" type="checkbox" checked={notificationPreferences[key]} disabled={preferencesSaving || !preferencesLoaded} onChange={(event) => void updateNotificationPreference(key, event.target.checked)}/><span><span className="block text-xs font-medium text-white">{title}</span><span className="mt-1 block text-[11px] leading-5 text-slate-400">{description}</span></span></label>)}
      </div>}
      {!preferencesLoading && !preferencesLoaded && <button type="button" onClick={() => void loadPreferences()} className="mt-3 text-xs text-cyan-200">Retry loading preferences</button>}
      <div className="mt-4 flex flex-wrap items-center gap-3"><button type="button" disabled={browserPermission === "unsupported" || browserPermission === "granted"} onClick={() => void requestBrowserPermission()} className="rounded-lg border border-cyan-400/30 px-3 py-2 text-xs text-cyan-100 disabled:opacity-60">{browserPermission === "granted" ? "Browser alerts allowed" : browserPermission === "denied" ? "Browser alerts blocked in browser settings" : browserPermission === "unsupported" ? "Browser alerts unsupported" : "Enable browser alerts"}</button><p className="text-[11px] text-slate-400">Permission is requested only after clicking. Alerts are checked while the app is open; background push is not configured.</p></div>
      {preferencesSaving && <p className="mt-3 text-xs text-slate-400" role="status">Saving preferences…</p>}{preferencesMessage && <p className="mt-3 text-xs text-teal-200" role="status">{preferencesMessage}</p>}{preferencesError && <p className="mt-3 text-xs text-rose-200" role="alert">{preferencesError}</p>}
    </section>
    <section className="scam-card rounded-2xl p-5" aria-labelledby="privacy-title">
      <div><h2 id="privacy-title" className="text-sm font-semibold text-white">Privacy controls</h2><p className="mt-1 text-xs text-slate-400">Control future scan storage and manage the history already saved to this account.</p></div>
      {preferencesLoading ? <p className="mt-4 text-xs text-slate-400">Loading privacy preferences…</p> : <label className="mt-4 flex items-start gap-3 rounded-xl border border-slate-700/70 bg-slate-950/20 p-3"><input className="mt-0.5 accent-cyan-400" type="checkbox" checked={privacyPreferences.store_scan_history} disabled={preferencesSaving || !preferencesLoaded} onChange={(event) => void updateHistoryPreference(event.target.checked)}/><span><span className="block text-xs font-medium text-white">Store scan history</span><span className="mt-1 block text-[11px] leading-5 text-slate-400">When off, scans are still analyzed and returned, but new inputs, previews, analysis results, and indicators are not saved as history. Existing scans are kept until you delete them.</span></span></label>}
      {!preferencesLoading && !preferencesLoaded && <button type="button" onClick={() => void loadPreferences()} className="mt-3 text-xs text-cyan-200">Retry loading preferences</button>}
      <div className="mt-4 flex flex-wrap gap-2"><button type="button" disabled={privacyBusy} onClick={() => void downloadExport()} className="rounded-lg border border-cyan-400/30 px-3 py-2 text-xs text-cyan-100 disabled:opacity-60">{privacyBusy ? "Working…" : "Export my scan data"}</button><button type="button" disabled={privacyBusy} onClick={() => void deleteHistory()} className="rounded-lg border border-rose-400/30 px-3 py-2 text-xs text-rose-200 disabled:opacity-60">Delete my scan history</button></div>
      {privacyMessage && <p className="mt-3 text-xs text-teal-200" role="status">{privacyMessage}</p>}{privacyError && <p className="mt-3 text-xs text-rose-200" role="alert">{privacyError}</p>}
    </section>
    <section className="scam-card rounded-2xl p-5"><div className="flex items-start justify-between gap-3"><div><div className="flex items-center gap-2"><KeyRound className="h-5 w-5 text-cyan-300"/><h2 id="recovery-title" className="text-sm font-semibold text-white">Password recovery authenticator</h2></div><p className="mt-2 text-xs leading-5 text-slate-400">{enabled ? "Use an authenticator or unused recovery code to reset your password. Normal sign-in uses your email and password." : "Set up an authenticator for password recovery. It is not requested during normal sign-in."}</p></div><span className={`rounded-full px-2 py-1 text-[10px] font-semibold ${enabled ? "bg-teal-400/15 text-teal-200" : "bg-slate-700 text-slate-300"}`}>{loading ? "Checking status" : error ? "Status unavailable" : enabled ? "Recovery enabled" : "Not configured"}</span></div>
      {!enabled && !enrollment && <button className="mt-5 rounded-lg bg-cyan-400 px-3 py-2 text-xs font-semibold text-slate-950" onClick={() => void execute(async () => { const value = await beginMfaEnrollment(); setEnrollment(value); return "Authenticator setup started."; })}>Set up authenticator</button>}
      {enrollment && <div className="mt-4 space-y-3 rounded-xl border border-cyan-400/20 bg-cyan-400/[0.05] p-4"><p className="text-xs text-slate-300">Add this setup key to your authenticator, then verify its current code to enable password recovery.</p><code className="block break-all rounded bg-slate-950/60 p-3 text-xs text-cyan-200">{enrollment.manual_key}</code><input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" placeholder="Authenticator code" className="h-10 w-full rounded-lg border border-slate-700 bg-slate-950/40 px-3 text-sm text-white"/><button disabled={code.length < 6} className="rounded-lg bg-cyan-400 px-3 py-2 text-xs font-semibold text-slate-950 disabled:opacity-50" onClick={() => void execute(async () => { const value = await verifyMfaEnrollment(code); setEnabled(value.enabled); setCodes(value.recovery_codes ?? null); setEnrollment(null); setCode(""); return await load(true) ? "Authenticator recovery enabled. Save these recovery codes now." : undefined; })}>Verify and enable</button></div>}
      {enabled && <div className="mt-5 flex flex-wrap gap-3"><button className="rounded-lg border border-cyan-400/30 px-3 py-2 text-xs text-cyan-100" onClick={() => void execute(async () => { if (!window.confirm("Regenerate recovery codes? Existing codes stop working.")) return; const value = await regenerateRecoveryCodes(); setCodes(value.recovery_codes ?? null); return "New recovery codes generated."; })}>Regenerate recovery codes</button><button className="rounded-lg border border-rose-400/30 px-3 py-2 text-xs text-rose-200" onClick={() => { if (window.confirm("Disable authenticator-based password recovery?")) { setError(""); setMessage("Verify a current authenticator or recovery code to disable password recovery."); setDisableMode(true); } }}>Disable recovery</button></div>}
      {disableMode && <div className="mt-4 flex flex-wrap items-center gap-3"><input type="text" value={code} onChange={(e) => setCode(e.target.value)} placeholder="Authenticator or recovery code" className="h-10 rounded-lg border border-slate-700 bg-slate-950/40 px-3 text-sm text-white"/><label className="text-xs text-slate-300"><input type="checkbox" checked={recover} onChange={(e) => setRecover(e.target.checked)} /> Recovery code</label><button className="rounded-lg bg-rose-400 px-3 py-2 text-xs font-semibold text-slate-950" onClick={() => void execute(async () => { const value = await disableMfa(code, recover); setEnabled(value.enabled); setDisableMode(false); setCode(""); return await load(true) ? "Authenticator-based recovery disabled." : undefined; })}>Verify and disable</button></div>}
    </section>
    {codes && <section className="scam-card rounded-2xl border border-amber-400/30 p-5"><div className="flex items-center justify-between"><div><h2 className="text-sm font-semibold text-white">Recovery codes</h2><p className="mt-1 text-xs text-amber-200">Displayed once. Store them securely.</p></div><button className="inline-flex items-center gap-2 rounded-lg border border-slate-600 px-3 py-2 text-xs" onClick={() => void navigator.clipboard.writeText(codes.join("\n"))}><Copy className="h-3.5 w-3.5"/>Copy</button></div><div className="mt-4 grid grid-cols-2 gap-2 rounded-xl bg-slate-950/60 p-4 font-mono text-xs text-cyan-100">{codes.map((item) => <span key={item}>{item}</span>)}</div><button className="mt-3 text-xs text-slate-400" onClick={() => setCodes(null)}>I have stored these codes</button></section>}
    <section className="scam-card rounded-2xl p-5"><div className="flex flex-wrap items-center justify-between gap-3"><div className="flex items-center gap-2"><Laptop className="h-5 w-5 text-cyan-300"/><div><h2 id="sessions-title" className="text-sm font-semibold text-white">Active sessions</h2><p className="mt-1 text-xs text-slate-400">Revoked, expired, and idle sessions cannot access protected APIs.</p></div></div><button disabled={!sessions.some((s) => !s.current)} className="rounded-lg border border-slate-600 px-3 py-2 text-xs text-slate-100 disabled:opacity-50" onClick={() => void execute(async () => { if (!window.confirm("Revoke every other session?")) return; await revokeOtherSessions(); return await load(true) ? "Other sessions revoked." : undefined; })}>Revoke other sessions</button></div><div className="mt-4 space-y-2">{loading ? <p className="text-xs text-slate-400">Loading sessions…</p> : sessions.length === 0 ? <p className="text-xs text-slate-400">No active sessions found.</p> : sessions.map((session) => <div key={session.id} className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-700 p-3"><div><p className="text-xs font-medium text-white">{session.current ? "Current session" : "Active session"}</p><p className="mt-1 text-[11px] text-slate-400">{session.user_agent || "Browser information unavailable"} · Last active {fmt(session.last_activity_at)}</p></div>{!session.current && <button className="rounded-lg border border-rose-400/30 px-3 py-2 text-xs text-rose-200" onClick={() => void execute(async () => { if (!window.confirm("Revoke this session?")) return; await revokeSession(session.id); return await load(true) ? "Session revoked." : undefined; })}>Revoke</button>}</div>)}</div></section>
    <button type="button" onClick={() => void load()} className="inline-flex items-center gap-2 text-xs text-slate-400 hover:text-cyan-200"><RefreshCw className="h-3.5 w-3.5"/>Refresh security data</button>
  </div>;
}
