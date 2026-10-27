import { useCallback, useEffect, useRef, useState } from "react";
import { Bell, CheckCheck, ExternalLink } from "lucide-react";
import { useNavigate } from "react-router";
import { getNotifications, markAllNotificationsRead, markNotificationRead, type NotificationList, type UserNotification } from "@/lib/api";

const dateLabel = (value: string) => new Date(value).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });

export function NotificationCenter() {
  const [open, setOpen] = useState(false);
  const [data, setData] = useState<NotificationList>({ items: [], unread_count: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const seen = useRef(new Set<string>());
  const firstLoad = useRef(true);
  const navigate = useNavigate();

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const result = await getNotifications();
      if (firstLoad.current) {
        result.items.forEach((item) => seen.current.add(item.id));
        firstLoad.current = false;
      } else if ("Notification" in window && Notification.permission === "granted") {
        result.items.forEach((item) => {
          if (!seen.current.has(item.id) && !item.read_at) {
            new Notification(item.title, { body: item.message, tag: item.id });
          }
          seen.current.add(item.id);
        });
      }
      setData(result);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load notifications.");
    } finally { setLoading(false); }
  }, []);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => { void load(); }, 60_000);
    const onFocus = () => { void load(); };
    const onHistoryChanged = () => { void load(); };
    window.addEventListener("focus", onFocus);
    window.addEventListener("scamshield:scan-history-changed", onHistoryChanged);
    return () => { window.clearInterval(timer); window.removeEventListener("focus", onFocus); window.removeEventListener("scamshield:scan-history-changed", onHistoryChanged); };
  }, [load]);

  const markOne = async (item: UserNotification) => {
    try {
      if (!item.read_at) await markNotificationRead(item.id);
      if (item.link_path?.startsWith("/") && !item.link_path.startsWith("//")) navigate(item.link_path);
      setOpen(false);
      await load();
    } catch (err) { setError(err instanceof Error ? err.message : "Unable to update notification."); }
  };

  const markAll = async () => {
    try { await markAllNotificationsRead(); await load(); }
    catch (err) { setError(err instanceof Error ? err.message : "Unable to update notifications."); }
  };

  return <div className="relative">
    <button type="button" onClick={() => { setOpen((value) => !value); if (!open) void load(); }} className="relative flex h-9 w-9 items-center justify-center rounded-lg text-slate-500 transition hover:bg-slate-800/60 hover:text-cyan-300" aria-label={`Notifications${data.unread_count ? `, ${data.unread_count} unread` : ""}`} aria-expanded={open} aria-controls="notification-panel">
      <Bell className="h-4 w-4" />
      {data.unread_count > 0 && <span className="absolute -right-1 -top-1 min-w-4 rounded-full bg-rose-400 px-1 text-center text-[9px] font-bold leading-4 text-slate-950">{data.unread_count > 99 ? "99+" : data.unread_count}</span>}
    </button>
    {open && <section id="notification-panel" className="scam-card absolute right-0 top-12 z-50 w-[min(22rem,calc(100vw-2rem))] overflow-hidden rounded-2xl shadow-2xl" aria-label="Notifications">
      <div className="flex items-center justify-between border-b border-slate-700/60 px-4 py-3"><div><h2 className="text-sm font-semibold text-white">Notifications</h2><p className="mt-0.5 text-[11px] text-slate-400">{data.unread_count} unread</p></div><button type="button" onClick={() => void markAll()} disabled={!data.unread_count} className="inline-flex items-center gap-1.5 rounded-lg px-2 py-1.5 text-[11px] text-cyan-200 hover:bg-cyan-400/10 disabled:opacity-50"><CheckCheck className="h-3.5 w-3.5"/>Read all</button></div>
      <div className="max-h-[min(65vh,28rem)] overflow-y-auto p-2">
        {loading && data.items.length === 0 ? <p className="p-4 text-xs text-slate-400">Loading notifications…</p> : error && data.items.length === 0 ? <div className="p-4"><p role="alert" className="text-xs text-rose-200">{error}</p><button type="button" onClick={() => void load()} className="mt-2 text-xs text-cyan-200">Retry</button></div> : data.items.length === 0 ? <p className="p-4 text-xs text-slate-400">No notifications yet. Genuine scan and account-security events will appear here.</p> : data.items.map((item) => <button type="button" key={item.id} onClick={() => void markOne(item)} className={`block w-full rounded-xl p-3 text-left transition hover:bg-slate-800/50 ${item.read_at ? "opacity-75" : "bg-cyan-400/[0.04]"}`}><span className="flex items-start justify-between gap-2"><span className="text-xs font-semibold text-white">{item.title}</span>{!item.read_at && <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-cyan-300"/>}</span><span className="mt-1 block text-xs leading-5 text-slate-300">{item.message}</span><span className="mt-2 flex items-center justify-between text-[10px] text-slate-500"><span>{dateLabel(item.created_at)}</span>{item.link_path && <span className="inline-flex items-center gap-1 text-cyan-200">Open scan <ExternalLink className="h-3 w-3"/></span>}</span></button>)}
      </div>
      {error && data.items.length > 0 && <p role="alert" className="border-t border-slate-700/60 px-4 py-2 text-xs text-rose-200">{error}</p>}
    </section>}
  </div>;
}
