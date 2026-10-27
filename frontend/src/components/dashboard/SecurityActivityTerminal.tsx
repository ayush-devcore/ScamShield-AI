import { AlertTriangle, CircleDot, RefreshCw, Terminal } from "lucide-react";
import type { SecurityActivity } from "@/lib/api";

const severityClass = {
  info: "text-cyan-300",
  warning: "text-amber-300",
  high: "text-orange-300",
  critical: "text-rose-300",
};

export function SecurityActivityTerminal({
  activity,
  loading,
  error,
  onRetry,
}: {
  activity: SecurityActivity[];
  loading: boolean;
  error: string;
  onRetry: () => void;
}) {
  return (
    <section className="overflow-hidden rounded-2xl border border-cyan-400/15 bg-[#091420] shadow-[0_18px_40px_rgba(0,0,0,0.22)]">
      <div className="flex items-center justify-between border-b border-slate-700/60 bg-[#101f30] px-5 py-4">
        <div className="flex items-center gap-2"><Terminal className="h-4 w-4 text-cyan-300" /><h2 className="text-sm font-semibold text-slate-100">Security Activity Terminal</h2></div>
        <span className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-teal-300"><CircleDot className="h-3 w-3" /> Live records</span>
      </div>
      <div className="min-h-48 p-4 font-mono text-xs">
        {loading ? <p className="text-slate-400">Loading your authorized activity…</p> : error ? (
          <div className="flex items-center justify-between gap-3 text-rose-300"><span className="flex items-center gap-2"><AlertTriangle className="h-4 w-4" />Activity feed unavailable.</span><button type="button" onClick={onRetry} className="inline-flex items-center gap-1 rounded border border-slate-600 px-2 py-1 text-slate-200 hover:border-cyan-300"><RefreshCw className="h-3 w-3" />Retry</button></div>
        ) : activity.length === 0 ? <p className="text-slate-400">No recorded security activity yet. Completed scans and security actions appear here.</p> : (
          <ol className="space-y-3">{activity.map((event) => <li key={event.id} className="flex gap-3 border-l border-slate-700 pl-3"><time className="shrink-0 text-slate-500">{new Date(event.created_at).toLocaleString([], { dateStyle: "short", timeStyle: "short" })}</time><span className={`font-semibold uppercase ${severityClass[event.severity]}`}>[{event.severity}]</span><span className="text-slate-200">{event.message}</span></li>)}</ol>
        )}
      </div>
    </section>
  );
}
