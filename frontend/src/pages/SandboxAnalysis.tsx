import { useCallback, useEffect, useState, type FormEvent } from "react";
import { AlertTriangle, FileSearch, Globe2, RefreshCw, ShieldAlert, X } from "lucide-react";
import { useLocation } from "react-router";
import {
  cancelSandboxJob,
  getSandboxJob,
  getSandboxJobs,
  getSandboxStatus,
  submitSandboxUrl,
  type SandboxJob,
  type SandboxStatus,
} from "@/lib/api";

const ACTIVE_STATES = new Set(["queued", "provisioning", "running", "collecting_evidence", "analyzing"]);
const PIPELINE_STATES = ["queued", "provisioning", "running", "collecting_evidence", "analyzing", "completed"];
const LABELS: Record<string, string> = {
  queued: "Queued", provisioning: "Provisioning", running: "Browsing", collecting_evidence: "Collecting evidence",
  analyzing: "Analyzing evidence", completed: "Completed", failed: "Failed", timed_out: "Timed out", blocked: "Blocked",
};

function isActive(state?: string) {
  return Boolean(state && ACTIVE_STATES.has(state));
}

export default function SandboxAnalysis() {
  const location = useLocation();
  const initialJob = (location.state as { initialJob?: SandboxJob } | null)?.initialJob;
  const [runtime, setRuntime] = useState<SandboxStatus | null>(null);
  const [jobs, setJobs] = useState<SandboxJob[]>(() => initialJob ? [initialJob] : []);
  const [selected, setSelected] = useState<SandboxJob | null>(initialJob ?? null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [url, setUrl] = useState("");
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    setLoading(true);
    setError("");
    const [statusResult, jobsResult] = await Promise.allSettled([getSandboxStatus(), getSandboxJobs()]);
    if (statusResult.status === "fulfilled") setRuntime(statusResult.value);
    else setRuntime(null);
    if (jobsResult.status === "fulfilled") {
      setJobs(jobsResult.value);
      setSelected((current) => {
        const currentId = current?.id ?? initialJob?.id;
        return currentId ? jobsResult.value.find((job) => job.id === currentId) ?? current ?? initialJob ?? null : null;
      });
    }
    const failure = jobsResult.status === "rejected" ? jobsResult.reason : statusResult.status === "rejected" ? statusResult.reason : null;
    if (failure) setError(failure instanceof Error ? failure.message : "Unable to load sandbox data.");
    setLoading(false);
  }, [initialJob]);

  useEffect(() => { void refresh(); }, [refresh]);

  useEffect(() => {
    if (!selected || !isActive(selected.state)) return;
    const timer = window.setInterval(() => {
      void getSandboxJob(selected.id).then((job) => {
        setSelected(job);
        setJobs((current) => current.map((item) => item.id === job.id ? job : item));
      }).catch((reason: unknown) => {
        setError(reason instanceof Error ? reason.message : "Unable to refresh this sandbox job.");
      });
    }, 1500);
    return () => window.clearInterval(timer);
  }, [selected?.id, selected?.state]);

  const submitUrl = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!runtime?.available || submitting) return;
    setSubmitting(true);
    setError("");
    try {
      const job = await submitSandboxUrl(url.trim());
      setSelected(job);
      setJobs((current) => [job, ...current.filter((item) => item.id !== job.id)]);
      setUrl("");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Sandbox job could not be queued.");
    } finally {
      setSubmitting(false);
    }
  };

  const cancel = async () => {
    if (!selected || !isActive(selected.state) || cancelling) return;
    setCancelling(true);
    setError("");
    try {
      const result = await cancelSandboxJob(selected.id);
      setSelected((current) => current ? { ...current, state: result.state } : current);
      void refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Sandbox cancellation could not be requested.");
    } finally {
      setCancelling(false);
    }
  };

  const unavailable = !runtime?.available;
  const observations = selected?.observations ?? {};
  const navigation = (observations.navigation ?? {}) as Record<string, unknown>;
  const report = selected?.report;
  const stageIndex = selected ? PIPELINE_STATES.indexOf(selected.state) : -1;

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-cyan-300">Disposable browser execution</p>
          <h1 className="mt-2 text-3xl font-semibold text-white">Sandbox Analysis</h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">Each queued URL runs in a short-lived Chromium container behind a destination-validating egress proxy. Page forms are observed, never submitted.</p>
        </div>
        <button type="button" onClick={() => void refresh()} disabled={loading} className="inline-flex min-h-11 items-center gap-2 rounded-xl border border-slate-700 px-4 text-sm text-slate-200 hover:border-cyan-300/40 disabled:opacity-60">
          <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} /> Refresh
        </button>
      </header>

      {error && <div role="alert" className="rounded-xl border border-rose-400/25 bg-rose-400/[0.06] p-4 text-sm leading-6 text-rose-100">{error}</div>}

      <section className="scam-card rounded-2xl p-5 sm:p-6" aria-labelledby="runtime-title">
        <div className="flex items-start gap-4">
          <div className={`grid h-11 w-11 shrink-0 place-items-center rounded-xl ${loading ? "bg-slate-500/10 text-slate-300" : unavailable ? "bg-amber-300/10 text-amber-200" : "bg-lime-300/10 text-lime-200"}`}>
            {unavailable ? <AlertTriangle className="h-5 w-5" /> : <ShieldAlert className="h-5 w-5" />}
          </div>
          <div className="min-w-0 flex-1">
            <h2 id="runtime-title" className="text-base font-semibold text-white">{loading ? "Checking runtime…" : unavailable ? "Sandbox runtime unavailable" : "Sandbox runtime ready"}</h2>
            <p className="mt-1 text-sm leading-6 text-slate-300">{loading ? "Checking the worker image, internal network, and egress proxy." : runtime?.message ?? "Runtime status could not be confirmed."}</p>
            {runtime?.reason && <p className="mt-2 font-mono text-xs text-amber-200">{runtime.reason}</p>}
          </div>
        </div>
        <div className="mt-5 grid gap-3 sm:grid-cols-2">
          {[["Disposable Chromium", runtime?.capabilities.url_browser_runtime], ["Restricted outbound network", runtime?.capabilities.restricted_egress], ["File static analysis", runtime?.capabilities.file_static_analysis], ["Isolated file detonation", runtime?.capabilities.file_detonation]].map(([label, supported]) =>
            <div key={String(label)} className="flex items-center justify-between gap-3 rounded-xl border border-slate-700/80 bg-slate-950/20 px-4 py-3">
              <span className="text-sm text-slate-300">{label}</span>
              <span className={`text-xs font-semibold ${supported ? "text-lime-200" : "text-amber-200"}`}>{loading ? "Checking" : supported ? "Available" : "Unavailable"}</span>
            </div>)}
        </div>
      </section>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(18rem,0.8fr)]">
        <section className="scam-card rounded-2xl p-5" aria-labelledby="url-sandbox-title">
          <div className="flex items-center gap-3"><Globe2 className="h-5 w-5 text-cyan-300"/><h2 id="url-sandbox-title" className="text-sm font-semibold text-white">Analyze a public URL</h2></div>
          <p className="mt-2 text-xs leading-5 text-slate-400">Only HTTP and HTTPS on standard ports are accepted. Private or non-public destinations and every redirect are blocked by the egress filter.</p>
          <form className="mt-4 space-y-3" onSubmit={submitUrl}>
            <label htmlFor="sandbox-url" className="sr-only">HTTP or HTTPS URL</label>
            <input id="sandbox-url" type="url" inputMode="url" autoComplete="url" placeholder="https://example.com" value={url} onChange={(event) => setUrl(event.target.value)} disabled={loading || unavailable || submitting} className="h-11 w-full rounded-xl border border-slate-700 bg-slate-950/30 px-3 text-sm text-white placeholder:text-slate-500 disabled:opacity-60" />
            <button type="submit" disabled={loading || unavailable || submitting || !url.trim()} className="min-h-11 w-full rounded-xl bg-cyan-300 px-4 text-sm font-semibold text-[#07131f] disabled:cursor-not-allowed disabled:opacity-50">{submitting ? "Queueing…" : unavailable ? "Unavailable — runtime not verified" : "Queue isolated analysis"}</button>
          </form>
          <p className="mt-3 text-xs leading-5 text-slate-500">Jobs and reports use your existing scan-history preference. If history is disabled, no sandbox job is stored or run.</p>
        </section>

        <section className="scam-card rounded-2xl p-5" aria-labelledby="file-sandbox-title">
          <div className="flex items-center gap-3"><FileSearch className="h-5 w-5 text-cyan-300"/><h2 id="file-sandbox-title" className="text-sm font-semibold text-white">File analysis</h2></div>
          <p className="mt-2 text-xs leading-5 text-slate-400">File analysis remains unavailable. This phase does not execute or upload files.</p>
          <div className="mt-4 rounded-xl border border-dashed border-slate-700 bg-slate-950/20 p-4 text-center text-sm text-slate-500">File detonation requires a separate hardened runtime.</div>
        </section>
      </div>

      <section className="scam-card rounded-2xl p-5 sm:p-6" aria-labelledby="job-title">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div><h2 id="job-title" className="text-base font-semibold text-white">Sandbox jobs</h2><p className="mt-1 text-xs text-slate-400">Recent jobs and reports belong to your account.</p></div>
          {selected && isActive(selected.state) && <button type="button" onClick={() => void cancel()} disabled={cancelling} className="inline-flex min-h-10 items-center gap-2 rounded-lg border border-rose-400/30 px-3 text-xs font-semibold text-rose-100 disabled:opacity-50"><X className="h-4 w-4"/>{cancelling ? "Requesting…" : "Cancel job"}</button>}
        </div>
        {jobs.length === 0 ? <p className="mt-5 rounded-xl border border-slate-800 p-5 text-sm text-slate-400">{loading ? "Loading jobs…" : "No sandbox jobs yet."}</p> :
          <div className="mt-4 grid gap-4 lg:grid-cols-[15rem_minmax(0,1fr)]">
            <ul className="max-h-80 space-y-2 overflow-auto" aria-label="Recent sandbox jobs">
              {jobs.map((job) => <li key={job.id}><button type="button" onClick={() => setSelected(job)} className={`w-full rounded-xl border px-3 py-3 text-left ${selected?.id === job.id ? "border-cyan-300/50 bg-cyan-300/[0.06]" : "border-slate-800 hover:border-slate-600"}`}>
                <span className="block text-sm font-medium text-slate-100">{LABELS[job.state] ?? "Job"}</span><span className="mt-1 block text-xs text-slate-500">{new Date(job.created_at).toLocaleString()}</span><span className="mt-1 block truncate font-mono text-[11px] text-slate-400">{String((job.observations?.initial_origin as string | undefined) ?? "URL target")}</span>
              </button></li>)}
            </ul>
            {selected ? <div aria-live="polite" className="min-w-0 rounded-xl border border-slate-800 bg-slate-950/20 p-4">
              <div className="flex flex-wrap items-start justify-between gap-2"><div><p className="text-xs uppercase tracking-wide text-slate-500">Job state</p><h3 className="mt-1 text-lg font-semibold text-white">{LABELS[selected.state] ?? selected.state}</h3></div>{report && <div className="text-right"><p className="text-xs text-slate-500">Rule-based score</p><p className="text-xl font-semibold text-cyan-200">{report.risk_score ?? 0}<span className="text-xs text-slate-500"> / 100</span></p></div>}</div>
              {isActive(selected.state) && <ol className="mt-4 grid grid-cols-2 gap-2 md:grid-cols-3" aria-label="Actual worker stages">{PIPELINE_STATES.slice(0, 5).map((stage, index) => <li key={stage} className={`rounded-lg border px-2 py-2 text-xs ${stageIndex >= index ? "border-cyan-300/35 text-cyan-100" : "border-slate-800 text-slate-600"}`}>{LABELS[stage]}</li>)}</ol>}
              {selected.error_code && <p role="status" className="mt-4 rounded-lg border border-amber-300/20 bg-amber-300/[0.04] p-3 text-sm text-amber-100">The job ended with a safe failure state ({selected.error_code}). No raw target details are shown.</p>}
              {report && <div className="mt-4 space-y-4">
                <div><p className="text-xs uppercase tracking-wide text-slate-500">Conclusion</p><p className="mt-1 text-sm text-slate-200">{report.conclusion}</p><p className="mt-1 text-xs text-slate-400">Risk verdict: {report.classification}</p><p className="mt-1 text-xs text-slate-400">Reachability: {report.reachability ?? "unknown"}</p></div>
                <div className="grid gap-2 sm:grid-cols-2">
                  <p className="rounded-lg bg-slate-900/70 p-3 text-xs text-slate-300">Initial origin: <span className="font-mono">{String(observations.initial_origin ?? "Unavailable")}</span></p>
                  <p className="rounded-lg bg-slate-900/70 p-3 text-xs text-slate-300">Final origin: <span className="font-mono">{String(observations.final_origin ?? "Unavailable")}</span></p>
                  <p className="rounded-lg bg-slate-900/70 p-3 text-xs text-slate-300">HTTP status: {String(navigation.http_status ?? "Unavailable")}</p>
                  <p className="rounded-lg bg-slate-900/70 p-3 text-xs text-slate-300">Navigation duration: {String(navigation.duration_ms ?? "Unavailable")} ms</p>
                </div>
                {(report.findings?.length ?? 0) > 0 ? <div><h4 className="text-xs font-semibold uppercase tracking-wide text-slate-400">Observed findings</h4><ul className="mt-2 space-y-2">{report.findings?.map((finding) => <li key={finding.id} className="rounded-lg border border-slate-800 p-3"><div className="flex flex-wrap justify-between gap-2"><span className="text-sm text-slate-100">{finding.title}</span><span className="text-xs uppercase text-amber-200">{finding.severity}</span></div><p className="mt-1 font-mono text-[10px] text-slate-500">Rule {finding.rule} · evidence: {finding.observation_refs.join(", ")}</p></li>)}</ul></div> : <p className="text-sm text-slate-400">No configured risk rule matched the observations.</p>}
                <details className="rounded-lg border border-slate-800 p-3"><summary className="cursor-pointer text-xs font-medium text-slate-300">Limitations and evidence handling</summary><ul className="mt-2 list-disc space-y-1 pl-5 text-xs text-slate-400">{report.limitations?.map((item) => <li key={item}>{item}</li>)}</ul><p className="mt-2 text-xs text-slate-400">Observed requests: {Array.isArray(observations.requests) ? observations.requests.length : 0}; console errors: {String(observations.console_error_count ?? 0)}; download attempts: {String(observations.download_attempt_count ?? 0)}.</p></details>
              </div>}
              {!report && !selected.error_code && !isActive(selected.state) && <p className="mt-4 text-sm text-slate-400">No report was produced.</p>}
            </div> : <p className="rounded-xl border border-slate-800 p-4 text-sm text-slate-500">Select a job to view its state and report.</p>}
          </div>}
      </section>
    </div>
  );
}
