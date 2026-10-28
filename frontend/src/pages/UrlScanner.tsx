import { useState } from "react";
import { AlertCircle, ArrowRight, Link2, Database, ScanLine, FlaskConical } from "lucide-react";
import { Link, useNavigate } from "react-router";

import { createUrlDecision } from "@/lib/api";

export default function UrlScanner() {
  const [url, setUrl] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState("");
  const navigate = useNavigate();

  const analyze = async () => {
    const trimmedUrl = url.trim();

    if (!trimmedUrl || analyzing) {
      return;
    }

    if (!/^https?:\/\//i.test(trimmedUrl)) {
      setError("Use a full http:// or https:// URL.");
      return;
    }

    setError("");
    setAnalyzing(true);

    try {
      const result = await createUrlDecision(trimmedUrl);
      if (result.outcome === "sandbox_queued" && result.sandbox_job) {
        navigate("/sandbox", { state: { initialJob: result.sandbox_job } });
      } else if (result.scan) {
        navigate(`/threat/${result.scan.id}`, { state: { inlineScan: result.scan, urlDecision: result } });
      } else {
        setError("No URL assessment result was returned.");
      }
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to analyze this URL safely.",
      );
    } finally {
      setAnalyzing(false);
    }
  };

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <div>
        <Link to="/scan" className="text-xs text-slate-600 hover:text-cyan-300">← Back to scan center</Link>
        <div className="mt-5 flex items-center gap-2 text-teal-300">
          <Link2 className="h-4 w-4" />
          <span className="text-[11px] font-semibold uppercase tracking-[0.18em]">URL intelligence</span>
        </div>
        <h1 className="mt-3 text-3xl font-semibold text-white">Analyze URL</h1>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">
          ScamShield first checks an imported malicious URL dataset. Unmatched URLs are sent to the isolated browser only when its restricted runtime is verified; otherwise the result remains unverified.
        </p>
      </div>

      <div className="url-workspace grid gap-5 lg:grid-cols-[minmax(0,1.4fr)_minmax(16rem,.7fr)]">
      <section className="scam-card rounded-2xl p-5 sm:p-6" aria-label="URL analysis form">
        <div className="mb-5 flex items-center justify-between gap-3 border-b border-slate-700/50 pb-4"><div><p className="text-[10px] font-semibold uppercase tracking-[.18em] text-teal-200">Destination assessment</p><h2 className="mt-1 text-sm font-semibold text-white">Inspect a link before opening it</h2></div><span className="rounded-full border border-teal-300/15 bg-teal-300/[0.05] px-2.5 py-1 text-[10px] text-teal-100">No direct navigation</span></div>
        <label className="text-xs font-medium text-slate-400">Destination URL</label>

        <div className="mt-3 flex flex-col gap-3 sm:flex-row">
          <div className="relative flex-1">
            <Link2 className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-600" />
            <input
              value={url}
              onChange={(event) => {
                setUrl(event.target.value);
                if (error) setError("");
              }}
              placeholder="https://example.com/..."
              className="h-12 w-full rounded-xl border border-slate-800 bg-[#071014] pl-10 pr-3 text-sm text-slate-200 placeholder:text-slate-700 focus:border-cyan-300/20 focus:outline-none"
            />
          </div>

          <button
            onClick={analyze}
            disabled={!url.trim() || analyzing}
            className="inline-flex h-12 items-center justify-center gap-2 rounded-xl bg-cyan-400 px-5 text-xs font-semibold text-[#031014] hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {analyzing ? "Analyzing..." : "Analyze URL"}
            {!analyzing && <ArrowRight className="h-4 w-4" />}
          </button>
        </div>

        {error && (
          <div className="mt-4 flex items-start gap-2 rounded-xl border border-red-400/20 bg-red-400/[0.06] px-4 py-3 text-xs text-red-300" role="alert">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

      </section>
      <aside className="scan-guide rounded-2xl border border-teal-300/15 p-5">
        <p className="text-[10px] font-semibold uppercase tracking-[.18em] text-teal-200">Assessment path</p><h2 className="mt-2 text-base font-semibold text-white">Evidence is layered</h2>
        <ol className="url-evidence-steps mt-5 space-y-4">
          {[
            { icon: Database, title: "Known dataset", body: "Exact canonical URL lookup checks imported malicious records." },
            { icon: ScanLine, title: "URL structure", body: "Unmatched URLs are assessed for suspicious structural signals." },
            { icon: FlaskConical, title: "Isolated browser", body: "Sandbox evidence is used only when the restricted runtime is verified and the backend queues a job." },
          ].map(({ icon: Icon, title, body }, index) => <li key={title} className="flex gap-3"><span className="grid h-9 w-9 shrink-0 place-items-center rounded-xl border border-teal-300/15 bg-teal-300/[0.05] text-teal-100"><Icon className="h-4 w-4" /></span><span><span className="block text-xs font-medium text-white">{title}</span><span className="mt-1 block text-[11px] leading-5 text-slate-500">{body}</span></span><span className="ml-auto font-mono text-[9px] text-slate-600">0{index + 1}</span></li>)}
        </ol>
        <p className="mt-5 border-t border-slate-700/50 pt-4 text-[11px] leading-5 text-amber-100/80">A low heuristic score does not prove a destination is safe. Results report reachability and verification separately.</p>
      </aside>
      </div>
    </div>
  );
}
