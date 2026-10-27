import { useState } from "react";
import { AlertCircle, ArrowRight, Link2, ShieldCheck } from "lucide-react";
import { Link, useNavigate } from "react-router";

import { createUrlScan } from "@/lib/api";

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
      const scan = await createUrlScan(trimmedUrl);
      navigate(`/threat/${scan.id}`, { state: scan.analysis ? { inlineScan: scan } : undefined });
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
          The URL is inspected locally for suspicious structure. ScamShield never opens or fetches the submitted destination.
        </p>
      </div>

      <div className="scam-card rounded-2xl p-5 sm:p-6">
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

        <div className="mt-5 grid gap-3 sm:grid-cols-3">
          {[
            ["Structure", "Length, subdomains, ports, encoding, host anomalies"],
            ["Signals", "Suspicious keywords and URL deception patterns"],
            ["Safety", "No outbound fetch; only safe local structural checks"],
          ].map(([title, description]) => (
            <div key={title} className="rounded-xl border border-slate-800/70 bg-slate-950/20 p-4">
              <ShieldCheck className="h-4 w-4 text-teal-300" />
              <p className="mt-3 text-xs font-medium text-white">{title}</p>
              <p className="mt-1 text-[11px] leading-5 text-slate-600">{description}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
