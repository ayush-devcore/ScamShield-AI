import { Activity, Download, FileText, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";
import { Link } from "react-router";
import { getScanHistory, type ScanHistoryItem } from "@/lib/api";

function formatDate(date: string) {
  const parsed = new Date(date);
  if (Number.isNaN(parsed.getTime())) return "Unknown time";
  return parsed.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

export default function Reports() {
  const [report, setReport] = useState<ScanHistoryItem | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;

    async function loadReport() {
      try {
        setLoading(true);
        setError("");
        const scans = await getScanHistory();
        if (!cancelled) {
          setReport(scans[0] ?? null);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Unable to load report data.");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    loadReport();
    return () => {
      cancelled = true;
    };
  }, []);

  if (loading) {
    return (
      <div className="flex min-h-[220px] items-center justify-center">
        <div className="text-center">
          <div className="mx-auto h-8 w-8 animate-spin rounded-full border-2 border-cyan-400/20 border-t-cyan-400" />
          <p className="mt-4 text-xs text-slate-500">Loading report data...</p>
        </div>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="scam-card rounded-2xl border border-red-400/10 p-6">
        <p className="text-sm font-medium text-red-300">Unable to load threat reports</p>
        <p className="mt-2 text-xs text-slate-500">{error || "No scan data is available yet."}</p>
      </div>
    );
  }

  const riskLevel = report.risk_score ?? 0;
  const summaryTitle = report.threat_type ?? "Security Assessment";

  return (
    <div className="space-y-6">
      <div>
        <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-cyan-300">Threat intelligence</p>
        <h1 className="mt-3 text-3xl font-semibold text-white">Threat Reports</h1>
        <p className="mt-2 text-sm text-slate-500">Structured views of recent assessments and response recommendations.</p>
      </div>

      <div className="grid gap-4 lg:grid-cols-[0.7fr_1.3fr]">
        <div className="scam-card rounded-2xl p-5">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-400/[0.05]">
              <FileText className="h-5 w-5 text-cyan-300" />
            </div>
            <div>
              <p className="text-sm font-semibold text-white">{report.id.slice(0, 8).toUpperCase()}</p>
              <p className="text-[11px] text-slate-600">Generated report</p>
            </div>
          </div>

          <div className="mt-6 space-y-4">
            {[
              [formatDate(report.created_at).split(",")[1]?.trim() ?? "—", "Scan initiated"],
              ["Analysis", "Threat signals extracted"],
              ["Assessment", "Risk classification completed"],
              ["Action", "Recommendation generated"],
            ].map(([time, label]) => (
              <div key={label} className="flex gap-3">
                <span className="w-14 text-[10px] text-slate-700">{time}</span>
                <div className="relative flex-1 border-l border-slate-800 pl-4">
                  <div className="absolute -left-1.5 top-1 h-3 w-3 rounded-full border border-cyan-300/30 bg-[#071014]" />
                  <p className="text-xs text-slate-400">{label}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="scam-card rounded-2xl p-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold text-white">{summaryTitle}</h2>
              <p className="mt-1 text-xs text-slate-600">Risk score {riskLevel} / 100 · Confidence {report.confidence ?? 0}%</p>
            </div>
            <button className="inline-flex items-center gap-2 rounded-lg border border-slate-800 px-3 py-2 text-xs text-slate-400 hover:border-cyan-400/20 hover:text-white">
              <Download className="h-3.5 w-3.5" /> Export PDF
            </button>
          </div>

          <div className="mt-6 grid gap-3 sm:grid-cols-3">
            <div className="rounded-xl border border-red-400/10 bg-red-400/[0.03] p-4">
              <p className="text-[10px] uppercase tracking-wider text-slate-600">Risk</p>
              <p className="mt-2 text-2xl font-semibold text-red-300">{riskLevel}</p>
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-950/20 p-4">
              <p className="text-[10px] uppercase tracking-wider text-slate-600">Type</p>
              <p className="mt-2 text-sm font-semibold text-white">{report.input_type}</p>
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-950/20 p-4">
              <p className="text-[10px] uppercase tracking-wider text-slate-600">Status</p>
              <p className="mt-2 text-sm font-semibold text-white">{report.status}</p>
            </div>
          </div>

          <div className="mt-6 space-y-3">
            {[
              ["Signal fusion", "Risk cues were combined from the most relevant indicators captured during the scan."],
              ["Assessment", "This report is based on the latest authenticated analysis record available for the account."],
              ["Recommendation", "Do not trust urgency alone. Verify through the official channel before acting or sharing sensitive information."],
            ].map(([title, detail]) => (
              <div key={title} className="rounded-xl border border-slate-800/70 p-4">
                <div className="flex items-center gap-2">
                  {title === "Recommendation" ? <ShieldCheck className="h-4 w-4 text-emerald-300" /> : <Activity className="h-4 w-4 text-cyan-300" />}
                  <p className="text-xs font-semibold text-white">{title}</p>
                </div>
                <p className="mt-2 text-xs leading-5 text-slate-500">{detail}</p>
              </div>
            ))}
          </div>

          <Link to={`/threat/${report.id}`} className="mt-5 inline-block text-xs text-cyan-300 hover:text-cyan-200">Open full analysis →</Link>
        </div>
      </div>
    </div>
  );
}