import { Filter, Search } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { Link } from "react-router";
import { getScanHistory, type ScanHistoryItem } from "@/lib/api";

function formatDate(date: string) {
  const parsed = new Date(date);
  if (Number.isNaN(parsed.getTime())) return "Unknown time";
  return parsed.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

export default function History() {
  const [scans, setScans] = useState<ScanHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");

  useEffect(() => {
    let cancelled = false;

    async function loadHistory() {
      try {
        setLoading(true);
        setError("");
        const data = await getScanHistory();
        if (!cancelled) setScans(data);
      } catch (err) {
        if (!cancelled) {
          setError(
            err instanceof Error ? err.message : "Unable to load scan history.",
          );
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    loadHistory();
    return () => {
      cancelled = true;
    };
  }, []);

  const filteredScans = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return scans;

    return scans.filter((scan) => {
      const haystack = [
        scan.id,
        scan.input_type,
        scan.threat_type ?? "",
        scan.status,
      ].join(" ");
      return haystack.toLowerCase().includes(normalized);
    });
  }, [query, scans]);

  return (
    <div className="space-y-6">
      <div>
        <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-cyan-300">Intelligence</p>
        <h1 className="mt-3 text-3xl font-semibold text-white">Scan History</h1>
        <p className="mt-2 text-sm text-slate-500">Review previous analyses and their risk assessments.</p>
      </div>

      <div className="scam-card overflow-hidden rounded-2xl">
        <div className="flex flex-col gap-3 border-b border-slate-800/60 p-4 sm:flex-row">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-600" />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search scans..."
              className="h-10 w-full rounded-xl border border-slate-800 bg-slate-950/30 pl-10 pr-3 text-xs text-white placeholder:text-slate-700 focus:border-cyan-300/20 focus:outline-none"
            />
          </div>
          <button className="inline-flex h-10 items-center justify-center gap-2 rounded-xl border border-slate-800 px-4 text-xs text-slate-400 hover:border-cyan-400/20 hover:text-white">
            <Filter className="h-3.5 w-3.5" /> Filters
          </button>
        </div>

        {loading ? (
          <div className="flex min-h-[200px] items-center justify-center">
            <div className="text-center">
              <div className="mx-auto h-8 w-8 animate-spin rounded-full border-2 border-cyan-400/20 border-t-cyan-400" />
              <p className="mt-4 text-xs text-slate-500">Loading history...</p>
            </div>
          </div>
        ) : error ? (
          <div className="p-5 text-sm text-red-300">{error}</div>
        ) : filteredScans.length === 0 ? (
          <div className="flex min-h-[200px] items-center justify-center px-5 text-center">
            <div>
              <p className="text-sm text-slate-400">No scans found.</p>
              <p className="mt-1 text-xs text-slate-600">Your authenticated scan history will appear here.</p>
            </div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[720px]">
              <thead>
                <tr className="border-b border-slate-800/60">
                  {["Scan", "Type", "Risk", "Confidence", "Status", "Date"].map((heading) => (
                    <th key={heading} className="px-5 py-3 text-left text-[10px] uppercase tracking-wider text-slate-600">{heading}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredScans.map((scan) => (
                  <tr key={scan.id} className="border-b border-slate-800/40 hover:bg-slate-900/30">
                    <td className="px-5 py-4">
                      <Link to={`/threat/${scan.id}`} className="text-xs font-medium text-slate-200 hover:text-cyan-300">{scan.threat_type ?? scan.input_type}</Link>
                      <p className="mt-1 text-[10px] text-slate-700">{scan.id}</p>
                    </td>
                    <td className="px-5 py-4 text-xs text-slate-500">{scan.input_type}</td>
                    <td className="px-5 py-4 text-xs font-semibold text-white">{scan.risk_score ?? 0}/100</td>
                    <td className="px-5 py-4 text-xs text-slate-500">{scan.confidence ?? 0}%</td>
                    <td className="px-5 py-4"><StatusBadge status={scan.status} /></td>
                    <td className="px-5 py-4 text-[11px] text-slate-600">{formatDate(scan.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}