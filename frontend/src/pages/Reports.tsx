import { Download } from "lucide-react";
import { useEffect, useState } from "react";
import { Link } from "react-router";
import { getReports, type ReportSummary } from "@/lib/api";

function formatDate(date: string) {
  const parsed = new Date(date);
  if (Number.isNaN(parsed.getTime())) return "Unknown time";
  return parsed.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

function csvCell(value: string | number | null) {
  let text = String(value ?? "");
  if (typeof value === "string" && /^[\u0000-\u0020]*[=+@-]/.test(text)) {
    text = `'${text}`;
  }
  return `"${text.replaceAll('"', '""')}"`;
}

function exportReport(report: ReportSummary) {
  const rows = [
    ["ScamShield scan report"],
    ["Total scans", report.total_scans],
    [],
    ["Risk classification", "Scans"],
    ...report.risk_distribution.map(({ label, count }) => [label, count]),
    [],
    ["Scan type", "Scans"],
    ...report.scan_type_distribution.map(({ name, count }) => [name, count]),
    [],
    ["Threat type", "Scans"],
    ...report.threat_type_distribution.map(({ name, count }) => [name, count]),
    [],
    ["Recent scan ID", "Input type", "Threat type", "Risk score", "Created at"],
    ...report.recent_scans.map((scan) => [
      scan.id,
      scan.input_type,
      scan.threat_type ?? "",
      scan.risk_score ?? "",
      scan.created_at,
    ]),
  ];
  const csv = rows.map((row) => row.map(csvCell).join(",")).join("\r\n");
  const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = "scamshield-report.csv";
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

function Distribution({ title, items }: {
  title: string;
  items: { name: string; count: number }[];
}) {
  return (
    <section className="scam-card rounded-2xl p-5">
      <h2 className="text-sm font-semibold text-white">{title}</h2>
      {items.length === 0 ? (
        <p className="mt-4 text-xs text-slate-500">No classified scans yet.</p>
      ) : (
        <ul className="mt-4 space-y-3">
          {items.map(({ name, count }) => (
            <li key={name} className="flex justify-between gap-4 text-xs">
              <span className="text-slate-400">{name}</span>
              <span className="font-medium text-white">{count}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

export default function Reports() {
  const [report, setReport] = useState<ReportSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;

    async function loadReport() {
      try {
        setLoading(true);
        setError("");
        const data = await getReports();
        if (!cancelled) setReport(data);
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
      <div className="scam-card rounded-2xl border border-red-400/10 p-6" role="alert">
        <p className="text-sm font-medium text-red-300">Unable to load threat reports</p>
        <p className="mt-2 text-xs text-slate-500">{error || "Report data is unavailable."}</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-cyan-300">Scan analytics</p>
          <h1 className="mt-3 text-3xl font-semibold text-white">Threat Reports</h1>
          <p className="mt-2 text-sm text-slate-500">Database-backed summaries of your scan history.</p>
        </div>
        <button
          type="button"
          onClick={() => exportReport(report)}
          disabled={report.total_scans === 0}
          className="inline-flex items-center gap-2 rounded-lg border border-slate-800 px-3 py-2 text-xs text-slate-400 hover:border-cyan-400/20 hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
        >
          <Download className="h-3.5 w-3.5" /> Export CSV
        </button>
      </div>

      {report.total_scans === 0 ? (
        <div className="scam-card rounded-2xl p-8 text-center">
          <p className="text-sm text-slate-300">No scan data is available yet.</p>
          <p className="mt-2 text-xs text-slate-500">Reports will appear after you complete a scan.</p>
        </div>
      ) : (
        <>
          <section className="scam-card rounded-2xl p-5">
            <p className="text-[10px] uppercase tracking-wider text-slate-600">Total scans</p>
            <p className="mt-2 text-3xl font-semibold text-white">{report.total_scans}</p>
          </section>

          <div className="grid gap-4 md:grid-cols-3">
            <Distribution title="Risk classification" items={report.risk_distribution.map(({ label, count }) => ({ name: label, count }))} />
            <Distribution title="Scan types" items={report.scan_type_distribution} />
            <Distribution title="Threat classifications" items={report.threat_type_distribution} />
          </div>

          <section className="scam-card rounded-2xl p-5">
            <h2 className="text-sm font-semibold text-white">Recent scan activity</h2>
            <div className="mt-4 grid grid-cols-7 gap-2">
              {report.recent_trends.map(({ day, scans }) => (
                <div key={day} className="rounded-lg border border-slate-800/70 p-3 text-center">
                  <p className="text-[10px] text-slate-500">{day}</p>
                  <p className="mt-1 text-sm font-semibold text-cyan-300">{scans}</p>
                </div>
              ))}
            </div>
          </section>

          <section className="scam-card overflow-hidden rounded-2xl">
            <h2 className="border-b border-slate-800/60 p-5 text-sm font-semibold text-white">Latest scans</h2>
            {report.recent_scans.length === 0 ? (
              <p className="p-5 text-xs text-slate-500">No recent scans are available.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[620px]">
                  <thead>
                    <tr className="border-b border-slate-800/60">
                      {["Scan", "Type", "Risk", "Date"].map((heading) => (
                        <th key={heading} className="px-5 py-3 text-left text-[10px] uppercase tracking-wider text-slate-600">{heading}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {report.recent_scans.map((scan) => (
                      <tr key={scan.id} className="border-b border-slate-800/40">
                        <td className="px-5 py-4">
                          <Link to={`/threat/${scan.id}`} className="text-xs text-slate-200 hover:text-cyan-300">{scan.threat_type ?? scan.input_type}</Link>
                        </td>
                        <td className="px-5 py-4 text-xs text-slate-500">{scan.input_type}</td>
                        <td className="px-5 py-4 text-xs text-white">{scan.risk_score ?? "—"}</td>
                        <td className="px-5 py-4 text-xs text-slate-500">{formatDate(scan.created_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </>
      )}
    </div>
  );
}
