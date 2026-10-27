import {
  ArrowUpRight,
  Image,
  Link2,
  MessageSquare,
  QrCode,
} from "lucide-react";
import { Link } from "react-router";
import { StatusBadge } from "@/components/ui/StatusBadge";

interface RecentScan {
  id: string;
  title: string;
  type: string;
  score: number | null;
  confidence: number | null;
  status: "critical" | "high" | "medium" | "safe";
  date: string;
}

interface RecentScansProps {
  data: RecentScan[];
}

function ScanIcon({ type }: { type: string }) {
  if (type === "URL") {
    return <Link2 className="h-4 w-4 text-cyan-400" />;
  }

  if (type === "QR") {
    return <QrCode className="h-4 w-4 text-teal-300" />;
  }

  if (type === "SCREENSHOT") {
    return <Image className="h-4 w-4 text-sky-300" />;
  }

  return <MessageSquare className="h-4 w-4 text-cyan-400" />;
}

function formatScanDate(date: string) {
  const parsedDate = new Date(date);

  if (Number.isNaN(parsedDate.getTime())) {
    return "Unknown time";
  }

  return parsedDate.toLocaleString([], {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

export function RecentScans({ data }: RecentScansProps) {
  return (
    <div className="scam-card overflow-hidden rounded-2xl">
      <div className="flex items-center justify-between border-b border-slate-800/60 px-5 py-4">
        <div>
          <h2 className="text-sm font-semibold text-white">
            Recent Scans
          </h2>

          <p className="mt-1 text-xs text-slate-500">
            Latest security analyses
          </p>
        </div>

        <Link
          to="/history"
          className="flex items-center gap-1 text-xs text-cyan-300 transition hover:text-cyan-200"
        >
          View all
          <ArrowUpRight className="h-3.5 w-3.5" />
        </Link>
      </div>

      {data.length === 0 ? (
        <div className="flex min-h-[180px] items-center justify-center px-5">
          <div className="text-center">
            <div className="mx-auto flex h-10 w-10 items-center justify-center rounded-xl border border-slate-800 bg-slate-900/70">
              <MessageSquare className="h-4 w-4 text-slate-700" />
            </div>

            <p className="mt-4 text-sm text-slate-500">
              No scans yet
            </p>

            <p className="mt-1 text-xs text-slate-700">
              Your analyzed scans will appear here.
            </p>
          </div>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[680px]">
            <thead>
              <tr className="border-b border-slate-800/60 bg-slate-950/20 text-left">
                {[
                  "Scan",
                  "Type",
                  "Risk",
                  "Confidence",
                  "Status",
                  "Time",
                ].map((heading) => (
                  <th
                    key={heading}
                    className="px-5 py-3 text-[10px] font-medium uppercase tracking-wider text-slate-600"
                  >
                    {heading}
                  </th>
                ))}
              </tr>
            </thead>

            <tbody>
              {data.map((scan) => (
                <tr
                  key={scan.id}
                  className="border-b border-slate-800/40 transition hover:bg-slate-900/40"
                >
                  <td className="px-5 py-4">
                    <div className="flex items-center gap-3">
                      <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-slate-900">
                        <ScanIcon type={scan.type} />
                      </div>

                      <div>
                        <p className="text-xs font-medium text-slate-200">
                          {scan.title}
                        </p>

                        <p className="mt-1 text-[10px] text-slate-600">
                          {scan.id}
                        </p>
                      </div>
                    </div>
                  </td>

                  <td className="px-5 py-4 text-xs text-slate-400">
                    {scan.type}
                  </td>

                  <td className="px-5 py-4">
                    <span
                      className={`text-xs font-semibold ${
                        (scan.score ?? 0) >= 80
                          ? "text-red-400"
                          : (scan.score ?? 0) >= 60
                            ? "text-orange-400"
                            : (scan.score ?? 0) >= 30
                              ? "text-amber-400"
                              : "text-emerald-400"
                      }`}
                    >
                      {scan.score ?? 0}/100
                    </span>
                  </td>

                  <td className="px-5 py-4 text-xs text-slate-400">
                    {scan.confidence ?? 0}%
                  </td>

                  <td className="px-5 py-4">
                    <StatusBadge status={scan.status} />
                  </td>

                  <td className="px-5 py-4 text-[11px] text-slate-600">
                    {formatScanDate(scan.date)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}