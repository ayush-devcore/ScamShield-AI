import {
  AlertTriangle,
  CheckCircle2,
  ScanLine,
  ShieldAlert,
} from "lucide-react";
import { Link } from "react-router";
import { useEffect, useState } from "react";

import { StatCard } from "@/components/ui/StatCard";
import { ThreatActivity } from "@/components/dashboard/ThreatActivity";
import { ThreatDistribution } from "@/components/dashboard/ThreatDistribution";
import { RecentScans } from "@/components/dashboard/RecentScans";
import { SecurityActivityTerminal } from "@/components/dashboard/SecurityActivityTerminal";
import { getCurrentUser, getDashboard, getSecurityActivity, type DashboardData, type SecurityActivity, type UserSummary } from "@/lib/api";

export default function Dashboard() {
  const [dashboard, setDashboard] = useState<DashboardData | null>(null);
  const [currentUser, setCurrentUser] = useState<UserSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [activity, setActivity] = useState<SecurityActivity[]>([]);
  const [activityLoading, setActivityLoading] = useState(true);
  const [activityError, setActivityError] = useState("");

  useEffect(() => {
    let cancelled = false;
    let latestRequest = 0;

    async function loadDashboard(showLoading = true) {
      const requestId = ++latestRequest;
      try {
        if (showLoading) setLoading(true);
        setError("");

        const [data, user] = await Promise.all([getDashboard(), getCurrentUser()]);

        if (!cancelled && requestId === latestRequest) {
          setDashboard(data);
          setCurrentUser(user);
        }
      } catch (err) {
        if (!cancelled && requestId === latestRequest) {
          setError(
            err instanceof Error
              ? err.message
              : "Unable to load dashboard data.",
          );
        }
      } finally {
        if (!cancelled && requestId === latestRequest) {
          setLoading(false);
        }
      }
    }

    loadDashboard();
    async function loadActivity() {
      try { setActivityLoading(true); setActivityError(""); setActivity(await getSecurityActivity()); }
      catch (err) { setActivityError(err instanceof Error ? err.message : "Unable to load activity."); }
      finally { setActivityLoading(false); }
    }
    void loadActivity();
    const refreshWhenFocused = () => {
      if (document.visibilityState === "visible") void loadDashboard(false);
    };
    window.addEventListener("focus", refreshWhenFocused);

    return () => {
      cancelled = true;
      window.removeEventListener("focus", refreshWhenFocused);
    };
  }, []);

  if (loading) {
    return (
      <div className="flex min-h-[400px] items-center justify-center">
        <div className="text-center">
          <div className="mx-auto h-8 w-8 animate-spin rounded-full border-2 border-cyan-400/20 border-t-cyan-400" />
          <p className="mt-4 text-xs text-slate-500">
            Loading security dashboard...
          </p>
        </div>
      </div>
    );
  }

  if (error || !dashboard) {
    return (
      <div className="scam-card rounded-2xl border border-red-400/10 p-6">
        <p className="text-sm font-medium text-red-300">
          Unable to load dashboard
        </p>
        <p className="mt-2 text-xs text-slate-500">
          {error || "No dashboard data was returned."}
        </p>
      </div>
    );
  }

  const { stats, threat_activity, threat_distribution, recent_scans } =
    dashboard;

  return (
    <div className="space-y-6">
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div>
          <div className="mb-2 flex items-center gap-2">
            <span className="cyber-pulse h-2 w-2 rounded-full bg-emerald-400" />
            <span className="text-[11px] font-medium uppercase tracking-[0.15em] text-emerald-300">
              Protection active
            </span>
          </div>

          <h1 className="text-2xl font-semibold tracking-tight text-white sm:text-3xl">
            Hello, {currentUser?.name ?? "there"} 👋
          </h1>

          <p className="mt-2 text-sm text-slate-500">
            {currentUser?.email ?? "Stay protected. Stay informed."}
          </p>
        </div>

        <Link
          to="/scan"
          className="inline-flex items-center justify-center gap-2 rounded-xl bg-cyan-400 px-4 py-2.5 text-sm font-semibold text-[#031014] shadow-lg shadow-cyan-950/30 transition hover:bg-cyan-300"
        >
          <ScanLine className="h-4 w-4" />
          New Scan
        </Link>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          title="Total Scans"
          value={String(stats.total_scans)}
          subtitle="Across all scan types"
          icon={ScanLine}
        />

        <StatCard
          title="High-Risk Scans"
          value={String(stats.high_risk)}
          subtitle="Requiring attention"
          icon={ShieldAlert}
          iconClassName="text-red-400"
        />

        <StatCard
          title="Medium Risk"
          value={String(stats.medium_risk)}
          subtitle="Needs verification"
          icon={AlertTriangle}
          iconClassName="text-amber-400"
        />

        <StatCard
          title="Safe Scans"
          value={String(stats.safe_scans)}
          subtitle="No major threats detected"
          icon={CheckCircle2}
          iconClassName="text-emerald-400"
        />
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.7fr_1fr]">
        <ThreatActivity data={threat_activity} />
        <ThreatDistribution data={threat_distribution} total={stats.total_scans} />
      </div>

      <SecurityActivityTerminal activity={activity} loading={activityLoading} error={activityError} onRetry={() => { setActivityLoading(true); setActivityError(""); getSecurityActivity().then(setActivity).catch((err: unknown) => setActivityError(err instanceof Error ? err.message : "Unable to load activity.")).finally(() => setActivityLoading(false)); }} />

      <RecentScans data={recent_scans} />
    </div>
  );
}
