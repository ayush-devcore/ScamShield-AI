import { useEffect, useState } from "react";
import { ArrowLeft, Clock3, ShieldAlert } from "lucide-react";
import { Link, useLocation, useNavigate, useParams } from "react-router";

import { RiskGauge } from "@/components/ui/RiskGauge";
import { Indicator } from "@/components/threat/Indicator";
import { RecommendationCard } from "@/components/threat/RecommendationCard";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { getScanDetail, type MessageScanResponse, type ScanDetailData, type UrlDecisionResponse } from "@/lib/api";

function formatIndicatorTitle(type: string) {
  return type
    .split("_")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

function formatDate(date: string) {
  const parsed = new Date(date);

  if (Number.isNaN(parsed.getTime())) {
    return "Unknown time";
  }

  return parsed.toLocaleString([], {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function getRiskLabel(score: number | null, status?: string) {
  if (status === "runtime_unavailable") return "UNVERIFIED";
  if (score === null) return "PENDING";
  if (score >= 80) return "CRITICAL";
  if (score >= 60) return "HIGH RISK";
  if (score >= 30) return "MEDIUM RISK";
  return "SAFE";
}

export default function ThreatResult() {
  const { id } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  const routeState = location.state as { inlineScan?: MessageScanResponse; urlDecision?: UrlDecisionResponse } | null;
  const inlineScan = routeState?.inlineScan;
  const urlDecision = routeState?.urlDecision;

  const [scan, setScan] = useState<ScanDetailData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!id) {
      setError("Invalid scan ID.");
      setLoading(false);
      return;
    }

    const scanId = id;

    if (inlineScan?.id === scanId && inlineScan.analysis) {
      setScan({
        id: inlineScan.id,
        input_type: inlineScan.input_type,
        status: inlineScan.status,
        risk_score: inlineScan.risk_score,
        confidence: inlineScan.confidence,
        threat_type: inlineScan.threat_type,
        created_at: inlineScan.created_at,
        analysis: inlineScan.analysis,
        indicators: inlineScan.indicators ?? [],
      });
      setError("");
      setLoading(false);
      return;
    }

    let cancelled = false;

    async function loadScan() {
      try {
        setLoading(true);
        setError("");

        const data = await getScanDetail(scanId);

        if (!cancelled) {
          setScan(data);
        }
      } catch (err) {
        if (!cancelled) {
          setError(
            err instanceof Error ? err.message : "Unable to load scan result.",
          );
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    loadScan();

    return () => {
      cancelled = true;
    };
  }, [id, inlineScan]);

  if (loading) {
    return (
      <div className="flex min-h-[400px] items-center justify-center">
        <div className="text-center">
          <div className="mx-auto h-8 w-8 animate-spin rounded-full border-2 border-cyan-400/20 border-t-cyan-400" />
          <p className="mt-4 text-xs text-slate-500">
            Loading security assessment...
          </p>
        </div>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="scam-card rounded-2xl border border-red-400/10 p-6">
        <p className="text-sm font-medium text-red-300">Unable to load scan</p>

        <p className="mt-2 text-xs text-slate-500">
          {error || "Scan was not found."}
        </p>

        <button
          type="button"
          onClick={() => navigate("/scan")}
          className="mt-5 rounded-xl bg-cyan-400 px-4 py-2 text-xs font-semibold text-[#031014]"
        >
          Back to scanner
        </button>
      </div>
    );
  }

  const status = scan.status;
  const score = scan.risk_score ?? 0;
  const riskLabel = getRiskLabel(scan.risk_score, scan.status);

  const indicatorData = scan.indicators.map((indicator) => {
    const severity: "medium" | "high" | "critical" =
      indicator.severity === "critical"
        ? "critical"
        : indicator.severity === "high"
          ? "high"
          : "medium";

    return {
      title: formatIndicatorTitle(indicator.indicator_type),
      detail: indicator.description,
      severity,
    };
  });

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <Link
          to="/scan"
          className="inline-flex items-center gap-2 text-xs text-slate-600 hover:text-cyan-300"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          Back to scanner
        </Link>

        <div className="flex items-center gap-2 text-[11px] text-slate-600">
          <Clock3 className="h-3.5 w-3.5" />
          Scan ID: {scan.id}
        </div>
      </div>

      {urlDecision && <section className={`rounded-2xl border p-5 ${urlDecision.outcome === "dataset_match" ? "border-red-400/30 bg-red-400/[0.05]" : "border-amber-300/25 bg-amber-300/[0.04]"}`} aria-label="URL detection source and reachability">
        <h2 className="text-sm font-semibold text-white">{urlDecision.outcome === "dataset_match" ? "Known malicious URL" : "URL not fully verified"}</h2>
        <p className="mt-2 text-sm leading-6 text-slate-300">{urlDecision.risk_assessment?.explanation}</p>
        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          <div className="rounded-xl border border-slate-700/70 bg-slate-950/30 p-3 text-xs text-slate-300">
            <p className="text-[10px] uppercase tracking-wide text-slate-500">Dataset match</p>
            <p className="mt-1">{urlDecision.dataset_lookup.status.replaceAll("_", " ")}</p>
            {urlDecision.dataset_lookup.status === "known_malicious" && <>
              <p className="mt-1">Label: {urlDecision.dataset_lookup.source_label}</p>
              <p>Match type: {urlDecision.dataset_lookup.match_type?.replaceAll("_", " ") || "exact URL"}</p>
              <p>Source: {urlDecision.dataset_lookup.record_source || urlDecision.dataset_lookup.dataset_name}</p>
              {urlDecision.dataset_lookup.imported_at && <p>Imported: {formatDate(urlDecision.dataset_lookup.imported_at)}</p>}
              <p>{urlDecision.dataset_lookup.recorded_at ? `Record date: ${formatDate(urlDecision.dataset_lookup.recorded_at)}` : "The dataset does not provide a per-record timestamp."}</p>
            </>}
          </div>
          <div className="rounded-xl border border-slate-700/70 bg-slate-950/30 p-3 text-xs text-slate-300">
            <p className="text-[10px] uppercase tracking-wide text-slate-500">Website reachability</p>
            <p className="mt-1">{urlDecision.reachability.replaceAll("_", " ")}</p>
            {urlDecision.reason && <p className="mt-1 text-slate-400">Reason: {urlDecision.reason.replaceAll("_", " ")}</p>}
          </div>
        </div>
        {urlDecision.risk_assessment?.limitations?.length ? <ul className="mt-3 list-disc space-y-1 pl-5 text-xs text-slate-400">{urlDecision.risk_assessment.limitations.map((item) => <li key={item}>{item}</li>)}</ul> : null}
      </section>}

      <div className="grid gap-4 xl:grid-cols-[0.9fr_1.1fr]">
        <div className="scam-card risk-pulse rounded-2xl p-5 sm:p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-[10px] uppercase tracking-[0.18em] text-slate-600">
                Security assessment
              </p>

              <h1 className="mt-2 text-xl font-semibold text-white">
                Threat Result
              </h1>
            </div>

            <ShieldAlert className="h-5 w-5 text-red-300" />
          </div>

          <RiskGauge score={score} label={riskLabel} />

          <div className="text-center">
            <StatusBadge status={status} />

            <h2 className="mt-4 text-lg font-semibold text-white">
              {scan.threat_type ?? "Analysis Pending"}
            </h2>

            <p className="mt-2 text-xs leading-5 text-slate-500">
              {status === "queued"
                ? "This scan is waiting for analysis."
                : status === "analyzing"
                  ? "The security engine is analyzing this scan."
                  : "Assessment generated from the ScamShield analysis pipeline."}
            </p>
          </div>

          <div className="mt-6 grid grid-cols-2 gap-3">
            <div className="rounded-xl border border-slate-800 bg-slate-950/30 p-4">
              <p className="text-[10px] uppercase tracking-wider text-slate-600">
                Confidence
              </p>

              <p className="mt-2 text-xl font-semibold text-white">
                {scan.confidence !== null ? `${scan.confidence}%` : "—"}
              </p>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-950/30 p-4">
              <p className="text-[10px] uppercase tracking-wider text-slate-600">
                Scan time
              </p>

              <p className="mt-2 text-sm font-semibold text-white">
                {formatDate(scan.created_at)}
              </p>
            </div>
          </div>
        </div>

        <div className="space-y-4">
          <div className="scam-card rounded-2xl p-5">
            <div>
              <h2 className="text-sm font-semibold text-white">
                Why was this flagged?
              </h2>

              <p className="mt-1 text-xs text-slate-500">
                These are the interpretable signals behind the current
                assessment.
              </p>
            </div>

            {indicatorData.length > 0 ? (
              <div className="mt-5 grid gap-3 sm:grid-cols-2">
                {indicatorData.map((indicator) => (
                  <Indicator key={indicator.title} {...indicator} />
                ))}
              </div>
            ) : (
              <div className="mt-5 rounded-xl border border-slate-800/60 bg-slate-950/30 p-4">
                <p className="text-xs text-slate-600">
                  No threat indicators are available yet.
                </p>
              </div>
            )}
          </div>

          <RecommendationCard />
        </div>
      </div>
    </div>
  );
}
