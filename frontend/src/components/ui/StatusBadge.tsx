interface StatusBadgeProps {
  status:
    | "queued"
    | "analyzing"
    | "safe"
    | "medium"
    | "high"
    | "critical"
    | "runtime_unavailable";
}

const styles = {
  queued:
    "border-slate-400/20 bg-slate-400/10 text-slate-300",
  analyzing:
    "border-cyan-400/20 bg-cyan-400/10 text-cyan-300",
  safe:
    "border-emerald-400/20 bg-emerald-400/10 text-emerald-300",
  medium:
    "border-amber-400/20 bg-amber-400/10 text-amber-300",
  high:
    "border-orange-400/20 bg-orange-400/10 text-orange-300",
  critical:
    "border-red-400/20 bg-red-400/10 text-red-300",
  runtime_unavailable:
    "border-amber-400/20 bg-amber-400/10 text-amber-200",
};

const labels = {
  queued: "Queued",
  analyzing: "Analyzing",
  safe: "Safe",
  medium: "Medium",
  high: "High Risk",
  critical: "Critical",
  runtime_unavailable: "Unverified",
};

export function StatusBadge({ status }: StatusBadgeProps) {
  return (
    <span
      className={`inline-flex items-center rounded-md border px-2 py-1 text-[11px] font-medium ${styles[status]}`}
    >
      {labels[status]}
    </span>
  );
}
