import { ShieldAlert } from "lucide-react";

interface IndicatorProps {
  title: string;
  detail: string;
  severity: "critical" | "high" | "medium";
}

const severityClass = {
  critical: "border-red-400/15 bg-red-400/[0.05] text-red-300",
  high: "border-orange-400/15 bg-orange-400/[0.05] text-orange-300",
  medium: "border-amber-400/15 bg-amber-400/[0.05] text-amber-300",
};

export function Indicator({ title, detail, severity }: IndicatorProps) {
  return (
    <div className={`rounded-xl border p-4 ${severityClass[severity]}`}>
      <div className="flex items-start gap-3">
        <div className="mt-0.5 rounded-lg bg-black/15 p-2">
          <ShieldAlert className="h-4 w-4" />
        </div>

        <div>
          <p className="text-sm font-semibold">{title}</p>
          <p className="mt-1 text-xs leading-5 text-slate-400">{detail}</p>
        </div>
      </div>
    </div>
  );
}