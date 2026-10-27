import type { LucideIcon } from "lucide-react";
import { ArrowUpRight } from "lucide-react";

interface StatCardProps {
  title: string;
  value: string;
  subtitle: string;
  trend?: string;
  icon: LucideIcon;
  iconClassName?: string;
}

export function StatCard({
  title,
  value,
  subtitle,
  trend,
  icon: Icon,
  iconClassName = "text-cyan-400",
}: StatCardProps) {
  return (
    <div className="scam-card rounded-2xl p-4 sm:p-5">
      <div className="flex items-start justify-between">
        <div className="min-w-0">
          <p className="text-xs font-medium text-slate-500">{title}</p>

          <p className="mt-2 text-2xl font-semibold tracking-tight text-white sm:mt-3">
            {value}
          </p>

          <p className="mt-1 truncate text-xs text-slate-600">
            {subtitle}
          </p>
        </div>

        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-slate-800 bg-slate-900/70">
          <Icon className={`h-4 w-4 ${iconClassName}`} />
        </div>
      </div>

      {trend && (
        <div className="mt-4 flex items-center gap-1.5 text-[11px]">
          <span className="inline-flex items-center text-emerald-400">
            <ArrowUpRight className="mr-0.5 h-3.5 w-3.5" />
            {trend}
          </span>

          <span className="hidden text-slate-700 sm:inline">
            vs last 30 days
          </span>
        </div>
      )}
    </div>
  );
}