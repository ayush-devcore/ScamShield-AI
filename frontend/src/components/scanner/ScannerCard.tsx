import type { LucideIcon } from "lucide-react";
import { ArrowUpRight } from "lucide-react";
import { Link } from "react-router";

interface ScannerCardProps {
  title: string;
  description: string;
  to: string;
  icon: LucideIcon;
  accent: "cyan" | "teal" | "amber" | "sky";
}

const accents = {
  cyan: {
    icon: "text-cyan-300",
    border: "hover:border-cyan-300/20",
    glow: "group-hover:bg-cyan-400/[0.06]",
  },
  teal: {
    icon: "text-teal-300",
    border: "hover:border-teal-300/20",
    glow: "group-hover:bg-teal-400/[0.06]",
  },
  amber: {
    icon: "text-amber-300",
    border: "hover:border-amber-300/20",
    glow: "group-hover:bg-amber-400/[0.06]",
  },
  sky: {
    icon: "text-sky-300",
    border: "hover:border-sky-300/20",
    glow: "group-hover:bg-sky-400/[0.06]",
  },
};

export function ScannerCard({
  title,
  description,
  to,
  icon: Icon,
  accent,
}: ScannerCardProps) {
  const style = accents[accent];

  return (
    <Link
      to={to}
      className={`group scam-card relative overflow-hidden rounded-2xl p-5 transition hover:-translate-y-0.5 ${style.border}`}
    >
      <div className={`absolute -right-8 -top-8 h-28 w-28 rounded-full blur-2xl transition ${style.glow}`} />

      <div className="relative">
        <div className="mb-6 flex items-start justify-between">
          <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-slate-800 bg-slate-950/50">
            <Icon className={`h-5 w-5 ${style.icon}`} />
          </div>

          <ArrowUpRight className="h-4 w-4 text-slate-700 transition group-hover:text-slate-300" />
        </div>

        <h3 className="text-base font-semibold text-white">{title}</h3>
        <p className="mt-2 max-w-xs text-xs leading-5 text-slate-500">{description}</p>

        <span className="mt-5 inline-flex text-[11px] font-medium text-slate-400 transition group-hover:text-cyan-300">
          Start analysis →
        </span>
      </div>
    </Link>
  );
}