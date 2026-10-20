import { ShieldCheck } from "lucide-react";

interface BrandProps {
  collapsed?: boolean;
}

export function Brand({ collapsed = false }: BrandProps) {
  return (
    <div className="flex items-center gap-3">
      <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-cyan-400/15 bg-cyan-400/[0.06]">
        <ShieldCheck className="h-5 w-5 text-cyan-400" />
      </div>

      {!collapsed && (
        <div className="leading-none">
          <div className="text-sm font-semibold tracking-tight text-white">
            ScamShield <span className="text-cyan-300">AI</span>
          </div>
          <div className="mt-1 text-[10px] uppercase tracking-[0.18em] text-slate-600">
            Threat Intelligence
          </div>
        </div>
      )}
    </div>
  );
}