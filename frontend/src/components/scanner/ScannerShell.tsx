import type { ReactNode } from "react";
import { ArrowLeft, ShieldCheck } from "lucide-react";
import { Link } from "react-router";

export function ScannerShell({ title, description, children }: { title: string; description: string; children: ReactNode }) {
  return (
    <div className="mx-auto max-w-5xl">
      <Link to="/scan" className="mb-5 inline-flex items-center gap-2 text-xs text-slate-500 hover:text-white"><ArrowLeft className="size-3.5" /> Back to Scan Center</Link>
      <div className="mb-7 flex items-start gap-4">
        <div className="grid size-11 shrink-0 place-items-center rounded-xl border border-indigo-400/15 bg-indigo-500/10 text-indigo-300"><ShieldCheck className="size-5" /></div>
        <div><h1 className="text-2xl font-semibold tracking-tight text-white sm:text-3xl">{title}</h1><p className="mt-1.5 max-w-2xl text-sm text-slate-500">{description}</p></div>
      </div>
      {children}
    </div>
  );
}
