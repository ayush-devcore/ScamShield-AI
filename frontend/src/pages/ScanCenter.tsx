import { ArrowUpRight, FlaskConical, Image, Link2, MessageSquare, QrCode, ScanLine } from "lucide-react";
import { Link } from "react-router";
import { ScannerCard } from "@/components/scanner/ScannerCard";

export default function ScanCenter() {
  return (
    <div className="space-y-6">
      <section className="scan-center-hero relative overflow-hidden rounded-3xl border border-cyan-300/15 p-6 sm:p-8">
        <div className="flex flex-col justify-between gap-5 sm:flex-row sm:items-end">
        <div>
        <div className="flex items-center gap-2 text-cyan-300">
          <ScanLine className="h-4 w-4" />
          <span className="text-[11px] font-semibold uppercase tracking-[0.18em]">Security scanner</span>
        </div>
        <h1 className="mt-3 max-w-2xl text-3xl font-semibold tracking-tight text-white sm:text-4xl">Start with what you received.</h1>
        <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-400">
          Choose a scan type. ScamShield combines AI predictions, structured signals and explainable indicators to assess suspicious content.
        </p>
        </div>
        <Link to="/sandbox" className="inline-flex min-h-11 items-center justify-center gap-2 self-start rounded-xl border border-slate-600/70 bg-slate-950/20 px-4 text-xs font-medium text-slate-200 transition hover:border-cyan-300/30 hover:text-cyan-100 sm:self-auto"><FlaskConical className="h-4 w-4 text-cyan-200"/> Sandbox status <ArrowUpRight className="h-3.5 w-3.5"/></Link>
        </div>
        <div className="mt-6 flex flex-wrap gap-2 border-t border-slate-700/50 pt-4 text-[10px] text-slate-400"><span className="rounded-full border border-slate-700/70 px-2.5 py-1">Review destinations safely</span><span className="rounded-full border border-slate-700/70 px-2.5 py-1">Understand available evidence</span><span className="rounded-full border border-slate-700/70 px-2.5 py-1">Results may be unverified</span></div>
      </section>

      <div className="scanner-choice-grid grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <ScannerCard title="Message Scanner" description="Analyze suspicious SMS, WhatsApp or email text for social-engineering signals." to="/scan/message" icon={MessageSquare} accent="cyan" />
        <ScannerCard title="URL Scanner" description="Inspect links for suspicious structure and phishing-related characteristics." to="/scan/url" icon={Link2} accent="teal" />
        <ScannerCard title="QR Scanner" description="Decode QR destinations and route them through URL risk analysis." to="/scan/qr" icon={QrCode} accent="amber" />
        <ScannerCard title="Screenshot Scanner" description="Extract text from screenshots and combine signals into a single assessment." to="/scan/screenshot" icon={Image} accent="sky" />
      </div>

      <div className="scan-reminder rounded-2xl border border-amber-300/15 p-5">
        <h2 className="text-sm font-semibold text-white">Safe scanning reminder</h2>
        <p className="mt-2 max-w-3xl text-xs leading-6 text-slate-500">
          ScamShield is an assessment tool. A high-risk result means the content warrants caution and independent verification; it does not mean the model knows the ground truth with certainty.
        </p>
      </div>

      <Link to="/dashboard" className="text-xs text-slate-600 hover:text-cyan-300">← Return to dashboard</Link>
    </div>
  );
}
