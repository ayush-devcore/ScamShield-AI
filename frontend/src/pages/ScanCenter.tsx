import { Image, Link2, MessageSquare, QrCode, ScanLine } from "lucide-react";
import { Link } from "react-router";
import { ScannerCard } from "@/components/scanner/ScannerCard";

export default function ScanCenter() {
  return (
    <div className="space-y-6">
      <div>
        <div className="flex items-center gap-2 text-cyan-300">
          <ScanLine className="h-4 w-4" />
          <span className="text-[11px] font-semibold uppercase tracking-[0.18em]">Security scanner</span>
        </div>
        <h1 className="mt-3 text-3xl font-semibold tracking-tight text-white">What would you like to analyze?</h1>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">
          Choose a scan type. ScamShield combines AI predictions, structured signals and explainable indicators to assess suspicious content.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <ScannerCard title="Message Scanner" description="Analyze suspicious SMS, WhatsApp or email text for social-engineering signals." to="/scan/message" icon={MessageSquare} accent="cyan" />
        <ScannerCard title="URL Scanner" description="Inspect links for suspicious structure and phishing-related characteristics." to="/scan/url" icon={Link2} accent="teal" />
        <ScannerCard title="QR Scanner" description="Decode QR destinations and route them through URL risk analysis." to="/scan/qr" icon={QrCode} accent="amber" />
        <ScannerCard title="Screenshot Scanner" description="Extract text from screenshots and combine signals into a single assessment." to="/scan/screenshot" icon={Image} accent="sky" />
      </div>

      <div className="scam-card rounded-2xl p-5">
        <h2 className="text-sm font-semibold text-white">Safe scanning reminder</h2>
        <p className="mt-2 max-w-3xl text-xs leading-6 text-slate-500">
          ScamShield is an assessment tool. A high-risk result means the content warrants caution and independent verification; it does not mean the model knows the ground truth with certainty.
        </p>
      </div>

      <Link to="/dashboard" className="text-xs text-slate-600 hover:text-cyan-300">← Return to dashboard</Link>
    </div>
  );
}