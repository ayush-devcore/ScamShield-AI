import { CheckCircle2, CircleAlert, ShieldCheck } from "lucide-react";

const actions = [
  { icon: CircleAlert, text: "Do not click suspicious links or open unknown attachments." },
  { icon: CircleAlert, text: "Never share OTPs, passwords, PINs or remote-access codes." },
  { icon: ShieldCheck, text: "Verify the organization through an official channel." },
  { icon: CheckCircle2, text: "Report the suspicious communication to the appropriate service." },
];

export function RecommendationCard() {
  return (
    <div className="scam-card rounded-2xl p-5">
      <div className="flex items-start gap-3">
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-emerald-400/10 bg-emerald-400/[0.05]">
          <ShieldCheck className="h-5 w-5 text-emerald-300" />
        </div>

        <div>
          <h3 className="text-sm font-semibold text-white">Recommended Action</h3>
          <p className="mt-1 text-xs text-slate-500">Safer next steps based on this assessment.</p>
        </div>
      </div>

      <div className="mt-5 space-y-3">
        {actions.map((item) => {
          const Icon = item.icon;
          return (
            <div key={item.text} className="flex items-start gap-3 rounded-xl border border-slate-800/70 bg-slate-950/20 p-3">
              <Icon className="mt-0.5 h-4 w-4 shrink-0 text-cyan-300" />
              <p className="text-xs leading-5 text-slate-400">{item.text}</p>
            </div>
          );
        })}
      </div>
    </div>
  );
}