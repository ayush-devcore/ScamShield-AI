import { ArrowRight, CheckCircle2, Link2, QrCode, ShieldCheck } from "lucide-react";
import { Link } from "react-router";

const features = [
  "Explainable risk assessment",
  "Message and URL analysis",
  "QR and screenshot inspection",
  "Actionable safety guidance",
];

export default function Landing() {
  return (
    <main className="relative min-h-screen overflow-hidden bg-[#05090c] text-white">
      <div className="pointer-events-none absolute inset-0 grid-bg opacity-70" />
      <div className="absolute left-1/2 top-[-18rem] h-[38rem] w-[38rem] -translate-x-1/2 rounded-full bg-cyan-400/[0.04] blur-3xl" />

      <nav className="relative z-10 mx-auto flex max-w-7xl items-center justify-between px-5 py-5 sm:px-8">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-cyan-400/15 bg-cyan-400/[0.06]">
            <ShieldCheck className="h-5 w-5 text-cyan-300" />
          </div>
          <span className="text-sm font-semibold">ScamShield <span className="text-cyan-300">AI</span></span>
        </div>

        <div className="flex items-center gap-3">
          <a href="#features" className="hidden text-xs text-slate-500 hover:text-white sm:block">Features</a>
          <Link to="/login" className="rounded-lg border border-slate-800 px-3 py-2 text-xs text-slate-300 hover:border-cyan-400/20 hover:text-white">
            Sign in
          </Link>
        </div>
      </nav>

      <section className="relative z-10 mx-auto grid max-w-7xl gap-10 px-5 pb-20 pt-12 sm:px-8 lg:grid-cols-[1.05fr_0.95fr] lg:items-center lg:py-24">
        <div>
          <span className="inline-flex items-center gap-2 rounded-full border border-cyan-300/10 bg-cyan-300/[0.03] px-3 py-1.5 text-[10px] font-semibold uppercase tracking-[0.18em] text-cyan-300">
            AI-assisted cyber-fraud assessment
          </span>

          <h1 className="mt-6 max-w-3xl text-5xl font-semibold leading-[0.95] tracking-[-0.045em] sm:text-6xl lg:text-7xl">
            Detect before
            <span className="block text-cyan-300">you regret.</span>
          </h1>

          <p className="mt-6 max-w-xl text-base leading-7 text-slate-500 sm:text-lg">
            Analyze suspicious messages, URLs, QR codes and screenshots with an explainable risk engine built to help users pause before they act.
          </p>

          <div className="mt-8 flex flex-col gap-3 sm:flex-row">
            <Link to="/scan" className="inline-flex items-center justify-center gap-2 rounded-xl bg-cyan-400 px-5 py-3 text-sm font-semibold text-[#031014] hover:bg-cyan-300">
              Start a Scan <ArrowRight className="h-4 w-4" />
            </Link>
            <a href="#features" className="inline-flex items-center justify-center rounded-xl border border-slate-800 px-5 py-3 text-sm text-slate-300 hover:border-cyan-400/20 hover:text-white">
              Explore Features
            </a>
          </div>

          <div className="mt-8 grid gap-3 sm:grid-cols-2">
            {features.map((feature) => (
              <div key={feature} className="flex items-center gap-2 text-xs text-slate-500">
                <CheckCircle2 className="h-4 w-4 text-emerald-300" />
                {feature}
              </div>
            ))}
          </div>
        </div>

        <div className="scam-card relative overflow-hidden rounded-3xl p-5 sm:p-7">
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_0%,rgba(34,211,238,0.08),transparent_50%)]" />
          <div className="relative">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-[10px] uppercase tracking-[0.18em] text-slate-600">Live analysis</p>
                <p className="mt-1 text-sm font-semibold text-white">Suspicious message</p>
              </div>
              <div className="flex items-center gap-2 text-[10px] text-emerald-300"><span className="cyber-pulse h-1.5 w-1.5 rounded-full bg-emerald-300" /> Engine online</div>
            </div>

            <div className="mt-5 rounded-2xl border border-slate-800 bg-[#081014]/80 p-4">
              <p className="text-xs leading-5 text-slate-300">
                "Your account will be blocked today. Complete KYC immediately using the verification link below."
              </p>
              <div className="mt-4 h-1.5 overflow-hidden rounded-full bg-slate-800">
                <div className="h-full w-[92%] rounded-full bg-cyan-300" />
              </div>
              <div className="mt-2 flex justify-between text-[10px] text-slate-600">
                <span>Signal fusion</span>
                <span>92%</span>
              </div>
            </div>

            <div className="mt-5 grid grid-cols-3 gap-3">
              <div className="rounded-xl border border-red-400/10 bg-red-400/[0.04] p-3">
                <p className="text-2xl font-semibold text-red-300">94</p>
                <p className="mt-1 text-[10px] text-slate-600">Risk score</p>
              </div>
              <div className="rounded-xl border border-cyan-400/10 bg-cyan-400/[0.03] p-3">
                <p className="text-2xl font-semibold text-cyan-300">4</p>
                <p className="mt-1 text-[10px] text-slate-600">Indicators</p>
              </div>
              <div className="rounded-xl border border-slate-800 bg-slate-950/20 p-3">
                <p className="text-2xl font-semibold text-white">96%</p>
                <p className="mt-1 text-[10px] text-slate-600">Confidence</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section id="features" className="relative z-10 mx-auto max-w-7xl px-5 pb-24 sm:px-8">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {[
            { icon: ShieldCheck, title: "Explainable AI", text: "Show users why content was flagged." },
            { icon: Link2, title: "URL Intelligence", text: "Inspect structural phishing signals." },
            { icon: QrCode, title: "QR Analysis", text: "Decode and assess QR destinations." },
            { icon: CheckCircle2, title: "Safety Actions", text: "Turn a prediction into a clear next step." },
          ].map((item) => {
            const Icon = item.icon;
            return (
              <div key={item.title} className="scam-card rounded-2xl p-5">
                <Icon className="h-5 w-5 text-cyan-300" />
                <h3 className="mt-5 text-sm font-semibold text-white">{item.title}</h3>
                <p className="mt-2 text-xs leading-5 text-slate-500">{item.text}</p>
              </div>
            );
          })}
        </div>
      </section>
    </main>
  );
}