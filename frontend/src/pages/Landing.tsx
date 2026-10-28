import { ArrowRight, CheckCircle2, Link2, QrCode, ShieldCheck, ScanLine, LockKeyhole, Activity } from "lucide-react";
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
          <Link to="/register" className="rounded-lg bg-cyan-400 px-3 py-2 text-xs font-semibold text-[#031014] hover:bg-cyan-300">
            Create account
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
            <Link to="/register" className="inline-flex items-center justify-center gap-2 rounded-xl bg-cyan-400 px-5 py-3 text-sm font-semibold text-[#031014] hover:bg-cyan-300">
              Create account <ArrowRight className="h-4 w-4" />
            </Link>
            <Link to="/login" className="inline-flex items-center justify-center rounded-xl border border-slate-800 px-5 py-3 text-sm text-slate-300 hover:border-cyan-400/20 hover:text-white">Sign in</Link>
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

        <div className="product-preview relative overflow-hidden rounded-[1.75rem] p-5 sm:p-7">
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_70%_10%,rgba(34,211,238,0.1),transparent_50%)]" />
          <div className="relative">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-[10px] uppercase tracking-[0.18em] text-slate-500">Inside the workspace</p>
                <p className="mt-1 text-sm font-semibold text-white">A clearer way to assess risk</p>
              </div>
              <div className="flex items-center gap-2 rounded-full border border-cyan-300/15 bg-cyan-300/[0.06] px-2.5 py-1.5 text-[10px] text-cyan-200"><ShieldCheck className="h-3.5 w-3.5" /> Explainable</div>
            </div>

            <div className="preview-flow mt-7 space-y-3">
              {[
                { icon: ScanLine, title: "Choose what to inspect", detail: "Messages · URLs · QR codes · screenshots", tone: "cyan" },
                { icon: Activity, title: "Review the evidence", detail: "See the signals behind each assessment", tone: "lime" },
                { icon: LockKeyhole, title: "Decide with context", detail: "Understand limits before taking action", tone: "slate" },
              ].map(({ icon: Icon, title, detail, tone }, index) => (
                <div key={title} className="preview-step flex items-center gap-4 rounded-2xl border border-white/[0.07] bg-slate-950/30 p-4" style={{ animationDelay: `${index * 110}ms` }}>
                  <div className={`grid h-10 w-10 shrink-0 place-items-center rounded-xl ${tone === "lime" ? "bg-lime-300/[0.09] text-lime-200" : tone === "cyan" ? "bg-cyan-300/[0.09] text-cyan-200" : "bg-white/[0.05] text-slate-300"}`}><Icon className="h-4 w-4" /></div>
                  <div className="min-w-0 flex-1"><p className="text-sm font-medium text-white">{title}</p><p className="mt-1 text-xs text-slate-500">{detail}</p></div>
                  <span className="font-mono text-[10px] text-slate-600">0{index + 1}</span>
                </div>
              ))}
            </div>
            <p className="mt-4 border-t border-white/[0.06] pt-4 text-[11px] leading-5 text-slate-500">Assessments are signals to support your judgment. ScamShield does not guarantee that a link or message is safe.</p>
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
              <div key={item.title} className="landing-feature scam-card rounded-2xl p-5">
                <Icon className="h-5 w-5 text-cyan-300" />
                <h3 className="mt-5 text-sm font-semibold text-white">{item.title}</h3>
                <p className="mt-2 text-xs leading-5 text-slate-500">{item.text}</p>
              </div>
            );
          })}
        </div>
      </section>
      <section className="relative z-10 mx-auto max-w-7xl px-5 pb-24 sm:px-8">
        <div className="trust-band flex flex-col gap-5 rounded-3xl border border-white/[0.07] p-6 sm:flex-row sm:items-center sm:justify-between sm:p-8">
          <div><p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-lime-200">Built for careful decisions</p><h2 className="mt-2 text-xl font-semibold tracking-tight text-white sm:text-2xl">Know what was checked.<br className="hidden sm:block" /> Know what still needs your judgment.</h2></div>
          <Link to="/register" className="inline-flex items-center justify-center gap-2 self-start rounded-xl bg-lime-300 px-5 py-3 text-sm font-semibold text-[#09120d] transition hover:bg-lime-200 sm:self-center">Get started <ArrowRight className="h-4 w-4" /></Link>
        </div>
      </section>
    </main>
  );
}
