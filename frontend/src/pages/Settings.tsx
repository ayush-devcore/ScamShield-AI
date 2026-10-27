import { Bell, LockKeyhole, Palette, ShieldCheck, UserRound } from "lucide-react";

const sections = [
  { title: "Profile", icon: UserRound },
  { title: "Security", icon: LockKeyhole },
  { title: "Notifications", icon: Bell },
  { title: "Privacy", icon: ShieldCheck },
  { title: "Appearance", icon: Palette },
];

export default function Settings() {
  return (
    <div className="space-y-6">
      <div>
        <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-cyan-300">Account</p>
        <h1 className="mt-3 text-3xl font-semibold text-white">Settings</h1>
        <p className="mt-2 text-sm text-slate-500">Manage your ScamShield workspace and security preferences.</p>
      </div>

      <div className="grid gap-4 lg:grid-cols-[250px_1fr]">
        <nav className="scam-card rounded-2xl p-2">
          {sections.map((section, index) => {
            const Icon = section.icon;
            return (
              <button
                key={section.title}
                className={`flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-left text-xs ${
                  index === 0 ? "bg-cyan-400/[0.06] text-cyan-200" : "text-slate-500 hover:bg-slate-900/50 hover:text-white"
                }`}
              >
                <Icon className="h-4 w-4" />
                {section.title}
              </button>
            );
          })}
        </nav>

        <div className="space-y-4">
          <section className="scam-card rounded-2xl p-5">
            <div className="flex items-center gap-3">
              <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-cyan-400/10 bg-cyan-400/[0.05]">
                <UserRound className="h-5 w-5 text-cyan-300" />
              </div>
              <div>
                <h2 className="text-sm font-semibold text-white">Account profile</h2>
                <p className="mt-1 text-xs text-slate-600">Administrator workspace</p>
              </div>
            </div>

            <div className="mt-5 grid gap-4 sm:grid-cols-2">
              <label>
                <span className="mb-2 block text-xs text-slate-500">Full name</span>
                <input defaultValue="Ayush Bhatnagar" className="h-10 w-full rounded-xl border border-slate-800 bg-slate-950/20 px-3 text-xs text-white focus:border-cyan-300/20 focus:outline-none" />
              </label>
              <label>
                <span className="mb-2 block text-xs text-slate-500">Email</span>
                <input defaultValue="ayush@example.com" className="h-10 w-full rounded-xl border border-slate-800 bg-slate-950/20 px-3 text-xs text-white focus:border-cyan-300/20 focus:outline-none" />
              </label>
            </div>
          </section>

          <section className="scam-card rounded-2xl p-5">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold text-white">Security controls</h2>
                <p className="mt-1 text-xs text-slate-600">Keep your analysis workspace protected.</p>
              </div>
              <ShieldCheck className="h-5 w-5 text-emerald-300" />
            </div>

            <div className="mt-5 space-y-3">
              {[
                ["Two-factor authentication", "Add another verification step to your account."],
                ["Threat notifications", "Receive alerts when a saved scan is classified as high risk."],
                ["Session protection", "Expire inactive sessions and limit suspicious login attempts."],
              ].map(([title, description]) => (
                <label key={title} className="flex cursor-pointer items-center justify-between gap-4 rounded-xl border border-slate-800/70 bg-slate-950/20 p-4">
                  <span>
                    <span className="block text-xs font-medium text-white">{title}</span>
                    <span className="mt-1 block text-[11px] leading-5 text-slate-600">{description}</span>
                  </span>
                  <input type="checkbox" defaultChecked className="h-4 w-4 accent-cyan-400" />
                </label>
              ))}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}