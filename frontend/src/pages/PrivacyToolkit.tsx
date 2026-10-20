import { useMemo, useState, type ComponentType } from "react";
import {
  BadgeCheck,
  ExternalLink,
  Eye,
  FileLock2,
  KeyRound,
  Mail,
  RotateCcw,
  Search,
  ShieldCheck,
  ShieldEllipsis,
  type LucideProps,
} from "lucide-react";
import {
  filterPrivacyTools,
  privacyCategories,
  privacyTools,
  type PrivacyCategory,
  type PrivacyTool,
} from "@/data/privacyTools";

const categoryIcons: Record<PrivacyCategory, ComponentType<LucideProps>> = {
  "Password managers & credentials": KeyRound,
  "Two-factor authentication": BadgeCheck,
  "Private browsers & search": Eye,
  "Tracker & ad blocking": ShieldEllipsis,
  "VPN & secure DNS": ShieldCheck,
  "Encrypted communication & email": Mail,
  "Email aliases & address protection": Mail,
  "File encryption & metadata removal": FileLock2,
  "Privacy checks & account protection": Search,
};

function initials(name: string) {
  return name.split(/\s+/).map((word) => word[0]).join("").slice(0, 2).toUpperCase();
}

function ToolMark({ tool }: { tool: PrivacyTool }) {
  const Icon = categoryIcons[tool.category];
  return (
    <div className="relative flex h-12 w-12 shrink-0 items-center justify-center rounded-xl border border-cyan-400/15 bg-cyan-400/[0.07] text-cyan-200" aria-label={`${tool.name} directory mark`}>
      <Icon className="h-5 w-5" aria-hidden="true" />
      <span className="absolute bottom-1 right-1 rounded bg-[#071014] px-1 text-[8px] font-bold leading-3 text-cyan-100" aria-hidden="true">{initials(tool.name)}</span>
    </div>
  );
}

function ToolLogo({ tool }: { tool: PrivacyTool }) {
  const [failed, setFailed] = useState(false);

  if (failed) return <ToolMark tool={tool} />;

  return (
    <div className="flex h-12 w-12 shrink-0 items-center justify-center overflow-hidden rounded-xl border border-cyan-400/15 bg-white/[0.04] p-1.5">
      <img
        src={tool.logo}
        alt={`${tool.name} logo`}
        loading="lazy"
        onError={() => setFailed(true)}
        className="h-full w-full object-contain"
      />
    </div>
  );
}

function ToolCard({ tool }: { tool: PrivacyTool }) {
  return (
    <article className="scam-card flex h-full flex-col rounded-2xl p-5">
      <div className="flex items-start gap-3">
        <ToolLogo tool={tool} />
        <div className="min-w-0">
          <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-cyan-300">{tool.category}</p>
          <h2 className="mt-1 text-lg font-semibold text-white">{tool.name}</h2>
        </div>
      </div>
      <p className="mt-4 text-sm leading-6 text-slate-400">{tool.description}</p>
      <div className="mt-4 rounded-xl border border-slate-800/80 bg-black/10 p-3">
        <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Best for</p>
        <p className="mt-1 text-xs leading-5 text-slate-300">{tool.bestFor}</p>
      </div>
      <div className="mt-4 flex flex-wrap gap-2">
        {tool.labels?.map((label) => <span key={label} className="rounded-full border border-teal-400/15 bg-teal-400/[0.06] px-2 py-1 text-[10px] font-medium text-teal-200">{label}</span>)}
      </div>
      <div className="mt-auto pt-5">
        <p className="mb-3 text-xs text-slate-500">Official website: <span className="text-slate-300">{tool.domain}</span></p>
        <a href={tool.url} target="_blank" rel="noopener noreferrer" className="inline-flex w-full items-center justify-center gap-2 rounded-lg border border-cyan-400/20 bg-cyan-400/[0.07] px-3 py-2.5 text-xs font-medium text-cyan-100 transition hover:border-cyan-300/40 hover:bg-cyan-400/[0.12]">
          Visit Official Website <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
        </a>
      </div>
    </article>
  );
}

export default function PrivacyToolkit() {
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState<PrivacyCategory | "All tools">("All tools");
  const tools = useMemo(() => filterPrivacyTools(privacyTools, query, category), [query, category]);
  const filtered = query || category !== "All tools";
  const reset = () => { setQuery(""); setCategory("All tools"); };

  return (
    <div className="space-y-6">
      <section className="scam-card grid-bg rounded-2xl p-6 sm:p-8">
        <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-cyan-300">Independent privacy directory</p>
        <h1 className="mt-3 text-3xl font-semibold tracking-tight text-white sm:text-4xl">Privacy Toolkit</h1>
        <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-400">Discover trusted tools to protect your accounts, block trackers, secure your communications, and take control of your personal data.</p>
        <p className="mt-4 max-w-3xl text-xs leading-5 text-slate-500">This directory links to independent third-party tools. Each provider has its own policies, limitations, and pricing; ScamShield does not guarantee complete anonymity or protection.</p>
      </section>

      <section className="scam-card rounded-2xl p-4 sm:p-5" aria-label="Find privacy tools">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <label className="relative block min-w-0 flex-1 lg:max-w-xl">
            <span className="sr-only">Search privacy tools</span>
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" aria-hidden="true" />
            <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search tools, categories, or use cases" className="w-full rounded-xl border border-slate-800 bg-[#081216] py-2.5 pl-10 pr-3 text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-400/40 focus:outline-none" />
          </label>
          <div className="flex items-center justify-between gap-3">
            <p className="text-xs text-slate-400" aria-live="polite">{tools.length} {tools.length === 1 ? "tool" : "tools"} found</p>
            <button type="button" onClick={reset} disabled={!filtered} className="inline-flex items-center gap-2 rounded-lg px-2.5 py-2 text-xs text-slate-400 transition hover:bg-slate-800/60 hover:text-cyan-200 disabled:cursor-not-allowed disabled:opacity-40"><RotateCcw className="h-3.5 w-3.5" aria-hidden="true" /> Reset</button>
          </div>
        </div>
        <div className="mt-4 flex gap-2 overflow-x-auto pb-1" role="group" aria-label="Filter by category">
          {(["All tools", ...privacyCategories] as const).map((item) => (
            <button type="button" key={item} onClick={() => setCategory(item)} className={`shrink-0 rounded-full border px-3 py-1.5 text-xs transition ${category === item ? "border-cyan-400/35 bg-cyan-400/[0.1] text-cyan-100" : "border-slate-800 text-slate-500 hover:border-cyan-400/20 hover:text-slate-300"}`} aria-pressed={category === item}>{item}</button>
          ))}
        </div>
      </section>

      {tools.length ? (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">{tools.map((tool) => <ToolCard key={tool.name} tool={tool} />)}</div>
      ) : (
        <section className="scam-card rounded-2xl p-10 text-center">
          <Search className="mx-auto h-7 w-7 text-cyan-300" aria-hidden="true" />
          <h2 className="mt-4 text-base font-semibold text-white">No tools match those filters</h2>
          <p className="mt-2 text-sm text-slate-500">Try a different search or reset the directory.</p>
          <button type="button" onClick={reset} className="mt-5 rounded-lg border border-cyan-400/20 px-3 py-2 text-xs text-cyan-100 hover:bg-cyan-400/[0.08]">Reset filters</button>
        </section>
      )}
    </div>
  );
}
