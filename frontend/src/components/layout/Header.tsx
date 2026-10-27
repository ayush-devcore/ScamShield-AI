import { Bell, LogOut, Menu, Search, ShieldCheck } from "lucide-react";
import { logout } from "@/lib/api";

interface HeaderProps {
  onMenuClick: () => void;
}

export function Header({ onMenuClick }: HeaderProps) {
  return (
    <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-cyan-400/[0.07] bg-[#05090c]/80 px-4 backdrop-blur-xl sm:px-6">
      <div className="flex items-center gap-3">
        <button
          onClick={onMenuClick}
          className="flex h-9 w-9 items-center justify-center rounded-lg border border-slate-800 bg-slate-900/60 text-slate-500 transition hover:border-cyan-400/20 hover:text-cyan-300 lg:hidden"
          aria-label="Open navigation"
        >
          <Menu className="h-4 w-4" />
        </button>

        <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-cyan-400/10 bg-cyan-400/[0.06] lg:hidden">
          <ShieldCheck className="h-5 w-5 text-cyan-400" />
        </div>

        <div className="hidden items-center gap-2 md:flex">
          <span className="text-xs text-slate-600">Workspace</span>
          <span className="text-slate-800">/</span>
          <span className="text-xs font-medium text-slate-300">ScamShield Security Console</span>
        </div>
      </div>

      <div className="flex items-center gap-2">
        <button className="hidden h-9 items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/60 px-3 text-xs text-slate-600 transition hover:border-cyan-400/15 hover:text-slate-300 sm:flex">
          <Search className="h-3.5 w-3.5" />
          Search
          <span className="ml-4 rounded border border-slate-800 px-1.5 py-0.5 text-[9px]">/</span>
        </button>

        <button className="relative flex h-9 w-9 items-center justify-center rounded-lg text-slate-500 transition hover:bg-slate-800/60 hover:text-cyan-300" aria-label="Notifications">
          <Bell className="h-4 w-4" />
          <span className="cyber-pulse absolute right-2 top-2 h-1.5 w-1.5 rounded-full bg-red-400" />
        </button>

        <button
          type="button"
          onClick={logout}
          className="inline-flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/60 px-2.5 py-1.5 text-[11px] text-slate-300 transition hover:border-cyan-400/20 hover:text-cyan-200"
          aria-label="Logout"
        >
          <LogOut className="h-3.5 w-3.5" />
          <span className="hidden sm:inline">Logout</span>
        </button>

        <div className="flex items-center gap-2 rounded-lg px-2 py-1.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-full border border-cyan-400/10 bg-cyan-400/[0.07] text-xs font-semibold text-cyan-300">
            A
          </div>
          <div className="hidden text-left sm:block">
            <p className="text-xs font-medium text-white">Ayush</p>
            <p className="text-[10px] text-slate-600">Admin</p>
          </div>
        </div>
      </div>
    </header>
  );
}