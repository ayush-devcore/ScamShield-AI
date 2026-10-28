import { LogOut, Menu, ShieldCheck } from "lucide-react";
import { getCurrentUser, logout, type UserSummary } from "@/lib/api";
import { NotificationCenter } from "./NotificationCenter";
import { useEffect, useState } from "react";
import { useLocation } from "react-router";

interface HeaderProps {
  onMenuClick: () => void;
}

export function Header({ onMenuClick }: HeaderProps) {
  const [user, setUser] = useState<UserSummary | null>(null);
  const location = useLocation();
  useEffect(() => { let active = true; void getCurrentUser().then((value) => { if (active) setUser(value); }).catch(() => undefined); return () => { active = false; }; }, []);
  const page = location.pathname.split("/").filter(Boolean).at(-1)?.replaceAll("-", " ") || "Dashboard";
  const pageTitles: Record<string, string> = { "/dashboard": "Overview", "/scan": "Scan center", "/scan/message": "Message scanner", "/scan/url": "URL scanner", "/scan/qr": "QR scanner", "/scan/screenshot": "Screenshot scanner", "/sandbox": "Sandbox analysis", "/history": "Scan history", "/reports": "Threat reports", "/settings": "Settings", "/privacy-tools": "Privacy toolkit" };
  const title = location.pathname.startsWith("/threat/") ? "Threat assessment" : pageTitles[location.pathname] ?? page.replace(/\b\w/g, (letter) => letter.toUpperCase());
  const initials = user?.name?.trim().split(/\s+/).map((part) => part[0]).join("").slice(0, 2).toUpperCase() || "SS";
  return (
    <header className="app-header sticky top-0 z-30 flex h-16 items-center justify-between border-b border-cyan-400/[0.07] px-4 backdrop-blur-xl sm:px-6">
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

        <div className="hidden items-center gap-2 md:flex" aria-label="Current page">
          <span className="text-xs text-slate-600">Workspace</span>
          <span className="text-slate-700">/</span>
          <span className="text-xs font-semibold text-slate-200">{title}</span>
        </div>
      </div>

      <div className="flex items-center gap-2">
        <NotificationCenter />

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
            {initials}
          </div>
          <div className="hidden text-left sm:block">
            <p className="max-w-32 truncate text-xs font-medium text-white">{user?.name ?? "Account"}</p>
            <p className="max-w-32 truncate text-[10px] text-slate-500">{user?.email ?? "ScamShield member"}</p>
          </div>
        </div>
      </div>
    </header>
  );
}
