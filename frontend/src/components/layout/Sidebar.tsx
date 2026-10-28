import {
  FileText,
  History,
  Image as ImageIcon,
  LayoutDashboard,
  Link2,
  MessageSquare,
  QrCode,
  ScanLine,
  ShieldAlert,
  Settings,
  ShieldCheck,
  ShieldPlus,
} from "lucide-react";
import { NavLink } from "react-router";
import { Brand } from "@/components/ui/Brand";

const navigation = [
  {
    heading: "Overview",
    items: [{ label: "Dashboard", to: "/dashboard", icon: LayoutDashboard }],
  },
  {
    heading: "Scan",
    items: [
      { label: "Scan Center", to: "/scan", icon: ScanLine },
      { label: "Message", to: "/scan/message", icon: MessageSquare },
      { label: "URL", to: "/scan/url", icon: Link2 },
      { label: "QR Code", to: "/scan/qr", icon: QrCode },
      { label: "Screenshot", to: "/scan/screenshot", icon: ImageIcon },
      { label: "Sandbox Analysis", to: "/sandbox", icon: ShieldAlert },
    ],
  },
  {
    heading: "Intelligence",
    items: [
      { label: "Scan History", to: "/history", icon: History },
      { label: "Threat Reports", to: "/reports", icon: FileText },
      { label: "Privacy Toolkit", to: "/privacy-tools", icon: ShieldPlus },
    ],
  },
  {
    heading: "Account",
    items: [{ label: "Settings", to: "/settings", icon: Settings }],
  },
];

interface SidebarProps {
  mobileOpen: boolean;
  onClose: () => void;
  collapsed: boolean;
  onToggleCollapse: () => void;
}

export function Sidebar({ mobileOpen, onClose, collapsed, onToggleCollapse }: SidebarProps) {

  const links = (collapsedMode = false) =>
    navigation.map((section) => (
      <div key={section.heading} className="mb-7">
        {!collapsedMode && (
          <p className="mb-2 px-3 text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-700">
            {section.heading}
          </p>
        )}

        <div className="space-y-1">
          {section.items.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                onClick={onClose}
                className={({ isActive }) =>
                  [
                    "group flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm transition-all",
                    isActive
                      ? "border border-cyan-400/10 bg-cyan-400/[0.07] text-cyan-100"
                      : "text-slate-500 hover:bg-slate-800/50 hover:text-slate-200",
                  ].join(" ")
                }
                title={collapsedMode ? item.label : undefined}
              >
                <Icon className="h-4 w-4 shrink-0" />
                {!collapsedMode && <span>{item.label}</span>}
              </NavLink>
            );
          })}
        </div>
      </div>
    ));

  return (
    <>
      <aside
        className={`app-sidebar fixed inset-y-0 left-0 z-50 hidden border-r border-cyan-400/[0.08] backdrop-blur-xl transition-all duration-300 lg:flex lg:flex-col ${
          collapsed ? "w-[78px]" : "w-[250px]"
        }`}
      >
        <div className="flex h-16 items-center border-b border-slate-800/60 px-4">
          <Brand collapsed={collapsed} />
          <button
            onClick={onToggleCollapse}
            className="ml-auto rounded-lg p-2 text-slate-600 transition hover:bg-slate-800/60 hover:text-cyan-300"
            title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            <span className="text-base">{collapsed ? "›" : "‹"}</span>
          </button>
        </div>

        <div className="flex-1 overflow-y-auto px-3 py-6">
          {links(collapsed)}
        </div>

        {!collapsed && (
          <div className="border-t border-slate-800/60 p-3">
            <div className="flex items-center gap-3 rounded-xl bg-[#0a161a] p-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-full border border-cyan-400/10 bg-cyan-400/[0.07]">
                <ShieldCheck className="h-4 w-4 text-cyan-400" />
              </div>
              <div className="min-w-0">
                <p className="truncate text-xs font-medium text-white">Ayush Bhatnagar</p>
                <p className="mt-0.5 truncate text-[10px] text-slate-600">Administrator</p>
              </div>
            </div>
          </div>
        )}
      </aside>

      <div className={`fixed inset-0 z-[60] lg:hidden ${mobileOpen ? "pointer-events-auto" : "pointer-events-none"}`}>
        <button
          aria-label="Close navigation"
          onClick={onClose}
          className={`absolute inset-0 bg-black/60 backdrop-blur-sm transition-opacity ${
            mobileOpen ? "opacity-100" : "opacity-0"
          }`}
        />

        <aside
          className={`app-sidebar relative flex h-full w-[285px] flex-col border-r border-cyan-400/10 shadow-2xl shadow-black transition-transform duration-300 ${
            mobileOpen ? "translate-x-0" : "-translate-x-full"
          }`}
        >
          <div className="flex h-16 items-center border-b border-slate-800/60 px-4">
            <Brand />
            <button onClick={onClose} className="ml-auto rounded-lg p-2 text-slate-500 hover:bg-slate-800 hover:text-white">
              ✕
            </button>
          </div>

          <div className="flex-1 overflow-y-auto px-3 py-5">{links(false)}</div>
        </aside>
      </div>

      <nav className="app-mobile-nav safe-area-bottom fixed bottom-0 left-0 right-0 z-40 border-t border-cyan-400/[0.08] px-2 pt-2 backdrop-blur-xl lg:hidden">
        <div className="mx-auto grid max-w-md grid-cols-4 gap-1">
          {[
            { label: "Home", to: "/dashboard", icon: LayoutDashboard },
            { label: "Scan", to: "/scan", icon: ScanLine },
            { label: "History", to: "/history", icon: History },
            { label: "Settings", to: "/settings", icon: Settings },
          ].map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  `flex flex-col items-center gap-1 rounded-xl py-2 text-[10px] ${
                    isActive ? "bg-cyan-400/[0.08] text-cyan-300" : "text-slate-600"
                  }`
                }
              >
                <Icon className="h-5 w-5" />
                {item.label}
              </NavLink>
            );
          })}
        </div>
      </nav>
    </>
  );
}
