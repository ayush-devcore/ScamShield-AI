import { useState } from "react";
import { Outlet } from "react-router";
import { Header } from "./Header";
import { Sidebar } from "./Sidebar";
import { CyberBackground } from "@/components/ui/CyberBackground";
import { AppearanceProvider } from "@/contexts/AppearanceContext";

export function AppLayout() {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <AppearanceProvider>
      <div className="app-shell relative min-h-screen overflow-x-hidden text-slate-100">
        <CyberBackground />
        <Sidebar mobileOpen={mobileOpen} onClose={() => setMobileOpen(false)} />

        <div className="lg:pl-[250px]">
          <Header onMenuClick={() => setMobileOpen(true)} />
          <main className="relative min-h-[calc(100vh-4rem)]">
            <div className="mx-auto w-full max-w-[1600px] p-4 pb-24 sm:p-6 sm:pb-24 lg:p-8 lg:pb-8">
              <Outlet />
            </div>
          </main>
        </div>
      </div>
    </AppearanceProvider>
  );
}
