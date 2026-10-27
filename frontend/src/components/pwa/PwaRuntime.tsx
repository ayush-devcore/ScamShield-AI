import { useEffect, useRef, useState } from "react";
import { Download, RefreshCw, WifiOff, X } from "lucide-react";

interface InstallPromptEvent extends Event {
  prompt: () => Promise<void>;
  userChoice: Promise<{ outcome: "accepted" | "dismissed"; platform: string }>;
}

function isStandalone() {
  return window.matchMedia("(display-mode: standalone)").matches
    || (navigator as Navigator & { standalone?: boolean }).standalone === true;
}

function isIosDevice() {
  return /iphone|ipad|ipod/i.test(navigator.userAgent)
    || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
}

function wasInstallOfferDismissed() {
  try { return localStorage.getItem("scamshield-install-dismissed") === "1"; }
  catch { return false; }
}

export function PwaRuntime() {
  const [online, setOnline] = useState(() => navigator.onLine);
  const [standalone, setStandalone] = useState(isStandalone);
  const [ios, setIos] = useState(false);
  const [installPrompt, setInstallPrompt] = useState<InstallPromptEvent | null>(null);
  const [updateWaiting, setUpdateWaiting] = useState<ServiceWorker | null>(null);
  const [showIosHelp, setShowIosHelp] = useState(false);
  const [serviceWorkerUnavailable, setServiceWorkerUnavailable] = useState(false);
  const [installError, setInstallError] = useState(false);
  const [installDismissed, setInstallDismissed] = useState(wasInstallOfferDismissed);
  const reloadOnControllerChange = useRef(false);

  useEffect(() => {
    const onlineChanged = () => setOnline(navigator.onLine);
    const installed = () => {
      setStandalone(true);
      setInstallPrompt(null);
      setShowIosHelp(false);
    };
    const promptAvailable = (event: Event) => {
      event.preventDefault();
      setInstallPrompt(event as InstallPromptEvent);
    };
    const modeChanged = () => setStandalone(isStandalone());
    setIos(isIosDevice());
    window.addEventListener("online", onlineChanged);
    window.addEventListener("offline", onlineChanged);
    window.addEventListener("appinstalled", installed);
    window.addEventListener("beforeinstallprompt", promptAvailable);
    const displayMode = window.matchMedia("(display-mode: standalone)");
    displayMode.addEventListener("change", modeChanged);

    let active = true;
    const controllerChanged = () => {
      if (reloadOnControllerChange.current) window.location.reload();
    };
    if (import.meta.env.PROD && "serviceWorker" in navigator) {
      navigator.serviceWorker.addEventListener("controllerchange", controllerChanged);
      void navigator.serviceWorker.register("/sw.js").then((value) => {
        if (!active) return;
        const inspectWaiting = () => {
          if (value.waiting && navigator.serviceWorker.controller) setUpdateWaiting(value.waiting);
        };
        inspectWaiting();
        value.addEventListener("updatefound", () => {
          const installing = value.installing;
          installing?.addEventListener("statechange", () => {
            if (installing.state === "installed") inspectWaiting();
          });
        });
      }).catch(() => {
        if (active) setServiceWorkerUnavailable(true);
      });
    } else if (import.meta.env.PROD) {
      setServiceWorkerUnavailable(true);
    }

    return () => {
      active = false;
      window.removeEventListener("online", onlineChanged);
      window.removeEventListener("offline", onlineChanged);
      window.removeEventListener("appinstalled", installed);
      window.removeEventListener("beforeinstallprompt", promptAvailable);
      displayMode.removeEventListener("change", modeChanged);
      if ("serviceWorker" in navigator) navigator.serviceWorker.removeEventListener("controllerchange", controllerChanged);
    };
  }, []);

  const runInstall = async () => {
    if (!installPrompt) return;
    try {
      await installPrompt.prompt();
      const choice = await installPrompt.userChoice;
      setInstallPrompt(null);
      if (choice.outcome === "accepted") setStandalone(true);
    } catch {
      setInstallPrompt(null);
      setInstallError(true);
    }
  };

  const runUpdate = () => {
    if (!updateWaiting) return;
    reloadOnControllerChange.current = true;
    updateWaiting.postMessage({ type: "SKIP_WAITING" });
    setUpdateWaiting(null);
  };

  const dismissInstall = () => {
    setInstallDismissed(true);
    try { localStorage.setItem("scamshield-install-dismissed", "1"); }
    catch { /* The install offer remains dismissed for this app session. */ }
  };

  const showInstallOffer = !standalone && !installDismissed && Boolean(installPrompt || ios);
  if (!showInstallOffer && !updateWaiting && online && !serviceWorkerUnavailable && !installError) return null;

  return (
    <>
      <aside className="fixed bottom-[5.25rem] right-3 z-[70] w-[min(22rem,calc(100vw-1.5rem))] space-y-2 sm:right-5 lg:bottom-5" aria-live="polite">
        {!online && <div className="flex items-start gap-2 rounded-xl border border-amber-300/25 bg-[#121d30] p-3 text-xs text-amber-100 shadow-xl">
          <WifiOff className="mt-0.5 h-4 w-4 shrink-0" />
          <span><strong className="block">Offline</strong>Server-backed scans and account actions are unavailable. No work is queued.</span>
        </div>}
        {serviceWorkerUnavailable && import.meta.env.PROD && <p className="rounded-xl border border-slate-600 bg-[#121d30] p-3 text-xs text-slate-300">App installation and offline fallback require HTTPS (or localhost) and service-worker support.</p>}
        {installError && <p role="alert" className="rounded-xl border border-rose-300/25 bg-[#121d30] p-3 text-xs text-rose-100">The browser could not open the installation prompt. Try again from the browser menu.</p>}
        {updateWaiting && <button type="button" onClick={runUpdate} className="flex min-h-11 w-full items-center justify-center gap-2 rounded-xl border border-cyan-300/30 bg-[#121d30] px-4 text-sm font-medium text-cyan-100 shadow-xl hover:bg-[#192840]">
          <RefreshCw className="h-4 w-4" /> Update ScamShield
        </button>}
        {showInstallOffer && installPrompt && <div className="flex gap-2"><button type="button" onClick={() => void runInstall()} className="flex min-h-11 flex-1 items-center justify-center gap-2 rounded-xl bg-cyan-300 px-4 text-sm font-semibold text-[#07131f] shadow-xl hover:bg-cyan-200">
          <Download className="h-4 w-4" /> Install ScamShield
        </button><button type="button" onClick={dismissInstall} aria-label="Dismiss install option" className="rounded-xl border border-slate-600 bg-[#121d30] px-3 text-slate-300 hover:bg-[#192840]"><X className="h-4 w-4" /></button></div>}
        {showInstallOffer && !installPrompt && ios && <div className="flex gap-2"><button type="button" onClick={() => setShowIosHelp(true)} className="flex min-h-11 flex-1 items-center justify-center gap-2 rounded-xl border border-cyan-300/30 bg-[#121d30] px-4 text-sm font-medium text-cyan-100 shadow-xl hover:bg-[#192840]">
          <Download className="h-4 w-4" /> Add to Home Screen
        </button><button type="button" onClick={dismissInstall} aria-label="Dismiss install option" className="rounded-xl border border-slate-600 bg-[#121d30] px-3 text-slate-300 hover:bg-[#192840]"><X className="h-4 w-4" /></button></div>}
      </aside>
      {showIosHelp && <div className="fixed inset-0 z-[90] grid place-items-center bg-black/65 p-4" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) setShowIosHelp(false); }}>
        <section role="dialog" aria-modal="true" aria-labelledby="ios-install-title" className="w-full max-w-sm rounded-2xl border border-[#2d405c] bg-[#121d30] p-5 text-[#f6f9ff] shadow-2xl">
          <div className="flex items-center justify-between gap-3"><h2 id="ios-install-title" className="text-base font-semibold">Add ScamShield to your Home Screen</h2><button type="button" onClick={() => setShowIosHelp(false)} aria-label="Close instructions" className="rounded-lg p-2 text-slate-300 hover:bg-white/10"><X className="h-4 w-4" /></button></div>
          <ol className="mt-4 list-decimal space-y-2 pl-5 text-sm leading-6 text-[#bdcadb]"><li>Open this site in Safari over HTTPS.</li><li>Tap the Share button.</li><li>Choose <strong className="text-white">Add to Home Screen</strong>, then confirm.</li></ol>
          <p className="mt-4 text-xs leading-5 text-slate-400">Installation availability depends on browser and hosting support. The app needs a reachable API to scan or load account data.</p>
          <button type="button" onClick={() => setShowIosHelp(false)} className="mt-5 min-h-11 w-full rounded-xl bg-cyan-300 text-sm font-semibold text-[#07131f]">Got it</button>
        </section>
      </div>}
    </>
  );
}
