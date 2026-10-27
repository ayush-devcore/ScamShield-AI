import { lazy, Suspense } from "react";
import { Routes, Route, Navigate } from "react-router";
import { AppLayout } from "@/components/layout/AppLayout";
import { PwaRuntime } from "@/components/pwa/PwaRuntime";
import { protectedRouteRedirect, publicRouteRedirect } from "@/lib/authForm.mjs";

const Landing = lazy(() => import("@/pages/Landing"));
const Login = lazy(() => import("@/pages/Login"));
const Register = lazy(() => import("@/pages/Register"));
const Dashboard = lazy(() => import("@/pages/Dashboard"));
const ScanCenter = lazy(() => import("@/pages/ScanCenter"));
const MessageScanner = lazy(() => import("@/pages/MessageScanner"));
const UrlScanner = lazy(() => import("@/pages/UrlScanner"));
const QRScanner = lazy(() => import("@/pages/QRScanner"));
const ScreenshotScanner = lazy(() => import("@/pages/ScreenshotScanner"));
const ThreatResult = lazy(() => import("@/pages/ThreatResult"));
const History = lazy(() => import("@/pages/History"));
const Reports = lazy(() => import("@/pages/Reports"));
const Settings = lazy(() => import("@/pages/Settings"));
const PrivacyToolkit = lazy(() => import("@/pages/PrivacyToolkit"));
const SandboxAnalysis = lazy(() => import("@/pages/SandboxAnalysis"));
const NotFound = lazy(() => import("@/pages/NotFound"));

function isAuthenticated() {
  return Boolean(sessionStorage.getItem("scamshield_access_token"));
}

function ProtectedRoute() {
  const redirect = protectedRouteRedirect(isAuthenticated());
  return redirect ? <Navigate to={redirect} replace /> : <AppLayout />;
}

function PublicRoute({ children }: { children: React.ReactNode }) {
  const redirect = publicRouteRedirect(isAuthenticated());
  return redirect ? <Navigate to={redirect} replace /> : children;
}

export default function App() {
  return (
    <>
    <PwaRuntime />
    <Suspense fallback={<div className="grid min-h-screen place-items-center bg-[#0B1220] p-6 text-sm text-slate-300" role="status">Loading ScamShield…</div>}>
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/login" element={<PublicRoute><Login /></PublicRoute>} />
      <Route path="/register" element={<PublicRoute><Register /></PublicRoute>} />

      <Route element={<ProtectedRoute />}>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/scan" element={<ScanCenter />} />
        <Route path="/scan/message" element={<MessageScanner />} />
        <Route path="/scan/url" element={<UrlScanner />} />
        <Route path="/scan/qr" element={<QRScanner />} />
        <Route path="/scan/screenshot" element={<ScreenshotScanner />} />
        <Route path="/sandbox" element={<SandboxAnalysis />} />
        <Route path="/threat/:id" element={<ThreatResult />} />
        <Route path="/history" element={<History />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/privacy-tools" element={<PrivacyToolkit />} />
        <Route path="/settings" element={<Settings />} />
      </Route>

      <Route path="/app" element={<Navigate to="/dashboard" replace />} />
      <Route path="*" element={<NotFound />} />
    </Routes>
    </Suspense>
    </>
  );
}
