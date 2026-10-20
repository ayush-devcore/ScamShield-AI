import { Routes, Route, Navigate } from "react-router";
import { AppLayout } from "@/components/layout/AppLayout";
import Landing from "@/pages/Landing";
import Login from "@/pages/Login";
import Dashboard from "@/pages/Dashboard";
import ScanCenter from "@/pages/ScanCenter";
import MessageScanner from "@/pages/MessageScanner";
import UrlScanner from "@/pages/UrlScanner";
import QRScanner from "@/pages/QRScanner";
import ScreenshotScanner from "@/pages/ScreenshotScanner";
import ThreatResult from "@/pages/ThreatResult";
import History from "@/pages/History";
import Reports from "@/pages/Reports";
import Settings from "@/pages/Settings";
import NotFound from "@/pages/NotFound";

function isAuthenticated() {
  return Boolean(sessionStorage.getItem("scamshield_access_token"));
}

function ProtectedRoute() {
  return isAuthenticated() ? <AppLayout /> : <Navigate to="/login" replace />;
}

function PublicRoute() {
  return isAuthenticated() ? <Navigate to="/dashboard" replace /> : <Login />;
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/login" element={<PublicRoute />} />

      <Route element={<ProtectedRoute />}>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/scan" element={<ScanCenter />} />
        <Route path="/scan/message" element={<MessageScanner />} />
        <Route path="/scan/url" element={<UrlScanner />} />
        <Route path="/scan/qr" element={<QRScanner />} />
        <Route path="/scan/screenshot" element={<ScreenshotScanner />} />
        <Route path="/threat/:id" element={<ThreatResult />} />
        <Route path="/history" element={<History />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/settings" element={<Settings />} />
      </Route>

      <Route path="/app" element={<Navigate to="/dashboard" replace />} />
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}