import { Link } from "react-router";
import { ShieldAlert } from "lucide-react";

export default function NotFound() {
  return (
    <main className="not-found-shell flex min-h-screen items-center justify-center bg-[#05090c] px-5 text-center text-white">
      <div className="not-found-panel">
        <ShieldAlert className="mx-auto h-10 w-10 text-red-300" />
        <p className="mt-5 text-xs uppercase tracking-[0.18em] text-slate-600">404</p>
        <h1 className="mt-2 text-3xl font-semibold">Page not found</h1>
        <p className="mt-2 text-sm text-slate-600">The requested route doesn't exist.</p>
        <Link to="/" className="mt-6 inline-flex rounded-xl bg-cyan-400 px-4 py-2.5 text-xs font-semibold text-[#031014] hover:bg-cyan-300">Return home</Link>
      </div>
    </main>
  );
}
