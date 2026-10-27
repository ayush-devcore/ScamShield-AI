import { useState } from "react";
import { ShieldCheck } from "lucide-react";
import { Link, useNavigate } from "react-router";

const API_BASE_URL = "http://127.0.0.1:8000/api/v1";

export default function Login() {
  const navigate = useNavigate();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();

    setError("");
    setLoading(true);

    try {
      const response = await fetch(`${API_BASE_URL}/auth/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email,
          password,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        if (response.status === 429) {
          setError(
            "Too many failed login attempts. Please try again later.",
          );
        } else if (response.status === 401) {
          setError("Invalid email or password.");
        } else {
          setError(data.detail || "Unable to sign in.");
        }

        return;
      }

      // Temporary client-side token storage.
      // We will move authentication to secure httpOnly cookies
      // before production deployment.
      sessionStorage.setItem("scamshield_access_token", data.access_token);
      sessionStorage.setItem(
        "scamshield_user",
        JSON.stringify(data.user),
      );

      navigate("/dashboard", { replace: true });
    } catch {
      setError(
        "Unable to connect to ScamShield AI. Make sure the backend is running.",
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="grid min-h-screen bg-[#05090c] text-white lg:grid-cols-2">
      <section className="relative hidden overflow-hidden border-r border-cyan-400/[0.07] lg:block">
        <div className="absolute inset-0 grid-bg" />
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_45%_50%,rgba(34,211,238,0.12),transparent_38%)]" />

        <div className="relative flex h-full items-center justify-center p-16">
          <div className="max-w-lg text-center">
            <div className="mx-auto flex h-20 w-20 items-center justify-center rounded-3xl border border-cyan-300/15 bg-cyan-300/[0.05] shadow-2xl shadow-cyan-950/30">
              <ShieldCheck className="h-10 w-10 text-cyan-300" />
            </div>

            <h1 className="mt-8 text-4xl font-semibold tracking-tight">
              ScamShield AI
            </h1>

            <p className="mt-4 text-sm leading-7 text-slate-500">
              AI-assisted risk assessment for suspicious messages, URLs, QR
              codes and screenshots.
            </p>
          </div>
        </div>
      </section>

      <section className="flex items-center justify-center px-5 py-10">
        <div className="w-full max-w-md">
          <Link
            to="/"
            className="text-xs text-slate-600 hover:text-cyan-300"
          >
            ← Back
          </Link>

          <div className="mt-10">
            <p className="text-xs uppercase tracking-[0.18em] text-cyan-300">
              Secure access
            </p>

            <h2 className="mt-3 text-3xl font-semibold tracking-tight">
              Sign in
            </h2>

            <p className="mt-2 text-sm text-slate-500">
              Access your ScamShield security workspace.
            </p>
          </div>

          <form
            className="mt-8 space-y-5"
            onSubmit={handleSubmit}
          >
            <label className="block">
              <span className="mb-2 block text-xs font-medium text-slate-400">
                Email
              </span>

              <input
                type="email"
                required
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                placeholder="you@example.com"
                autoComplete="email"
                disabled={loading}
                className="h-11 w-full rounded-xl border border-slate-800 bg-[#0a1115] px-3 text-sm text-white placeholder:text-slate-700 focus:border-cyan-300/30 focus:outline-none disabled:cursor-not-allowed disabled:opacity-60"
              />
            </label>

            <label className="block">
              <div className="mb-2 flex items-center justify-between">
                <span className="text-xs font-medium text-slate-400">
                  Password
                </span>

                <button
                  type="button"
                  disabled
                  className="text-[11px] text-slate-700"
                >
                  Forgot password?
                </button>
              </div>

              <input
                type="password"
                required
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="••••••••"
                autoComplete="current-password"
                disabled={loading}
                className="h-11 w-full rounded-xl border border-slate-800 bg-[#0a1115] px-3 text-sm text-white placeholder:text-slate-700 focus:border-cyan-300/30 focus:outline-none disabled:cursor-not-allowed disabled:opacity-60"
              />
            </label>

            {error && (
              <div
                role="alert"
                className="rounded-xl border border-red-400/20 bg-red-400/[0.06] px-3 py-3 text-xs leading-5 text-red-300"
              >
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="h-11 w-full rounded-xl bg-cyan-400 text-sm font-semibold text-[#031014] transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {loading ? "Signing in..." : "Sign in"}
            </button>
          </form>

          <p className="mt-7 text-center text-xs text-slate-600">
            Your account is authenticated securely through ScamShield AI.
          </p>
        </div>
      </section>
    </main>
  );
}