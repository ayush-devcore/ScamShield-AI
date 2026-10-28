import { useState } from "react";
import { Eye, EyeOff, ShieldCheck } from "lucide-react";
import { Link, useLocation, useNavigate } from "react-router";
import { ApiError, loginWithPassword, resetPasswordWithAuthenticator } from "@/lib/api";
import { authErrorMessage, establishSession } from "@/lib/authForm.mjs";


export default function Login() {
  const navigate = useNavigate();
  const location = useLocation();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(() => (location.state as { accountCreated?: boolean } | null)?.accountCreated ? "Your account was created. Sign in with your new credentials." : "");
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showRecovery, setShowRecovery] = useState(false);
  const [recoveryCode, setRecoveryCode] = useState("");
  const [useRecoveryCode, setUseRecoveryCode] = useState(false);
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();

    setError("");
    setSuccess("");
    setLoading(true);

    try {
      await establishSession(email.trim(), password, loginWithPassword, sessionStorage, navigate);
    } catch (err) {
      setError(authErrorMessage("login", err instanceof ApiError ? err.status : undefined, err instanceof Error ? err.message : ""));
    } finally {
      setLoading(false);
    }
  }

  async function handlePasswordRecovery(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (newPassword !== confirmPassword) {
      setError("The new passwords do not match.");
      setSuccess("");
      return;
    }
    setLoading(true);
    setError("");
    setSuccess("");
    try {
      const data = await resetPasswordWithAuthenticator({ email: email.trim(), code: recoveryCode, new_password: newPassword, confirm_password: confirmPassword });
      setRecoveryCode("");
      setNewPassword("");
      setConfirmPassword("");
      setSuccess(data.message || "Password updated. Sign in with your new password.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to connect to ScamShield AI. Make sure the backend is running.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="auth-shell grid min-h-screen bg-[#05090c] text-white lg:grid-cols-2">
      <section className="auth-aside relative hidden overflow-hidden border-r border-cyan-400/[0.07] lg:block">
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
            <div className="auth-capabilities mt-8 grid gap-3 text-left">{[["01", "Inspect suspicious content"], ["02", "Review explainable signals"], ["03", "Choose your next step"]].map(([number, text]) => <div key={number} className="flex items-center gap-3 rounded-xl border border-white/[0.07] bg-slate-950/25 px-4 py-3"><span className="font-mono text-[10px] text-cyan-200">{number}</span><span className="text-xs text-slate-300">{text}</span></div>)}</div>
          </div>
        </div>
      </section>

      <section className="auth-main flex items-center justify-center px-5 py-10 sm:px-8">
        <div className="auth-panel w-full max-w-md">
          <Link
            to="/"
            className="inline-flex min-h-11 items-center text-xs text-slate-400 hover:text-cyan-300 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-300"
          >
            ← Back to home
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

          {!showRecovery && <form
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
                <span className="text-xs font-medium text-slate-400">Password</span>

                <button
                  type="button"
                  disabled={loading}
                  onClick={() => { setShowRecovery(true); setError(""); setSuccess(""); }}
                  className="text-[11px] text-cyan-300 hover:text-cyan-200 disabled:opacity-60"
                >
                  Recover with authenticator
                </button>
              </div>

              <div className="relative">
                <input id="login-password" type={showPassword ? "text" : "password"} required value={password} onChange={(event) => setPassword(event.target.value)} placeholder="••••••••" autoComplete="current-password" disabled={loading} className="h-11 w-full rounded-xl border border-slate-800 bg-[#0a1115] px-3 pr-12 text-sm text-white placeholder:text-slate-700 focus:border-cyan-300/30 focus:outline-none disabled:cursor-not-allowed disabled:opacity-60" />
                <button type="button" aria-label={showPassword ? "Hide password" : "Show password"} aria-pressed={showPassword} disabled={loading} onClick={() => setShowPassword((visible) => !visible)} className="absolute inset-y-0 right-0 grid w-11 place-items-center text-slate-400 hover:text-white disabled:opacity-50"><span className="sr-only">{showPassword ? "Hide password" : "Show password"}</span>{showPassword ? <EyeOff className="h-4 w-4" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}</button>
              </div>
            </label>

            {success && <div role="status" className="rounded-xl border border-teal-400/20 bg-teal-400/[0.06] px-3 py-3 text-xs leading-5 text-teal-200">{success}</div>}

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
          </form>}

          {showRecovery && <form className="mt-8 space-y-5" onSubmit={handlePasswordRecovery}>
            <p className="text-sm leading-6 text-slate-400">Use the authenticator configured for password recovery, or one unused recovery code. Normal sign-in uses only your email and password.</p>
            <label className="block">
              <span className="mb-2 block text-xs font-medium text-slate-400">Account email</span>
              <input type="email" required value={email} onChange={(event) => setEmail(event.target.value)} autoComplete="email" disabled={loading} className="h-11 w-full rounded-xl border border-slate-800 bg-[#0a1115] px-3 text-sm text-white focus:border-cyan-300/30 focus:outline-none disabled:opacity-60" />
            </label>
            <label className="block">
              <span className="mb-2 block text-xs font-medium text-slate-400">{useRecoveryCode ? "Recovery code" : "Authenticator code"}</span>
              <input type="text" inputMode={useRecoveryCode ? "text" : "numeric"} autoComplete={useRecoveryCode ? "off" : "one-time-code"} autoCapitalize={useRecoveryCode ? "characters" : "off"} required value={recoveryCode} onChange={(event) => setRecoveryCode(event.target.value)} disabled={loading} className="h-11 w-full rounded-xl border border-slate-800 bg-[#0a1115] px-3 text-sm text-white focus:border-cyan-300/30 focus:outline-none disabled:opacity-60" />
            </label>
            <button type="button" disabled={loading} onClick={() => { setUseRecoveryCode((current) => !current); setRecoveryCode(""); setError(""); setSuccess(""); }} className="w-full text-left text-xs text-cyan-300 hover:text-cyan-200 disabled:opacity-60">
              {useRecoveryCode ? "Use an authenticator code instead" : "Use a recovery code instead"}
            </button>
            <label className="block">
              <span className="mb-2 block text-xs font-medium text-slate-400">New password</span>
              <input type="password" minLength={8} maxLength={128} required value={newPassword} onChange={(event) => setNewPassword(event.target.value)} autoComplete="new-password" disabled={loading} className="h-11 w-full rounded-xl border border-slate-800 bg-[#0a1115] px-3 text-sm text-white focus:border-cyan-300/30 focus:outline-none disabled:opacity-60" />
            </label>
            <label className="block">
              <span className="mb-2 block text-xs font-medium text-slate-400">Confirm new password</span>
              <input type="password" minLength={8} maxLength={128} required value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} autoComplete="new-password" disabled={loading} className="h-11 w-full rounded-xl border border-slate-800 bg-[#0a1115] px-3 text-sm text-white focus:border-cyan-300/30 focus:outline-none disabled:opacity-60" />
            </label>
            {error && <div role="alert" className="rounded-xl border border-red-400/20 bg-red-400/[0.06] px-3 py-3 text-xs leading-5 text-red-300">{error}</div>}
            {success && <div role="status" className="rounded-xl border border-teal-400/20 bg-teal-400/[0.06] px-3 py-3 text-xs leading-5 text-teal-200">{success}</div>}
            <button type="submit" disabled={loading} className="h-11 w-full rounded-xl bg-cyan-400 text-sm font-semibold text-[#031014] disabled:opacity-60">{loading ? "Updating password..." : "Reset password"}</button>
            <button type="button" disabled={loading} onClick={() => { setShowRecovery(false); setRecoveryCode(""); setNewPassword(""); setConfirmPassword(""); setError(""); setSuccess(""); }} className="w-full text-sm text-slate-400 hover:text-white disabled:opacity-60">Return to sign in</button>
          </form>}

          <p className="mt-7 text-center text-xs text-slate-600">
            Your account is authenticated securely through ScamShield AI.
          </p>
          {!showRecovery && <p className="mt-5 text-center text-sm text-slate-400">Don&apos;t have an account? <Link to="/register" className="font-medium text-cyan-300 hover:text-cyan-200 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-300">Create account</Link></p>}
        </div>
      </section>
    </main>
  );
}
