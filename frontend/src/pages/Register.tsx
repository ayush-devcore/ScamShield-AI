import { useState, type FormEvent } from "react";
import { Eye, EyeOff, ShieldCheck } from "lucide-react";
import { Link, useNavigate } from "react-router";
import { ApiError, registerAccount } from "@/lib/api";
import { authErrorMessage, createAccountAndContinue, validateRegistration } from "@/lib/authForm.mjs";

export default function Register() {
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    const invalidField = validateRegistration({ name, email, password, confirmPassword });
    if (invalidField) {
      setError({
        name: "Enter your name using at least 2 characters.",
        email: "Enter a valid email address.",
        password: "Password must be between 8 and 128 characters.",
        confirmation: "The passwords do not match.",
      }[invalidField]);
      return;
    }

    setLoading(true);
    try {
      await createAccountAndContinue(name.trim(), email.trim(), password, registerAccount, navigate);
    } catch (reason) {
      setError(authErrorMessage("register", reason instanceof ApiError ? reason.status : undefined, reason instanceof Error ? reason.message : ""));
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="grid min-h-screen bg-[#05090c] text-white lg:grid-cols-2">
      <section className="relative hidden overflow-hidden border-r border-cyan-400/[0.07] lg:block" aria-label="ScamShield AI introduction">
        <div className="absolute inset-0 grid-bg" />
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_45%_50%,rgba(34,211,238,0.12),transparent_38%)]" />
        <div className="relative flex h-full items-center justify-center p-16">
          <div className="max-w-lg text-center">
            <div className="mx-auto flex h-20 w-20 items-center justify-center rounded-3xl border border-cyan-300/15 bg-cyan-300/[0.05] shadow-2xl shadow-cyan-950/30"><ShieldCheck className="h-10 w-10 text-cyan-300" /></div>
            <h1 className="mt-8 text-4xl font-semibold tracking-tight">ScamShield AI</h1>
            <p className="mt-4 text-sm leading-7 text-slate-500">Create an account to assess suspicious messages, URLs, QR codes, and screenshots.</p>
          </div>
        </div>
      </section>

      <section className="flex items-center justify-center px-5 py-10 sm:px-8">
        <div className="w-full max-w-md">
          <Link to="/" className="inline-flex min-h-11 items-center text-xs text-slate-400 hover:text-cyan-300 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-300">← Back to home</Link>
          <header className="mt-8">
            <p className="text-xs uppercase tracking-[0.18em] text-cyan-300">Create your account</p>
            <h2 className="mt-3 text-3xl font-semibold tracking-tight">Get started</h2>
            <p className="mt-2 text-sm text-slate-400">Register with your email, then sign in to continue.</p>
          </header>

          <form className="mt-8 space-y-5" onSubmit={handleSubmit}>
            <label className="block" htmlFor="register-name">
              <span className="mb-2 block text-xs font-medium text-slate-300">Full name</span>
              <input id="register-name" name="name" type="text" autoComplete="name" required minLength={2} maxLength={120} value={name} onChange={(event) => setName(event.target.value)} disabled={loading} className="h-11 w-full rounded-xl border border-slate-700 bg-[#0a1115] px-3 text-sm text-white placeholder:text-slate-600 focus:border-cyan-300/50 focus:outline-none focus:ring-2 focus:ring-cyan-300/15 disabled:opacity-60" />
            </label>
            <label className="block" htmlFor="register-email">
              <span className="mb-2 block text-xs font-medium text-slate-300">Email address</span>
              <input id="register-email" name="email" type="email" autoComplete="email" required maxLength={255} value={email} onChange={(event) => setEmail(event.target.value)} disabled={loading} className="h-11 w-full rounded-xl border border-slate-700 bg-[#0a1115] px-3 text-sm text-white placeholder:text-slate-600 focus:border-cyan-300/50 focus:outline-none focus:ring-2 focus:ring-cyan-300/15 disabled:opacity-60" />
            </label>
            <label className="block" htmlFor="register-password">
              <span className="mb-2 block text-xs font-medium text-slate-300">Password</span>
              <span className="relative block">
                <input id="register-password" name="password" type={showPassword ? "text" : "password"} autoComplete="new-password" required minLength={8} maxLength={128} value={password} onChange={(event) => setPassword(event.target.value)} disabled={loading} aria-describedby="password-requirement" className="h-11 w-full rounded-xl border border-slate-700 bg-[#0a1115] px-3 pr-12 text-sm text-white placeholder:text-slate-600 focus:border-cyan-300/50 focus:outline-none focus:ring-2 focus:ring-cyan-300/15 disabled:opacity-60" />
                <button type="button" aria-label={showPassword ? "Hide password" : "Show password"} aria-pressed={showPassword} disabled={loading} onClick={() => setShowPassword((visible) => !visible)} className="absolute inset-y-0 right-0 grid w-11 place-items-center rounded-r-xl text-slate-400 hover:text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan-300 disabled:opacity-50">{showPassword ? <EyeOff className="h-4 w-4" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}</button>
              </span>
              <span id="password-requirement" className="mt-2 block text-[11px] text-slate-500">Use 8–128 characters.</span>
            </label>
            <label className="block" htmlFor="register-confirm-password">
              <span className="mb-2 block text-xs font-medium text-slate-300">Confirm password</span>
              <span className="relative block">
                <input id="register-confirm-password" name="confirmPassword" type={showConfirmPassword ? "text" : "password"} autoComplete="new-password" required minLength={8} maxLength={128} value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} disabled={loading} className="h-11 w-full rounded-xl border border-slate-700 bg-[#0a1115] px-3 pr-12 text-sm text-white placeholder:text-slate-600 focus:border-cyan-300/50 focus:outline-none focus:ring-2 focus:ring-cyan-300/15 disabled:opacity-60" />
                <button type="button" aria-label={showConfirmPassword ? "Hide confirmation password" : "Show confirmation password"} aria-pressed={showConfirmPassword} disabled={loading} onClick={() => setShowConfirmPassword((visible) => !visible)} className="absolute inset-y-0 right-0 grid w-11 place-items-center rounded-r-xl text-slate-400 hover:text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan-300 disabled:opacity-50">{showConfirmPassword ? <EyeOff className="h-4 w-4" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}</button>
              </span>
            </label>

            {error && <div role="alert" className="rounded-xl border border-red-400/20 bg-red-400/[0.06] px-3 py-3 text-xs leading-5 text-red-200">{error}</div>}
            <button type="submit" disabled={loading || !name.trim() || !email.trim() || !password || !confirmPassword} className="h-11 w-full rounded-xl bg-cyan-400 text-sm font-semibold text-[#031014] transition hover:bg-cyan-300 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-200 disabled:cursor-not-allowed disabled:opacity-60" aria-busy={loading}>{loading ? "Creating account…" : "Create account"}</button>
          </form>

          <p className="mt-7 text-center text-sm text-slate-400">Already have an account? <Link to="/login" className="font-medium text-cyan-300 hover:text-cyan-200 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-300">Sign in</Link></p>
        </div>
      </section>
    </main>
  );
}
