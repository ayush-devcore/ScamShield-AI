import { useState } from "react";
import { ArrowRight, ScanLine, ShieldAlert, BrainCircuit, LockKeyhole, Sparkles } from "lucide-react";
import { Link, useNavigate } from "react-router";

import { createMessageScan } from "@/lib/api";

const sample =
  "ALERT: Your account will be blocked today. Complete KYC immediately using the verification link below.";

export default function MessageScanner() {
  const navigate = useNavigate();

  const [message, setMessage] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState("");
  const [externalProcessingAcknowledged, setExternalProcessingAcknowledged] = useState(false);

  const analyze = async () => {
    const trimmedMessage = message.trim();

    if (!trimmedMessage || analyzing) {
      return;
    }

    setError("");
    setAnalyzing(true);

    try {
      const scan = await createMessageScan(trimmedMessage);

      navigate(`/threat/${scan.id}`, { state: scan.analysis ? { inlineScan: scan } : undefined });
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to analyze this message.",
      );
    } finally {
      setAnalyzing(false);
    }
  };

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      {/* Header */}
      <div>
        <Link
          to="/scan"
          className="text-xs text-slate-600 transition hover:text-cyan-300"
        >
          ← Back to scan center
        </Link>

        <div className="mt-5 flex items-center gap-2 text-cyan-300">
          <ShieldAlert className="h-4 w-4" />

          <span className="text-[11px] font-semibold uppercase tracking-[0.18em]">
            Message intelligence
          </span>
        </div>

        <h1 className="mt-3 text-3xl font-semibold text-white">
          Analyze Message
        </h1>

        <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">
          Paste suspicious SMS, WhatsApp or email content for a rule-based and, when configured, AI-assisted fraud assessment.
        </p>
      </div>

      {/* Scanner */}
      <div className="message-workspace grid gap-5 lg:grid-cols-[minmax(0,1.45fr)_minmax(17rem,.7fr)]">
      <section className="scam-card message-composer rounded-2xl p-5 sm:p-6" aria-label="Message analysis form">
        <div className="mb-5 flex items-center justify-between gap-3 border-b border-slate-700/50 pb-4">
          <div><p className="text-[10px] font-semibold uppercase tracking-[.18em] text-cyan-200">Text assessment</p><h2 className="mt-1 text-sm font-semibold text-white">Paste a message to inspect</h2></div>
          <span className="rounded-full border border-slate-700/80 bg-slate-950/30 px-2.5 py-1 text-[10px] text-slate-400">Up to 10,000 characters</span>
        </div>
        <label
          htmlFor="message-input"
          className="text-xs font-medium text-slate-400"
        >
          Suspicious message
        </label>

        <textarea
          id="message-input"
          value={message}
          onChange={(event) => {
            setMessage(event.target.value);

            if (error) {
              setError("");
            }
          }}
          placeholder="Paste SMS, WhatsApp or email text here..."
          disabled={analyzing}
          maxLength={10000}
          className="mt-3 min-h-[220px] w-full resize-y rounded-2xl border border-slate-800 bg-[#071014] p-4 text-sm leading-6 text-slate-200 placeholder:text-slate-700 focus:border-cyan-300/20 focus:outline-none disabled:cursor-not-allowed disabled:opacity-60"
        />

        {/* Character count */}
        <div className="mt-2 flex justify-end">
          <span className="text-[10px] text-slate-700">
            {message.length.toLocaleString()} / 10,000
          </span>
        </div>

        {/* Error */}
        {error && (
          <div
            role="alert"
            className="mt-4 rounded-xl border border-red-400/20 bg-red-400/[0.06] px-4 py-3 text-xs leading-5 text-red-300"
          >
            {error}
          </div>
        )}

        {/* Actions */}
        <label className="mt-4 flex items-start gap-3 rounded-xl border border-amber-300/20 bg-amber-300/[0.04] p-3 text-[11px] leading-5 text-slate-300">
          <input
            type="checkbox"
            className="mt-1 accent-cyan-400"
            checked={externalProcessingAcknowledged}
            disabled={analyzing}
            onChange={(event) => setExternalProcessingAcknowledged(event.target.checked)}
          />
          <span>I understand that if OpenRouter AI is configured, the message text I submit will be sent to OpenRouter and its selected model provider for analysis. I will remove information I do not want to share.</span>
        </label>

        <div className="mt-4 flex flex-col gap-3 sm:flex-row">
          <button
            type="button"
            onClick={() => {
              setMessage(sample);
              setError("");
            }}
            disabled={analyzing}
            className="rounded-xl border border-slate-800 px-4 py-2.5 text-xs text-slate-400 transition hover:border-cyan-400/20 hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
          >
            Use demo message
          </button>

          <button
            type="button"
            onClick={analyze}
            disabled={!message.trim() || analyzing || !externalProcessingAcknowledged}
            className="inline-flex items-center justify-center gap-2 rounded-xl bg-cyan-400 px-5 py-2.5 text-xs font-semibold text-[#031014] transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {analyzing ? (
              <>
                Analyzing
                <ScanLine className="h-4 w-4 animate-pulse" />
              </>
            ) : (
              <>
                Analyze Message
                <ArrowRight className="h-4 w-4" />
              </>
            )}
          </button>
        </div>

        {analyzing && <p className="mt-4 flex items-center gap-2 text-xs text-cyan-200" role="status" aria-live="polite"><ScanLine className="h-4 w-4 animate-pulse" />Running deterministic rules and requesting a bounded AI assessment when available…</p>}

        {/* Privacy note */}
      </section>
      <aside className="scan-guide rounded-2xl border border-cyan-300/15 p-5">
        <div className="grid h-10 w-10 place-items-center rounded-xl border border-cyan-300/20 bg-cyan-300/[0.07] text-cyan-100"><BrainCircuit className="h-5 w-5" /></div>
        <h2 className="mt-4 text-base font-semibold text-white">How analysis works</h2>
        <div className="mt-4 space-y-3">
          <div className="rounded-xl border border-slate-700/60 bg-slate-950/20 p-3"><p className="flex items-center gap-2 text-xs font-medium text-slate-200"><ShieldAlert className="h-3.5 w-3.5 text-cyan-200"/> Deterministic rules</p><p className="mt-1.5 text-[11px] leading-5 text-slate-500">Rule-based indicators are evaluated for each submission.</p></div>
          <div className="rounded-xl border border-slate-700/60 bg-slate-950/20 p-3"><p className="flex items-center gap-2 text-xs font-medium text-slate-200"><Sparkles className="h-3.5 w-3.5 text-lime-200"/> Optional AI assessment</p><p className="mt-1.5 text-[11px] leading-5 text-slate-500">When configured, OpenRouter returns a bounded assessment. Provider status appears with the result.</p></div>
          <div className="rounded-xl border border-slate-700/60 bg-slate-950/20 p-3"><p className="flex items-center gap-2 text-xs font-medium text-slate-200"><LockKeyhole className="h-3.5 w-3.5 text-teal-200"/> Privacy boundary</p><p className="mt-1.5 text-[11px] leading-5 text-slate-500">Only submitted text is sent for external AI analysis. Remove sensitive content first.</p></div>
        </div>
        <p className="mt-4 border-t border-slate-700/50 pt-4 text-[11px] leading-5 text-slate-500">Provider retention and training practices depend on OpenRouter settings and the routed provider. ScamShield does not store the original message or evidence excerpts. <a className="text-cyan-200 underline" href="https://openrouter.ai/privacy" target="_blank" rel="noreferrer">OpenRouter privacy</a></p>
      </aside>
      </div>
    </div>
  );
}
