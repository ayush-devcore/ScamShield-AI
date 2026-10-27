import { useState } from "react";
import { ArrowRight, ScanLine, ShieldAlert } from "lucide-react";
import { Link, useNavigate } from "react-router";

import { createMessageScan } from "@/lib/api";

const sample =
  "ALERT: Your account will be blocked today. Complete KYC immediately using the verification link below.";

export default function MessageScanner() {
  const navigate = useNavigate();

  const [message, setMessage] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState("");

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
          Paste suspicious SMS, WhatsApp or email content and ScamShield AI
          will analyze it for fraud and social-engineering indicators.
        </p>
      </div>

      {/* Scanner */}
      <div className="scam-card rounded-2xl p-5 sm:p-6">
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
            disabled={!message.trim() || analyzing}
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

        {/* Privacy note */}
        <div className="mt-5 rounded-xl border border-slate-800/60 bg-slate-950/20 px-4 py-3">
          <p className="text-[11px] leading-5 text-slate-600">
            ScamShield stores a SHA-256 hash of the submitted message for
            scan tracking rather than permanently storing the original
            message in the scan record.
          </p>
        </div>
      </div>
    </div>
  );
}
