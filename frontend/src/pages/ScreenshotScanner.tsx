import { AlertCircle, ArrowRight, FileImage, ScanLine } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router";

import { UploadBox } from "@/components/scanner/UploadBox";
import { createScreenshotScan } from "@/lib/api";

const MAX_FILE_SIZE = 8 * 1024 * 1024;

export default function ScreenshotScanner() {
  const [file, setFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState("");
  const [error, setError] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const navigate = useNavigate();

  useEffect(() => () => { if (previewUrl) URL.revokeObjectURL(previewUrl); }, [previewUrl]);

  const analyze = async () => {
    if (!file || analyzing) return;

    setError("");
    setAnalyzing(true);

    try {
      const scan = await createScreenshotScan(file);
      navigate(`/threat/${scan.id}`, { state: scan.analysis ? { inlineScan: scan } : undefined });
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to analyze this screenshot safely.",
      );
    } finally {
      setAnalyzing(false);
    }
  };

  const handleFile = (nextFile: File) => {
    if (!nextFile.type || !nextFile.type.startsWith("image/")) {
      setError("Please upload a PNG, JPEG, or WebP screenshot.");
      setFile(null);
      setPreviewUrl("");
      return;
    }

    if (nextFile.size > MAX_FILE_SIZE) {
      setError("The screenshot is too large. Please use a file smaller than 8 MB.");
      setFile(null);
      setPreviewUrl("");
      return;
    }

    setError("");
    setFile(nextFile);
    setPreviewUrl(URL.createObjectURL(nextFile));
  };

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <div>
        <Link to="/scan" className="text-xs text-slate-600 hover:text-cyan-300">← Back to scan center</Link>
        <div className="mt-5 flex items-center gap-2 text-sky-300">
          <FileImage className="h-4 w-4" />
          <span className="text-[11px] font-semibold uppercase tracking-[0.18em]">Visual intelligence</span>
        </div>
        <h1 className="mt-3 text-3xl font-semibold text-white">Screenshot Scanner</h1>
        <p className="mt-2 text-sm leading-6 text-slate-500">Upload a screenshot to extract text with OCR and analyze it safely without opening the source image anywhere else.</p>
      </div>

      <div className="scanner-workspace grid gap-5 lg:grid-cols-[minmax(0,1.35fr)_minmax(16rem,.65fr)]">
      <section className="scam-card rounded-2xl p-5 sm:p-6" aria-label="Screenshot input">
        {previewUrl ? <div className="screenshot-preview mb-4 overflow-hidden rounded-2xl border border-slate-700/70 bg-slate-950/40"><img src={previewUrl} alt="Selected screenshot preview" className="mx-auto max-h-[360px] max-w-full object-contain" /></div> : null}
        <UploadBox label={file ? `${file.name} · choose another` : "Upload screenshot for OCR analysis"} accept="image/png,image/jpeg,image/webp" onFile={handleFile} />

        {error && (
          <div className="mt-4 flex items-start gap-2 rounded-xl border border-red-400/20 bg-red-400/[0.06] px-4 py-3 text-xs text-red-300" role="alert">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <button
          onClick={analyze}
          disabled={!file || analyzing}
          className="mt-4 inline-flex w-full items-center justify-center gap-2 rounded-xl bg-cyan-400 px-5 py-3 text-xs font-semibold text-[#031014] hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {analyzing ? (
            <>
              Analyzing <ScanLine className="h-4 w-4 animate-pulse" />
            </>
          ) : (
            <>
              Analyze Screenshot <ArrowRight className="h-4 w-4" />
            </>
          )}
        </button>
      </section>
      <aside className="scan-guide rounded-2xl border border-slate-700/60 p-5">
        <p className="text-[10px] font-semibold uppercase tracking-[.18em] text-sky-200">Image assessment</p>
        <h2 className="mt-2 text-base font-semibold text-white">From screenshot to signals</h2>
        <ol className="scan-guide-steps mt-5 space-y-4">
          {["The image is submitted to ScamShield for OCR processing.", "Extracted text is assessed for fraud signals.", "The result shows available indicators and limitations."].map((item, index) => <li key={item} className="flex gap-3"><span className="grid h-7 w-7 shrink-0 place-items-center rounded-lg border border-sky-300/20 bg-sky-300/[0.06] font-mono text-[10px] text-sky-100">0{index + 1}</span><span className="pt-1 text-xs leading-5 text-slate-400">{item}</span></li>)}
        </ol>
        <p className="mt-5 border-t border-slate-700/50 pt-4 text-[11px] leading-5 text-slate-500">Only upload screenshots you are comfortable submitting to the configured analysis service. Avoid exposing private information.</p>
      </aside>
      </div>
    </div>
  );
}
