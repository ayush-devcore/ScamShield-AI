import { AlertCircle, ArrowRight, FileImage, ScanLine } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate } from "react-router";

import { UploadBox } from "@/components/scanner/UploadBox";
import { createScreenshotScan } from "@/lib/api";

const MAX_FILE_SIZE = 8 * 1024 * 1024;

export default function ScreenshotScanner() {
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const navigate = useNavigate();

  const analyze = async () => {
    if (!file || analyzing) return;

    setError("");
    setAnalyzing(true);

    try {
      const scan = await createScreenshotScan(file);
      navigate(`/threat/${scan.id}`);
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
      return;
    }

    if (nextFile.size > MAX_FILE_SIZE) {
      setError("The screenshot is too large. Please use a file smaller than 8 MB.");
      setFile(null);
      return;
    }

    setError("");
    setFile(nextFile);
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

      <div className="scam-card rounded-2xl p-5 sm:p-6">
        <UploadBox label={file ? file.name : "Upload screenshot for OCR analysis"} accept="image/png,image/jpeg,image/webp" onFile={handleFile} />

        {error && (
          <div className="mt-4 flex items-start gap-2 rounded-xl border border-red-400/20 bg-red-400/[0.06] px-4 py-3 text-xs text-red-300" role="alert">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <div className="mt-4 grid gap-3 sm:grid-cols-3">
          {["OCR extraction", "Threat indicators", "Risk fusion"].map((item) => (
            <div key={item} className="rounded-xl border border-slate-800/70 bg-slate-950/20 p-3 text-xs text-slate-500">
              {item}
            </div>
          ))}
        </div>

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
      </div>
    </div>
  );
}