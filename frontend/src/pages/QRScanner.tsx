import { AlertCircle, ArrowRight, QrCode, ScanLine } from "lucide-react";
import jsQR from "jsqr";
import { useState } from "react";
import { Link, useNavigate } from "react-router";

import { UploadBox } from "@/components/scanner/UploadBox";
import { createQrScan } from "@/lib/api";

const MAX_FILE_SIZE = 4 * 1024 * 1024;

function getOtsuThreshold(histogram: Uint32Array, total: number): number {
  let totalWeighted = 0;

  for (let i = 0; i < 256; i++) {
    totalWeighted += i * histogram[i];
  }

  let backgroundWeight = 0;
  let backgroundSum = 0;
  let bestVariance = -1;
  let threshold = 127;

  for (let i = 0; i < 256; i++) {
    backgroundWeight += histogram[i];

    if (backgroundWeight === 0) continue;

    const foregroundWeight = total - backgroundWeight;
    if (foregroundWeight === 0) break;

    backgroundSum += i * histogram[i];

    const backgroundMean = backgroundSum / backgroundWeight;
    const foregroundMean =
      (totalWeighted - backgroundSum) / foregroundWeight;

    const difference = backgroundMean - foregroundMean;
    const variance =
      backgroundWeight * foregroundWeight * difference * difference;

    if (variance > bestVariance) {
      bestVariance = variance;
      threshold = i;
    }
  }

  return threshold;
}

function decodeQrImage(image: HTMLImageElement): string | null {
  const maxSide = Math.max(image.naturalWidth, image.naturalHeight);
  if (!maxSide) return null;

  const maxScale = Math.min(1.5, 1600 / maxSide);
  const initialScale = Math.min(1, maxScale);

  const scales = [
    ...new Set([
      initialScale,
      Math.min(initialScale * 1.25, maxScale),
      initialScale * 0.75,
      initialScale * 0.5,
    ]),
  ].filter((scale) => scale > 0);

  const canvas = document.createElement("canvas");
  const context = canvas.getContext("2d", {
    willReadFrequently: true,
  });

  if (!context) return null;

  for (const scale of scales) {
    canvas.width = Math.max(1, Math.round(image.naturalWidth * scale));
    canvas.height = Math.max(1, Math.round(image.naturalHeight * scale));

    context.imageSmoothingEnabled = scale < 1;
    context.imageSmoothingQuality = "high";
    context.drawImage(image, 0, 0, canvas.width, canvas.height);

    const imageData = context.getImageData(
      0,
      0,
      canvas.width,
      canvas.height,
    );

    const { data, width, height } = imageData;
    const options = { inversionAttempts: "attemptBoth" as const };

    const originalResult = jsQR(data, width, height, options);
    if (originalResult?.data) return originalResult.data;

    const gray = new Uint8ClampedArray(data.length);
    const histogram = new Uint32Array(256);
    const pixelCount = width * height;

    for (let i = 0; i < data.length; i += 4) {
      const value = Math.round(
        0.299 * data[i] +
          0.587 * data[i + 1] +
          0.114 * data[i + 2],
      );

      gray[i] = value;
      gray[i + 1] = value;
      gray[i + 2] = value;
      gray[i + 3] = data[i + 3];

      histogram[value]++;
    }

    const grayResult = jsQR(gray, width, height, options);
    if (grayResult?.data) return grayResult.data;

    const threshold = getOtsuThreshold(histogram, pixelCount);
    const binary = new Uint8ClampedArray(gray);

    for (let i = 0; i < binary.length; i += 4) {
      const value = gray[i] < threshold ? 0 : 255;

      binary[i] = value;
      binary[i + 1] = value;
      binary[i + 2] = value;
    }

    const binaryResult = jsQR(binary, width, height, options);
    if (binaryResult?.data) return binaryResult.data;
  }

  return null;
}

export default function QRScanner() {
  const [fileName, setFileName] = useState("");
  const [error, setError] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const [payload, setPayload] = useState("");

  const navigate = useNavigate();

  const analyze = async () => {
    const trimmed = payload.trim();

    if (!trimmed || analyzing) return;

    setError("");
    setAnalyzing(true);

    try {
      const scan = await createQrScan(trimmed);
      navigate(`/threat/${scan.id}`, { state: scan.analysis ? { inlineScan: scan } : undefined });
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to analyze this QR payload.",
      );
    } finally {
      setAnalyzing(false);
    }
  };

  const handleFile = (file: File) => {
    if (!file.type.startsWith("image/")) {
      setError("Please upload a valid image file for the QR code.");
      setPayload("");
      setFileName("");
      return;
    }

    if (file.size > MAX_FILE_SIZE) {
      setError("QR image is too large. Please upload an image smaller than 4 MB.");
      setPayload("");
      setFileName("");
      return;
    }

    setFileName(file.name);
    setError("");
    setPayload("");

    const reader = new FileReader();

    reader.onload = () => {
      const dataUrl =
        typeof reader.result === "string" ? reader.result : "";

      if (!dataUrl) {
        setError("The image could not be read. Please try another file.");
        return;
      }

      const image = new Image();

      image.onload = () => {
        try {
          const decoded = decodeQrImage(image);

          if (!decoded) {
            setError(
              "No QR code was detected. Try a sharper image with a clear white border around the QR code.",
            );
            setPayload("");
            return;
          }

          setPayload(decoded);
          setError("");
        } catch {
          setError(
            "The QR image could not be processed. Please try another image.",
          );
          setPayload("");
        }
      };

      image.onerror = () => {
        setError(
          "The QR image could not be decoded. Please try another file.",
        );
        setPayload("");
      };

      image.src = dataUrl;
    };

    reader.onerror = () => {
      setError(
        "The QR image could not be processed. Please try a different file.",
      );
    };

    reader.readAsDataURL(file);
  };

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <div>
        <Link
          to="/scan"
          className="text-xs text-slate-600 hover:text-cyan-300"
        >
          ← Back to scan center
        </Link>

        <div className="mt-5 flex items-center gap-2 text-amber-300">
          <QrCode className="h-4 w-4" />
          <span className="text-[11px] font-semibold uppercase tracking-[0.18em]">
            QR intelligence
          </span>
        </div>

        <h1 className="mt-3 text-3xl font-semibold text-white">
          QR Scanner
        </h1>

        <p className="mt-2 text-sm leading-6 text-slate-500">
          Upload a QR code image to decode it safely. ScamShield never opens
          the decoded destination.
        </p>
      </div>

      <div className="scam-card rounded-2xl p-5 sm:p-6">
        <UploadBox
          label={fileName || "Upload a QR code image"}
          accept="image/*"
          onFile={handleFile}
        />

        <div className="mt-5 rounded-2xl border border-slate-800 bg-[#071014] p-4">
          <label
            htmlFor="qr-payload"
            className="text-[11px] uppercase tracking-[0.18em] text-slate-500"
          >
            Decoded payload
          </label>

          <textarea
            id="qr-payload"
            value={payload}
            onChange={(event) => {
              setPayload(event.target.value);
              if (error) setError("");
            }}
            placeholder="Decoded text or URL will appear here..."
            className="mt-3 min-h-[110px] w-full resize-y rounded-xl border border-slate-800 bg-slate-950/40 p-3 text-sm text-slate-200 placeholder:text-slate-700 focus:border-cyan-300/20 focus:outline-none"
          />
        </div>

        {error && (
          <div
            className="mt-4 flex items-start gap-2 rounded-xl border border-red-400/20 bg-red-400/[0.06] px-4 py-3 text-xs text-red-300"
            role="alert"
          >
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <button
          type="button"
          onClick={analyze}
          disabled={!payload.trim() || analyzing}
          className="mt-4 inline-flex w-full items-center justify-center gap-2 rounded-xl bg-cyan-400 px-5 py-3 text-xs font-semibold text-[#031014] hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {analyzing ? (
            <>
              Analyzing
              <ScanLine className="h-4 w-4 animate-pulse" />
            </>
          ) : (
            <>
              Decode & Analyze
              <ArrowRight className="h-4 w-4" />
            </>
          )}
        </button>
      </div>
    </div>
  );
}
