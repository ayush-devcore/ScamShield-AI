import { UploadCloud } from "lucide-react";
import { useRef } from "react";

interface UploadBoxProps {
  label: string;
  accept?: string;
  onFile?: (file: File) => void;
}

export function UploadBox({ label, accept, onFile }: UploadBoxProps) {
  const inputRef = useRef<HTMLInputElement>(null);

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => inputRef.current?.click()}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          inputRef.current?.click();
        }
      }}
      className="flex min-h-[280px] cursor-pointer flex-col items-center justify-center rounded-2xl border border-dashed border-cyan-300/15 bg-slate-950/30 p-8 text-center transition hover:border-cyan-300/30 hover:bg-cyan-300/[0.02]"
    >
      <input
        ref={inputRef}
        type="file"
        accept={accept}
        className="hidden"
        onChange={(event) => {
          const file = event.target.files?.[0];
          if (file) onFile?.(file);
        }}
      />

      <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-slate-800 bg-slate-900/70">
        <UploadCloud className="h-6 w-6 text-cyan-300" />
      </div>

      <p className="mt-5 text-sm font-medium text-slate-200">{label}</p>
      <p className="mt-2 text-xs text-slate-600">Click to select a file</p>
    </div>
  );
}