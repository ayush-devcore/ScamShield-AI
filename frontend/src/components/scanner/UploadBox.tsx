import { UploadCloud } from "lucide-react";
import { useRef, useState } from "react";

interface UploadBoxProps {
  label: string;
  accept?: string;
  onFile?: (file: File) => void;
}

export function UploadBox({ label, accept, onFile }: UploadBoxProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);

  function chooseFile(file?: File) {
    if (file) onFile?.(file);
  }

  return (
    <div
      role="button"
      tabIndex={0}
      aria-label={label}
      onClick={() => inputRef.current?.click()}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          inputRef.current?.click();
        }
      }}
      onDragOver={(event) => { event.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={(event) => { event.preventDefault(); setDragging(false); chooseFile(event.dataTransfer.files[0]); }}
      className={`upload-box flex min-h-[240px] cursor-pointer flex-col items-center justify-center rounded-2xl border border-dashed p-6 text-center transition sm:min-h-[270px] sm:p-8 ${dragging ? "border-cyan-200/60 bg-cyan-300/[0.07]" : "border-cyan-300/15 bg-slate-950/30 hover:border-cyan-300/30 hover:bg-cyan-300/[0.02]"}`}
    >
      <input
        ref={inputRef}
        type="file"
        accept={accept}
        className="hidden"
        onChange={(event) => {
          chooseFile(event.target.files?.[0]);
          event.currentTarget.value = "";
        }}
      />

      <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-slate-800 bg-slate-900/70">
        <UploadCloud className="h-6 w-6 text-cyan-300" />
      </div>

      <p className="mt-5 text-sm font-medium text-slate-200">{label}</p>
      <p className="mt-2 text-xs text-slate-600">Choose a file or drag it here</p>
    </div>
  );
}
