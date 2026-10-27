interface RiskGaugeProps {
  score: number;
  label?: string;
}

export function RiskGauge({ score, label }: RiskGaugeProps) {
  const circumference = 2 * Math.PI * 48;
  const progress = circumference * (1 - Math.min(Math.max(score, 0), 100) / 100);
  const unverified = label === "UNVERIFIED";

  return (
    <div className="relative mx-auto flex h-52 w-52 items-center justify-center">
      <svg
        viewBox="0 0 120 120"
        className="h-52 w-52 -rotate-90"
        aria-label={unverified ? "Risk score unverified" : `Risk score ${score} out of 100`}
      >
        <circle
          cx="60"
          cy="60"
          r="48"
          fill="none"
          stroke="rgba(148,163,184,0.10)"
          strokeWidth="10"
        />

        <circle
          cx="60"
          cy="60"
          r="48"
          fill="none"
          stroke={unverified ? "#fbbf24" : score >= 80 ? "#ef4444" : score >= 60 ? "#f97316" : score >= 30 ? "#f59e0b" : "#22c55e"}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={progress}
          className="transition-all duration-700"
        />
      </svg>

      <div className="absolute text-center">
        <p className="text-4xl font-semibold tracking-tight text-white">{unverified ? "?" : score}</p>
        <p className="text-[10px] uppercase tracking-[0.18em] text-slate-600">{unverified ? "not verified" : "/ 100"}</p>
        {label && <p className="mt-2 text-xs font-semibold text-red-300">{label}</p>}
      </div>
    </div>
  );
}
