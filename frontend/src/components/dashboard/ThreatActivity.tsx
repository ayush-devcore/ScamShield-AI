import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

interface ThreatActivityPoint {
  day: string;
  scans: number;
}

interface ThreatActivityProps {
  data: ThreatActivityPoint[];
}

export function ThreatActivity({ data }: ThreatActivityProps) {
  return (
    <div className="scam-card rounded-2xl p-5">
      <div className="mb-6 flex items-start justify-between">
        <div>
          <h2 className="text-sm font-semibold text-white">
            Threat Activity
          </h2>
          <p className="mt-1 text-xs text-slate-500">
            Scan volume over the last 7 days
          </p>
        </div>

        <button className="rounded-lg border border-slate-800 bg-slate-900 px-3 py-1.5 text-[11px] text-slate-400 transition hover:border-cyan-400/15 hover:text-white">
          Last 7 days
        </button>
      </div>

      <div className="h-[260px] w-full">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart
            data={data}
            margin={{ top: 10, right: 5, left: -20, bottom: 0 }}
          >
            <defs>
              <linearGradient id="scanFill" x1="0" y1="0" x2="0" y2="1">
                <stop
                  offset="0%"
                  stopColor="#22d3ee"
                  stopOpacity={0.22}
                />
                <stop
                  offset="100%"
                  stopColor="#0891b2"
                  stopOpacity={0}
                />
              </linearGradient>
            </defs>

            <CartesianGrid
              stroke="rgba(148,163,184,0.08)"
              vertical={false}
            />

            <XAxis
              dataKey="day"
              axisLine={false}
              tickLine={false}
              tick={{ fill: "#64748b", fontSize: 11 }}
            />

            <YAxis
              axisLine={false}
              tickLine={false}
              tick={{ fill: "#64748b", fontSize: 10 }}
            />

            <Tooltip
              contentStyle={{
                background: "#0b1519",
                border: "1px solid rgba(103,232,249,0.14)",
                borderRadius: "12px",
                color: "#fff",
              }}
              labelStyle={{
                color: "#94a3b8",
                marginBottom: "4px",
              }}
            />

            <Area
              type="monotone"
              dataKey="scans"
              stroke="#22d3ee"
              strokeWidth={2}
              fill="url(#scanFill)"
              activeDot={{
                r: 5,
                fill: "#22d3ee",
                stroke: "#05090c",
                strokeWidth: 3,
              }}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}