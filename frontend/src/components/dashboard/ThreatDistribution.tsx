import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";

interface ThreatDistributionItem {
  name: string;
  value: number;
}

interface ThreatDistributionProps {
  data: ThreatDistributionItem[];
  total: number;
}

const COLORS = [
  "#22d3ee",
  "#ef4444",
  "#f59e0b",
  "#14b8a6",
  "#64748b",
];

export function ThreatDistribution({
  data,
  total,
}: ThreatDistributionProps) {
  return (
    <div className="scam-card rounded-2xl p-5">
      <div>
        <h2 className="text-sm font-semibold text-white">
          Threat Distribution
        </h2>
        <p className="mt-1 text-xs text-slate-500">
          Detected threat categories
        </p>
      </div>

      <div className="relative mx-auto mt-3 h-[220px] w-full">
        {data.length > 0 ? (
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                innerRadius={58}
                outerRadius={84}
                paddingAngle={3}
                stroke="transparent"
              >
                {data.map((item, index) => (
                  <Cell
                    key={item.name}
                    fill={COLORS[index % COLORS.length]}
                  />
                ))}
              </Pie>

              <Tooltip
                contentStyle={{
                  background: "#0b1519",
                  border: "1px solid rgba(103,232,249,0.14)",
                  borderRadius: "12px",
                  color: "#fff",
                }}
              />
            </PieChart>
          </ResponsiveContainer>
        ) : (
          <div className="flex h-full items-center justify-center">
            <p className="text-xs text-slate-600">
              No classified scans yet
            </p>
          </div>
        )}

        <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
          <div className="text-center">
            <p className="text-2xl font-semibold text-white">
              {total}
            </p>
            <p className="text-[10px] uppercase tracking-wider text-slate-600">
              Total scans
            </p>
          </div>
        </div>
      </div>

      {data.length > 0 ? (
        <div className="space-y-3">
          {data.map((item, index) => (
            <div
              key={item.name}
              className="flex items-center justify-between"
            >
              <div className="flex items-center gap-2">
                <span
                  className="h-2 w-2 rounded-full"
                  style={{
                    backgroundColor:
                      COLORS[index % COLORS.length],
                  }}
                />

                <span className="text-xs text-slate-400">
                  {item.name}
                </span>
              </div>

              <span className="text-xs font-medium text-slate-200">
                {item.value}%
              </span>
            </div>
          ))}
        </div>
      ) : (
        <div className="rounded-xl border border-slate-800/60 bg-slate-950/20 px-4 py-3">
          <p className="text-xs text-slate-600">
            Threat distribution will appear after your scans are analyzed.
          </p>
        </div>
      )}
    </div>
  );
}