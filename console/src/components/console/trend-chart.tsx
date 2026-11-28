/**
 * v0.3 resource chart on Recharts (roadmap items 56 and 58): soft gradient
 * areas that draw in from the left, a pointer tooltip, and gaps (never zeros)
 * for missing samples. Under reduced motion it renders without drawing.
 */
import { useId } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  type TooltipContentProps,
  XAxis,
  YAxis,
} from "recharts";

import { useCalmMotion } from "@/components/console/motion-kit";

const SERIES = [
  { key: "cpu", label: "CPU", color: "var(--cpu)" },
  { key: "memory", label: "Memory", color: "var(--memory)" },
  { key: "disk", label: "Disk", color: "var(--disk)" },
] as const;

export type TrendRow = {
  label: string;
  cpu: number | null;
  memory: number | null;
  disk: number | null;
};

function ChartTooltip({ active, payload, label }: Partial<TooltipContentProps<number, string>>) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg border border-border bg-popover/95 px-3 py-2 text-xs shadow-lg backdrop-blur">
      <p className="mb-1 font-medium text-foreground">{label}</p>
      {payload.map((entry) => (
        <p key={String(entry.dataKey)} className="flex items-center gap-2 text-muted-foreground">
          <span
            className="size-2 rounded-full"
            style={{ background: entry.color }}
            aria-hidden="true"
          />
          {entry.name}
          <span className="ms-auto ps-3 font-medium text-foreground tabular-nums">
            {entry.value === null || entry.value === undefined ? "No sample" : `${entry.value}%`}
          </span>
        </p>
      ))}
    </div>
  );
}

export function TrendChart({
  rows,
  label,
  height = 220,
}: {
  rows: TrendRow[];
  label: string;
  height?: number;
}) {
  const id = useId().replace(/:/g, "");
  const calm = useCalmMotion();
  return (
    <div role="img" aria-label={label}>
      <ResponsiveContainer width="100%" height={height}>
        <AreaChart data={rows} margin={{ top: 8, right: 8, bottom: 0, left: -16 }}>
          <defs>
            {SERIES.map((s) => (
              <linearGradient key={s.key} id={`${id}-${s.key}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={s.color} stopOpacity={0.28} />
                <stop offset="100%" stopColor={s.color} stopOpacity={0} />
              </linearGradient>
            ))}
          </defs>
          <CartesianGrid vertical={false} stroke="var(--border)" strokeDasharray="3 6" />
          <XAxis
            dataKey="label"
            tickLine={false}
            axisLine={false}
            minTickGap={48}
            tick={{ fill: "var(--muted-foreground)", fontSize: 11 }}
          />
          <YAxis
            domain={[0, 100]}
            ticks={[0, 50, 100]}
            tickFormatter={(v: number) => `${v}%`}
            tickLine={false}
            axisLine={false}
            tick={{ fill: "var(--muted-foreground)", fontSize: 11 }}
          />
          <Tooltip content={<ChartTooltip />} cursor={{ stroke: "var(--border-strong)" }} />
          {SERIES.map((s, index) => (
            <Area
              key={s.key}
              type="monotone"
              dataKey={s.key}
              name={s.label}
              stroke={s.color}
              strokeWidth={2}
              fill={`url(#${id}-${s.key})`}
              connectNulls={false}
              dot={false}
              activeDot={{ r: 3.5, strokeWidth: 0 }}
              isAnimationActive={!calm}
              animationDuration={900}
              animationBegin={index * 120}
              animationEasing="ease-out"
            />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

export function TrendLegend() {
  return (
    <ul className="flex flex-wrap gap-4 text-xs text-muted-foreground" aria-label="Chart legend">
      {SERIES.map((s) => (
        <li key={s.key} className="flex items-center gap-1.5">
          <span
            className="size-2 rounded-full"
            style={{ background: s.color }}
            aria-hidden="true"
          />
          {s.label}
        </li>
      ))}
    </ul>
  );
}
