import { Link } from "@tanstack/react-router";
import { Check, ChevronRight, Copy, type LucideIcon, ServerOff, Trash2 } from "lucide-react";
import { type CSSProperties, type PointerEvent, type ReactNode, useEffect, useState } from "react";

import { toastManager } from "@/components/ui/toast";
import { hostLabel, isRealHost, useData } from "./data";
import { evidenceLabel, fields, type Mark } from "./fixture";
import type { HostHistory } from "./live";
import type { TrendRow } from "@/components/console/trend-chart";

export function Glyph({ icon: Icon, className }: { icon: LucideIcon; className?: string }) {
  return <Icon className={className} aria-hidden="true" strokeWidth={2} />;
}

/**
 * W741 (QA-10): a delete button that asks once. The first click arms it and
 * shows "Confirm"; the second runs `onConfirm`. Leaving the button (blur or
 * Escape) disarms it.
 */
export function ConfirmDeleteButton({
  label,
  disabled = false,
  onConfirm,
}: {
  label: string;
  disabled?: boolean;
  onConfirm: () => void;
}) {
  const [armed, setArmed] = useState(false);
  return (
    <button
      type="button"
      className={armed ? "btn danger sm" : "icon-btn"}
      disabled={disabled}
      aria-label={armed ? `Confirm: ${label}` : label}
      onBlur={() => setArmed(false)}
      onKeyDown={(e) => {
        if (e.key === "Escape") setArmed(false);
      }}
      onClick={() => {
        if (!armed) {
          setArmed(true);
          return;
        }
        setArmed(false);
        onConfirm();
      }}
    >
      <Glyph icon={Trash2} />
      {armed ? "Confirm" : null}
    </button>
  );
}

const markClass: Record<Mark, string> = {
  pass: "p",
  fail: "f",
  unknown: "u",
  not_run: "n",
};

export function EvidenceStrip({ marks }: { marks: Mark[] }) {
  return (
    <span className="evstrip" role="img" aria-label={evidenceLabel(marks)}>
      {fields.map((name, index) => {
        const mark = marks[index] ?? "not_run";
        return (
          <b
            key={name}
            className={markClass[mark]}
            title={`${name}: ${mark === "not_run" ? "not run" : mark}`}
          />
        );
      })}
    </span>
  );
}

export function EmptyState({
  icon: Icon,
  title,
  description,
  command,
  action,
}: {
  icon: LucideIcon;
  title: string;
  description: string;
  command?: string;
  action?: ReactNode;
}) {
  return (
    <section className="panel empty-state" role="status">
      <div className="empty-icon" aria-hidden="true">
        <Glyph icon={Icon} />
      </div>
      <h2>{title}</h2>
      <p className="muted">{description}</p>
      {command ? <pre className="code signed-bytes">{command}</pre> : null}
      {action ? (
        <div className="row" style={{ gap: 8 }}>
          {action}
        </div>
      ) : null}
    </section>
  );
}

export function Crumbs({ items }: { items: { href?: string; label: string }[] }) {
  return (
    <nav className="crumbs" aria-label="Breadcrumb">
      {items.map((item, index) => (
        <span key={item.label} className="row" style={{ gap: 6 }}>
          {index > 0 ? <Glyph icon={ChevronRight} /> : null}
          {item.href ? (
            <Link to={item.href}>{item.label}</Link>
          ) : (
            <span aria-current="page">{item.label}</span>
          )}
        </span>
      ))}
    </nav>
  );
}

/**
 * W682: copies `text` and reports the result as a toast. Never rejects: a missing
 * clipboard (plain-HTTP origin) or a denied write shows an error toast instead.
 */
export async function copyText(text: string, title: string): Promise<boolean> {
  try {
    if (!navigator.clipboard) throw new Error("clipboard unavailable");
    await navigator.clipboard.writeText(text);
    toastManager.add({ id: "clipboard-copy", type: "success", title });
    return true;
  } catch {
    toastManager.add({
      id: "clipboard-copy",
      type: "error",
      title: "Copy failed",
      description: "This browser blocked the clipboard. Select the text and copy it manually.",
    });
    return false;
  }
}

/** True for two seconds after `markCopied()`. */
function useCopiedFlag(): [boolean, () => void] {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return undefined;
    const timer = setTimeout(() => setCopied(false), 2000);
    return () => clearTimeout(timer);
  }, [copied]);
  return [copied, () => setCopied(true)];
}

export function CopyButton({
  text,
  label,
  toastTitle = "Command copied",
}: {
  text: string;
  label: string;
  toastTitle?: string;
}) {
  const [copied, markCopied] = useCopiedFlag();
  return (
    <button
      type="button"
      className="btn quiet sm"
      aria-label={label}
      onClick={async () => {
        if (await copyText(text, toastTitle)) markCopied();
      }}
    >
      <Glyph icon={copied ? Check : Copy} className={copied ? "check-pop list-ok" : undefined} />
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

export function CopyId({ id, label }: { id: string; label: string }) {
  const [copied, markCopied] = useCopiedFlag();
  return (
    <span className="copy-id">
      <span translate="no">{id}</span>
      <button
        type="button"
        aria-label={copied ? `${label} copied` : `Copy ${label}`}
        onClick={async () => {
          if (await copyText(id, `${label} copied`)) markCopied();
        }}
      >
        <Glyph icon={copied ? Check : Copy} className={copied ? "check-pop list-ok" : undefined} />
      </button>
    </span>
  );
}

function series(seed: number, count: number, base: number, amp: number, drift = 0) {
  let value = base;
  let state = seed;
  const out: number[] = [];
  for (let index = 0; index < count; index += 1) {
    state = (state * 1664525 + 1013904223) % 4294967296;
    const next = state / 4294967296;
    value += (next - 0.5) * amp + (base - value) * 0.15 + drift;
    out.push(Math.max(1, Math.min(99, value)));
  }
  return out;
}

/** Horizontally scrolling table wrapper that keyboard users can focus and scroll. */
export function TableScroll({
  label,
  style,
  children,
}: {
  label: string;
  style?: CSSProperties;
  children: ReactNode;
}) {
  return (
    <div
      className="table-scroll"
      role="region"
      aria-label={label}
      // oxlint-disable-next-line jsx-a11y/no-noninteractive-tabindex -- scroll regions must be keyboard reachable
      tabIndex={0}
      style={style}
    >
      {children}
    </div>
  );
}

/** Decorative trend line; the value it belongs to is always shown as text beside it. */
export function Sparkline({
  seed,
  base,
  color,
}: {
  seed: number;
  base: number;
  color: "cpu" | "memory" | "disk";
}) {
  const width = 120;
  const height = 36;
  const data = series(seed, 40, base, 8);
  const path = data
    .map(
      (value, index) =>
        `${index ? "L" : "M"}${((index * width) / 39).toFixed(1)} ${(height - (value / 100) * height).toFixed(1)}`,
    )
    .join("");
  return (
    <svg
      className="spark"
      viewBox={`0 0 ${width} ${height}`}
      width={width}
      height={height}
      aria-hidden="true"
    >
      <path d={path} fill="none" stroke={`var(--${color})`} strokeWidth="1.6" />
    </svg>
  );
}

const utcClock = new Intl.DateTimeFormat("en-GB", {
  timeZone: "UTC",
  hour: "2-digit",
  minute: "2-digit",
  hourCycle: "h23",
});

function clockLabel(unix: number) {
  return utcClock.format(new Date(unix * 1000));
}

type PlotLine = {
  key: "cpu" | "mem" | "disk";
  name: string;
  color: string;
  dash: string;
  points: [number, number | null][];
};

type PlotData = {
  labels: string[];
  lines: PlotLine[];
  gap: { from: number; to: number } | null;
  timeAt: (unit: number) => string;
};

type HoverReadout = {
  unit: number;
  label: string;
  isGap: boolean;
  values: { key: PlotLine["key"]; name: string; color: string; value: number }[];
};

function fixturePlot(only?: "cpu" | "mem" | "disk"): PlotData {
  const count = 96;
  const xs = Array.from({ length: count }, (_, index) => index / (count - 1));
  const labels = ["16:45", "19:45", "22:45", "01:45", "04:45", "07:45", "10:45", "13:45", "16:45"];
  const gap = { from: 61 / (count - 1), to: 66 / (count - 1) };
  const inGap = (i: number) => i >= 61 && i <= 66;
  return {
    labels,
    gap,
    timeAt: (unit) => labels[Math.round(unit * (labels.length - 1))] ?? "",
    lines: (
      [
        {
          key: "cpu",
          name: "CPU",
          color: "var(--cpu)",
          dash: "",
          points: series(7, count, 24, 14).map((value, i): [number, number | null] => [
            xs[i] ?? 0,
            inGap(i) ? null : value,
          ]),
        },
        {
          key: "mem",
          name: "Memory",
          color: "var(--memory)",
          dash: "7 5",
          points: series(19, count, 56, 4).map((value, i): [number, number | null] => [
            xs[i] ?? 0,
            inGap(i) ? null : value,
          ]),
        },
        {
          key: "disk",
          name: "Disk /var",
          color: "var(--disk)",
          dash: "2 4",
          points: series(31, count, 70, 0.6, 0.02).map((value, i): [number, number | null] => [
            xs[i] ?? 0,
            inGap(i) ? null : value,
          ]),
        },
      ] as PlotLine[]
    ).filter((item) => !only || item.key === only),
  };
}

function livePlot(history: HostHistory, only?: "cpu" | "mem" | "disk"): PlotData {
  const span = Math.max(1, history.to - history.from);
  const ticks = 5;
  const labels = Array.from({ length: ticks }, (_, index) =>
    clockLabel(history.from + Math.round((index / (ticks - 1)) * span)),
  );
  const deltas = history.samples
    .slice(1)
    .map((sample, index) => sample.t - (history.samples[index]?.t ?? sample.t))
    .sort((left, right) => left - right);
  const typical = deltas[Math.floor(deltas.length / 2)] ?? 15;
  const gapAfter = Math.max(45, typical * 3);
  const seriesOf = (key: "cpu" | "mem" | "disk"): [number, number | null][] => {
    const points: [number, number | null][] = [];
    for (const [index, sample] of history.samples.entries()) {
      const unit = (sample.t - history.from) / span;
      const previous = history.samples[index - 1];
      if (previous !== undefined && sample.t - previous.t > gapAfter) {
        points.push([unit, null]);
      }
      points.push([unit, sample[key]]);
    }
    return points;
  };
  return {
    labels,
    gap: null,
    timeAt: (unit) => clockLabel(history.from + Math.round(unit * span)),
    lines: (
      [
        { key: "cpu", name: "CPU", color: "var(--cpu)", dash: "", points: seriesOf("cpu") },
        {
          key: "mem",
          name: "Memory",
          color: "var(--memory)",
          dash: "7 5",
          points: seriesOf("mem"),
        },
        {
          key: "disk",
          name: "Disk /var",
          color: "var(--disk)",
          dash: "2 4",
          points: seriesOf("disk"),
        },
      ] as PlotLine[]
    ).filter((item) => !only || item.key === only),
  };
}

function nearestPoint(
  points: [number, number | null][],
  target: number,
): [number, number | null] | null {
  let best: [number, number | null] | null = null;
  let bestDist = Infinity;
  for (const pt of points) {
    const dist = Math.abs(pt[0] - target);
    if (dist < bestDist) {
      bestDist = dist;
      best = pt;
    }
  }
  return best;
}

function hoverValues(lines: PlotLine[], unit: number): HoverReadout["values"] {
  const out: HoverReadout["values"] = [];
  for (const line of lines) {
    const pt = nearestPoint(line.points, unit);
    if (pt?.[1] !== null && pt?.[1] !== undefined) {
      out.push({ key: line.key, name: line.name, color: line.color, value: pt[1] });
    }
  }
  return out;
}

function resolveHover(plot: PlotData, targetUnit: number): HoverReadout | null {
  const firstLine = plot.lines[0];
  const anchor = firstLine ? nearestPoint(firstLine.points, targetUnit) : null;
  if (!anchor) return null;
  const [unit, anchorValue] = anchor;
  const inGapBand = plot.gap !== null && unit >= plot.gap.from && unit <= plot.gap.to;
  const isGap = inGapBand || anchorValue === null;
  return {
    unit,
    label: plot.timeAt(unit),
    isGap,
    values: isGap ? [] : hoverValues(plot.lines, unit),
  };
}

function ChartReadoutBar({ readout }: { readout: HoverReadout | null }) {
  if (!readout) {
    return (
      <div className="chart-readout" aria-live="polite">
        <span className="muted">Hover across the series to inspect sample values</span>
      </div>
    );
  }
  return (
    <div className="chart-readout" aria-live="polite">
      <span className="chart-readout-pill">
        <span className="mono">{readout.label}</span>
        {readout.isGap ? (
          <span className="muted">· No samples collected in this window</span>
        ) : (
          readout.values.map((entry) => (
            <span key={entry.key} className="chart-readout-item">
              <span className="chart-dot" aria-hidden="true" style={{ background: entry.color }} />
              <span className="muted">{entry.name}</span>
              <strong>{entry.value.toFixed(0)}%</strong>
            </span>
          ))
        )}
      </span>
    </div>
  );
}

function splitSegments(
  points: [number, number | null][],
  x: (unit: number) => number,
  y: (value: number) => number,
): [number, number][][] {
  const segments: [number, number][][] = [[]];
  for (const [unit, value] of points) {
    const current = segments[segments.length - 1];
    if (!current) break;
    if (value === null) {
      if (current.length) segments.push([]);
      continue;
    }
    current.push([x(unit), y(value)]);
  }
  return segments.filter((segment) => segment.length >= 2);
}

function ChartSeries({
  line,
  x,
  y,
}: {
  line: PlotLine;
  x: (unit: number) => number;
  y: (value: number) => number;
}) {
  const baseline = y(0);
  return splitSegments(line.points, x, y).map((segment, segmentIndex) => {
    const path = segment
      .map((point, index) => `${index ? "L" : "M"}${point[0].toFixed(1)} ${point[1].toFixed(1)}`)
      .join("");
    const first = segment[0];
    const last = segment[segment.length - 1];
    if (!first || !last) return null;
    const area = `${path}L${last[0].toFixed(1)} ${baseline}L${first[0].toFixed(1)} ${baseline}Z`;
    return (
      <g key={`${line.key}-${segmentIndex}`}>
        <path d={area} fill={line.color} opacity={0.07} className="motion-area-fade" />
        <path
          d={path}
          fill="none"
          stroke={line.color}
          strokeWidth={2}
          strokeDasharray={line.dash}
          strokeLinejoin="round"
          strokeLinecap="round"
        />
      </g>
    );
  });
}

/** W787: the same fixture or live plot as rows for the Recharts trend chart. */
export function trendRows(history: HostHistory | null): TrendRow[] {
  const plot = history ? livePlot(history) : fixturePlot();
  const [cpu, mem, disk] = plot.lines;
  return (cpu?.points ?? []).map(([unit, value], index) => ({
    label: plot.timeAt(unit),
    cpu: value,
    memory: mem?.points[index]?.[1] ?? null,
    disk: disk?.points[index]?.[1] ?? null,
  }));
}

export function ResourceChart({
  label,
  height = 240,
  only,
  history,
  live = false,
}: {
  label: string;
  height?: number;
  only?: "cpu" | "mem" | "disk";
  history?: HostHistory | null;
  live?: boolean;
}) {
  const [hoverUnit, setHoverUnit] = useState<number | null>(null);
  if (live && !history) {
    return (
      <div className="empty-state compact" role="status">
        <p className="t">Waiting for host metric samples</p>
        <p className="muted">
          No synthetic chart is drawn in live mode. Graphs appear automatically once at least two
          samples are collected by <span className="mono">rustiron-control --record-samples</span>.
        </p>
      </div>
    );
  }
  const width = 1000;
  const left = 40;
  const right = 8;
  const top = 8;
  const bottom = 26;
  const plotWidth = width - left - right;
  const plotHeight = height - top - bottom;
  const plot = history ? livePlot(history, only) : fixturePlot(only);
  const x = (unit: number) => left + unit * plotWidth;
  const y = (value: number) => top + plotHeight - (value / 100) * plotHeight;
  const readout = hoverUnit !== null ? resolveHover(plot, hoverUnit) : null;

  const onPointerMove = (event: PointerEvent<SVGSVGElement>) => {
    const rect = event.currentTarget.getBoundingClientRect();
    if (!rect.width) return;
    const svgX = ((event.clientX - rect.left) / rect.width) * width;
    setHoverUnit(Math.max(0, Math.min(1, (svgX - left) / plotWidth)));
  };

  return (
    <div>
      <ChartReadoutBar readout={readout} />
      <div
        className="chart"
        // oxlint-disable-next-line jsx-a11y/no-noninteractive-tabindex -- the chart scrolls sideways on phones
        tabIndex={0}
        role="group"
        aria-label={`${label}. Scrolls sideways on narrow screens.`}
      >
        <svg
          viewBox={`0 0 ${width} ${height}`}
          role="img"
          aria-label={label}
          onPointerMove={onPointerMove}
          onPointerLeave={() => setHoverUnit(null)}
        >
          {[0, 25, 50, 75, 100].map((tick) => (
            <g key={tick}>
              <line className="gridline" x1={left} x2={width - right} y1={y(tick)} y2={y(tick)} />
              <text className="axis" x={left - 8} y={y(tick) + 4} textAnchor="end">
                {tick}%
              </text>
            </g>
          ))}
          {plot.labels.map((text, index) => (
            <text
              key={`${text}-${index}`}
              className="axis"
              x={left + (index / (plot.labels.length - 1)) * plotWidth}
              y={height - 6}
              textAnchor={
                index === 0 ? "start" : index === plot.labels.length - 1 ? "end" : "middle"
              }
            >
              {text}
            </text>
          ))}
          {plot.gap ? (
            <>
              <rect
                className="gap-band"
                x={x(plot.gap.from)}
                y={top}
                width={x(plot.gap.to) - x(plot.gap.from)}
                height={plotHeight}
              />
              <text
                className="gap-label"
                x={(x(plot.gap.from) + x(plot.gap.to)) / 2}
                y={top + 14}
                textAnchor="middle"
              >
                No samples
              </text>
            </>
          ) : null}
          {plot.lines.map((line) => (
            <ChartSeries key={line.key} line={line} x={x} y={y} />
          ))}
          {readout ? (
            <g aria-hidden="true">
              <line
                x1={x(readout.unit)}
                x2={x(readout.unit)}
                y1={top}
                y2={top + plotHeight}
                stroke="var(--border-strong)"
                strokeWidth={1}
                strokeDasharray="2 2"
              />
              {readout.values.map((entry) => (
                <circle
                  key={entry.key}
                  cx={x(readout.unit)}
                  cy={y(entry.value)}
                  r={3.5}
                  fill={entry.color}
                  stroke="var(--surface)"
                  strokeWidth={1.5}
                />
              ))}
            </g>
          ) : null}
        </svg>
      </div>
    </div>
  );
}

/** `live` pages read the data source; others are mockup samples and say so
 * whenever the Console runs on a real host (live, loading, or unavailable), so
 * sample rows are never taken as the host (W732, QA-01). */
export function Page({ children, live = false }: { children: ReactNode; live?: boolean }) {
  const { source } = useData();
  return (
    <div className="page motion-stage">
      {!live && isRealHost(source) ? (
        <div className="preview-banner" role="note">
          <span>
            <strong>Sample screen.</strong> This page still shows mockup data, not{" "}
            {hostLabel(source)}.
          </span>
        </div>
      ) : null}
      {live && source.kind === "unavailable" && source.notEnrolled ? <NotEnrolled /> : null}
      {live && source.kind === "unavailable" && !source.notEnrolled ? (
        <div className="attention err" role="alert">
          <span className="att-body">
            <strong>Live data unavailable.</strong> {source.reason}. Nothing is shown rather than
            old or sample data.
          </span>
        </div>
      ) : null}
      {children}
    </div>
  );
}

/** W347: an installed executor without an enrolled policy has no journal, which is not a fault. */
function NotEnrolled() {
  return (
    <section className="panel not-enrolled" role="status" aria-label="Executor not enrolled">
      <div className="empty-sample">
        <Glyph icon={ServerOff} />
        <p className="t">Executor not enrolled</p>
        <p className="muted">
          The executor answered <code translate="no">EXECUTOR_NOT_ENROLLED</code>: it is installed,
          but this host has no enrolled policy, so there is no journal to show. Nothing is shown
          rather than old or sample data.
        </p>
        <p className="muted">
          Enroll the host with the operator kit&rsquo;s product enrollment, then this page reads the
          journal. The answer does not prove why the policy is absent: a deleted policy gives the
          same code.
        </p>
      </div>
    </section>
  );
}
