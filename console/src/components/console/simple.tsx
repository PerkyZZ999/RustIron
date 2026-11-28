/**
 * v0.3 simple-page parts (roadmap item 57, docs/CONSOLE-SIMPLIFICATION.md):
 * the answer line, health tiles that open the details drawer, a quiet
 * disclosure for technical facts, and a short attention list.
 */
import { Link } from "@tanstack/react-router";
import {
  ChevronDown,
  CircleCheck,
  CircleHelp,
  CircleX,
  TriangleAlert,
  type LucideIcon,
} from "lucide-react";
import type { ReactNode } from "react";

import { AnimatedIcon } from "@/components/console/motion-kit";
import { Collapsible, CollapsiblePanel, CollapsibleTrigger } from "@/components/ui/collapsible";
import { cn } from "@/lib/utils";

export type Tone = "ok" | "warn" | "err" | "unknown";

const toneText: Record<Tone, string> = {
  ok: "text-success",
  warn: "text-warning",
  err: "text-destructive",
  unknown: "text-muted-foreground",
};

const toneIcon: Record<Exclude<Tone, "ok">, LucideIcon> = {
  warn: TriangleAlert,
  err: CircleX,
  unknown: CircleHelp,
};

/** The page's one-sentence answer, under the title. */
export function AnswerLine({ tone, children }: { tone: Tone; children: ReactNode }) {
  // Static Lucide icons: every page shows this line, and `lucide-animated`
  // would put about 120 KB gzip on the first load (W792).
  const Icon = tone === "ok" ? CircleCheck : toneIcon[tone];
  return (
    <div className="flex items-center gap-2 text-[15px] leading-6 text-foreground">
      <Icon
        aria-hidden="true"
        className={cn("size-4.5 shrink-0", tone === "ok" && "motion-hero", toneText[tone])}
        strokeWidth={2}
      />
      <p>{children}</p>
    </div>
  );
}

/** A simple page header: title, answer line, and one primary action. */
export function SimpleHeader({
  title,
  answer,
  action,
}: {
  title: string;
  answer: ReactNode;
  action?: ReactNode;
}) {
  return (
    <header className="flex flex-wrap items-end justify-between gap-4">
      <div className="flex min-w-0 flex-col gap-2">
        <h1 className="text-[30px] font-semibold leading-9 tracking-[-0.02em] text-foreground">
          {title}
        </h1>
        {answer}
      </div>
      {action ? <div className="flex shrink-0 items-center gap-2">{action}</div> : null}
    </header>
  );
}

/**
 * A health tile: one big value, a word, and a meter or line. The whole tile
 * links to its details; its icon plays on hover.
 */
export function HealthTile({
  label,
  icon,
  value,
  word,
  wordTone = "ok",
  children,
  to,
  hash,
}: {
  label: string;
  icon: Parameters<typeof AnimatedIcon>[0]["icon"];
  value: ReactNode;
  word: string;
  wordTone?: Tone;
  children?: ReactNode;
  to: string;
  hash?: string;
}) {
  return (
    <Link
      to={to}
      hash={hash}
      data-anim-group
      className="group flex w-full flex-col gap-3 rounded-panel border border-border bg-surface p-5 text-start no-underline matte-surface transition-[border-color,transform,box-shadow] duration-200 hover:-translate-y-0.5 hover:border-border-strong/70 hover:shadow-[0_8px_24px_-12px_rgba(0,0,0,0.5)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus motion-reduce:transition-none motion-reduce:hover:translate-y-0"
    >
      <span className="flex items-center justify-between gap-2 text-sm font-medium text-muted-foreground">
        <span className="flex items-center gap-2">
          <AnimatedIcon
            icon={icon}
            size={18}
            className="text-muted-foreground group-hover:text-foreground"
          />
          {label}
        </span>
        <span className={cn("text-xs font-medium", toneText[wordTone])}>{word}</span>
      </span>
      <span className="text-[30px] font-semibold leading-9 tracking-[-0.02em] text-foreground">
        {value}
      </span>
      {children}
    </Link>
  );
}

/**
 * Technical facts, one click away. Closed by default; the summary line says
 * what is inside so nobody has to open it to know it is there.
 */
export function QuietDetails({
  title = "Technical details",
  summary,
  children,
  defaultOpen = false,
}: {
  title?: string;
  summary?: string;
  children: ReactNode;
  defaultOpen?: boolean;
}) {
  return (
    <Collapsible
      defaultOpen={defaultOpen}
      className="rounded-panel border border-border bg-surface/60"
    >
      <CollapsibleTrigger
        data-anim-group
        className="group flex w-full cursor-pointer items-center justify-between gap-3 px-5 py-3.5 text-start focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus"
      >
        <span className="flex min-w-0 flex-col">
          <span className="text-sm font-medium text-foreground">{title}</span>
          {summary ? (
            <span className="truncate text-xs text-muted-foreground">{summary}</span>
          ) : null}
        </span>
        <span className="transition-transform duration-200 group-data-panel-open:rotate-180 motion-reduce:transition-none">
          <ChevronDown aria-hidden="true" className="size-4.5 text-muted-foreground" />
        </span>
      </CollapsibleTrigger>
      <CollapsiblePanel className="ease-[cubic-bezier(0.16,1,0.3,1)] motion-reduce:transition-none">
        <div className="border-t border-border/80 px-5 py-4">{children}</div>
      </CollapsiblePanel>
    </Collapsible>
  );
}
