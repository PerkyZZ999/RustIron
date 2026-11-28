/**
 * v0.3 motion kit (roadmap item 56, docs/CONSOLE-SIMPLIFICATION.md#motion).
 *
 * Every motion explains arrival, change, or feedback. It all stops when the
 * operating system asks for reduced motion or the Console preference
 * `data-motion="reduce"` is set on <html>.
 */
import NumberFlow, { type Format } from "@number-flow/react";
import {
  type ComponentType,
  type RefAttributes,
  useEffect,
  useRef,
  useState,
  useSyncExternalStore,
} from "react";

import { Meter, MeterIndicator, MeterTrack } from "@/components/ui/meter";
import { cn } from "@/lib/utils";

function subscribeMotionPreference(onChange: () => void): () => void {
  const observer = new MutationObserver(onChange);
  observer.observe(document.documentElement, {
    attributes: true,
    attributeFilter: ["data-motion"],
  });
  return () => observer.disconnect();
}

function subscribeSystemMotion(onChange: () => void): () => void {
  const query = window.matchMedia("(prefers-reduced-motion: reduce)");
  query.addEventListener("change", onChange);
  return () => query.removeEventListener("change", onChange);
}

/**
 * True when either the system or the Console asks for reduced motion. Plain
 * `matchMedia`, so shared page parts do not pull `motion` into the first load.
 */
export function useCalmMotion(): boolean {
  const system = useSyncExternalStore(
    subscribeSystemMotion,
    () => window.matchMedia("(prefers-reduced-motion: reduce)").matches,
    () => false,
  );
  const preferCalm = useSyncExternalStore(
    subscribeMotionPreference,
    () => document.documentElement.dataset.motion === "reduce",
    () => false,
  );
  return system || preferCalm;
}

/** A number that counts to its value on arrival and on every change. */
export function AnimatedNumber({
  value,
  format,
  suffix,
  className,
}: {
  value: number;
  format?: Format;
  suffix?: string;
  className?: string;
}) {
  const calm = useCalmMotion();
  const [shown, setShown] = useState(calm ? value : 0);
  useEffect(() => {
    const frame = requestAnimationFrame(() => setShown(value));
    return () => cancelAnimationFrame(frame);
  }, [value]);
  // The animated digits live in a shadow root that screen readers may skip.
  const text = `${new Intl.NumberFormat("en-US", format).format(value)}${suffix ?? ""}`;
  return (
    <>
      <span aria-hidden="true">
        <NumberFlow
          value={shown}
          format={format}
          suffix={suffix}
          animated={!calm}
          className={cn("tabular-nums", className)}
        />
      </span>
      <span className="sr-only">{text}</span>
    </>
  );
}

export type MeterTone = "ok" | "warn" | "err" | "info";

const toneClass: Record<MeterTone, string> = {
  ok: "bg-success",
  warn: "bg-warning",
  err: "bg-destructive",
  info: "bg-primary",
};

/** The tone of a usage meter: calm below 70 %, warning to 90 %, then error. */
export function usageTone(percent: number): Exclude<MeterTone, "info"> {
  if (percent >= 90) return "err";
  if (percent >= 70) return "warn";
  return "ok";
}

/**
 * A Coss `Meter` that fills from zero on arrival and glides to new values
 * (the indicator's width transition does the motion).
 */
export function FillMeter({
  value,
  label,
  tone = usageTone(value),
  className,
}: {
  value: number;
  label: string;
  tone?: MeterTone;
  className?: string;
}) {
  const calm = useCalmMotion();
  const [shown, setShown] = useState(calm ? value : 0);
  useEffect(() => {
    const frame = requestAnimationFrame(() => setShown(value));
    return () => cancelAnimationFrame(frame);
  }, [value]);
  return (
    <Meter value={shown} aria-label={label} className={className}>
      <MeterTrack className="h-1.5 rounded-full">
        <MeterIndicator
          className={cn(
            "rounded-full duration-700 ease-[cubic-bezier(0.16,1,0.3,1)] motion-reduce:transition-none",
            toneClass[tone],
          )}
        />
      </MeterTrack>
    </Meter>
  );
}

/** The handle every `lucide-animated` icon exposes. */
interface AnimatedIconHandle {
  startAnimation: () => void;
  stopAnimation: () => void;
}

type AnimatedIconComponent = ComponentType<
  {
    size?: number;
    animateOnHover?: boolean;
    className?: string;
  } & RefAttributes<AnimatedIconHandle>
>;

/**
 * A `lucide-animated` icon that plays on hover of its own row or card (the
 * nearest `group/anim` ancestor) and whenever `playKey` changes, for example
 * after a refresh or a state change. Decorative: hidden from assistive tech.
 */
export function AnimatedIcon({
  icon: Icon,
  size = 18,
  playKey,
  className,
}: {
  icon: AnimatedIconComponent;
  size?: number;
  playKey?: unknown;
  className?: string;
}) {
  const ref = useRef<AnimatedIconHandle>(null);
  const host = useRef<HTMLSpanElement>(null);
  const calm = useCalmMotion();
  useEffect(() => {
    if (calm || playKey === undefined) return;
    ref.current?.startAnimation();
  }, [playKey, calm]);
  useEffect(() => {
    const group = host.current?.closest("[data-anim-group]");
    if (!group || calm) return;
    const start = () => ref.current?.startAnimation();
    const stop = () => ref.current?.stopAnimation();
    group.addEventListener("pointerenter", start);
    group.addEventListener("pointerleave", stop);
    group.addEventListener("focusin", start);
    group.addEventListener("focusout", stop);
    return () => {
      group.removeEventListener("pointerenter", start);
      group.removeEventListener("pointerleave", stop);
      group.removeEventListener("focusin", start);
      group.removeEventListener("focusout", stop);
    };
  }, [calm]);
  return (
    <span ref={host} aria-hidden="true" className={cn("inline-flex shrink-0", className)}>
      <Icon ref={ref} size={size} animateOnHover={false} />
    </span>
  );
}
