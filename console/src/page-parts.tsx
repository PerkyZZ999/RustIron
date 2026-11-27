// W714 (pass 33, fix 7): Parts that more than one page area uses. Split from `pages.tsx`.
import { Link } from "@tanstack/react-router";
import { CircleCheck, CircleDashed, CircleMinus, CircleX } from "lucide-react";
import { isRealHost, useData } from "./data";
import { type RecoveryState } from "./fixture";
import { Glyph, Page } from "./ui";

/** How old the shown data is, in words. */
/** How long ago an observation was taken, for status lines. */
export function ageText(observedAt: number): string {
  const seconds = Math.max(0, Math.round((Date.now() - observedAt) / 1000));
  if (seconds < 60) return `${seconds} s ago`;
  const minutes = Math.round(seconds / 60);
  return minutes < 60 ? `${minutes} min ago` : `${Math.round(minutes / 60)} h ago`;
}

/** "16:57 UTC · 40 s ago" for an observation time (W737, QA-06). */
export function observedText(observedAt: number): string {
  const time = new Date(observedAt).toISOString().slice(11, 16);
  return `${time} UTC · ${ageText(observedAt)}`;
}

export function SourceNote() {
  const { source } = useData();
  if (source.kind === "live") {
    return (
      <>
        {source.stale ? "stale observation" : "live observation"} of {source.host.host_id}
      </>
    );
  }
  if (source.kind === "unavailable") return <>live data unavailable</>;
  return <>fixture data</>;
}

const recoveryStateIcon = {
  ok: CircleCheck,
  err: CircleX,
  notrun: CircleMinus,
  unknown: CircleDashed,
} as const;

export function RecoveryStateLabel({ state }: { state: RecoveryState }) {
  return (
    <span className={`state ${state.kind}`}>
      <Glyph icon={recoveryStateIcon[state.kind]} />
      {state.label}
    </span>
  );
}

export function EvidenceKey() {
  const keys = [
    ["p", "Pass"],
    ["f", "Fail"],
    ["u", "Unknown"],
    ["n", "Not run"],
  ] as const;
  return (
    <div className="row cap evidence-key">
      {keys.map(([mark, label]) => (
        <span key={mark} className="row">
          <span className="evstrip" aria-hidden="true">
            <b className={mark} />
          </span>
          {label}
        </span>
      ))}
      <span>
        Order: artifacts · integrity · decryption · app consistency · isolated restore · health
        checks · independent copy
      </span>
    </div>
  );
}

export function Missing({
  name,
  back = "/sites",
}: {
  name: string;
  back?: "/sites" | "/operations" | "/recovery";
}) {
  const { source } = useData();
  const live = isRealHost(source);
  const backLabel =
    back === "/operations"
      ? "Back to operations"
      : back === "/recovery"
        ? "Back to recovery"
        : "Back to sites";
  return (
    <Page live={live}>
      <h1>Not in this {live ? "observation" : "fixture"}</h1>
      <p className="sub">
        No record named {name} is in the {live ? "current observation" : "fixture set"}.
      </p>
      <Link to={back}>{backLabel}</Link>
    </Page>
  );
}

export function matchesOutcome(outcome: string, filter: string) {
  if (filter === "All outcomes") return true;
  if (filter === "Running") return outcome.startsWith("Running");
  if (filter === "Failed") return outcome.startsWith("Failed ·");
  return outcome === filter;
}
