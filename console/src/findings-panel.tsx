// W714 (pass 33, fix 7): the findings chip, the owner badge, and the Host
// Overview's open-findings panel. The Overview loads this, not the platform pages.
import { Link } from "@tanstack/react-router";
import { CircleAlert, CircleCheck, CircleHelp, CircleX } from "lucide-react";

import { isRealHost, useData } from "./data";
import { type DiagnosisFinding, fixtureFindings, liveFindings } from "./platform-data";
import { Glyph } from "./ui";

export function FindingChip({ state }: { state: DiagnosisFinding["state"] }) {
  const icon =
    state === "fail"
      ? CircleX
      : state === "warn"
        ? CircleAlert
        : state === "ok"
          ? CircleCheck
          : CircleHelp;
  const cls =
    state === "fail"
      ? "pill err"
      : state === "warn"
        ? "pill warn"
        : state === "ok"
          ? "pill ok"
          : "pill";
  return (
    <span className={cls}>
      <Glyph icon={icon} />
      {state}
    </span>
  );
}

export function OwnerBadge({
  owner,
  prefix = "",
}: {
  owner: "rustiron" | "host";
  prefix?: string;
}) {
  return (
    <span className={owner === "host" ? "owner-badge host" : "owner-badge"}>
      {prefix}
      {owner}
    </span>
  );
}

/** Compact open-findings panel shown beside Resource history on Host Overview (overview.html). */
export function OverviewFindingsPanel() {
  const data = useData();
  const findings = isRealHost(data.source)
    ? data.observation
      ? liveFindings(data.observation, data.machine)
      : []
    : fixtureFindings;
  const open = findings.filter((f) => f.state !== "ok");
  const passedCount = findings.length - open.length;

  return (
    <section className="panel" aria-labelledby="overview-findings-title">
      <div className="panel-head">
        <h2 id="overview-findings-title">Open findings</h2>
        <Link to="/host/diagnoses">All diagnoses</Link>
      </div>
      {open.length === 0 ? (
        <p className="muted">No open findings in this observation.</p>
      ) : (
        <div>
          {open.slice(0, 4).map((finding) => (
            <div key={finding.id} className="findings-row">
              <div style={{ display: "flex", flexDirection: "column", gap: 4, minWidth: 0 }}>
                <FindingChip state={finding.state} />
                <strong>{finding.check}</strong>
                <span className="mono muted" style={{ fontSize: 12 }}>
                  {finding.subject}
                </span>
              </div>
              <OwnerBadge owner={finding.owner} />
            </div>
          ))}
        </div>
      )}
      <div className="findings-row" style={{ marginTop: 8 }}>
        <span className="muted">{passedCount} passed checks</span>
        <Link to="/host/diagnoses">Show</Link>
      </div>
    </section>
  );
}
