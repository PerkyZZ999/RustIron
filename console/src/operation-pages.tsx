// W714 (pass 33, fix 7): Operations list, operation detail, and plan detail pages. Split from `pages.tsx`.
import { Button } from "@/components/ui/button";
import { Link } from "@tanstack/react-router";
import {
  Activity,
  ChevronDown,
  Download,
  FileCode,
  FileText,
  Lock,
  Signature,
  CircleAlert,
  CircleCheck,
  CircleDashed,
  CircleX,
  LoaderCircle,
  Plus,
  RefreshCw,
  Search,
} from "lucide-react";
import { Fragment, useState } from "react";
import { isRealHost, useData } from "./data";
import { LiveOperationEvidenceBar } from "./live-coordinator";
import { ReceiptAttestationPanel, SignedBytesPanel } from "./signed-panel";
import { liveOperation, type Observation, type LiveOperation } from "./live";
import { CopyId, Crumbs, EvidenceStrip, Glyph, Page, TableScroll } from "./ui";
import { matchesOutcome, Missing } from "./page-parts";

export function OperationsPage() {
  const [query, setQuery] = useState("");
  const [outcome, setOutcome] = useState("All outcomes");
  const [action, setAction] = useState("All actions");
  const [pageNote, setPageNote] = useState("");
  const needle = query.trim().toLowerCase();
  const data = useData();
  const rows = data.operations;
  const count = (filter: string) =>
    rows.filter((row) => matchesOutcome(row.outcome, filter)).length;
  const visible = rows.filter((row) => {
    const haystack = `${row.action} ${row.id} ${row.resources}`.toLowerCase();
    return (
      matchesOutcome(row.outcome, outcome) &&
      (action === "All actions" || row.action === action) &&
      (needle === "" || haystack.includes(needle))
    );
  });

  return (
    <Page live>
      <div className="page-head">
        <div>
          <h1>Operations</h1>
          <p className="sub">
            Executor-recorded operations and their verified outcomes. Pending requests are never
            shown as completed.
          </p>
        </div>
        <Link className="btn primary sm" to="/plans/new">
          <Glyph icon={Plus} />
          New plan
        </Link>
      </div>
      <div className="grid g4">
        <button className="panel" type="button" onClick={() => setOutcome("Needs attention")}>
          <div className="row between">
            <span className="state err">
              <Glyph icon={CircleAlert} />
              Needs attention
            </span>
            <strong className="tnum" style={{ fontSize: 24 }}>
              {count("Needs attention")}
            </strong>
          </div>
          <p className="cap" style={{ marginTop: 6 }}>
            {isRealHost(data.source)
              ? "Blocks new work on what it touched"
              : "Blocks shop.lab.test and global config"}
          </p>
        </button>
        <div className="panel">
          <div className="row between">
            <span className="state info">
              <Glyph icon={LoaderCircle} />
              Running
            </span>
            <strong className="tnum" style={{ fontSize: 24 }}>
              {count("Running")}
            </strong>
          </div>
          <p className="cap" style={{ marginTop: 6 }}>
            {isRealHost(data.source) ? "Recorded, not finished" : "Backup capture · wiki.lab.test"}
          </p>
        </div>
        <div className="panel">
          <div className="row between">
            <span className="state err">
              <Glyph icon={CircleX} />
              Failed
            </span>
            <strong className="tnum" style={{ fontSize: 24 }}>
              {count("Failed") + count("Failed, compensated")}
            </strong>
          </div>
          <p className="cap" style={{ marginTop: 6 }}>
            {isRealHost(data.source)
              ? "Including compensated and partial"
              : "Partial resources retained"}
          </p>
        </div>
        <div className="panel">
          <div className="row between">
            <span className="state ok">
              <Glyph icon={CircleCheck} />
              Succeeded
            </span>
            <strong className="tnum" style={{ fontSize: 24 }}>
              {count("Succeeded")}
            </strong>
          </div>
          <p className="cap" style={{ marginTop: 6 }}>
            {isRealHost(data.source)
              ? "Each verified by its observer"
              : "Each verified by its observer"}
          </p>
        </div>
      </div>
      <section className="panel flush" aria-label="Operations table">
        <div className="toolbar">
          <label className="input search-input">
            <Glyph icon={Search} />
            <input
              aria-label="Operation, plan or site ID"
              placeholder="Operation, plan or site ID"
              autoComplete="off"
              spellCheck={false}
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
          </label>
          <label className="field">
            Outcome
            <select
              className="input"
              value={outcome}
              onChange={(event) => setOutcome(event.target.value)}
            >
              <option>All outcomes</option>
              <option>Needs attention</option>
              <option>Running</option>
              <option>Failed</option>
              <option>Failed, compensated</option>
              <option>Succeeded</option>
              <option>Rejected</option>
            </select>
          </label>
          <label className="field">
            Action
            <select
              className="input"
              value={action}
              onChange={(event) => setAction(event.target.value)}
            >
              <option>All actions</option>
              <option>Site provision</option>
              <option>Config activation</option>
              <option>Backup capture</option>
              <option>Restore probe</option>
              <option>Site eject</option>
            </select>
          </label>
          <label className="field">
            Range
            <select className="input" defaultValue="Last 7 days">
              <option>Last 7 days</option>
            </select>
          </label>
        </div>
        <TableScroll label="Operations">
          <table className="data">
            <thead>
              <tr>
                <th>Operation</th>
                <th>Outcome</th>
                <th>Resources</th>
                <th>Requester</th>
                <th>Started (UTC)</th>
                <th className="num">Duration</th>
              </tr>
            </thead>
            <tbody>
              {visible.length === 0 ? (
                <tr>
                  <td colSpan={6}>No operations match this filter.</td>
                </tr>
              ) : (
                visible.map((row) => (
                  <tr key={`${row.action}-${row.id}-${row.started}`}>
                    <td className="primary-cell">
                      {row.linked ? (
                        <Link to="/operations/$operationId" params={{ operationId: row.id }}>
                          {row.action}
                        </Link>
                      ) : (
                        <strong>{row.action}</strong>
                      )}
                      <small className="mono" translate="no">
                        {row.id}
                      </small>
                    </td>
                    <td>
                      <span className={`state ${row.kind}`}>
                        <Glyph icon={row.icon} />
                        {row.outcome}
                      </span>
                    </td>
                    <td>{row.resources}</td>
                    <td>{row.requester}</td>
                    <td className="tnum">{row.started}</td>
                    <td className="num tnum">{row.duration}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </TableScroll>
        <div className="pager">
          <span>
            {visible.length !== rows.length
              ? `${visible.length} shown · newest first`
              : isRealHost(data.source)
                ? `${rows.length} recorded · newest first`
                : "1–8 of 27 · newest first"}
          </span>
          <span className="row">
            <button className="btn sm" type="button" disabled>
              Previous
            </button>
            <button
              className="btn sm"
              type="button"
              onClick={() => setPageNote("The fixture only includes this page.")}
            >
              Next
            </button>
          </span>
        </div>
        {pageNote ? (
          <p className="cap" style={{ padding: "0 20px 12px" }} aria-live="polite">
            {pageNote}
          </p>
        ) : null}
      </section>
    </Page>
  );
}

export function OperationDetail({ operationId }: { operationId: string }) {
  const data = useData();
  if (data.source.kind === "unavailable") {
    return (
      <Page live>
        <h1>Operation {operationId}</h1>
        <p className="sub">No observation is available to show this record.</p>
        <Link to="/operations">Back to operations</Link>
      </Page>
    );
  }
  if (data.observation) {
    const record = liveOperation(data.observation, operationId);
    if (!record) return <Missing name={operationId} back="/operations" />;
    return <LiveOperationPage record={record} observation={data.observation} />;
  }
  if (operationId !== "op_7Q2KX9") return <Missing name={operationId} />;
  return <FixtureOperationDetail />;
}

function LiveOperationPage({
  record,
  observation,
}: {
  record: LiveOperation;
  observation: Observation;
}) {
  const attention = record.kind === "err";
  return (
    <Page live>
      <Crumbs items={[{ href: "/operations", label: "Operations" }, { label: record.id }]} />
      <div className="page-head">
        <div>
          <h1>{record.title}</h1>
          <div className="row" style={{ marginTop: 6 }}>
            <span className={`pill ${record.kind}`}>
              <Glyph icon={record.icon} />
              {record.outcome}
            </span>
            <CopyId id={record.id} label="operation ID" />
            <span className="cap">{record.timing}</span>
          </div>
        </div>
      </div>
      {record.notice ? (
        <div className={attention ? "attention err" : "attention"} role="note">
          <Glyph icon={attention ? CircleAlert : CircleDashed} />
          <span className="att-body journal-note">{record.notice}</span>
        </div>
      ) : null}
      <section
        className="panel"
        style={attention ? { borderColor: "var(--error-border)" } : undefined}
      >
        <div className="panel-head">
          <h2>What is recorded</h2>
          <span className="meta">Executor journal, not inferred</span>
        </div>
        <div className="grid g3">
          <div>
            <p className="cap">Observed</p>
            {record.observed.map((line) => (
              <p key={line}>{line}</p>
            ))}
          </div>
          <div>
            <p className="cap">Not in this observation</p>
            {record.unknown.map((line) => (
              <p key={line}>{line}</p>
            ))}
          </div>
          <div>
            <p className="cap">This console</p>
            <p>Read-only. It cannot approve, retry or compensate.</p>
          </div>
        </div>
        {record.marks ? (
          <p className="row" style={{ marginTop: 16 }}>
            <EvidenceStrip marks={record.marks} />
          </p>
        ) : null}
        {record.siteId && record.hostname ? (
          <p style={{ marginTop: 16 }}>
            <Link to="/sites/$siteId" params={{ siteId: record.siteId }}>
              Open {record.hostname}
            </Link>
          </p>
        ) : null}
      </section>
      <section className="panel">
        <div className="panel-head">
          <h2>Record</h2>
        </div>
        <dl className="kv">
          {record.facts.map((fact) => (
            <Fragment key={fact.label}>
              <dt>{fact.label}</dt>
              <dd translate="no">{fact.value}</dd>
            </Fragment>
          ))}
        </dl>
      </section>
      <SignedBytesPanel observation={observation} operationId={record.id} />
      <ReceiptAttestationPanel observation={observation} operationId={record.id} />
      <LiveOperationEvidenceBar operationId={record.id} fallbackPayload={record} />
    </Page>
  );
}

function FixtureOperationDetail() {
  return (
    <Page>
      <Crumbs items={[{ href: "/operations", label: "Operations" }, { label: "op_7Q2KX9" }]} />
      <div className="page-head">
        <div>
          <h1>Config activation · shop.lab.test</h1>
          <div className="row" style={{ marginTop: 6 }}>
            <span className="pill err">
              <Glyph icon={CircleAlert} />
              Needs attention
            </span>
            <CopyId id="op_7Q2KX9" label="operation ID" />
            <span className="cap">Admitted 24 Oct 2026, 16:06:31 UTC · stopped 16:07:43 UTC</span>
          </div>
        </div>
      </div>
      <section className="panel" style={{ borderColor: "var(--error-border)" }}>
        <div className="panel-head">
          <h2>What is uncertain</h2>
          <span className="meta">Executor record, not inferred</span>
        </div>
        <div className="grid g3">
          <div>
            <p className="cap">Observed</p>
            <p>
              Generation 42 include was switched and OpenLiteSpeed restarted gracefully. 6 of 8 site
              probes answered with generation 42 headers.
            </p>
          </div>
          <div>
            <p className="cap">Unknown</p>
            <p>
              Probes for shop.lab.test and wiki.lab.test timed out after 30 s. Whether they serve
              generation 41 or 42 is not established.
            </p>
          </div>
          <div>
            <p className="cap">Blocked until resolved</p>
            <p>
              New operations on shop.lab.test and on the global OpenLiteSpeed configuration.
              Read-only inspection continues.
            </p>
          </div>
        </div>
        <p style={{ marginTop: 16 }}>
          <Link to="/plans/$planId" params={{ planId: "plan_3HV8RA" }}>
            Inspect plan plan_3HV8RA
          </Link>
        </p>
      </section>
    </Page>
  );
}

const planSteps = [
  ["Check preconditions", "Generation = 41", "Registry read-back", "None"],
  ["Render include", "Settings schema v1", "Artifact digest", "None"],
  ["Stage and check", "Staging path free", "Structural check", "Remove staged file"],
  ["Switch include", "Staged digest", "Pointer read-back", "Switch to 41"],
  ["Graceful restart", "Service running", "New worker PIDs", "Bounded restart"],
  ["Probe all sites", "—", "8 of 8 answer gen 42", "Switch to 41"],
] as const;

export function PlanDetail({ planId }: { planId: string }) {
  const data = useData();
  if (data.source.kind === "unavailable") {
    return (
      <Page live>
        <h1>Plan {planId}</h1>
        <p className="sub">No observation is available to show this record.</p>
        <Link to="/operations">Back to operations</Link>
      </Page>
    );
  }
  if (data.observation) {
    return (
      <Page live>
        <Crumbs items={[{ href: "/operations", label: "Operations" }, { label: planId }]} />
        <h1>Plan {planId}</h1>
        <p className="sub">
          Plans are not listed by plan ID in this observation. Each operation page shows its signed
          plan and grant when the journal recorded them.
        </p>
        <Link to="/operations">Back to operations</Link>
      </Page>
    );
  }
  if (planId !== "plan_3HV8RA") return <Missing name={planId} back="/operations" />;
  return <FixturePlanDetail />;
}

function FixturePlanDetail() {
  return (
    <Page>
      <Crumbs
        items={[
          { href: "/operations", label: "Operations" },
          { href: "/operations/op_7Q2KX9", label: "op_7Q2KX9" },
          { label: "plan_3HV8RA" },
        ]}
      />
      <div className="page-head">
        <div>
          <h1>Plan: config activation for shop.lab.test</h1>
          <div className="row" style={{ marginTop: 6 }}>
            <span className="pill">
              Executed ·{" "}
              <Link to="/operations/$operationId" params={{ operationId: "op_7Q2KX9" }}>
                op_7Q2KX9
              </Link>
            </span>
            <span className="pill">Risk class: global reload</span>
            <CopyId id="plan_3HV8RA" label="plan ID" />
          </div>
        </div>
        <div className="head-actions action-note">
          <Button variant="outline" size="sm" disabled>
            <Glyph icon={Download} />
            Export signed plan
          </Button>
          <span className="cap">Available with live host data</span>
        </div>
      </div>
      <div className="preview-banner">
        <Glyph icon={Lock} />
        <span>
          <strong>Inspection only.</strong> This plan is immutable. Approvals are signed outside the
          browser; the console never holds signing keys.
        </span>
      </div>
      <div className="grid g-main-side">
        <div className="stack">
          <section className="panel">
            <div className="panel-head">
              <h2>Expected effects</h2>
            </div>
            <ul className="list">
              <li>
                <Glyph icon={FileCode} className="list-muted" />
                <span className="grow">
                  <span className="t">Render generation 42 of the shop.lab.test include</span>
                  <span className="s">PHP worker limit 6 → 8 · all other settings unchanged</span>
                </span>
              </li>
              <li>
                <Glyph icon={RefreshCw} className="list-warn" />
                <span className="grow">
                  <span className="t">Gracefully restart OpenLiteSpeed</span>
                  <span className="s">Global: affects all 8 registered sites</span>
                </span>
              </li>
              <li>
                <Glyph icon={Activity} className="list-muted" />
                <span className="grow">
                  <span className="t">Probe every registered site</span>
                  <span className="s">HTTP + generation header · 30 s timeout each</span>
                </span>
              </li>
            </ul>
          </section>
          <section className="panel">
            <div className="panel-head">
              <h2>Risk and reversibility</h2>
            </div>
            <dl className="kv">
              <dt>Blast radius</dt>
              <dd>1 site changed · 8 sites restarted</dd>
              <dt>Downtime estimate</dt>
              <dd>
                <span className="state unknown">
                  <Glyph icon={CircleDashed} />
                  Unknown
                </span>{" "}
                <span className="cap">graceful restart; no measured baseline on this host</span>
              </dd>
              <dt>Data-loss exposure</dt>
              <dd>None declared: configuration only, no database or file content</dd>
              <dt>Reversibility</dt>
              <dd>
                Switch back to verified generation 41 and restart. Does not roll back application
                data.
              </dd>
              <dt>Compensation</dt>
              <dd>
                Signed last-known-good switch + bounded restart, only after a verified failure
              </dd>
              <dt>Limitations</dt>
              <dd>Probes check headers, not WooCommerce checkout behaviour</dd>
            </dl>
          </section>
          <section className="panel flush">
            <div className="panel-head">
              <h2>Steps</h2>
            </div>
            <TableScroll label="Plan steps" style={{ marginTop: 12 }}>
              <table className="data">
                <thead>
                  <tr>
                    <th scope="col">#</th>
                    <th scope="col">Step</th>
                    <th scope="col">Precheck</th>
                    <th scope="col">Verification</th>
                    <th scope="col">Compensation</th>
                  </tr>
                </thead>
                <tbody>
                  {planSteps.map(([step, precheck, verification, compensation], index) => (
                    <tr key={step}>
                      <td className="tnum">{index + 1}</td>
                      <td>{step}</td>
                      <td>{precheck}</td>
                      <td>{verification}</td>
                      <td className={compensation === "None" ? "muted" : undefined}>
                        {compensation}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableScroll>
          </section>
        </div>
        <aside className="stack" aria-label="Plan approval and identity">
          <section className="panel">
            <div className="panel-head">
              <h2>Approval</h2>
              <span className="state ok">
                <Glyph icon={Signature} />
                Signature verified
              </span>
            </div>
            <dl className="kv">
              <dt>Issuer</dt>
              <dd>
                operator key <code>SHA256:Qm4…f2c</code>
              </dd>
              <dt>Requester</dt>
              <dd>operator (CLI)</dd>
              <dt>Scope</dt>
              <dd>
                <code>config_activate</code> on site_8KD2QW
              </dd>
              <dt>Valid</dt>
              <dd className="tnum">16:06 → 16:36 UTC</dd>
              <dt>Nonce</dt>
              <dd>
                <code>n_51f0…77ac</code> · used once
              </dd>
            </dl>
          </section>
          <section className="panel">
            <div className="panel-head">
              <h2>Plan identity</h2>
            </div>
            <dl className="kv">
              <dt>Digest</dt>
              <dd>
                <code>sha256:4b7d…e19c</code>
              </dd>
              <dt>Schema</dt>
              <dd>plan v1</dd>
              <dt>Host / epoch</dt>
              <dd>lab-01 · 3</dd>
              <dt>Profile</dt>
              <dd>
                <code>sha256:a2f0…31bd</code>
              </dd>
              <dt>Generator</dt>
              <dd>coordinator 0.4.0</dd>
              <dt>Created</dt>
              <dd className="tnum">24 Oct, 16:04 UTC</dd>
            </dl>
          </section>
          <details className="disclose">
            <summary>
              <Glyph icon={FileText} />
              <span>Observations used</span>
              <Glyph icon={ChevronDown} className="chev" />
            </summary>
            <div className="d-body">
              <ul className="list">
                {["Generation 41 active", "No drift in owned include", "8 sites registered"].map(
                  (item) => (
                    <li key={item}>
                      <span className="grow">{item}</span>
                      <span className="r tnum">16:03</span>
                    </li>
                  ),
                )}
              </ul>
            </div>
          </details>
        </aside>
      </div>
    </Page>
  );
}
