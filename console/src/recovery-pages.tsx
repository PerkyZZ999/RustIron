// W714 (pass 33, fix 7): Recovery, artifact, and receipt pages. Split from `pages.tsx`.
import { AnswerLine, QuietDetails, SimpleHeader } from "@/components/console/simple";
import {
  type BulkAction,
  BulkBar,
  PageCheck,
  RowCheck,
  type Selection,
  useSelection,
} from "@/components/console/bulk";
import {
  FilterChips,
  ListArea,
  ListControls,
  ListToolbar,
  matches,
  rowClass,
  rowLinkClass,
  usePaged,
} from "@/components/console/list";
import { buildProductBackupCaptureCmd, buildProductRestoreProbeCmd } from "./cli-commands";
import { Button } from "@/components/ui/button";
import { Link } from "@tanstack/react-router";
import {
  BookOpen,
  ChevronDown,
  Download,
  CircleCheck,
  CircleDashed,
  CircleMinus,
  CircleX,
  LoaderCircle,
  TriangleAlert,
} from "lucide-react";
import { Fragment, type ReactNode, useState } from "react";
import { BackupRestoreActionsPanel } from "./backup-migration-wizards";
import { isRealHost, useData } from "./data";
import { RecoveryTabs } from "./platform-subviews";
import { liveReceipt, liveSnapshot, type LiveReceipt, type LiveSnapshot } from "./live";
import { type Mark, type RecoveryRow, type Site, sites } from "./fixture";
import { CopyId, Crumbs, EvidenceStrip, Glyph, Page, TableScroll } from "./ui";
import { EvidenceKey, Missing, RecoveryStateLabel } from "./page-parts";

function ReceiptCell({ receipt, live }: { receipt: string | null; live: boolean }) {
  if (receipt && (live || receipt === "rcpt_2YB7")) {
    return (
      <Link className="mono" to="/recovery/evidence/$receiptId" params={{ receiptId: receipt }}>
        {receipt}
      </Link>
    );
  }
  return <span className="mono muted">{receipt ?? "—"}</span>;
}

/** W790 (v0.3 item 60): "Am I protected?" counted from each site's evidence fields. */
function RecoveryAnswer({ data }: { data: ReturnType<typeof useData> }) {
  if (data.source.kind === "loading") {
    return <AnswerLine tone="unknown">Checking this server…</AnswerLine>;
  }
  const recorded = data.recovery.flatMap((row) => data.sites.filter((s) => s.id === row.siteId));
  if (recorded.length === 0)
    return <AnswerLine tone="unknown">No backups recorded yet.</AnswerLine>;
  const proven = recorded.filter((s) => s.marks.every((m) => m === "pass")).length;
  const failing = recorded.filter((s) => s.marks.includes("fail")).length;
  const text =
    `${proven} of ${recorded.length} ${recorded.length === 1 ? "website passes" : "websites pass"} every recovery check` +
    (failing > 0 ? `; ${failing} ${failing === 1 ? "has" : "have"} a failed check.` : ".");
  return (
    <AnswerLine tone={failing > 0 ? "err" : proven === recorded.length ? "ok" : "warn"}>
      {text}
    </AnswerLine>
  );
}

type RecoveryFilter = "all" | "attention" | "proven";
type RecoveryEntry = { row: RecoveryRow; site: Site };

/** How many of the seven recovery checks are not passing. */
const weakness = (site: Site) => site.marks.filter((mark) => mark !== "pass").length;

/** Signed backup changes for several websites: one plan per website (item 64). */
const recoveryBulkActions: BulkAction[] = [
  {
    label: "Back up now",
    question: (n) => `Back up ${n} ${n === 1 ? "website" : "websites"} now?`,
    command: (siteId) => buildProductBackupCaptureCmd({ siteId, consistency: "marker" }),
  },
  {
    label: "Test a restore",
    question: (n) => `Test a restore of ${n} ${n === 1 ? "website" : "websites"}?`,
    command: (siteId) => buildProductRestoreProbeCmd({ siteId }),
  },
];

function recoveryFilterMatch(site: Site, filter: RecoveryFilter): boolean {
  if (filter === "all") return true;
  return filter === "attention" ? weakness(site) > 0 : weakness(site) === 0;
}

function ExportRecoveryButton() {
  const data = useData();
  return (
    <button
      type="button"
      className="btn sm"
      disabled={data.source.kind !== "live" || data.source.stale}
      title={
        data.source.kind !== "live"
          ? "Disabled on fixture sample data"
          : data.source.stale
            ? "Disabled while live observation is stale"
            : "Export live recovery rows with provenance metadata"
      }
      onClick={() => {
        const hostId = data.observation?.host.host_id ?? "host";
        const payload = {
          schema: "rustiron-console-recovery-export/1",
          authoritative_evidence: data.source.kind === "live" && !data.source.stale,
          source: data.source,
          host_id: hostId,
          exported_at: new Date().toISOString(),
          recovery: data.recovery,
        };
        const blob = new Blob([JSON.stringify(payload, null, 2)], {
          type: "application/json;charset=utf-8",
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `rustiron-recovery-${hostId}.json`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
      }}
    >
      <Glyph icon={Download} />
      Export recovery JSON
    </button>
  );
}

function BackupRow({
  row,
  site,
  selection,
  live,
}: {
  row: RecoveryRow;
  site: Site;
  selection: Selection | null;
  live: boolean;
}) {
  return (
    <li className={rowClass}>
      {selection ? <RowCheck selection={selection} id={site.id} label={site.domain} /> : null}
      <div className="min-w-0 flex-1">
        <Link
          className={rowLinkClass}
          to="/sites/$siteId/recovery"
          params={{ siteId: site.id }}
          translate="no"
        >
          {site.domain}
        </Link>
        <p className="truncate text-sm text-muted-foreground">
          {row.snapshot ? `Newest backup ${row.snapshot}` : row.snapshotNote}
          {row.snapshot && row.exposure ? ` · ${row.exposure}` : ""}
          {row.receipt ? (
            <>
              {" · "}
              <span className="relative z-10">
                <ReceiptCell receipt={row.receipt} live={live} />
              </span>
            </>
          ) : null}
        </p>
      </div>
      <span className="hidden md:block">
        <EvidenceStrip marks={site.marks} />
      </span>
      <span className="flex justify-end sm:w-44">
        {row.restore ? (
          <RecoveryStateLabel state={row.restore} />
        ) : (
          <span className="muted">No restore test</span>
        )}
      </span>
    </li>
  );
}

function RecoveryList() {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<RecoveryFilter>("all");
  const [sort, setSort] = useState<"weakest" | "name">("weakest");
  const selection = useSelection();
  const data = useData();
  const all: RecoveryEntry[] = data.recovery.flatMap((row) => {
    const site = data.sites.find((candidate) => candidate.id === row.siteId);
    return site ? [{ row, site }] : [];
  });
  const attention = all.filter(({ site }) => weakness(site) > 0).length;
  const rows = all
    .filter(({ row, site }) => matches(query, site.domain, row.snapshot ?? "", row.receipt ?? ""))
    .filter(({ site }) => recoveryFilterMatch(site, filter))
    .sort((a, b) =>
      sort === "name"
        ? a.site.domain.localeCompare(b.site.domain)
        : weakness(b.site) - weakness(a.site) || a.site.domain.localeCompare(b.site.domain),
    );
  const paged = usePaged(rows, `${query}|${filter}|${sort}|${all.length}`);
  const bulk = all.length > 1;
  return (
    <>
      <ListToolbar
        filters={
          <FilterChips
            label="Show"
            value={filter}
            onChange={setFilter}
            options={[
              { value: "all", label: "All", count: all.length },
              { value: "attention", label: "Needs a look", count: attention },
              { value: "proven", label: "Every check passed", count: all.length - attention },
            ]}
          />
        }
      >
        <ListControls
          count={all.length}
          searchLabel="Find a website, backup, or receipt"
          query={query}
          onQuery={setQuery}
          sort={sort}
          onSort={setSort}
          sorts={[
            { value: "weakest", label: "Weakest first" },
            { value: "name", label: "Name A–Z" },
          ]}
        />
      </ListToolbar>
      <ListArea
        label="Backups by website"
        noun="websites"
        total={all.length}
        paged={paged}
        onReset={() => {
          setQuery("");
          setFilter("all");
        }}
        top={
          <PageCheck
            enabled={bulk}
            selection={selection}
            wholeList={paged.pageCount === 1}
            pageIds={paged.rows.map(({ site }) => site.id)}
            noun="websites"
          />
        }
        bottom={
          <BulkBar
            selection={selection}
            matchingIds={rows.map(({ site }) => site.id)}
            nameOf={(id) => data.sites.find((site) => site.id === id)?.domain ?? id}
            noun="websites"
            one="website"
            actions={recoveryBulkActions}
          />
        }
      >
        {paged.rows.map(({ row, site }) => (
          <BackupRow
            key={site.id}
            row={row}
            site={site}
            selection={bulk ? selection : null}
            live={data.source.kind === "live"}
          />
        ))}
      </ListArea>
    </>
  );
}

export function RecoveryPage() {
  const data = useData();
  return (
    <Page live>
      <div className="page-head">
        <SimpleHeader title="Backups" answer={<RecoveryAnswer data={data} />} />
        <ExportRecoveryButton />
      </div>
      <RecoveryTabs current="/recovery" />
      <BackupRestoreActionsPanel />
      {isRealHost(data.source) ? null : (
        <>
          <div className="attention err">
            <Glyph icon={CircleX} />
            <div className="att-body">
              <strong>Decryption test failed for portfolio.lab.test.</strong> snap_R3T6 could not be
              decrypted with the recovered repository key during the 11:20 drill. Later snapshots
              use the same key.
              <div className="att-meta">Receipt rcpt_2YB7 · 24 Oct, 11:31 UTC</div>
            </div>
            <Link
              className="btn sm"
              to="/recovery/evidence/$receiptId"
              params={{ receiptId: "rcpt_2YB7" }}
            >
              Inspect receipt
            </Link>
          </div>
        </>
      )}
      <div className="flex flex-col gap-4">
        <RecoveryList />
        <p className="text-xs text-muted-foreground">
          {data.source.kind === "live"
            ? `Repository: ${data.source.host.backup_destination ?? "none enrolled"} (lab store on the operator PC, not independent)`
            : isRealHost(data.source)
              ? "Repository: not observed"
              : "Repositories: offsite-b2 (independent provider) · local-stage"}
        </p>
        <QuietDetails
          title="The seven recovery checks"
          summary="Each is recorded separately; there is no combined “backup healthy” score."
        >
          <div className="mb-3">
            <EvidenceKey />
          </div>
          <ol className="grid g4 field-key">
            {[
              ["1 · Artifacts complete", "Every expected file and database artifact exists"],
              ["2 · Repository integrity checked", "Repository check covered this snapshot"],
              ["3 · Decryption tested", "Decrypted with a recovered key"],
              ["4 · Application consistency assessed", "File and database capture skew evaluated"],
              ["5 · Restored in isolation", "Restored into a fresh sandbox without egress"],
              ["6 · Health checks passed", "Restored site answered application probes"],
              ["7 · Independent copy confirmed", "A physically independent off-host copy exists"],
            ].map(([title, detail]) => (
              <li key={title}>
                <strong>{title}</strong>
                <p className="cap">{detail}</p>
              </li>
            ))}
          </ol>
        </QuietDetails>
      </div>
    </Page>
  );
}

const snapshotArtifacts = [
  ["art_F1X8", "Site files (public, uploads)", "1.5 GiB", "e3b9…7c21"],
  ["art_D2B4", "Database dump db_shop", "388 MiB", "51aa…0f9e"],
  ["art_M0N3", "Manifest and ownership export", "48 KiB", "9f02…b6d4"],
] as const;

export function ArtifactPage({ artifactId }: { artifactId: string }) {
  const data = useData();
  if (data.source.kind === "unavailable") {
    return (
      <Page live>
        <h1>Snapshot {artifactId}</h1>
        <p className="sub">No observation is available to show this record.</p>
        <Link to="/recovery">Back to recovery</Link>
      </Page>
    );
  }
  if (data.observation) {
    const record = liveSnapshot(data.observation, artifactId);
    if (!record) return <Missing name={artifactId} back="/recovery" />;
    return <LiveSnapshotPage record={record} />;
  }
  if (artifactId !== "snap_P8Q1") return <Missing name={artifactId} />;
  return <FixtureArtifactPage />;
}

function LiveSnapshotPage({ record }: { record: LiveSnapshot }) {
  return (
    <Page live>
      <Crumbs
        items={[
          { href: "/recovery", label: "Backups" },
          ...(record.hostname
            ? [{ href: `/sites/${record.siteId}/recovery`, label: record.hostname }]
            : []),
          { label: record.shortId },
        ]}
      />
      <div className="page-head">
        <div>
          <h1>Snapshot {record.shortId}</h1>
          <div className="row" style={{ marginTop: 6 }}>
            <span className="pill" translate="no">
              {record.hostname ?? record.siteId}
            </span>
            <span className="pill">{record.stateLabel}</span>
            <span className="cap">{record.timing}</span>
          </div>
        </div>
        <div className="head-actions action-note">
          <Button variant="outline" size="sm" disabled>
            <Glyph icon={Download} />
            Export manifest
          </Button>
          <span className="cap">Artifact manifest is not in this observation</span>
        </div>
      </div>
      <div className="grid g-main-side">
        <section className="panel">
          <div className="panel-head">
            <h2>Recorded</h2>
            <span className="meta">Executor journal</span>
          </div>
          <dl className="kv">
            <dt>Snapshot</dt>
            <dd>
              <CopyId id={record.id} label="snapshot ID" />
            </dd>
            <dt>Capture</dt>
            <dd>
              <Link to="/operations/$operationId" params={{ operationId: record.operationId }}>
                {record.operationId}
              </Link>
            </dd>
            <dt>Repository</dt>
            <dd>{record.repository}</dd>
            <dt>Restore test</dt>
            <dd>{record.restoreLabel}</dd>
            <dt>Receipt</dt>
            <dd>
              {record.receiptId ? (
                <Link to="/recovery/evidence/$receiptId" params={{ receiptId: record.receiptId }}>
                  {record.receiptId}
                </Link>
              ) : (
                "No fielded probe"
              )}
            </dd>
          </dl>
          {record.marks ? (
            <p className="row" style={{ marginTop: 16 }}>
              <EvidenceStrip marks={record.marks} />
            </p>
          ) : null}
        </section>
        <section className="panel">
          <div className="panel-head">
            <h2>Not in this observation</h2>
          </div>
          <ul className="list">
            <li>
              <Glyph icon={CircleMinus} />
              Artifact file list, sizes and digests
            </li>
            <li>
              <Glyph icon={CircleMinus} />
              Quiescence window and file/database skew
            </li>
          </ul>
        </section>
      </div>
    </Page>
  );
}

function FixtureArtifactPage() {
  const shop = sites.find((site) => site.id === "site_8KD2QW");
  return (
    <Page>
      <Crumbs
        items={[
          { href: "/recovery", label: "Backups" },
          { href: "/sites/site_8KD2QW/recovery", label: "shop.lab.test" },
          { label: "snap_P8Q1" },
        ]}
      />
      <div className="page-head">
        <div>
          <h1>Snapshot snap_P8Q1</h1>
          <div className="row" style={{ marginTop: 6 }}>
            <span className="pill">shop.lab.test</span>
            <span className="pill">Files + database</span>
            <span className="cap">Captured 23 Oct 2026, 02:00:12–02:06:53 UTC by op_9JW3LE</span>
          </div>
        </div>
        <div className="head-actions action-note">
          <Button variant="outline" size="sm" disabled>
            <Glyph icon={Download} />
            Export manifest
          </Button>
          <span className="cap">Available with live host data</span>
        </div>
      </div>
      <div className="attention">
        <Glyph icon={TriangleAlert} />
        <div className="att-body">
          <strong>Captured and checked, but not proven restorable.</strong> No isolated restore has
          used this snapshot yet. Fields 4–6 are not run and field 7 is unknown.
        </div>
      </div>
      <div className="grid g-main-side">
        <div className="stack">
          <section className="panel flush">
            <div className="panel-head">
              <h2>Artifacts</h2>
              <span className="meta">3 artifacts · 1.9 GiB encrypted</span>
            </div>
            <TableScroll label="Artifacts">
              <table className="data">
                <thead>
                  <tr>
                    <th scope="col">Artifact</th>
                    <th scope="col">Content</th>
                    <th scope="col" className="num">
                      Size
                    </th>
                    <th scope="col">SHA-256</th>
                    <th scope="col">Integrity</th>
                  </tr>
                </thead>
                <tbody>
                  {snapshotArtifacts.map(([id, content, size, digest]) => (
                    <tr key={id}>
                      <td className="id">{id}</td>
                      <td>{content}</td>
                      <td className="num tnum">{size}</td>
                      <td className="id">{digest}</td>
                      <td>
                        <span className="state ok">
                          <Glyph icon={CircleCheck} />
                          Checked 02:31
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableScroll>
          </section>
          <section className="panel">
            <div className="panel-head">
              <h2>Capture consistency</h2>
            </div>
            <dl className="kv tnum">
              <dt>Method</dt>
              <dd>Site PHP paused · DB single-transaction dump · file copy</dd>
              <dt>Quiescence window</dt>
              <dd>41 s (02:00:31–02:01:12)</dd>
              <dt>File / DB skew</dt>
              <dd>≤ 41 s, within the window</dd>
              <dt>Services restored</dt>
              <dd>Verified 02:01:14</dd>
              <dt>Limitations</dt>
              <dd>WordPress cron jobs scheduled inside the window run late</dd>
            </dl>
          </section>
        </div>
        <aside className="stack">
          <section className="panel">
            <div className="panel-head">
              <h2>Repository</h2>
            </div>
            <dl className="kv">
              <dt>Destination</dt>
              <dd>offsite-b2</dd>
              <dt>Location</dt>
              <dd>Separate provider and account from lab-01</dd>
              <dt>Independence</dt>
              <dd>
                <span className="state unknown">
                  <Glyph icon={CircleDashed} />
                  Unknown for this snapshot
                </span>
                <p className="cap">Last confirmed for snap_K2M9</p>
              </dd>
              <dt>Encryption</dt>
              <dd>
                Repository key · id <code>key_7Fp…</code> (key not shown)
              </dd>
              <dt>Tooling</dt>
              <dd>restic 0.18.0</dd>
            </dl>
          </section>
          <section className="panel">
            <div className="panel-head">
              <h2>Receipts using this snapshot</h2>
            </div>
            <ul className="list">
              <li>
                <span className="grow">
                  <span className="t mono">rcpt_9PL1</span>
                  <span className="s">Capture receipt · 23 Oct 02:31</span>
                </span>
                {shop ? <EvidenceStrip marks={shop.marks} /> : null}
              </li>
            </ul>
            <p className="cap" style={{ marginTop: 8 }}>
              A restore probe would add a new receipt.
            </p>
          </section>
        </aside>
      </div>
    </Page>
  );
}

type ReceiptField = {
  name: string;
  short: string;
  scope: string;
  mark: Mark;
  rows: [string, ReactNode][];
  open?: boolean;
};

const receiptFields: ReceiptField[] = [
  {
    name: "Artifacts complete",
    short: "Artifacts complete",
    scope: "files, database, manifest",
    mark: "pass",
    rows: [
      ["Status", "Pass"],
      ["Scope", "3 of 3 expected artifacts present with matching sizes"],
      ["Observed", "11:21 UTC"],
      [
        "Evidence",
        <span key="value" className="pill">
          manifest-diff #881
        </span>,
      ],
      ["Limitations", "Presence only; not content correctness"],
    ],
  },
  {
    name: "Repository integrity checked",
    short: "Integrity checked",
    scope: "pack files for this snapshot",
    mark: "pass",
    rows: [
      ["Status", "Pass"],
      ["Scope", "Read-data check of packs referenced by snap_R3T6 (not the whole repository)"],
      ["Observed", "11:24 UTC"],
      [
        "Evidence",
        <span key="value" className="pill">
          restic-check #882
        </span>,
      ],
      ["Limitations", "Hash verification is not application health"],
    ],
  },
  {
    name: "Decryption tested",
    short: "Decryption tested",
    scope: "with the recovered key",
    mark: "fail",
    open: true,
    rows: [
      [
        "Status",
        <span key="value" className="state err">
          Fail
        </span>,
      ],
      ["Scope", "Key recovered from the offline escrow copy, used on a clean sandbox"],
      ["Observed", "11:27 UTC"],
      [
        "Result",
        <>
          Recovered key id <code>key_9Ab…</code> does not match the repository key id{" "}
          <code>key_7Fp…</code>. The escrow copy appears outdated after the 3 Oct key rotation.
        </>,
      ],
      [
        "Evidence",
        <>
          <span className="pill">decrypt-attempt #883</span>{" "}
          <span className="pill">key-provenance #61</span>
        </>,
      ],
      [
        "Limitations",
        "The live host key still decrypts; this failure concerns recovery without the host",
      ],
    ],
  },
  {
    name: "Application consistency assessed",
    short: "App consistency",
    scope: "not run",
    mark: "not_run",
    open: true,
    rows: [
      ["Status", "Not run"],
      ["Reason", "Depends on decryption, which failed"],
    ],
  },
  {
    name: "Restored in isolation",
    short: "Restored in isolation",
    scope: "not run",
    mark: "not_run",
    rows: [
      ["Status", "Not run"],
      ["Reason", "Depends on decryption, which failed"],
    ],
  },
  {
    name: "Health checks passed",
    short: "Health checks",
    scope: "not run",
    mark: "not_run",
    rows: [
      ["Status", "Not run"],
      [
        "Reason",
        "No restored site to probe. The 17 Oct pass for snap_Q1V9 is recorded on its own receipt and is not carried over.",
      ],
    ],
  },
  {
    name: "Independent copy confirmed",
    short: "Independent copy",
    scope: "offsite-b2",
    mark: "pass",
    rows: [
      ["Status", "Pass"],
      [
        "Scope",
        "Snapshot listed from a separate provider account using recovered read credentials",
      ],
      ["Observed", "11:22 UTC"],
      [
        "Evidence",
        <span key="value" className="pill">
          remote-list #884
        </span>,
      ],
    ],
  },
];

const markState = {
  pass: { kind: "ok", icon: CircleCheck, word: "Pass" },
  fail: { kind: "err", icon: CircleX, word: "Fail" },
  unknown: { kind: "unknown", icon: CircleDashed, word: "Unknown" },
  not_run: { kind: "notrun", icon: CircleMinus, word: "Not run" },
} as const;

function ReceiptExport({ caption }: { caption: string }) {
  return (
    <div className="head-actions">
      <div className="action-note">
        <Button variant="outline" size="sm" disabled>
          <Glyph icon={Download} />
          Export receipt (JSON)
        </Button>
        <span className="cap">{caption}</span>
      </div>
      <Link className="btn sm" to="/help/$slug" params={{ slug: "backups-and-recovery" }}>
        <Glyph icon={BookOpen} />
        Recovery guide
      </Link>
    </div>
  );
}

function FieldDisclosure({
  name,
  mark,
  open,
  scopeNote,
  children,
}: {
  name: string;
  mark: Mark;
  open?: boolean;
  scopeNote?: string;
  children: ReactNode;
}) {
  const state = markState[mark];
  return (
    <details className={`disclose ev-${state.kind}`} open={open}>
      <summary>
        <Glyph icon={state.icon} className={`ev-icon ${state.kind}`} />
        <span>
          <span className="ev-name">{name}</span>
          {scopeNote ? <span className="ev-scope"> · {scopeNote}</span> : null}
          <span className="sr-only">: {state.word}</span>
        </span>
        <Glyph icon={ChevronDown} className="chev" />
      </summary>
      <div className="d-body">{children}</div>
    </details>
  );
}

function EvidenceSummary({ fields }: { fields: { key: string; label: string; mark: Mark }[] }) {
  return (
    <ul className="evgrid" aria-label="Evidence summary">
      {fields.map((field) => {
        const state = markState[field.mark];
        return (
          <li key={field.key} className={`evcell ${state.kind}`}>
            <span className="ev-label">{field.label}</span>
            <span className={`state ${state.kind}`}>
              <Glyph icon={state.icon} />
              {state.word}
            </span>
          </li>
        );
      })}
    </ul>
  );
}

export function ReceiptPage({ receiptId }: { receiptId: string }) {
  const data = useData();
  if (data.source.kind === "unavailable") {
    return (
      <Page live>
        <h1>Recovery receipt {receiptId}</h1>
        <p className="sub">No observation is available to show this record.</p>
        <Link to="/recovery">Back to recovery</Link>
      </Page>
    );
  }
  if (data.observation) {
    const record = liveReceipt(data.observation, receiptId);
    if (!record) return <Missing name={receiptId} back="/recovery" />;
    return <LiveReceiptPage record={record} />;
  }
  if (receiptId !== "rcpt_2YB7") return <Missing name={receiptId} />;
  return <FixtureReceiptPage />;
}

function LiveReceiptPage({ record }: { record: LiveReceipt }) {
  const shortSnapshot = record.snapshotId.slice(0, 8);
  return (
    <Page live>
      <Crumbs
        items={[
          { href: "/recovery", label: "Backups" },
          ...(record.hostname
            ? [{ href: `/sites/${record.siteId}/recovery`, label: record.hostname }]
            : []),
          { label: record.id },
        ]}
      />
      <div className="page-head">
        <div>
          <h1>Recovery receipt {record.id}</h1>
          <div className="row" style={{ marginTop: 6 }}>
            <span className={record.stateKind === "unknown" ? "pill" : `pill ${record.stateKind}`}>
              <Glyph
                icon={
                  record.stateKind === "ok"
                    ? CircleCheck
                    : record.stateKind === "err"
                      ? CircleX
                      : LoaderCircle
                }
              />
              {record.stateLabel}
            </span>
            <span className="pill" translate="no">
              {record.hostname ?? record.siteId}
            </span>
            <span className="pill" translate="no">
              {shortSnapshot}
            </span>
            <span className="cap">{record.timing}</span>
          </div>
        </div>
        <ReceiptExport caption="Signed receipt bytes are not in this observation" />
      </div>
      <EvidenceSummary
        fields={record.fields.map((field) => ({
          key: field.name,
          label: field.name,
          mark: field.mark,
        }))}
      />
      {record.independence ? (
        <div className="attention journal-note" role="note">
          <Glyph icon={CircleDashed} />
          <span className="att-body">{record.independence}</span>
        </div>
      ) : null}
      <div className="grid g-main-side">
        <section aria-labelledby="fields-t">
          <h2 id="fields-t" className="sr-only">
            Evidence fields
          </h2>
          {record.fields.map((field) => (
            <FieldDisclosure
              key={field.name}
              name={field.name}
              mark={field.mark}
              open={
                field.mark === "fail" ||
                (record.independence !== null && field.name === "Independent copy confirmed")
              }
            >
              <dl className="kv">
                <dt>Status</dt>
                <dd>{markState[field.mark].word}</dd>
                <dt>Scope</dt>
                <dd>{field.scope ?? "Scope not recorded"}</dd>
              </dl>
            </FieldDisclosure>
          ))}
        </section>
        <aside className="stack">
          <section className="panel">
            <div className="panel-head">
              <h2>Recorded</h2>
              <span className="meta">Executor journal</span>
            </div>
            <dl className="kv">
              <dt>Probe</dt>
              <dd translate="no">{record.id}</dd>
              <dt>Snapshot</dt>
              <dd translate="no">{record.snapshotId}</dd>
              <dt>Site</dt>
              <dd>
                {record.hostname ? (
                  <Link to="/sites/$siteId/recovery" params={{ siteId: record.siteId }}>
                    {record.hostname}
                  </Link>
                ) : (
                  <span translate="no">{record.siteId}</span>
                )}
              </dd>
            </dl>
            <p style={{ marginTop: 12 }}>
              <Link to="/operations/$operationId" params={{ operationId: record.id }}>
                Open operation {record.id}
              </Link>
            </p>
          </section>
          <section className="panel">
            <div className="panel-head">
              <h2>Not in this observation</h2>
            </div>
            <ul className="list">
              <li>
                <Glyph icon={CircleMinus} />
                Sandbox identity, cleanup result and phase timings
              </li>
              <li>
                <Glyph icon={CircleMinus} />
                Attester key
              </li>
              <li>
                <Glyph icon={CircleMinus} />
                Signed receipt bytes
              </li>
            </ul>
          </section>
        </aside>
      </div>
    </Page>
  );
}

function FixtureReceiptPage() {
  return (
    <Page>
      <Crumbs
        items={[
          { href: "/recovery", label: "Backups" },
          { href: "/sites/site_2PL7VB/recovery", label: "portfolio.lab.test" },
          { label: "rcpt_2YB7" },
        ]}
      />
      <div className="page-head">
        <div>
          <h1>Recovery receipt rcpt_2YB7</h1>
          <div className="row" style={{ marginTop: 6 }}>
            <span className="pill">portfolio.lab.test</span>
            <span className="pill">snap_R3T6</span>
            <span className="cap">
              Restore probe op_6TT0CV · 24 Oct 2026, 11:20–11:31 UTC · receipt schema v1
            </span>
          </div>
        </div>
        <ReceiptExport caption="Available with live host data" />
      </div>
      <EvidenceSummary
        fields={receiptFields.map((field) => ({
          key: field.name,
          label: field.short,
          mark: field.mark,
        }))}
      />
      <div className="grid g-main-side">
        <section aria-labelledby="fields-t">
          <h2 id="fields-t" className="sr-only">
            Evidence fields
          </h2>
          {receiptFields.map((field) => (
            <FieldDisclosure
              key={field.name}
              name={field.name}
              mark={field.mark}
              open={field.open}
              scopeNote={field.scope}
            >
              <dl className="kv">
                {field.rows.map(([term, value]) => (
                  <Fragment key={term}>
                    <dt>{term}</dt>
                    <dd>{value}</dd>
                  </Fragment>
                ))}
              </dl>
            </FieldDisclosure>
          ))}
        </section>
        <aside className="stack">
          <section className="panel">
            <div className="panel-head">
              <h2>Restore environment</h2>
            </div>
            <dl className="kv">
              <dt>Sandbox</dt>
              <dd>sbx-probe-v1 · new, no egress</dd>
              <dt>Physical host</dt>
              <dd>lab-02 (separate VM)</dd>
              <dt>Cleanup</dt>
              <dd>
                <span className="state ok">
                  <Glyph icon={CircleCheck} />
                  Verified 11:31
                </span>
              </dd>
              <dt>Attester</dt>
              <dd>
                executor on lab-02 · key <code>SHA256:Lx2…9ae</code>
                <p className="cap">Self-attested. This is not independent evidence.</p>
              </dd>
            </dl>
          </section>
          <section className="panel">
            <div className="panel-head">
              <h2>Timing</h2>
            </div>
            <dl className="kv tnum">
              <dt>Snapshot age at test</dt>
              <dd>9 h 20 m</dd>
              <dt>RPO target</dt>
              <dd>24 h target; daily capture, not yet measured</dd>
              <dt>Fetch</dt>
              <dd>2 m 10 s</dd>
              <dt>Decrypt</dt>
              <dd>Failed after 14 s</dd>
              <dt>Restore</dt>
              <dd className="muted">Not run</dd>
            </dl>
          </section>
          <section className="panel">
            <div className="panel-head">
              <h2>Safe next step</h2>
            </div>
            <p className="muted">
              Update the offline escrow copy of the repository key, then record a new key-recovery
              drill. The recovery guide covers both steps without RustIron.
            </p>
            <p style={{ marginTop: 8 }}>
              <Link to="/help/$slug" params={{ slug: "backups-and-recovery" }}>
                Repository key recovery guide
              </Link>
            </p>
          </section>
        </aside>
      </div>
    </Page>
  );
}
