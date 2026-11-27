// W714 (pass 33, fix 7): Site list and per-site pages. Split from `pages.tsx`.
import { Link } from "@tanstack/react-router";
import {
  BookOpen,
  ChevronDown,
  FileCode,
  CircleAlert,
  CircleCheck,
  CircleDashed,
  CircleMinus,
  CircleX,
  Clock,
  ClockAlert,
  KeyRound,
  Search,
  TriangleAlert,
} from "lucide-react";
import { type ReactNode, useState } from "react";
import { useData } from "./data";
import { LiveSiteCoordinatorPanel } from "./live-coordinator";
import { useDrawerSelection } from "./inspector";
import { SiteInspector } from "./platform-subviews";
import {
  type OperationRow,
  type Site,
  type SiteJournal,
  type SiteSnapshot,
  sites,
} from "./fixture";
import { CopyId, Crumbs, EvidenceStrip, Glyph, Page, Sparkline, TableScroll } from "./ui";
import {
  EvidenceKey,
  Missing,
  RecoveryStateLabel,
  SourceNote,
  matchesOutcome,
  observedText,
} from "./page-parts";

function matchesSiteFilter(site: Site, needle: string, stateFilter: string): boolean {
  if (stateFilter !== "all" && site.servingKind !== stateFilter) return false;
  if (!needle) return true;
  return `${site.domain} ${site.id} ${site.runtime}`.toLowerCase().includes(needle);
}

export function SitesPage() {
  const data = useData();
  const [query, setQuery] = useState("");
  const [stateFilter, setStateFilter] = useState("all");
  const [selectedId, setSelectedId] = useDrawerSelection<string>();
  const needle = query.trim().toLowerCase();
  const visible = data.sites.filter((site) => matchesSiteFilter(site, needle, stateFilter));
  const selected = visible.find((site) => site.id === selectedId) ?? null;

  return (
    <Page live>
      <div className="page-head">
        <div>
          <h1>Sites</h1>
          <p className="sub">
            WordPress sites registered on{" "}
            {data.source.kind === "live"
              ? data.source.host.host_id
              : data.source.kind === "fixture"
                ? "lab-01"
                : "this host"}
            , with serving state, ownership and recovery evidence.
          </p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <Link className="btn primary sm" to="/sites/new">
            Add website
          </Link>
          <Link className="btn quiet sm" to="/help/$slug" params={{ slug: "wordpress-sites" }}>
            <Glyph icon={BookOpen} />
            Site guide
          </Link>
        </div>
      </div>
      <section className="panel flush" aria-label="Sites table">
        <div className="toolbar">
          <label className="input search-input">
            <Glyph icon={Search} />
            <input
              aria-label="Filter sites by hostname"
              placeholder="Filter by hostname"
              autoComplete="off"
              spellCheck={false}
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
          </label>
          <label className="field">
            State
            <select
              className="input"
              aria-label="Filter sites by state"
              value={stateFilter}
              onChange={(event) => setStateFilter(event.target.value)}
            >
              <option value="all">All states</option>
              <option value="ok">Serving</option>
              <option value="err">Blocked</option>
              <option value="muted">Not serving</option>
            </select>
          </label>
          <span className="muted" style={{ marginLeft: "auto", fontSize: 13 }}>
            {visible.length} of {data.sites.length} sites · <SourceNote />
          </span>
        </div>
        <TableScroll label="Sites">
          <table className="data">
            <thead>
              <tr>
                <th>Site</th>
                <th>Serving</th>
                <th>Runtime</th>
                <th>Ownership</th>
                <th>Last operation</th>
                <th>Recovery evidence</th>
                <th>HTTP</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((site) => (
                <SiteRow
                  key={site.id}
                  site={site}
                  selected={selected?.id === site.id}
                  onInspect={() => setSelectedId((prev) => (prev === site.id ? null : site.id))}
                />
              ))}
            </tbody>
          </table>
        </TableScroll>
        <div className="pager">
          <span>
            {visible.length ? `1–${visible.length} of ${visible.length}` : "No matching sites"}
          </span>
          <span>
            Order: artifacts · integrity · decryption · app consistency · isolated restore · health
            checks · independent copy
          </span>
        </div>
      </section>

      {selected ? <SiteInspector site={selected} onClose={() => setSelectedId(null)} /> : null}
    </Page>
  );
}

function operationParams(href: string | null): { operationId: string } | undefined {
  if (!href?.startsWith("/operations/")) return undefined;
  return { operationId: href.slice("/operations/".length) };
}

function OperationLink({ site }: { site: Site }) {
  const params = operationParams(site.operationHref);
  return params ? (
    <Link to="/operations/$operationId" params={params}>
      {site.operation}
    </Link>
  ) : (
    <>{site.operation}</>
  );
}

function SiteRow({
  site,
  selected,
  onInspect,
}: {
  site: Site;
  selected: boolean;
  onInspect: () => void;
}) {
  return (
    <tr className={selected ? "selected" : undefined}>
      <td className="primary-cell">
        <Link to="/sites/$siteId" params={{ siteId: site.id }}>
          {site.domain}
        </Link>
        <small className="mono" translate="no">
          {site.id}
        </small>
      </td>
      <td>
        <span className={`state ${site.servingKind}`}>{site.serving}</span>
      </td>
      <td className={site.runtime === "Not identified" ? "muted" : undefined}>{site.runtime}</td>
      <td>{site.ownership}</td>
      <td>
        <OperationLink site={site} />
        {site.operationDetail ? (
          <small className="cap" style={{ display: "block" }}>
            {site.operationDetail}
          </small>
        ) : null}
      </td>
      <td>
        <EvidenceStrip marks={site.marks} />
      </td>
      <td className={`tnum ${site.httpKind === "muted" ? "muted" : ""}`}>
        <span
          className={
            site.httpKind === "warn" || site.httpKind === "stale"
              ? `state ${site.httpKind}`
              : undefined
          }
        >
          {site.http}
        </span>
      </td>
      <td>
        <button
          type="button"
          className="btn quiet sm"
          aria-pressed={selected}
          aria-label={`Inspect ${site.domain}`}
          onClick={onInspect}
        >
          {selected ? "Close" : "Inspect"}
        </button>
      </td>
    </tr>
  );
}

function SiteTabs({ site, current }: { site: Site; current: string }) {
  const base = `/sites/${site.id}`;
  const tabs = [
    ["Overview", base],
    ["Configuration", `${base}/configuration`],
    ["Maintenance", `${base}/maintenance`],
    ["Operations", `${base}/operations`],
    ["Recovery", `${base}/recovery`],
  ];
  return (
    <nav className="tabs" aria-label="Site sections">
      {tabs.map(([label, href]) => (
        <Link key={label} to={href} aria-current={current === label ? "page" : undefined}>
          {label}
        </Link>
      ))}
    </nav>
  );
}

/** The detailed fixture covers shop.lab.test, the site every mockup uses. */
const detailedSiteId = "site_8KD2QW";

const httpState = {
  ok: { label: "Serving", icon: CircleCheck },
  warn: { label: "Serving, slow", icon: ClockAlert },
  stale: { label: "Observation stale", icon: Clock },
  muted: { label: "Not observed", icon: CircleMinus },
} as const;

/** W372 adopted sites were verified by a re-adoption; Rustiron did not create them. */
function ownershipLabel(ownership: string): string {
  if (ownership === "Created") return "Created by Rustiron";
  if (ownership === "Adopted") return "Adopted by re-adoption";
  return ownership;
}

/**
 * W737 (QA-06): the HTTP card names the observation the status came from. A
 * live status other than 200 is shown as such, not as "slow".
 */
function httpObservation(site: Site, source: ReturnType<typeof useData>["source"]) {
  const state = httpState[site.httpKind];
  if (site.httpKind === "muted") return { ...state, note: "No HTTP observation" };
  if (source.kind !== "live") return { ...state, note: "HTTP observed 16:41 UTC · 1 min ago" };
  const label = site.httpKind === "warn" ? `Answers HTTP ${site.http}` : state.label;
  return {
    ...state,
    label,
    note: `HTTP ${site.http} · observed ${observedText(source.observedAt)}`,
  };
}

function SiteHead({ site }: { site: Site }) {
  const { source } = useData();
  const http = httpObservation(site, source);
  return (
    <div className="page-head">
      <div>
        <h1 translate="no">{site.domain}</h1>
        <div className="row" style={{ marginTop: 6 }}>
          {site.id === detailedSiteId && site.servingKind === "err" ? (
            <span className="pill err">
              <Glyph icon={CircleAlert} />
              Blocked by operation
            </span>
          ) : (
            <span className={site.servingKind === "err" ? "pill err" : "pill"}>
              Serving: {site.serving}
            </span>
          )}
          {/* W750 (QA-19): each chip names its fact, so two "Not observed" read apart. */}
          <span className="pill">Runtime: {site.runtime}</span>
          <span className="pill">{ownershipLabel(site.ownership)}</span>
          <CopyId id={site.id} label="site ID" />
        </div>
      </div>
      <div className="host-ctx" aria-label="Site HTTP observation">
        <div>
          <span className={`state ${site.httpKind}`}>
            <Glyph icon={http.icon} />
            {http.label}
          </span>
          <small>{http.note}</small>
        </div>
      </div>
    </div>
  );
}

function SiteSection({
  siteId,
  tab,
  children,
}: {
  siteId: string;
  tab: string;
  children: (site: Site) => ReactNode;
}) {
  const data = useData();
  const site = data.sites.find((item) => item.id === siteId);
  if (!site) return <Missing name={siteId} />;
  const crumbs =
    tab === "Overview"
      ? [{ href: "/sites", label: "Sites" }, { label: site.domain }]
      : [
          { href: "/sites", label: "Sites" },
          { href: `/sites/${site.id}`, label: site.domain },
          { label: tab },
        ];
  return (
    <Page live={site.id !== detailedSiteId}>
      <Crumbs items={crumbs} />
      <SiteHead site={site} />
      <SiteTabs site={site} current={tab} />
      {children(site)}
      {site.id === detailedSiteId ? null : (
        <p className="cap muted">
          {data.source.kind === "live"
            ? site.httpKind === "muted"
              ? "From the executor journal: ownership, operations and recovery. Serving, HTTP and runtime are not observed yet."
              : "From the executor journal: ownership, operations and recovery. HTTP comes from the host status of the same observation; runtime is not observed yet."
            : "The detailed fixture covers shop.lab.test. Other sites show their summary records only."}
        </p>
      )}
    </Page>
  );
}

function BlockedNotice() {
  return (
    <div className="attention err">
      <Glyph icon={TriangleAlert} />
      <div className="att-body">
        <strong>New operations are blocked for this site.</strong> Configuration activation
        op_7Q2KX9 could not verify the all-site probe. The site is serving, but generation 42 may or
        may not be active for every listener.
        <div className="att-meta">
          Read-only diagnosis remains available · resolving requires a new reviewed recovery plan
        </div>
      </div>
      <Link className="btn sm" to="/operations/$operationId" params={{ operationId: "op_7Q2KX9" }}>
        Inspect operation
      </Link>
    </div>
  );
}

function ExposureTerm({ text }: { text: string | undefined }) {
  if (!text) return null;
  return (
    <>
      <dt>Local data-loss gap</dt>
      <dd>{text}</dd>
    </>
  );
}

function RecoveryReadiness({ site }: { site: Site }) {
  const row = useData().recovery.find((item) => item.siteId === site.id);
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Recovery readiness</h2>
        <Link to="/sites/$siteId/recovery" params={{ siteId: site.id }}>
          Details
        </Link>
      </div>
      <dl className="kv">
        <dt>Latest snapshot</dt>
        <dd>{row?.snapshot ?? row?.snapshotNote ?? "No snapshot"}</dd>
        <ExposureTerm text={row?.exposure} />
        <dt>Last restore test</dt>
        <dd>
          {row?.restore ? (
            <RecoveryStateLabel state={row.restore} />
          ) : (
            <span className="muted">Not run</span>
          )}
        </dd>
        <dt>Evidence</dt>
        <dd>
          <EvidenceStrip marks={site.marks} />
        </dd>
      </dl>
      {site.id === detailedSiteId ? (
        <p className="cap" style={{ marginTop: 12 }}>
          Capture and integrity checks passed. Restore, health checks and independence are not
          proven for this snapshot.
        </p>
      ) : null}
    </section>
  );
}

function ShopOverviewPanels() {
  return (
    <>
      <div className="grid g3 detail-cards">
        <section className="panel">
          <div className="panel-head">
            <h2>HTTP observation</h2>
            <span className="meta">16:41 UTC</span>
          </div>
          <dl className="kv tnum">
            <dt>Request</dt>
            <dd>
              <code>GET https://shop.lab.test/</code>
            </dd>
            <dt>Status</dt>
            <dd>200 OK</dd>
            <dt>Time to first byte</dt>
            <dd>
              <span className="state warn">1.9 s</span>{" "}
              <span className="cap">(7-day median 210 ms)</span>
            </dd>
            <dt>TLS certificate</dt>
            <dd>Valid until 18 Jan 2027</dd>
            <dt>Generation served</dt>
            <dd>
              <span className="state unknown">
                <Glyph icon={CircleDashed} />
                Unknown (41 or 42)
              </span>
            </dd>
          </dl>
        </section>
        <section className="panel">
          <div className="panel-head">
            <h2>Runtime and identity</h2>
            <span className="meta">16:05 UTC</span>
          </div>
          <dl className="kv">
            <dt>PHP process identity</dt>
            <dd>
              <code>u_shop:g_shop</code>{" "}
              <span className="state ok">
                <Glyph icon={CircleCheck} />
                Verified
              </span>
            </dd>
            <dt>PHP workers</dt>
            <dd className="tnum">3 of 6 max</dd>
            <dt>Database</dt>
            <dd>
              <code>db_shop</code> · 412 MiB
            </dd>
            <dt>Document root</dt>
            <dd>
              <code>/srv/sites/site_8KD2QW/public</code>
            </dd>
            <dt>Files</dt>
            <dd className="tnum">2.3 GiB · 41,208 inodes</dd>
          </dl>
        </section>
        <section className="panel">
          <div className="panel-head">
            <h2>Resource use</h2>
            <span className="meta">last 24 h</span>
          </div>
          <ul className="list tnum">
            {(
              [
                ["PHP CPU", "Mean across workers", "cpu", 11, 30, "9.1%"],
                ["PHP memory", "Resident", "memory", 5, 45, "610 MiB"],
                ["Disk", "Files + database", "disk", 2, 60, "2.7 GiB"],
              ] as const
            ).map(([title, detail, color, seed, base, value]) => (
              <li key={title}>
                <span className="grow">
                  <span className="t">{title}</span>
                  <span className="s">{detail}</span>
                </span>
                <Sparkline seed={seed} base={base} color={color} />
                <span className="r">{value}</span>
              </li>
            ))}
          </ul>
        </section>
      </div>
      <div className="grid g2">
        <section className="panel">
          <div className="panel-head">
            <h2>Recent operations</h2>
            <Link to="/sites/$siteId/operations" params={{ siteId: detailedSiteId }}>
              View all
            </Link>
          </div>
          <ul className="list">
            <li>
              <Glyph icon={CircleAlert} className="list-err" />
              <span className="grow">
                <span className="t">Config activation · generation 42</span>
                <span className="s">Needs attention · op_7Q2KX9</span>
              </span>
              <span className="r">16:07</span>
            </li>
            <li>
              <Glyph icon={CircleCheck} className="list-ok" />
              <span className="grow">
                <span className="t">Backup capture</span>
                <span className="s">Succeeded · snapshot snap_P8Q1</span>
              </span>
              <span className="r">Yesterday</span>
            </li>
            <li>
              <Glyph icon={CircleCheck} className="list-ok" />
              <span className="grow">
                <span className="t">Config activation · generation 41</span>
                <span className="s">Succeeded · op_4MN2P1</span>
              </span>
              <span className="r">Tue</span>
            </li>
          </ul>
        </section>
        <RecoveryReadiness site={sites.find((site) => site.id === detailedSiteId) as Site} />
      </div>
    </>
  );
}

export function SiteOverview({ siteId }: { siteId: string }) {
  return (
    <SiteSection siteId={siteId} tab="Overview">
      {(current) =>
        current.id === detailedSiteId ? (
          <>
            <BlockedNotice />
            <ShopOverviewPanels />
          </>
        ) : (
          <>
            <div className="grid g3">
              <section className="panel">
                <div className="panel-head">
                  <h2>HTTP observation</h2>
                </div>
                <dl className="kv tnum">
                  <dt>Status</dt>
                  <dd>{current.http}</dd>
                  <dt>Runtime</dt>
                  <dd>{current.runtime}</dd>
                  <dt>Ownership</dt>
                  <dd>{ownershipLabel(current.ownership)}</dd>
                </dl>
              </section>
              <section className="panel">
                <div className="panel-head">
                  <h2>Last operation</h2>
                </div>
                <p>
                  <OperationLink site={current} />
                </p>
                <p className="cap">{current.operationDetail || "No recorded operation"}</p>
              </section>
              <RecoveryReadiness site={current} />
            </div>
            {current.journal ? <SiteJournalPanel journal={current.journal} /> : null}
            <LiveSiteCoordinatorPanel siteId={current.id} />
          </>
        )
      }
    </SiteSection>
  );
}

/** W379: page cache, quota and adoption as the journal records them; nothing is read live. */
function SiteJournalPanel({ journal }: { journal: SiteJournal }) {
  return (
    <section className="panel" aria-labelledby="site-journal-t">
      <div className="panel-head">
        <h2 id="site-journal-t">Recorded settings</h2>
        <span className="meta">Executor journal, not a live read</span>
      </div>
      <dl className="kv">
        <dt>Page cache</dt>
        <dd>{journal.pageCache}</dd>
        <dt>Cache state</dt>
        <dd>Plugin state and cache hits are not in this observation</dd>
        <dt>Disk quota limit</dt>
        <dd className="tnum">{journal.quotaLimit}</dd>
        <dt>Disk quota usage</dt>
        <dd>{journal.quotaUsage}</dd>
        {journal.adoption ? (
          <>
            <dt>Re-adoption</dt>
            <dd>
              <Link
                to="/operations/$operationId"
                params={{ operationId: journal.adoption.operationId }}
              >
                {journal.adoption.operationId}
              </Link>{" "}
              · from epoch <span translate="no">{journal.adoption.previousEpoch}</span> ·{" "}
              <span translate="no">{journal.adoption.evidence}</span>
            </dd>
          </>
        ) : null}
      </dl>
    </section>
  );
}

type Comparison = { label: string; kind: "ok" | "warn" | "unknown" };

const comparisonIcon = { ok: CircleCheck, warn: TriangleAlert, unknown: CircleDashed } as const;

function shopSettings(generation: 41 | 42): [string, ReactNode, ReactNode, Comparison][] {
  const matches: Comparison = { label: "Matches", kind: "ok" };
  return [
    ["Hostname", <code key="m">shop.lab.test</code>, <code key="o">shop.lab.test</code>, matches],
    ["Runtime profile", "wordpress-lsphp84 · rev 3", "lsphp84 · 8.4.13", matches],
    [
      "Rewrite recipe",
      "wordpress-pretty-permalinks · v2",
      "wordpress-pretty-permalinks · v2",
      matches,
    ],
    ["Cache recipe", "none", "LSCache rule block present", { label: "Drift", kind: "warn" }],
    generation === 41
      ? ["PHP worker limit", "6", "6", matches]
      : ["PHP worker limit", "8", "6 or 8", { label: "Activation uncertain", kind: "unknown" }],
    [
      "Document root",
      <>
        <code>site_8KD2QW/public</code> (derived)
      </>,
      <code key="o">/srv/sites/site_8KD2QW/public</code>,
      matches,
    ],
    [
      "TLS certificate",
      "Host ACME account",
      <span key="o" className="muted">
        Not readable by observer
      </span>,
      { label: "Not checked", kind: "unknown" },
    ],
  ];
}

function ShopConfiguration() {
  const [generation, setGeneration] = useState<41 | 42>(41);
  return (
    <div className="grid g-main-side">
      <div className="stack">
        <section className="panel flush" aria-labelledby="cfg-t">
          <div className="panel-head">
            <div>
              <h2 id="cfg-t">Managed settings</h2>
              <p className="cap">
                Generation 41 is the last verified generation · generation 42 activation is
                uncertain
              </p>
            </div>
            <div className="seg" role="group" aria-label="Generation">
              {([41, 42] as const).map((value) => (
                <button
                  key={value}
                  type="button"
                  aria-pressed={generation === value}
                  onClick={() => setGeneration(value)}
                >
                  {value} · {value === 41 ? "verified" : "uncertain"}
                </button>
              ))}
            </div>
          </div>
          <TableScroll label="Site settings">
            <table className="data">
              <thead>
                <tr>
                  <th scope="col">Setting</th>
                  <th scope="col">Managed value</th>
                  <th scope="col">Observed on host</th>
                  <th scope="col">Comparison</th>
                </tr>
              </thead>
              <tbody>
                {shopSettings(generation).map(([name, managed, observed, comparison]) => (
                  <tr key={name}>
                    <td>{name}</td>
                    <td>{managed}</td>
                    <td>{observed}</td>
                    <td>
                      <span className={`state ${comparison.kind}`}>
                        <Glyph icon={comparisonIcon[comparison.kind]} />
                        {comparison.label}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableScroll>
          <div className="pager">
            <span>Observed 16:41 UTC · 7 settings</span>
            <span>Schema: site-settings v1</span>
          </div>
        </section>
        <section className="panel">
          <div className="panel-head">
            <h2>Drift: cache recipe</h2>
            <span className="pill warn">Explanation only</span>
          </div>
          <p>
            The owned include for this site contains an LSCache rule block that no managed
            generation rendered. It was absent at the 16:03 pre-activation check and first observed
            at 16:05. Its source is unknown.
          </p>
          <p className="muted" style={{ marginTop: 8 }}>
            Rustiron does not repair drift automatically. To keep it, adopt it in a reviewed plan;
            to remove it, activate a reviewed configuration that renders the managed value.
          </p>
          <details className="disclose" style={{ marginTop: 12 }}>
            <summary>
              <Glyph icon={FileCode} />
              <span>Observed difference (redacted)</span>
              <Glyph icon={ChevronDown} className="chev" />
            </summary>
            <div className="d-body">
              <pre className="code">
                {`--- rendered  generation 41
+++ observed  16:05 UTC
@@ context /srv/sites/site_8KD2QW (include)
 rewrite  {
   enable 1
   autoLoadHtaccess 1
 }
+module cache {
+  ls_enabled 1
+  checkPrivateCache 1
+}`}
              </pre>
            </div>
          </details>
        </section>
      </div>
      <aside className="stack">
        <section className="panel">
          <div className="panel-head">
            <h2>Configuration scope</h2>
          </div>
          <dl className="kv">
            <dt>Owned include</dt>
            <dd>
              <code>conf/rustiron/sites/site_8KD2QW.conf</code>
            </dd>
            <dt>Parent config</dt>
            <dd>Adopted at bootstrap · not edited per site</dd>
            <dt>Global effect</dt>
            <dd>
              Every activation gracefully restarts OpenLiteSpeed and probes all 8 registered sites
            </dd>
            <dt>Last verified</dt>
            <dd>Generation 41 · Tue 14:02 UTC</dd>
          </dl>
        </section>
        <section className="panel">
          <div className="panel-head">
            <h2>Changing configuration</h2>
          </div>
          <p className="muted">
            The read-only console shows configuration and drift. Changes are made through a
            reviewed, separately approved plan.
          </p>
          <p className="cap" style={{ marginTop: 8 }}>
            Blocked until op_7Q2KX9 is resolved.
          </p>
        </section>
        <section className="panel">
          <div className="panel-head">
            <h2>Generation history</h2>
          </div>
          <ul className="list">
            {(
              [
                ["42 · PHP worker limit 6 → 8", "op_7Q2KX9 · uncertain", "Today"],
                ["41 · rewrite recipe v1 → v2", "op_4MN2P1 · verified", "Tue"],
                ["40 · initial generation", "op_1AA0RS · verified", "2 Oct"],
              ] as const
            ).map(([title, detail, when]) => (
              <li key={title}>
                <span className="grow">
                  <span className="t">{title}</span>
                  <span className="s">{detail}</span>
                </span>
                <span className="r">{when}</span>
              </li>
            ))}
          </ul>
        </section>
      </aside>
    </div>
  );
}

function ObservedSiteFacts({ site }: { site: Site }) {
  const journal = site.journal;
  const rows: [string, string][] = [
    ["Hostname", site.domain],
    ["Serving", site.serving],
    ["Ownership", ownershipLabel(site.ownership)],
    ["Runtime", site.runtime],
    ["HTTP", site.http],
    ...(journal
      ? ([
          ["Page cache", journal.pageCache],
          ["Disk quota limit", journal.quotaLimit],
          ["Disk quota usage", journal.quotaUsage],
          ...(journal.adoption
            ? [["Re-adoption", `${journal.adoption.operationId} · ${journal.adoption.evidence}`]]
            : []),
        ] as [string, string][])
      : []),
  ];
  return (
    <section className="panel flush">
      <TableScroll label="Site facts in this observation">
        <table className="data">
          <thead>
            <tr>
              <th scope="col">Fact</th>
              <th scope="col">In this observation</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(([name, value]) => (
              <tr key={name}>
                <th scope="row">{name}</th>
                <td translate={name === "Hostname" ? "no" : undefined}>{value}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableScroll>
      <p className="cap" style={{ marginTop: 12 }}>
        Managed OLS and PHP settings are not in this observation. The console does not invent a
        match.
      </p>
    </section>
  );
}

export function SiteConfiguration({ siteId }: { siteId: string }) {
  return (
    <SiteSection siteId={siteId} tab="Configuration">
      {(current) => (
        <>
          {current.id === detailedSiteId ? (
            <ShopConfiguration />
          ) : (
            <ObservedSiteFacts site={current} />
          )}
          <section className="panel" aria-labelledby="p24-drift-t">
            <div className="panel-head">
              <h2 id="p24-drift-t">Ownership-aware drift explanation</h2>
              <span className="pill">auto_reset: false</span>
            </div>
            <p className="muted">
              Any package update, manual emergency edit, or foreign resource delta blocks signed OLS
              activation until explained with{" "}
              <span className="mono">rustiron-control --explain-drift</span> and explicitly resolved
              (<span className="mono">adopt</span>, <span className="mono">restore_owned</span> on
              owned resources only, <span className="mono">ignore</span>, or{" "}
              <span className="mono">eject</span>). Foreign state is never silently reset.
            </p>
          </section>
        </>
      )}
    </SiteSection>
  );
}

type SiteOperationRow = {
  title: string;
  id: string;
  outcome: string;
  kind: "err" | "ok" | "warn" | "muted" | "info";
  icon: typeof CircleAlert;
  scope: string;
  started: string;
  duration: string;
  plan: string;
  linked: boolean;
};

const shopOperations: SiteOperationRow[] = [
  {
    title: "Config activation · gen 42",
    id: "op_7Q2KX9",
    outcome: "Needs attention",
    kind: "err",
    icon: CircleAlert,
    scope: "This site + global OLS reload",
    started: "24 Oct, 16:06",
    duration: "1 m 12 s",
    plan: "plan_3HV8RA",
    linked: true,
  },
  {
    title: "Config activation · gen 42",
    id: "—",
    outcome: "Rejected",
    kind: "muted",
    icon: CircleX,
    scope: "This site",
    started: "24 Oct, 15:58",
    duration: "—",
    plan: "Grant expired before admission; no effects",
    linked: false,
  },
  {
    title: "Backup capture",
    id: "op_9JW3LE",
    outcome: "Succeeded",
    kind: "ok",
    icon: CircleCheck,
    scope: "This site",
    started: "23 Oct, 02:00",
    duration: "6 m 41 s",
    plan: "plan_8TT2MK",
    linked: false,
  },
  {
    title: "Config activation · gen 41",
    id: "op_4MN2P1",
    outcome: "Succeeded",
    kind: "ok",
    icon: CircleCheck,
    scope: "This site + global OLS reload",
    started: "22 Oct, 14:01",
    duration: "48 s",
    plan: "plan_5DG7NV",
    linked: false,
  },
  {
    title: "Config activation · gen 41",
    id: "op_2KK9QP",
    outcome: "Failed, compensated",
    kind: "warn",
    icon: CircleCheck,
    scope: "This site + global OLS reload",
    started: "22 Oct, 13:40",
    duration: "1 m 30 s",
    plan: "plan_5DG7NV",
    linked: false,
  },
  {
    title: "Site provision",
    id: "op_1AA0RS",
    outcome: "Succeeded",
    kind: "ok",
    icon: CircleCheck,
    scope: "This site",
    started: "2 Oct, 10:15",
    duration: "3 m 05 s",
    plan: "plan_0FQ4HB",
    linked: false,
  },
];

function siteOperations(site: Site, operations: OperationRow[]): SiteOperationRow[] {
  if (site.id === detailedSiteId) return shopOperations;
  return operations
    .filter((row) => row.resources.includes(site.domain) || row.resources.split(" ")[0] === site.id)
    .map((row) => ({
      title: row.action,
      id: row.id,
      outcome: row.outcome,
      kind: row.kind,
      icon: row.icon,
      scope: row.resources.includes("global")
        ? "This site + global OLS reload"
        : row.resources.includes("sandbox")
          ? "This site · restore sandbox"
          : "This site",
      started: row.started,
      duration: row.duration,
      plan: "—",
      linked: row.linked,
    }));
}

const siteOperationStates = [
  "All states",
  "Needs attention",
  "Succeeded",
  "Failed",
  "Failed, compensated",
  "Rejected",
];

const siteOperationActions = [
  "All actions",
  "Config activation",
  "Backup capture",
  "Restore probe",
  "Site provision",
];

export function SiteOperations({ siteId }: { siteId: string }) {
  const data = useData();
  const [state, setState] = useState("All states");
  const [action, setAction] = useState("All actions");
  return (
    <SiteSection siteId={siteId} tab="Operations">
      {(current) => {
        const all = siteOperations(current, data.operations);
        const rows = all.filter(
          (row) =>
            (state === "All states" || matchesOutcome(row.outcome, state)) &&
            (action === "All actions" || row.title.startsWith(action)),
        );
        return (
          <section className="panel flush" aria-label={`Operations for ${current.domain}`}>
            <div className="toolbar">
              <label className="field">
                State
                <select
                  className="input"
                  value={state}
                  onChange={(event) => setState(event.target.value)}
                >
                  {siteOperationStates.map((option) => (
                    <option key={option}>{option}</option>
                  ))}
                </select>
              </label>
              <label className="field">
                Action
                <select
                  className="input"
                  value={action}
                  onChange={(event) => setAction(event.target.value)}
                >
                  {siteOperationActions.map((option) => (
                    <option key={option}>{option}</option>
                  ))}
                </select>
              </label>
              <span className="muted toolbar-end" style={{ fontSize: 13 }}>
                Includes operations with host-wide effects on this site
              </span>
            </div>
            <TableScroll label="Site operations">
              <table className="data">
                <thead>
                  <tr>
                    <th scope="col">Operation</th>
                    <th scope="col">Outcome</th>
                    <th scope="col">Scope</th>
                    <th scope="col">Started (UTC)</th>
                    <th scope="col" className="num">
                      Duration
                    </th>
                    <th scope="col">Plan</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row) => (
                    <tr key={`${row.id}-${row.started}`}>
                      <td className="primary-cell">
                        {row.linked ? (
                          <Link to="/operations/$operationId" params={{ operationId: row.id }}>
                            {row.title}
                          </Link>
                        ) : (
                          <strong>{row.title}</strong>
                        )}
                        <small className="mono">{row.id}</small>
                      </td>
                      <td>
                        <span className={`state ${row.kind}`}>
                          <Glyph icon={row.icon} />
                          {row.outcome}
                        </span>
                      </td>
                      <td>{row.scope}</td>
                      <td className="tnum">{row.started}</td>
                      <td className={row.duration === "—" ? "num muted" : "num"}>{row.duration}</td>
                      <td>
                        {row.plan === "plan_3HV8RA" ? (
                          <Link className="mono" to="/plans/$planId" params={{ planId: row.plan }}>
                            {row.plan}
                          </Link>
                        ) : row.plan.startsWith("plan_") ? (
                          <span className="mono">{row.plan}</span>
                        ) : (
                          <span className="cap">{row.plan}</span>
                        )}
                      </td>
                    </tr>
                  ))}
                  {rows.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="muted">
                        No operation for this site matches these filters.
                      </td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </TableScroll>
            <div className="pager">
              <span>
                {rows.length} of {all.length}
              </span>
              <span>Failed, compensated: only the predefined compensation was verified</span>
            </div>
          </section>
        );
      }}
    </SiteSection>
  );
}

const shopSnapshots: SiteSnapshot[] = [
  {
    id: "snap_P8Q1",
    note: "Files + DB · consistent window 41 s",
    captured: "23 Oct, 02:00–02:06",
    repository: "offsite-b2 · independent",
    size: "1.9 GiB",
    marks: ["pass", "pass", "pass", "not_run", "not_run", "not_run", "unknown"],
    restore: { label: "Not run", kind: "notrun" },
  },
  {
    id: "snap_N4D7",
    note: "Files + DB · consistent window 39 s",
    captured: "22 Oct, 02:00–02:05",
    repository: "offsite-b2 · independent",
    size: "1.9 GiB",
    marks: ["pass", "pass", "pass", "not_run", "not_run", "not_run", "unknown"],
    restore: { label: "Not run", kind: "notrun" },
  },
  {
    id: "snap_K2M9",
    note: "Files + DB · consistent window 44 s",
    captured: "15 Oct, 02:00–02:07",
    repository: "offsite-b2 · independent",
    size: "1.8 GiB",
    marks: ["pass", "pass", "pass", "pass", "pass", "pass", "pass"],
    restore: { label: "Passed 15 Oct", kind: "ok" },
  },
  {
    id: "snap_H7X1",
    note: "Files + DB · window not verified",
    captured: "8 Oct, 02:00–02:09",
    repository: "offsite-b2 · independent",
    size: "1.8 GiB",
    marks: ["pass", "pass", "pass", "unknown", "fail", "not_run", "pass"],
    restore: { label: "Failed 8 Oct", kind: "err" },
  },
];

function SnapshotsPanel({
  snapshots,
  pagerLabel,
  emptyNote = "No snapshots recorded for this site.",
}: {
  snapshots: SiteSnapshot[];
  pagerLabel: string;
  /** W382: what an empty table says, e.g. that an unclaimed snapshot exists. */
  emptyNote?: string;
}) {
  return (
    <section className="panel flush" aria-labelledby="snaps-t">
      <div className="panel-head">
        <div>
          <h2 id="snaps-t">Snapshots</h2>
          <p className="cap">Newest first · retention follows repository policy</p>
        </div>
      </div>
      <TableScroll label="Snapshots">
        <table className="data">
          <thead>
            <tr>
              <th scope="col">Snapshot</th>
              <th scope="col">Captured (UTC)</th>
              <th scope="col">Repository</th>
              <th scope="col" className="num">
                Size
              </th>
              <th scope="col">Evidence</th>
              <th scope="col">Restore test</th>
            </tr>
          </thead>
          <tbody>
            {snapshots.map((snapshot) => (
              <tr key={`${snapshot.id}-${snapshot.captured}`}>
                <td className="primary-cell">
                  {snapshot.artifactId || snapshot.id === "snap_P8Q1" ? (
                    <Link
                      to="/recovery/artifacts/$artifactId"
                      params={{ artifactId: snapshot.artifactId ?? snapshot.id }}
                    >
                      {snapshot.id}
                    </Link>
                  ) : (
                    <strong className="mono">{snapshot.id}</strong>
                  )}
                  <small>{snapshot.note}</small>
                </td>
                <td className="tnum">{snapshot.captured}</td>
                <td>{snapshot.repository}</td>
                <td className={snapshot.size === "—" ? "num muted" : "num tnum"}>
                  {snapshot.size}
                </td>
                <td>
                  <EvidenceStrip marks={snapshot.marks} />
                </td>
                <td>
                  <RecoveryStateLabel state={snapshot.restore} />
                </td>
              </tr>
            ))}
            {snapshots.length === 0 ? (
              <tr>
                <td colSpan={6} className="muted">
                  {emptyNote}
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </TableScroll>
      <div className="pager">
        <span>{pagerLabel}</span>
        <EvidenceKey />
      </div>
    </section>
  );
}

function ShopRecovery() {
  return (
    <>
      <div className="attention">
        <Glyph icon={TriangleAlert} />
        <div className="att-body">
          <strong>Recovery is not proven for the latest snapshot.</strong> snap_P8Q1 was captured
          and checked, but no isolated restore has run against it. The last proven restore used
          snap_K2M9 (9 days old).
          <div className="att-meta">A successful upload is not a tested recovery</div>
        </div>
      </div>
      <SnapshotsPanel snapshots={shopSnapshots} pagerLabel="4 most recent of 14" />
      <div className="grid g2">
        <section className="panel">
          <div className="panel-head">
            <h2>Recovery objectives</h2>
            <span className="pill dashed">Targets · not measured</span>
          </div>
          <dl className="kv tnum">
            <dt>RPO target</dt>
            <dd>24 h target; daily capture at 02:00 UTC, not yet measured</dd>
            <dt>Last measured restore</dt>
            <dd>11 m 20 s in isolated sandbox (15 Oct)</dd>
            <dt>Production RTO</dt>
            <dd className="muted">
              Not promised: a timed sandbox restore is not an operational RTO
            </dd>
          </dl>
        </section>
        <section className="panel">
          <div className="panel-head">
            <h2>Guides</h2>
          </div>
          <ul className="list">
            <li>
              <Glyph icon={BookOpen} className="list-info" />
              <span className="grow">
                <Link className="t" to="/help/$slug" params={{ slug: "backups-and-recovery" }}>
                  Manual restore without RustIron
                </Link>
                <span className="s">Verified 15 Oct on clean host</span>
              </span>
            </li>
            <li>
              <Glyph icon={KeyRound} className="list-info" />
              <span className="grow">
                <Link className="t" to="/help/$slug" params={{ slug: "backups-and-recovery" }}>
                  Repository key recovery
                </Link>
                <span className="s">Drill recorded 1 Oct</span>
              </span>
            </li>
          </ul>
        </section>
      </div>
    </>
  );
}

export function SiteRecovery({ siteId }: { siteId: string }) {
  const data = useData();
  return (
    <SiteSection siteId={siteId} tab="Recovery">
      {(current) => {
        if (current.id === detailedSiteId) return <ShopRecovery />;
        if (data.source.kind === "live") {
          const snapshots = data.siteSnapshots[current.id] ?? [];
          // W382: a settled capture's unclaimed snapshot is named, never hidden.
          const note = data.recovery.find((row) => row.siteId === current.id)?.snapshotNote;
          return (
            <div className="stack">
              <RecoveryReadiness site={current} />
              <SnapshotsPanel
                snapshots={snapshots}
                pagerLabel={`${snapshots.length} recorded in journal`}
                emptyNote={note?.includes("unclaimed") ? note : undefined}
              />
            </div>
          );
        }
        return <RecoveryReadiness site={current} />;
      }}
    </SiteSection>
  );
}
