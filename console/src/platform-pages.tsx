// W604 (P29): Read-only developer hosting-platform views ported from
// docs/mockup/screens/ to Astryx + scoped CSS (Apps/EmDash, Host Diagnoses,
// Host Updates, Domains, Migration). No view here writes to or changes the host.
import { APP_TABS, type AppTab } from "./app-tabs";
import { Link } from "@tanstack/react-router";
import {
  ArrowLeft,
  ChevronDown,
  ChevronRight,
  CircleCheck,
  CircleMinus,
  CircleX,
  Copy,
  KeyRound,
  Layers,
  Server,
  ShieldCheck,
  Terminal,
} from "lucide-react";
import { useState } from "react";
import { AnswerLine, QuietDetails, SimpleHeader, type Tone } from "@/components/console/simple";

import { MigrationWizardsPanel } from "./backup-migration-wizards";
import { isRealHost, useData } from "./data";
import {
  type AppRecord,
  type DiagnosisFinding,
  type DomainRecord,
  fixtureApps,
  fixtureDomains,
  fixtureFindings,
  fixtureMigrations,
  liveApps,
  liveDomains,
  liveFindings,
  liveMigrations,
  liveSupportComponents,
  type MigrationRecord,
  type SupportComponent,
} from "./platform-data";
import { FindingChip, OwnerBadge } from "./findings-panel";
import { InspectorPanel, useDrawerSelection } from "./inspector";
import {
  type BulkAction,
  BulkBar,
  PageCheck,
  RowCheck,
  type Selection,
  useSelection,
} from "@/components/console/bulk";
import { buildAppLifecycleCmd } from "./cli-commands";
import {
  FilterChips,
  ListArea,
  ListControls,
  ListToolbar,
  matches,
  rowClass,
  rowLinkClass,
  SMALL_LIST,
  usePaged,
} from "@/components/console/list";
import { copyText, Crumbs, EmptyState, Glyph, Page, TableScroll } from "./ui";

function releasePillClass(state: AppRecord["releases"][number]["state"]) {
  if (state === "active") return "pill ok";
  if (state === "failed_compensated") return "pill err";
  return "pill";
}

function servingIcon(kind: AppRecord["servingKind"]) {
  if (kind === "ok") return CircleCheck;
  if (kind === "err") return CircleX;
  return CircleMinus;
}

type AppSort = "attention" | "name" | "kind";
/** A static app has no unit to restart, so it is never chosen for bulk restart. */
const restartable = (app: AppRecord) => app.runtimeProfile !== "static_v1";
const appHealthy = (app: AppRecord) => app.servingKind === "ok" && app.healthKind === "ok";
const appSorters: Record<AppSort, (a: AppRecord, b: AppRecord) => number> = {
  attention: (a, b) =>
    Number(appHealthy(a)) - Number(appHealthy(b)) || a.hostname.localeCompare(b.hostname),
  name: (a, b) => a.hostname.localeCompare(b.hostname),
  kind: (a, b) => a.kind.localeCompare(b.kind) || a.hostname.localeCompare(b.hostname),
};

/** Restart several apps: one signed `app-lifecycle` plan per app (item 64). */
const appBulkActions: BulkAction[] = [
  {
    label: "Restart",
    question: (n) => `Restart ${n} ${n === 1 ? "app" : "apps"}?`,
    command: (siteId) => buildAppLifecycleCmd({ siteId, action: "restart" }),
  },
];

const dbEngineLabels: Record<AppRecord["database"], string> = {
  none: "None",
  sqlite: "SQLite (WAL)",
  mariadb: "MariaDB 10.11",
  postgresql_18: "PostgreSQL 18",
};

function appFilterMatch(app: AppRecord, filter: "all" | "attention" | "running"): boolean {
  if (filter === "all") return true;
  return filter === "attention" ? !appHealthy(app) : appHealthy(app);
}

/** The app's one word: Running, or what is wrong. */
function appWord(app: AppRecord): { word: string; tone: string } {
  if (appHealthy(app)) return { word: "Running", tone: "ok" };
  if (app.servingKind === "ok") return { word: app.health, tone: app.healthKind };
  return { word: app.serving, tone: app.servingKind };
}

function AppRow({
  app,
  selection,
  open,
  onInspect,
}: {
  app: AppRecord;
  selection: Selection | null;
  open: boolean;
  onInspect: () => void;
}) {
  const word = appWord(app);
  return (
    <li className={rowClass}>
      {selection && restartable(app) ? (
        <RowCheck selection={selection} id={app.siteId} label={app.hostname} />
      ) : selection ? (
        <span className="size-8 shrink-0" />
      ) : null}
      <div className="min-w-0 flex-1">
        <Link className={rowLinkClass} to="/apps/$appId" params={{ appId: app.id }} translate="no">
          {app.hostname}
        </Link>
        <p className="truncate text-sm text-muted-foreground">
          {app.kind} · release <span className="mono">{app.currentRelease}</span>
        </p>
      </div>
      <span className="flex justify-end sm:w-44">
        <span className={`pill ${word.tone}`}>
          <Glyph icon={servingIcon(appHealthy(app) ? "ok" : app.servingKind)} />
          {word.word}
        </span>
      </span>
      <button
        type="button"
        className="btn quiet sm relative z-10"
        aria-pressed={open}
        aria-label={`Inspect ${app.hostname}`}
        onClick={onInspect}
      >
        {open ? "Close" : "Inspect"}
      </button>
    </li>
  );
}

function AppList({
  apps,
  selectedId,
  onSelect,
}: {
  apps: AppRecord[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<"all" | "attention" | "running">("all");
  const [sort, setSort] = useState<AppSort>("attention");
  const selection = useSelection();
  const attention = apps.filter((app) => !appHealthy(app)).length;
  const visible = apps
    .filter((app) => matches(query, app.hostname, app.kind))
    .filter((app) => appFilterMatch(app, filter))
    .sort(appSorters[sort]);
  const paged = usePaged(visible, `${query}|${filter}|${sort}|${apps.length}`);
  const bulk = apps.filter(restartable).length > 1;
  return (
    <div className="flex flex-col gap-4">
      <ListToolbar
        hidden={apps.length <= SMALL_LIST}
        filters={
          <FilterChips
            label="Show"
            value={filter}
            onChange={setFilter}
            options={[
              { value: "all", label: "All", count: apps.length },
              { value: "attention", label: "Needs a look", count: attention },
              { value: "running", label: "Running", count: apps.length - attention },
            ]}
          />
        }
      >
        <ListControls
          count={apps.length}
          searchLabel="Find an app"
          query={query}
          onQuery={setQuery}
          sort={sort}
          onSort={setSort}
          sorts={[
            { value: "attention", label: "Needs a look first" },
            { value: "name", label: "Name A–Z" },
            { value: "kind", label: "Kind of app" },
          ]}
        />
      </ListToolbar>
      <ListArea
        label="Apps"
        noun="apps"
        total={apps.length}
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
            pageIds={paged.rows.filter(restartable).map((app) => app.siteId)}
            noun="apps"
          />
        }
        bottom={
          <BulkBar
            selection={selection}
            matchingIds={visible.filter(restartable).map((app) => app.siteId)}
            nameOf={(id) => apps.find((app) => app.siteId === id)?.hostname ?? id}
            noun="apps"
            one="app"
            actions={appBulkActions}
          />
        }
      >
        {paged.rows.map((app) => (
          <AppRow
            key={app.id}
            app={app}
            selection={bulk ? selection : null}
            open={selectedId === app.id}
            onInspect={() => onSelect(app.id)}
          />
        ))}
      </ListArea>
    </div>
  );
}

function AppInspector({ selected, onClose }: { selected: AppRecord; onClose: () => void }) {
  return (
    <InspectorPanel
      ariaLabel="App details"
      title={selected.hostname}
      subtitle={`${selected.runtimeProfile} · ${selected.account}`}
      monoTitle
      closeLabel="Close app details"
      onClose={onClose}
    >
      {selected.failedReleaseNote ? (
        <div className="attention err" role="status">
          <Glyph icon={CircleX} />
          <div className="att-body">
            <strong>Automatic rollback preserved serving.</strong> {selected.failedReleaseNote}
          </div>
        </div>
      ) : null}
      <dl className="kv">
        <dt>Runtime</dt>
        <dd>{selected.runtime}</dd>
        <dt>Edge ingress</dt>
        <dd>
          {selected.ingress} · <span className="mono">{selected.topology}</span>
        </dd>
        <dt>Database</dt>
        <dd>{dbEngineLabels[selected.database]}</dd>
        {selected.blueGreen ? (
          <>
            <dt>Blue/Green slot</dt>
            <dd className="mono">
              active slot {selected.blueGreen.activeSlot.toUpperCase()} · standby 127.0.0.1:
              {selected.blueGreen.standbyPort}
            </dd>
          </>
        ) : null}
        <dt>Systemd unit</dt>
        <dd className="mono">{selected.unit}</dd>
        <dt>Worker unit</dt>
        <dd className="mono">{selected.workerUnit ?? "None"}</dd>
        <dt>WebSocket</dt>
        <dd className="mono">{selected.websocketPrefix ?? "Disabled"}</dd>
        <dt>Limits</dt>
        <dd>{selected.limits}</dd>
        <dt>Secrets (0400)</dt>
        <dd>
          {selected.envKeys.length} declared key names ({selected.envKeys.join(", ") || "none"});
          values never enter plans or browser
        </dd>
        <dt>App backup</dt>
        <dd>{selected.sqliteBackup}</dd>
      </dl>
      <div className="insp-actions">
        <Link className="btn sm" to="/apps/$appId" params={{ appId: selected.id }}>
          Open app record
        </Link>
        <Link className="btn quiet sm" to="/recovery">
          Recovery evidence
        </Link>
      </div>
    </InspectorPanel>
  );
}

export function AppsPage() {
  const data = useData();
  const isLive = isRealHost(data.source);
  const observedApps = data.observation ? liveApps(data.observation) : [];
  const allApps: AppRecord[] = isLive ? observedApps : fixtureApps;
  const apps = allApps;
  const [selectedId, setSelectedId] = useDrawerSelection<string>();
  const selected = apps.find((a) => a.id === selectedId) ?? null;

  return (
    <Page live>
      <Crumbs items={[{ href: "/", label: "Overview" }, { label: "Apps" }]} />
      <div className="page-head">
        <SimpleHeader
          title="Apps"
          answer={<AppsAnswer apps={allApps} loading={data.source.kind === "loading"} />}
        />
        <Link className="btn primary sm" to="/sites/new">
          Deploy app
        </Link>
      </div>
      {isLive && allApps.length === 0 ? (
        <EmptyState
          icon={Layers}
          title="No modern apps deployed on this host yet"
          description="Live mode never shows mock apps. Provision a Node.js 22, Bun 1.4, or EmDash 1.6.0 app with a signed plan and it will appear here automatically."
          command="rustiron plan create app-provision --site app1 --hostname app.example.test --runtime node_22_v1 --port 3210 --out ./req"
          action={
            <>
              <Link className="btn primary sm" to="/plans/new">
                Create app plan
              </Link>
              <Link
                className="btn quiet sm"
                to="/help/$slug"
                params={{ slug: "modern-apps-and-emdash" }}
              >
                Apps &amp; EmDash guide
              </Link>
            </>
          }
        />
      ) : (
        <>
          <AppList
            apps={apps}
            selectedId={selected?.id ?? null}
            onSelect={(id) => setSelectedId((cur) => (cur === id ? null : id))}
          />
          {selected ? (
            <AppInspector selected={selected} onClose={() => setSelectedId(null)} />
          ) : null}
        </>
      )}
    </Page>
  );
}

function AppOverviewTab({ app }: { app: AppRecord }) {
  return (
    <>
      <section className="grid g4" aria-label="App summary">
        <article className="panel metric">
          <div className="m-head">
            <Glyph icon={ShieldCheck} /> Health
          </div>
          <div className="m-val" style={{ fontSize: 22 }}>
            {app.health}
          </div>
          <div className="m-detail mono">
            127.0.0.1:{app.port}
            {app.healthPath}
          </div>
        </article>
        <article className="panel metric">
          <div className="m-head">
            <Glyph icon={Layers} /> Active release
          </div>
          <div className="m-val mono" style={{ fontSize: 20 }}>
            {app.currentRelease}
          </div>
          <div className="m-detail">Read-only tree under releases/</div>
        </article>
        <article className="panel metric">
          <div className="m-head">
            <Glyph icon={Server} /> Isolation
          </div>
          <div className="m-val" style={{ fontSize: 20 }}>
            {app.account}
          </div>
          <div className="m-detail">{app.limits}</div>
        </article>
        <article className="panel metric">
          <div className="m-head">
            <Glyph icon={KeyRound} /> Scoped secrets
          </div>
          <div className="m-val" style={{ fontSize: 22 }}>
            {app.envKeys.length} keys
          </div>
          <div className="m-detail">0400 private/app.env · values never shown</div>
        </article>
      </section>
      <section className="grid g2">
        <article className="panel">
          <div className="panel-head">
            <h2>Runtime, ingress &amp; database</h2>
          </div>
          <dl className="kv">
            <dt>Profile</dt>
            <dd className="mono">
              {app.runtimeProfile} · {app.topology}
            </dd>
            <dt>Edge ingress</dt>
            <dd>{app.ingress}</dd>
            <dt>Database engine</dt>
            <dd>{dbEngineLabels[app.database]}</dd>
            <dt>Unit</dt>
            <dd className="mono">{app.unit}</dd>
            <dt>Companion worker</dt>
            <dd className="mono">{app.workerUnit ?? "None"}</dd>
            <dt>Proxy target</dt>
            <dd className="mono">
              {app.port > 0 ? `http://127.0.0.1:${app.port}` : "Static root served by Caddy"}
              {app.blueGreen
                ? ` (slot ${app.blueGreen.activeSlot.toUpperCase()} · standby :${app.blueGreen.standbyPort})`
                : ""}
            </dd>
            <dt>WebSocket prefix</dt>
            <dd className="mono">{app.websocketPrefix ?? "Disabled"}</dd>
            <dt>Backup status</dt>
            <dd>{app.sqliteBackup}</dd>
          </dl>
        </article>
        <article className="panel">
          <div className="panel-head">
            <h2>Recent releases</h2>
          </div>
          <ul className="list">
            {app.releases.map((rel) => (
              <li key={rel.releaseId}>
                <span className="grow">
                  <span className="t mono">{rel.releaseId}</span>
                  <span className="s">
                    {rel.version} · {rel.when}
                  </span>
                </span>
                <span className={releasePillClass(rel.state)}>{rel.state}</span>
              </li>
            ))}
          </ul>
        </article>
      </section>
    </>
  );
}

function AppDeploymentsTab({ app }: { app: AppRecord }) {
  return (
    <div className="panel flush">
      <TableScroll label="App release history">
        <table className="data">
          <thead>
            <tr>
              <th>Release ID</th>
              <th>Version</th>
              <th>Migration</th>
              <th>State</th>
              <th>When</th>
              <th>Outcome</th>
            </tr>
          </thead>
          <tbody>
            {app.releases.map((rel) => (
              <tr key={rel.releaseId}>
                <td className="mono">{rel.releaseId}</td>
                <td>{rel.version}</td>
                <td className="mono">{rel.migration ?? "—"}</td>
                <td>
                  <span className={releasePillClass(rel.state)}>{rel.state}</span>
                </td>
                <td>{rel.when}</td>
                <td>{rel.note}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableScroll>
    </div>
  );
}

function AppConfigTab({ app }: { app: AppRecord }) {
  return (
    <section className="grid g2">
      <article className="panel">
        <div className="panel-head">
          <h2>Declared environment key names</h2>
        </div>
        <p className="muted" style={{ marginBottom: 12 }}>
          Only key names are signed in plans. Secret values live strictly in{" "}
          <span className="mono">/srv/sites/{app.account}/private/app.env</span> (mode 0400, loaded
          in-process) and are never readable by the console or coordinator.
        </p>
        <ul className="list">
          {app.envKeys.map((key) => (
            <li key={key}>
              <span className="mono grow">{key}</span>
              <span className="owner-badge host">0400 value hidden</span>
            </li>
          ))}
        </ul>
      </article>
      <article className="panel">
        <div className="panel-head">
          <h2>CLI deploy and lifecycle workflow</h2>
        </div>
        <pre className="code signed-bytes">
          {app.kind === "EmDash CMS"
            ? `# Build deterministic EmDash release off-host
python3 packaging/emdash-recipe.py package-release --src ./app --out ./out --release-id ${app.currentRelease}
# Draft signed app_deploy plan (requires <=24h capture when migrating)
rustiron plan create app-deploy --site-id ${app.siteId} --release-id ${app.currentRelease} --runtime ${app.runtimeProfile}`
            : `# Pack deterministic full-stack release off-host (zero server build step)
python3 packaging/rustiron-app-pack.py pack --site-id ${app.siteId} --release-id ${app.currentRelease} --out ./out --topology ${app.topology} --runtime ${app.runtimeProfile} --backend-dist ./dist${app.blueGreen ? " --blue-green-cutover" : ""}
# Draft signed app_deploy plan${app.blueGreen ? " with zero-downtime blue/green cutover" : ""}
rustiron plan create app-deploy --site-id ${app.siteId} --release-id ${app.currentRelease} --runtime ${app.runtimeProfile}${app.blueGreen ? " --blue-green-cutover" : ""}`}
        </pre>
      </article>
    </section>
  );
}

const appTabLabels: Record<AppTab, string> = {
  overview: "Overview",
  deployments: "Deployments",
  config: "Configuration & secrets",
};

/** W684: the tab lives in the URL (`?tab=`), like the other section navs, so it survives reload. */
export function AppDetailPage({ appId, tab }: { appId: string; tab: AppTab }) {
  const data = useData();
  const isLive = isRealHost(data.source);
  const observedApps = data.observation ? liveApps(data.observation) : [];
  const app = isLive
    ? (observedApps.find((item) => item.id === appId) ?? null)
    : (fixtureApps.find((item) => item.id === appId) ?? fixtureApps[0] ?? null);
  if (!app) {
    return (
      <Page live>
        <Crumbs
          items={[
            { href: "/", label: "Overview" },
            { href: "/apps", label: "Apps" },
            { label: appId },
          ]}
        />
        <div className="page-head">
          <div>
            <h1 className="mono">{appId}</h1>
            <p className="sub">This app ID is not present in the live host observation.</p>
          </div>
          <Link className="btn sm" to="/apps">
            <Glyph icon={ArrowLeft} />
            All apps
          </Link>
        </div>
        <EmptyState
          icon={Layers}
          title="App not found on this host"
          description="Live mode never substitutes mock app records. Provision the app or check the site ID on the Apps page."
          action={
            <Link className="btn primary sm" to="/plans/new">
              Create app plan
            </Link>
          }
        />
      </Page>
    );
  }

  return (
    <Page live>
      <Crumbs
        items={[
          { href: "/", label: "Overview" },
          { href: "/apps", label: "Apps" },
          { label: app.hostname },
        ]}
      />
      <div className="page-head">
        <div>
          <div className="row" style={{ gap: 10 }}>
            <h1 className="mono">{app.hostname}</h1>
            <span className={`pill ${app.servingKind}`}>{app.serving}</span>
            <span className="rm-tag">{app.kind}</span>
          </div>
          <p className="sub">
            {app.runtime} · current release <span className="mono">{app.currentRelease}</span> ·
            read-only inspection. Changes require a signed offline plan (
            <span className="mono">rustiron plan create app-deploy</span>).
          </p>
        </div>
        <Link className="btn sm" to="/apps">
          <Glyph icon={ArrowLeft} />
          All apps
        </Link>
      </div>

      <nav className="host-tabs" aria-label="App sections">
        {APP_TABS.map((key) => (
          <Link
            key={key}
            to="/apps/$appId"
            params={{ appId }}
            search={key === "overview" ? {} : { tab: key }}
            aria-current={tab === key ? "page" : undefined}
          >
            {appTabLabels[key]}
          </Link>
        ))}
      </nav>

      {tab === "overview" ? <AppOverviewTab app={app} /> : null}
      {tab === "deployments" ? <AppDeploymentsTab app={app} /> : null}
      {tab === "config" ? <AppConfigTab app={app} /> : null}
    </Page>
  );
}

function FindingRows({
  items,
  selectedId,
  showSeen,
  onSelect,
}: {
  items: DiagnosisFinding[];
  selectedId: string | null;
  showSeen: boolean;
  onSelect: (id: string) => void;
}) {
  return (
    <>
      {items.map((f) => (
        <tr key={f.id} className={selectedId === f.id ? "selected" : undefined}>
          <td>
            <FindingChip state={f.state} />
          </td>
          <td>
            <button
              type="button"
              className="row-btn"
              style={{ fontFamily: "var(--font)" }}
              onClick={() => onSelect(f.id)}
            >
              {f.check}
            </button>
          </td>
          <td className="mono">{f.subject}</td>
          <td>
            <OwnerBadge owner={f.owner} />
          </td>
          {showSeen ? <td>{f.seen}</td> : null}
        </tr>
      ))}
    </>
  );
}

function FindingInspector({
  finding,
  copiedId,
  onCopy,
  onClose,
}: {
  finding: DiagnosisFinding;
  copiedId: string | null;
  onCopy: (id: string, text: string) => void;
  onClose: () => void;
}) {
  return (
    <InspectorPanel
      ariaLabel="Finding details"
      title={finding.check}
      subtitle="Host diagnosis details"
      closeLabel="Close finding details"
      onClose={onClose}
    >
      <div className="row" style={{ gap: 8 }}>
        <FindingChip state={finding.state} />
        <OwnerBadge owner={finding.owner} prefix="owner: " />
      </div>
      <dl className="kv">
        <dt>Subject</dt>
        <dd className="mono">{finding.subject}</dd>
        <dt>Reason</dt>
        <dd>{finding.reason}</dd>
        <dt>Action</dt>
        <dd>{finding.action}</dd>
      </dl>
      {finding.command ? (
        <div>
          <div className="row" style={{ justifyContent: "space-between", marginBottom: 6 }}>
            <span className="cap">
              <Glyph icon={Terminal} /> Run on host as root
            </span>
            <button
              type="button"
              className="btn quiet sm"
              onClick={() => onCopy(finding.id, finding.command ?? "")}
            >
              <Glyph icon={Copy} />
              {copiedId === finding.id ? "Copied" : "Copy"}
            </button>
          </div>
          <pre className="code signed-bytes">{finding.command}</pre>
        </div>
      ) : null}
      <div className="insp-actions">
        <Link
          className="btn quiet sm"
          to="/help/$slug"
          params={{ slug: finding.guideSlug ?? "security-and-diagnoses" }}
        >
          {finding.runbook ?? "Open Docs & KB guide"}
        </Link>
      </div>
    </InspectorPanel>
  );
}

function diagnosisSummaryMessage(failCount: number, warnCount: number, unknownCount: number) {
  if (failCount > 0) return "Resolve failing checks before making host changes.";
  if (warnCount > 0) return "Warnings require review; critical checks are passing.";
  if (unknownCount > 0) {
    return `All observable checks passed; ${unknownCount} root-only host check(s) require shell verification.`;
  }
  return "All observed host checks passed.";
}

function DiagnosesSummaryBar({
  findings,
  passedCount,
}: {
  findings: DiagnosisFinding[];
  passedCount: number;
}) {
  const failCount = findings.filter((f) => f.state === "fail").length;
  const unknownCount = findings.filter((f) => f.state === "unknown").length;
  const warnCount = findings.filter((f) => f.state === "warn").length;
  const worst: DiagnosisFinding["state"] =
    failCount > 0 ? "fail" : unknownCount > 0 ? "unknown" : warnCount > 0 ? "warn" : "ok";
  return (
    <section className="panel diag-summary" aria-label="Diagnosis summary">
      <div className="row" style={{ gap: 12 }}>
        <FindingChip state={worst} />
        <span className="muted">{diagnosisSummaryMessage(failCount, warnCount, unknownCount)}</span>
      </div>
      <div className="diag-counts">
        <span className="diag-stat">
          <strong>{failCount}</strong> fail
        </span>
        <span className="diag-stat">
          <strong>{unknownCount}</strong> unknown
        </span>
        <span className="diag-stat">
          <strong>{warnCount}</strong> warn
        </span>
        <span className="diag-stat">
          <strong>{passedCount}</strong> ok
        </span>
        <span className="cap">Nothing was changed.</span>
      </div>
    </section>
  );
}

function DiagnosesTableCard({
  open,
  passed,
  selectedId,
  passedOpen,
  onTogglePassed,
  onSelect,
}: {
  open: DiagnosisFinding[];
  passed: DiagnosisFinding[];
  selectedId: string | null;
  passedOpen: boolean;
  onTogglePassed: () => void;
  onSelect: (id: string) => void;
}) {
  return (
    <div className="panel flush">
      <TableScroll label="Open host diagnosis findings">
        <table className="data">
          <thead>
            <tr>
              <th>State</th>
              <th>Check</th>
              <th>Subject</th>
              <th>Owner</th>
              <th>Seen</th>
            </tr>
          </thead>
          <tbody>
            {open.length === 0 ? (
              <tr>
                <td colSpan={5} className="muted">
                  No failing, unknown, or warning findings.
                </td>
              </tr>
            ) : (
              <FindingRows items={open} selectedId={selectedId} showSeen onSelect={onSelect} />
            )}
          </tbody>
        </table>
      </TableScroll>
      <button
        type="button"
        className="disc-btn"
        aria-expanded={passedOpen}
        onClick={onTogglePassed}
      >
        <span>Passed checks · {passed.length}</span>
        <Glyph icon={passedOpen ? ChevronDown : ChevronRight} />
      </button>
      {passedOpen ? (
        <TableScroll label="Passed host diagnosis checks">
          <table className="data">
            <thead>
              <tr>
                <th>State</th>
                <th>Check</th>
                <th>Subject</th>
                <th>Owner</th>
                <th>Seen</th>
              </tr>
            </thead>
            <tbody>
              <FindingRows items={passed} selectedId={selectedId} showSeen onSelect={onSelect} />
            </tbody>
          </table>
        </TableScroll>
      ) : null}
    </div>
  );
}

/** W789 (v0.3 item 59): "Which apps run here?" */
function AppsAnswer({ apps, loading }: { apps: AppRecord[]; loading: boolean }) {
  if (loading) return <AnswerLine tone="unknown">Checking this server…</AnswerLine>;
  if (apps.length === 0) return <AnswerLine tone="unknown">No apps deployed yet.</AnswerLine>;
  const down = apps.filter((app) => app.servingKind !== "ok");
  const count = `${apps.length} ${apps.length === 1 ? "app" : "apps"}`;
  if (down.length === 0) return <AnswerLine tone="ok">{count}, all serving.</AnswerLine>;
  return (
    <AnswerLine tone={down.some((app) => app.servingKind === "err") ? "err" : "warn"}>
      {count}. Not serving normally: {down.map((app) => app.hostname).join(", ")}.
    </AnswerLine>
  );
}

/** W789: "What am I moving in, and how far is it?" */
function MigrationAnswer({
  migrations,
  loading,
}: {
  migrations: MigrationRecord[];
  loading: boolean;
}) {
  if (loading) return <AnswerLine tone="unknown">Checking this server…</AnswerLine>;
  if (migrations.length === 0) {
    return <AnswerLine tone="unknown">No migrations recorded yet.</AnswerLine>;
  }
  const imported = migrations.filter((m) => m.importState === "ok").length;
  const failed = migrations.filter(
    (m) => m.importState === "fail" || m.dryRunState === "fail",
  ).length;
  const text = `${imported} of ${migrations.length} ${migrations.length === 1 ? "migration" : "migrations"} imported${failed > 0 ? `, ${failed} stopped` : ""}.`;
  return (
    <AnswerLine tone={failed > 0 ? "warn" : imported === migrations.length ? "ok" : "unknown"}>
      {text}
    </AnswerLine>
  );
}

/** W788 (v0.3 item 58): "Is anything wrong?" in one sentence. */
function diagnosesTone(open: DiagnosisFinding[]): Tone {
  if (open.some((f) => f.state === "fail")) return "err";
  if (open.some((f) => f.state === "warn")) return "warn";
  return open.length > 0 ? "unknown" : "ok";
}

function diagnosesText(open: DiagnosisFinding[]): string {
  if (open.length === 0) return "Nothing is wrong in this observation.";
  const failed = open.filter((f) => f.state === "fail").length;
  const warned = open.filter((f) => f.state === "warn").length;
  const unknown = open.length - failed - warned;
  const parts = [
    failed > 0 ? `${failed} ${failed === 1 ? "problem" : "problems"}` : "",
    warned > 0 ? `${warned} ${warned === 1 ? "warning" : "warnings"}` : "",
    unknown > 0 ? `${unknown} not checked` : "",
  ].filter(Boolean);
  return `${parts.join(", ")}. Open one to see what to do.`;
}

export function HostDiagnosesPage() {
  const data = useData();
  const findings = isRealHost(data.source)
    ? data.observation
      ? liveFindings(data.observation, data.machine)
      : []
    : fixtureFindings;
  const open = findings.filter((f) => f.state !== "ok");
  const passed = findings.filter((f) => f.state === "ok");
  // Never call a server healthy before anything was observed.
  const observed = !isRealHost(data.source) || data.observation !== null;
  const hasAlerts = open.some((f) => f.state === "fail" || f.state === "warn");
  const [selectedId, setSelectedId] = useDrawerSelection<string>();
  const [passedOpen, setPassedOpen] = useState(!hasAlerts && passed.length > 0);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const selected = findings.find((f) => f.id === selectedId) ?? null;

  async function handleCopy(id: string, text: string) {
    if (await copyText(text, "Command copied")) setCopiedId(id);
  }

  return (
    <Page live>
      <Crumbs items={[{ href: "/", label: "Overview" }, { label: "Host diagnoses" }]} />
      <div className="page-head">
        <SimpleHeader
          title="Host diagnoses"
          answer={
            observed ? (
              <AnswerLine tone={diagnosesTone(open)}>{diagnosesText(open)}</AnswerLine>
            ) : (
              <AnswerLine tone="unknown">
                {data.source.kind === "loading"
                  ? "Checking this server…"
                  : "No observation of this server yet."}
              </AnswerLine>
            )
          }
        />
      </div>
      <DiagnosesSummaryBar findings={findings} passedCount={passed.length} />

      <DiagnosesTableCard
        open={open}
        passed={passed}
        selectedId={selected?.id ?? null}
        passedOpen={passedOpen}
        onTogglePassed={() => setPassedOpen((prev) => !prev)}
        onSelect={(id) => setSelectedId((cur) => (cur === id ? null : id))}
      />

      {selected ? (
        <FindingInspector
          finding={selected}
          copiedId={copiedId}
          onCopy={handleCopy}
          onClose={() => setSelectedId(null)}
        />
      ) : null}
    </Page>
  );
}

function updatesTone(inRange: number, installed: number, unobserved: number): Tone {
  if (unobserved > 0) return "unknown";
  return inRange === installed ? "ok" : "warn";
}

export function HostUpdatesPage() {
  const data = useData();
  const isLive = isRealHost(data.source);
  const components: SupportComponent[] = liveSupportComponents(data.machine, isLive);
  const [selectedId, setSelectedId] = useDrawerSelection<string>();
  const selected = components.find((c) => c.id === selectedId) ?? null;
  const inRange = components.filter((c) => c.state === "supported").length;
  const optionalAbsent = components.filter((c) => c.state === "optional").length;
  const installedCount = components.length - optionalAbsent;
  const unobservedCount = components.filter((c) => c.state === "unknown").length;
  const buildLabel = isLive
    ? data.machine?.os.version
      ? `AlmaLinux ${data.machine.os.version}`
      : (data.observation?.host.host_id ?? "Enrolled host")
    : "AlmaLinux 10";

  return (
    <Page live>
      <Crumbs items={[{ href: "/", label: "Overview" }, { label: "Host updates" }]} />
      <div className="page-head">
        <SimpleHeader
          title="Host updates"
          answer={
            <AnswerLine tone={updatesTone(inRange, installedCount, unobservedCount)}>
              {unobservedCount > 0
                ? `${inRange} of ${installedCount} components are in a supported series; ${unobservedCount} not observed.`
                : inRange === installedCount
                  ? `All ${installedCount} components are in a supported series.`
                  : `${installedCount - inRange} of ${installedCount} components are outside a supported series.`}
            </AnswerLine>
          }
          action={
            <Link
              className="btn quiet sm"
              to="/help/$slug"
              params={{ slug: "updates-and-releases" }}
            >
              Update guide
            </Link>
          }
        />
      </div>

      <QuietDetails summary={`${buildLabel} · verified updates with automatic rollback`}>
        <dl className="kv">
          <dt>Server platform</dt>
          <dd>{buildLabel}</dd>
          <dt>Version policy</dt>
          <dd>Supported stack: pinned versions and security advisory checks</dd>
          <dt>Optional</dt>
          <dd>{optionalAbsent} optional components not installed</dd>
        </dl>
        <p className="cap">
          Run stack updates from the server CLI to apply verified updates with automatic rollback.
        </p>
      </QuietDetails>

      <div className="panel flush">
        <TableScroll label="Support matrix components">
          <table className="data">
            <thead>
              <tr>
                <th>Component</th>
                <th>Series</th>
                <th>Observed</th>
                <th>Minimum patch</th>
                <th>End of life</th>
                <th>State</th>
              </tr>
            </thead>
            <tbody>
              {components.map((comp) => (
                <tr key={comp.id} className={selected?.id === comp.id ? "selected" : undefined}>
                  <td>
                    <button
                      type="button"
                      className="row-btn"
                      style={{ fontFamily: "var(--font)" }}
                      onClick={() => setSelectedId((cur) => (cur === comp.id ? null : comp.id))}
                    >
                      {comp.component}
                    </button>
                  </td>
                  <td>{comp.series}</td>
                  <td className="mono">{comp.observed}</td>
                  <td className="mono">{comp.minimumPatch}</td>
                  <td>{comp.endOfLife}</td>
                  <td>
                    <span
                      className={
                        comp.state === "supported"
                          ? "pill ok"
                          : comp.state === "optional"
                            ? "pill"
                            : "pill warn"
                      }
                    >
                      {comp.stateLabel}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableScroll>
      </div>

      {selected ? (
        <InspectorPanel
          ariaLabel="Component details"
          title={`${selected.component} ${selected.series}`}
          closeLabel="Close component details"
          onClose={() => setSelectedId(null)}
        >
          <dl className="kv">
            <dt>Package pin</dt>
            <dd className="mono">{selected.packagePin}</dd>
            <dt>Minimum patch</dt>
            <dd className="mono">{selected.minimumPatch}</dd>
            <dt>End of life</dt>
            <dd>{selected.endOfLife}</dd>
          </dl>
          <p className="muted">{selected.note}</p>
          <div className="insp-actions">
            <Link
              className="btn quiet sm"
              to="/help/$slug"
              params={{ slug: "updates-and-releases" }}
            >
              Product &amp; stack updates guide
            </Link>
          </div>
        </InspectorPanel>
      ) : null}
    </Page>
  );
}

/**
 * Item 64: a domain's one word. Renewal that RustIron does by itself is news,
 * not a problem; a failed renewal, or one the operator must do, needs a look.
 */
function domainVerdict(d: DomainRecord): { word: string; tone: string; rank: number } {
  if (d.certificate === "renewal_failed") return { word: "Renewal failed", tone: "err", rank: 0 };
  if (d.certificate === "expires_soon" && d.renewedBy === "operator")
    return { word: "Renew it soon", tone: "warn", rank: 1 };
  if (d.certificate === "expires_soon") return { word: "Renews soon", tone: "info", rank: 2 };
  if (d.certificate === "not_issued") return { word: "No HTTPS yet", tone: "", rank: 3 };
  return { word: "Secure", tone: "ok", rank: 4 };
}

/** W790 / item 64: "Which domains point here, and is HTTPS fine?" */
function DomainsAnswer({ loading, domains }: { loading: boolean; domains: DomainRecord[] }) {
  if (loading) return <AnswerLine tone="unknown">Checking this server…</AnswerLine>;
  if (domains.length === 0)
    return <AnswerLine tone="unknown">No domains on this server yet.</AnswerLine>;
  const total = `${domains.length} ${domains.length === 1 ? "domain" : "domains"}.`;
  const problems = domains.filter((d) => domainVerdict(d).rank < 2);
  const renewing = domains.filter((d) => domainVerdict(d).rank === 2).length;
  const renewText =
    renewing > 0
      ? ` ${renewing} ${renewing === 1 ? "certificate renews" : "certificates renew"} soon; RustIron does it for you.`
      : "";
  if (problems.length > 0) {
    const failed = problems.some((d) => domainVerdict(d).rank === 0);
    return (
      <AnswerLine tone={failed ? "err" : "warn"}>
        {total} {problems.length} {problems.length === 1 ? "needs" : "need"} a look.{renewText}
      </AnswerLine>
    );
  }
  return (
    <AnswerLine tone="ok">
      {total} HTTPS is fine on every one.{renewText}
    </AnswerLine>
  );
}

type DomainFilter = "all" | "attention" | "fine";

function domainFilterMatch(d: DomainRecord, filter: DomainFilter): boolean {
  if (filter === "all") return true;
  return filter === "attention" ? domainVerdict(d).rank < 2 : domainVerdict(d).rank >= 2;
}

const domainSorters: Record<"attention" | "name", (a: DomainRecord, b: DomainRecord) => number> = {
  attention: (a, b) =>
    domainVerdict(a).rank - domainVerdict(b).rank || a.hostname.localeCompare(b.hostname),
  name: (a, b) => a.hostname.localeCompare(b.hostname),
};

/** "HTTPS until 10 Feb 2027", or nothing when the date is not known. */
function httpsUntil(notAfter: string): string {
  return notAfter.startsWith("—") || notAfter.startsWith("Not ")
    ? ""
    : ` · HTTPS until ${notAfter}`;
}

function DomainRow({
  dom,
  open,
  onInspect,
}: {
  dom: DomainRecord;
  open: boolean;
  onInspect: () => void;
}) {
  const v = domainVerdict(dom);
  return (
    <li className={rowClass}>
      <div className="min-w-0 flex-1">
        <Link
          className={rowLinkClass}
          to="/domains/$hostname"
          params={{ hostname: dom.hostname }}
          translate="no"
        >
          {dom.hostname}
        </Link>
        <p className="truncate text-sm text-muted-foreground">
          Serves {dom.serves}
          {httpsUntil(dom.notAfter)}
        </p>
      </div>
      <span className="flex justify-end sm:w-40">
        <span className={`pill ${v.tone}`}>{v.word}</span>
      </span>
      <button
        type="button"
        className="btn quiet sm relative z-10"
        aria-pressed={open}
        aria-label={`Inspect ${dom.hostname}`}
        onClick={onInspect}
      >
        {open ? "Close" : "Inspect"}
      </button>
    </li>
  );
}

function DomainsList({
  domains,
  selectedHost,
  onInspect,
}: {
  domains: DomainRecord[];
  selectedHost: string | null;
  onInspect: (host: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<DomainFilter>("all");
  const [sort, setSort] = useState<"attention" | "name">("attention");
  const needsLook = domains.filter((d) => domainVerdict(d).rank < 2).length;
  const visible = domains
    .filter((d) => matches(query, d.hostname, d.serves))
    .filter((d) => domainFilterMatch(d, filter))
    .sort(domainSorters[sort]);
  const paged = usePaged(visible, `${query}|${filter}|${sort}|${domains.length}`);
  const big = domains.length > SMALL_LIST;
  return (
    <div className="flex flex-col gap-4">
      <ListToolbar
        hidden={!big}
        filters={
          <FilterChips
            label="Show"
            value={filter}
            onChange={setFilter}
            options={[
              { value: "all", label: "All", count: domains.length },
              { value: "attention", label: "Needs a look", count: needsLook },
              { value: "fine", label: "Fine", count: domains.length - needsLook },
            ]}
          />
        }
      >
        <ListControls
          count={domains.length}
          searchLabel="Find a domain"
          query={query}
          onQuery={setQuery}
          sort={sort}
          onSort={setSort}
          sorts={[
            { value: "attention", label: "Needs a look first" },
            { value: "name", label: "Name A–Z" },
          ]}
        />
      </ListToolbar>
      <ListArea
        label="Domains"
        noun="domains"
        total={domains.length}
        paged={paged}
        onReset={() => {
          setQuery("");
          setFilter("all");
        }}
      >
        {paged.rows.map((dom) => (
          <DomainRow
            key={dom.hostname}
            dom={dom}
            open={selectedHost === dom.hostname}
            onInspect={() => onInspect(dom.hostname)}
          />
        ))}
      </ListArea>
    </div>
  );
}

export function DomainsPage() {
  const data = useData();
  const domains: DomainRecord[] = isRealHost(data.source)
    ? data.observation
      ? liveDomains(data.sites, data.observation)
      : []
    : fixtureDomains;
  const [selectedHost, setSelectedHost] = useDrawerSelection<string>();
  const selected = domains.find((d) => d.hostname === selectedHost) ?? null;

  const operatorManaged = domains.filter((d) => d.renewedBy === "operator").length;

  return (
    <Page live>
      <Crumbs items={[{ href: "/", label: "Overview" }, { label: "Domains" }]} />
      <div className="page-head">
        <SimpleHeader
          title="Domains"
          answer={<DomainsAnswer loading={data.source.kind === "loading"} domains={domains} />}
        />
        <Link className="btn primary sm" to="/domains/new">
          Add domain
        </Link>
      </div>

      <DomainsList
        domains={domains}
        selectedHost={selected?.hostname ?? null}
        onInspect={(host) => setSelectedHost((cur) => (cur === host ? null : host))}
      />
      <QuietDetails title="Technical details">
        <p className="muted">
          Authoritative DNS is PowerDNS 5.1, with signed zone imports and TSIG AXFR. RustIron renews
          the certificates of the websites it manages; {operatorManaged}{" "}
          {operatorManaged === 1 ? "hostname is" : "hostnames are"} renewed by the operator (an
          ejected website keeps its own HTTPS).
        </p>
      </QuietDetails>

      {selected ? (
        <InspectorPanel
          ariaLabel="Domain certificate details"
          title={selected.hostname}
          subtitle="Certificate & DNS inspector"
          monoTitle
          closeLabel="Close domain details"
          onClose={() => setSelectedHost(null)}
        >
          <dl className="kv">
            <dt>Issuer</dt>
            <dd>{selected.issuer}</dd>
            <dt>Chain digest</dt>
            <dd className="mono">{selected.chainDigest}</dd>
            <dt>Not after</dt>
            <dd>{selected.notAfter}</dd>
            <dt>renew_until</dt>
            <dd>{selected.renewUntil}</dd>
            <dt>Last result</dt>
            <dd>{selected.lastResult}</dd>
            <dt>DNS zone</dt>
            <dd>{selected.dnsZone}</dd>
            <dt>Transfer mode</dt>
            <dd>{selected.dnsMode}</dd>
          </dl>
          <div className="insp-actions">
            <Link
              className="btn sm"
              to="/domains/$hostname"
              params={{ hostname: selected.hostname }}
            >
              Open domain
            </Link>
            <Link
              className="btn quiet sm"
              to="/domains/$hostname/dns"
              params={{ hostname: selected.hostname }}
            >
              DNS records
            </Link>
            {selected.siteHref ? (
              <Link className="btn quiet sm" to={selected.siteHref}>
                Open workload
              </Link>
            ) : null}
          </div>
        </InspectorPanel>
      ) : null}
    </Page>
  );
}

function migrationStatePill(state: MigrationRecord["importState"]) {
  if (state === "ok") return "pill ok";
  if (state === "fail") return "pill err";
  return "pill";
}

function factSourceBadge(source: MigrationRecord["facts"][number]["source"]) {
  if (source === "observed") return "owner-badge";
  if (source === "declared") return "owner-badge host";
  return "pill";
}

function MigrationInspector({
  selected,
  onClose,
}: {
  selected: MigrationRecord;
  onClose: () => void;
}) {
  return (
    <InspectorPanel
      ariaLabel="Migration details"
      title={selected.id}
      subtitle={selected.kind}
      monoTitle
      closeLabel="Close migration details"
      onClose={onClose}
    >
      {selected.refusals.length > 0 ? (
        <div className="attention err" role="status">
          <Glyph icon={CircleX} />
          <div className="att-body">
            <strong>Import blocked by {selected.refusals.length} refusals</strong>
            {selected.refusals.map((r) => (
              <div key={r.code} style={{ marginTop: 4 }}>
                <span className="mono">{r.code}</span> · {r.detail}
              </div>
            ))}
          </div>
        </div>
      ) : null}
      <p className="muted">{selected.note}</p>
      <div>
        <h3 style={{ fontSize: 13, marginBottom: 8 }}>Facts by provenance</h3>
        <ul className="list">
          {selected.facts.map((fact) => (
            <li key={fact.name}>
              <span className="grow">{fact.name}</span>
              <span className={factSourceBadge(fact.source)}>{fact.source}</span>
            </li>
          ))}
        </ul>
      </div>
      <div className="insp-actions">
        {selected.kind.includes("EmDash") ? (
          <Link
            className="btn sm"
            to="/migration/emdash/$migrationId"
            params={{ migrationId: selected.id }}
          >
            Open WXR parity report
          </Link>
        ) : null}
        <Link className="btn quiet sm" to="/help/$slug" params={{ slug: "migrations" }}>
          Migration &amp; EmDash guide
        </Link>
      </div>
    </InspectorPanel>
  );
}

function MigrationTable({
  migrations,
  selectedId,
  onSelect,
}: {
  migrations: MigrationRecord[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  return (
    <div className="panel flush">
      <TableScroll label="Recorded migration rehearsals">
        <table className="data">
          <thead>
            <tr>
              <th>Rehearsal</th>
              <th>Path</th>
              <th>Target</th>
              <th>Dry run</th>
              <th>Import</th>
              <th>Post-step</th>
            </tr>
          </thead>
          <tbody>
            {migrations.map((mig) => (
              <tr key={mig.id} className={selectedId === mig.id ? "selected" : undefined}>
                <td>
                  <button type="button" className="row-btn" onClick={() => onSelect(mig.id)}>
                    {mig.id}
                  </button>
                  <div className="cap">{mig.source}</div>
                </td>
                <td>{mig.kind}</td>
                <td className="mono">{mig.targetHostname}</td>
                <td>
                  <span className={mig.dryRunState === "ok" ? "pill ok" : "pill err"}>
                    {mig.dryRunLabel}
                  </span>
                </td>
                <td>
                  <span className={migrationStatePill(mig.importState)}>{mig.importLabel}</span>
                </td>
                <td>{mig.scrubLabel}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableScroll>
    </div>
  );
}

export function MigrationPage() {
  const data = useData();
  const isLive = isRealHost(data.source);
  const migrations: MigrationRecord[] = isLive
    ? data.observation
      ? liveMigrations(data.observation)
      : []
    : fixtureMigrations;
  const [selectedId, setSelectedId] = useDrawerSelection<string>();
  const selected = migrations.find((m) => m.id === selectedId) ?? null;

  return (
    <Page live>
      <Crumbs items={[{ href: "/", label: "Overview" }, { label: "Migration" }]} />
      <div className="page-head">
        <SimpleHeader
          title="Migration"
          answer={
            <MigrationAnswer migrations={migrations} loading={data.source.kind === "loading"} />
          }
        />
        <Link className="btn sm" to="/help/$slug" params={{ slug: "migrations" }}>
          Migration guide
        </Link>
      </div>

      <MigrationWizardsPanel />

      <section className="panel" aria-label="How a migration works">
        <ol className="step-rail">
          <li>
            <span className="step-num ok">1</span>
            <span>Export & capture media offline</span>
          </li>
          <li className="muted" aria-hidden="true">
            →
          </li>
          <li>
            <span className="step-num ok">2</span>
            <span>Inventory worker + live target observation</span>
          </li>
          <li className="muted" aria-hidden="true">
            →
          </li>
          <li>
            <span className="step-num ok">3</span>
            <span>Signed OperatorDeclaration (SSHSIG)</span>
          </li>
          <li className="muted" aria-hidden="true">
            →
          </li>
          <li>
            <span className="step-num">4</span>
            <span>Review dry run & refusals</span>
          </li>
          <li className="muted" aria-hidden="true">
            →
          </li>
          <li>
            <span className="step-num">5</span>
            <span>Import, verify parity, scrub leftovers</span>
          </li>
        </ol>
      </section>

      {isLive && migrations.length === 0 ? (
        <EmptyState
          icon={Server}
          title="No migration or import operations recorded on this host yet"
          description="Live mode never shows mock migration rows. Run an offline CyberPanel dry run (rustiron-plan migrate) or WordPress-to-EmDash WXR rehearsal (packaging/wordpress-to-emdash.py), then import via a signed plan."
          command="rustiron-plan migrate --inventory ./inv.json --target-observation ./obs.json --declaration ./decl.json --declaration-sig ./decl.json.sig"
          action={
            <>
              <Link className="btn primary sm" to="/plans/new">
                Prepare plan
              </Link>
              <Link className="btn quiet sm" to="/help/$slug" params={{ slug: "migrations" }}>
                Migration guide
              </Link>
            </>
          }
        />
      ) : (
        <>
          <MigrationTable
            migrations={migrations}
            selectedId={selected?.id ?? null}
            onSelect={(id) => setSelectedId((cur) => (cur === id ? null : id))}
          />
          {selected ? (
            <MigrationInspector selected={selected} onClose={() => setSelectedId(null)} />
          ) : null}
        </>
      )}
    </Page>
  );
}
