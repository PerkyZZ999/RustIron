// W604 (P29): Read-only developer hosting-platform views ported from
// docs/mockup/screens/ to Astryx + scoped CSS (Apps/EmDash, Host Diagnoses,
// Host Updates, Domains, Migration). No view here writes to or changes the host.
import { Link } from "@tanstack/react-router";
import {
  ArrowLeft,
  ChevronDown,
  ChevronRight,
  CircleAlert,
  CircleCheck,
  CircleHelp,
  CircleMinus,
  CircleX,
  Copy,
  KeyRound,
  Layers,
  Server,
  ShieldCheck,
  Terminal,
  X,
} from "lucide-react";
import { type ReactNode, useEffect, useState } from "react";

import { toastManager } from "@/components/ui/toast";
import { MigrationWizardsPanel } from "./backup-migration-wizards";
import { useData } from "./data";
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
import { Crumbs, EmptyState, Glyph, Page, TableScroll } from "./ui";

export function InspectorPanel({
  ariaLabel,
  title,
  subtitle,
  monoTitle = false,
  closeLabel,
  onClose,
  children,
}: {
  ariaLabel: string;
  title: string;
  subtitle?: string;
  monoTitle?: boolean;
  closeLabel: string;
  onClose: () => void;
  children: ReactNode;
}) {
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <>
      <div className="insp-backdrop" aria-hidden="true" onClick={onClose} />
      <aside className="insp-drawer" aria-label={ariaLabel}>
        <div className="insp-head">
          <div style={{ minWidth: 0 }}>
            <h2
              className={monoTitle ? "mono" : undefined}
              style={{ fontSize: monoTitle ? 16 : 18 }}
            >
              {title}
            </h2>
            {subtitle ? <span className="cap">{subtitle}</span> : null}
          </div>
          <button type="button" className="icon-btn" aria-label={closeLabel} onClick={onClose}>
            <Glyph icon={X} />
          </button>
        </div>
        <div className="insp-body">{children}</div>
      </aside>
    </>
  );
}

function FindingChip({ state }: { state: DiagnosisFinding["state"] }) {
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

function OwnerBadge({ owner, prefix = "" }: { owner: "rustiron" | "host"; prefix?: string }) {
  return (
    <span className={owner === "host" ? "owner-badge host" : "owner-badge"}>
      {prefix}
      {owner}
    </span>
  );
}

function releasePillClass(state: AppRecord["releases"][number]["state"]) {
  if (state === "active") return "pill ok";
  if (state === "failed_compensated") return "pill err";
  return "pill";
}

/** Compact open-findings panel shown beside Resource history on Host Overview (overview.html). */
export function OverviewFindingsPanel() {
  const data = useData();
  const findings =
    data.source.kind === "live" && data.observation
      ? liveFindings(data.observation, data.machine)
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

function servingIcon(kind: AppRecord["servingKind"]) {
  if (kind === "ok") return CircleCheck;
  if (kind === "err") return CircleX;
  return CircleMinus;
}

const appStackFilters = [
  "All",
  "Full-stack app",
  "EmDash CMS",
  "Node.js app",
  "Bun app",
  "Static SPA",
] as const;
type AppStackFilter = (typeof appStackFilters)[number];

const dbEngineLabels: Record<AppRecord["database"], string> = {
  none: "None",
  sqlite: "SQLite (WAL)",
  mariadb: "MariaDB 10.11",
  postgresql_18: "PostgreSQL 18",
};

function AppStackFilterBar({
  value,
  onChange,
}: {
  value: AppStackFilter;
  onChange: (next: AppStackFilter) => void;
}) {
  return (
    <div className="filter-pills" role="group" aria-label="Filter apps by stack">
      {appStackFilters.map((filter) => (
        <button
          key={filter}
          type="button"
          aria-pressed={value === filter}
          onClick={() => onChange(filter)}
        >
          {filter}
        </button>
      ))}
    </div>
  );
}

function AppsTable({
  apps,
  selectedId,
  onSelect,
}: {
  apps: AppRecord[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  return (
    <div className="panel flush">
      <TableScroll label="Hosted modern apps">
        <table className="data">
          <thead>
            <tr>
              <th>App</th>
              <th>Stack</th>
              <th>Serving</th>
              <th>Health</th>
              <th>Current release</th>
              <th>Loopback</th>
            </tr>
          </thead>
          <tbody>
            {apps.map((app) => (
              <tr key={app.id} className={selectedId === app.id ? "selected" : undefined}>
                <td>
                  <button type="button" className="row-btn" onClick={() => onSelect(app.id)}>
                    {app.hostname}
                  </button>
                  <div className="cap">{app.kind}</div>
                </td>
                <td>{app.runtime}</td>
                <td>
                  <span className={`pill ${app.servingKind}`}>
                    <Glyph icon={servingIcon(app.servingKind)} />
                    {app.serving}
                  </span>
                </td>
                <td>
                  <span className={`pill ${app.healthKind}`}>
                    <Glyph icon={app.healthKind === "ok" ? CircleCheck : CircleX} />
                    {app.health}
                  </span>
                </td>
                <td className="mono">{app.currentRelease}</td>
                <td className="mono">
                  {app.port > 0 ? `127.0.0.1:${app.port}` : "Static files"}
                  <div className="cap">{app.ingress}</div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableScroll>
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
  const isLive = data.source.kind === "live";
  const observedApps = data.observation ? liveApps(data.observation) : [];
  const allApps: AppRecord[] = isLive ? observedApps : fixtureApps;
  const [stackFilter, setStackFilter] = useState<AppStackFilter>("All");
  const apps = stackFilter === "All" ? allApps : allApps.filter((app) => app.kind === stackFilter);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selected = apps.find((a) => a.id === selectedId) ?? null;

  return (
    <Page live>
      <Crumbs items={[{ href: "/", label: "Overview" }, { label: "Apps" }]} />
      <div className="page-head">
        <div>
          <h1>Apps</h1>
          <p className="sub">
            Managed full-stack Bun 1.4, Node.js 22, Static SPA, and EmDash CMS applications running
            in isolated per-site services behind confined Caddy HTTP/3 or OpenLiteSpeed.
          </p>
        </div>
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
          <AppStackFilterBar value={stackFilter} onChange={setStackFilter} />
          <AppsTable
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

export function AppDetailPage({ appId }: { appId: string }) {
  const data = useData();
  const isLive = data.source.kind === "live";
  const observedApps = data.observation ? liveApps(data.observation) : [];
  const app = isLive
    ? (observedApps.find((item) => item.id === appId) ?? null)
    : (fixtureApps.find((item) => item.id === appId) ?? fixtureApps[0] ?? null);
  const [tab, setTab] = useState<"overview" | "deployments" | "config">("overview");
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
        {(
          [
            ["overview", "Overview"],
            ["deployments", "Deployments"],
            ["config", "Configuration & secrets"],
          ] as const
        ).map(([key, label]) => (
          <a
            key={key}
            href={`#${key}`}
            aria-current={tab === key ? "page" : undefined}
            onClick={(event) => {
              event.preventDefault();
              setTab(key);
            }}
          >
            {label}
          </a>
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

export function HostDiagnosesPage() {
  const data = useData();
  const findings =
    data.source.kind === "live" && data.observation
      ? liveFindings(data.observation, data.machine)
      : fixtureFindings;
  const open = findings.filter((f) => f.state !== "ok");
  const passed = findings.filter((f) => f.state === "ok");
  const hasAlerts = open.some((f) => f.state === "fail" || f.state === "warn");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [passedOpen, setPassedOpen] = useState(!hasAlerts && passed.length > 0);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const selected = findings.find((f) => f.id === selectedId) ?? null;

  function handleCopy(id: string, text: string) {
    void navigator.clipboard?.writeText(text).then(() => {
      setCopiedId(id);
      toastManager.add({ id: "clipboard-copy", type: "success", title: "Command copied" });
    });
  }

  return (
    <Page live>
      <Crumbs items={[{ href: "/", label: "Overview" }, { label: "Host diagnoses" }]} />
      <div className="page-head">
        <div>
          <h1>Host diagnoses</h1>
          <p className="sub">
            Automated health checks for security, services, certificates, storage, and backups.
            Review open findings below for recommended actions.
          </p>
        </div>
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

export function HostUpdatesPage() {
  const data = useData();
  const isLive = data.source.kind === "live";
  const components: SupportComponent[] = liveSupportComponents(data.machine, isLive);
  const [selectedId, setSelectedId] = useState<string | null>(null);
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
        <div>
          <h1>Host updates</h1>
          <p className="sub">
            Installed server stack versions, support lifecycle dates, and security advisories. Run
            stack updates from the server CLI to apply verified updates with automatic rollback.
          </p>
        </div>
        <Link className="btn quiet sm" to="/help/$slug" params={{ slug: "updates-and-releases" }}>
          Update guide
        </Link>
      </div>

      <section className="grid g3" aria-label="Update summary">
        <article className="panel metric">
          <div className="m-head">Server platform</div>
          <div className="m-val" style={{ fontSize: 22 }}>
            {buildLabel}
          </div>
          <div className="m-detail">Verified updates with automatic rollback</div>
        </article>
        <article className="panel metric">
          <div className="m-head">Version policy</div>
          <div className="m-val" style={{ fontSize: 22 }}>
            Supported stack
          </div>
          <div className="m-detail">Pinned versions and security advisory checks</div>
        </article>
        <article className="panel metric">
          <div className="m-head">Components in range</div>
          <div className="m-val" style={{ fontSize: 22 }}>
            {inRange} of {installedCount}
          </div>
          <div className="m-detail">
            {unobservedCount > 0
              ? `${unobservedCount} not observed in this snapshot`
              : optionalAbsent > 0
                ? `${optionalAbsent} optional not installed`
                : "0 outside supported series"}
          </div>
        </article>
      </section>

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

export function DomainsPage() {
  const data = useData();
  const domains: DomainRecord[] =
    data.source.kind === "live" && data.observation
      ? liveDomains(data.sites, data.observation)
      : fixtureDomains;
  const [selectedHost, setSelectedHost] = useState<string | null>(null);
  const selected = domains.find((d) => d.hostname === selectedHost) ?? null;

  const expiring = domains.filter(
    (d) => d.certificate === "expires_soon" || d.certificate === "renewal_failed",
  ).length;
  const operatorManaged = domains.filter((d) => d.renewedBy === "operator").length;

  return (
    <Page live>
      <Crumbs items={[{ href: "/", label: "Overview" }, { label: "Domains" }]} />
      <div className="page-head">
        <div>
          <h1>Domains</h1>
          <p className="sub">
            Hosted domains, SSL/TLS certificates, and authoritative PowerDNS zones on this server.
          </p>
        </div>
        <Link className="btn primary sm" to="/domains/new">
          Add domain
        </Link>
      </div>

      <section className="grid g4" aria-label="Domain summary">
        <article className="panel metric">
          <div className="m-head">Hostnames</div>
          <div className="m-val">{domains.length}</div>
          <div className="m-detail">Websites, EmDash CMS, and modern apps</div>
        </article>
        <article className="panel metric">
          <div className="m-head">Renewal attention</div>
          <div className="m-val">{expiring}</div>
          <div className="m-detail">Inside 30-day window or failed check</div>
        </article>
        <article className="panel metric">
          <div className="m-head">Operator renewed</div>
          <div className="m-val">{operatorManaged}</div>
          <div className="m-detail">Ejected sites keep standalone HTTPS</div>
        </article>
        <article className="panel metric">
          <div className="m-head">Authoritative DNS</div>
          <div className="m-val" style={{ fontSize: 22 }}>
            PowerDNS 5.1
          </div>
          <div className="m-detail">Signed zone imports & TSIG AXFR</div>
        </article>
      </section>

      <div className="panel flush">
        <TableScroll label="Served hostnames and certificates">
          <table className="data">
            <thead>
              <tr>
                <th>Hostname</th>
                <th>Serves</th>
                <th>Certificate</th>
                <th>Not after</th>
                <th>Renewed by</th>
              </tr>
            </thead>
            <tbody>
              {domains.map((dom) => (
                <tr
                  key={dom.hostname}
                  className={selected?.hostname === dom.hostname ? "selected" : undefined}
                >
                  <td>
                    <button
                      type="button"
                      className="row-btn"
                      onClick={() =>
                        setSelectedHost((cur) => (cur === dom.hostname ? null : dom.hostname))
                      }
                    >
                      {dom.hostname}
                    </button>
                  </td>
                  <td>{dom.serves}</td>
                  <td>
                    <span
                      className={
                        dom.certificate === "valid"
                          ? "pill ok"
                          : dom.certificate === "not_issued"
                            ? "pill"
                            : "pill warn"
                      }
                    >
                      {dom.certificateLabel}
                    </span>
                  </td>
                  <td>{dom.notAfter}</td>
                  <td>
                    <span
                      className={dom.renewedBy === "operator" ? "owner-badge host" : "owner-badge"}
                    >
                      {dom.renewedBy}
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
  const isLive = data.source.kind === "live";
  const migrations: MigrationRecord[] = isLive
    ? data.observation
      ? liveMigrations(data.observation)
      : []
    : fixtureMigrations;
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selected = migrations.find((m) => m.id === selectedId) ?? null;

  return (
    <Page live>
      <Crumbs items={[{ href: "/", label: "Overview" }, { label: "Migration" }]} />
      <div className="page-head">
        <div>
          <h1>Migration</h1>
          <p className="sub">
            Import websites from CyberPanel or migrate WordPress sites to EmDash CMS. Your source
            server, DNS, and email stay untouched until you approve cutover.
          </p>
        </div>
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
