// W630 (P29 Slice 10): Dedicated Databases Manager (/databases) and CyberPanel-grade
// interactive Site Lifecycle Controls (PHP/Cache, WP Updates, Disk Quota, Staging Clone,
// Password Rotation, Restore, and Eject/Delete).
import { Link } from "@tanstack/react-router";
import {
  ChevronDown,
  Database,
  Download,
  HardDrive,
  KeyRound,
  Layers,
  ShieldCheck,
  TriangleAlert,
  Wrench,
} from "lucide-react";
import { useState } from "react";

import {
  buildConfigActivateCmd,
  buildManualVerbPlanNote,
  buildSiteCredentialRotateCmd,
  buildSiteEjectCmd,
  type CredentialRotateTarget,
  INSPECT_AND_SIGN_STEPS,
  shellQuote,
} from "./cli-commands";
import { isRealHost, useData } from "./data";
import { type AppRecord, fixtureApps, liveApps } from "./platform-data";
import { InspectorPanel, useDrawerSelection } from "./inspector";
import { CopyButton, Crumbs, EmptyState, Glyph, Page, TableScroll } from "./ui";
import { SeparateCustodyApplyPanel } from "./write-panel";

type DatabaseEngineLabel = "MariaDB" | "PostgreSQL 18" | "SQLite";

type DatabaseEntry = {
  id: string;
  siteId: string;
  domain: string;
  engine: DatabaseEngineLabel;
  dbName: string;
  dbUser: string;
  socketOrPath: string;
  canRotatePassword: boolean;
  rotateTarget?: CredentialRotateTarget;
  isAppDatabase: boolean;
};

function isWordPressSite(s: { runtime?: string; servingKind?: string }): boolean {
  const rt = (s.runtime ?? "").toLowerCase();
  if (!rt) return true;
  if (
    rt.includes("static") ||
    rt.includes("proxy") ||
    rt.includes("node") ||
    rt.includes("bun") ||
    rt.includes("emdash") ||
    rt.includes("ejected")
  ) {
    return false;
  }
  return true;
}

function appDatabaseEntry(app: AppRecord): DatabaseEntry | null {
  if (app.database === "postgresql_18") {
    return {
      id: `pg18_${app.siteId}`,
      siteId: app.siteId,
      domain: app.hostname,
      engine: "PostgreSQL 18",
      dbName: `rs_${app.siteId}_app`,
      dbUser: `rs_${app.siteId}`,
      socketOrPath: "127.0.0.1:5432 (SCRAM-SHA-256 · rustiron_app_pg_t)",
      canRotatePassword: true,
      rotateTarget: "app_postgresql_18_password",
      isAppDatabase: true,
    };
  }
  if (app.database === "mariadb") {
    return {
      id: `app_maria_${app.siteId}`,
      siteId: app.siteId,
      domain: app.hostname,
      engine: "MariaDB",
      dbName: `rs_${app.siteId}_app`,
      dbUser: `rs_${app.siteId}`,
      socketOrPath: "127.0.0.1:3306 (rustiron_app_mariadb_t)",
      canRotatePassword: true,
      rotateTarget: "app_mariadb_password",
      isAppDatabase: true,
    };
  }
  if (app.database === "sqlite" || app.kind === "EmDash CMS") {
    const isEmDash = app.kind === "EmDash CMS";
    return {
      id: `sqlite_${app.siteId}`,
      siteId: app.siteId,
      domain: app.hostname,
      engine: "SQLite",
      dbName: isEmDash ? "data/emdash.db (WAL + FTS5)" : "data/app.db (WAL)",
      dbUser: `rs_${app.siteId}`,
      socketOrPath: `/srv/sites/${app.siteId}/data/${isEmDash ? "emdash.db" : "app.db"}`,
      canRotatePassword: false,
      isAppDatabase: true,
    };
  }
  return null;
}

// W635 (H-04) + W661 (D-102 C2): derive MariaDB rows for WordPress/PHP sites and
// PostgreSQL 18 / MariaDB / SQLite rows for modern apps based on selected DB engine.
function buildDatabaseEntries(
  sites: { id: string; domain: string; runtime?: string; servingKind?: string }[],
  apps: AppRecord[],
): DatabaseEntry[] {
  const appHosts = new Set(apps.map((a) => a.hostname.toLowerCase()));
  const entries: DatabaseEntry[] = [];
  for (const s of sites) {
    if (appHosts.has(s.domain.toLowerCase())) continue;
    if (!isWordPressSite(s)) continue;
    entries.push({
      id: `db_${s.id}`,
      siteId: s.id,
      domain: s.domain,
      engine: "MariaDB",
      dbName: `rs_${s.id}_wp`,
      dbUser: `rs_${s.id}`,
      socketOrPath: "/run/mysqld/mysqld.sock",
      canRotatePassword: true,
      rotateTarget: "mariadb_user_password",
      isAppDatabase: false,
    });
  }
  for (const app of apps) {
    const entry = appDatabaseEntry(app);
    if (entry) entries.push(entry);
  }
  return entries;
}

function DatabaseActionDrawer({
  selected,
  onClose,
}: {
  selected: DatabaseEntry;
  onClose: () => void;
}) {
  const [snapshotId, setSnapshotId] = useState("");
  const qSite = shellQuote(selected.siteId);
  const qSnap = shellQuote(snapshotId.trim() || "<snapshot_id>");
  const rotateCmd = `# Prepare signed credential rotation plan (Runbook 35)\n${buildSiteCredentialRotateCmd({ siteId: selected.siteId, hostname: selected.domain, target: selected.rotateTarget })}\n${INSPECT_AND_SIGN_STEPS}`;
  const exportCmd =
    selected.engine === "PostgreSQL 18"
      ? `# Offline PostgreSQL 18 dump export from an encrypted backup capture (Runbook 27)\n# Snapshot: ${qSnap} · Site: ${qSite}\nrestic -r <repo> dump ${qSnap} /db.pgdump.zst | zstd -d > ./${selected.siteId}-pg18.dump`
      : `# Offline SQL export from an encrypted backup capture on the operator PC (Runbook 27)\n# Snapshot: ${qSnap} · Site: ${qSite}\nrestic -r <repo> dump ${qSnap} /db.sql.zst | zstd -d > ./${selected.siteId}-dump.sql`;

  return (
    <InspectorPanel
      ariaLabel={`Database details for ${selected.dbName}`}
      title={selected.dbName}
      subtitle={`${selected.engine} database for ${selected.domain} · Account ${selected.dbUser}`}
      monoTitle
      closeLabel="Close database details"
      onClose={onClose}
    >
      <dl className="kv">
        <dt>Website</dt>
        <dd className="mono">{selected.domain}</dd>
        <dt>Engine</dt>
        <dd>
          <span className="pill">{selected.engine}</span>
        </dd>
        <dt>Account</dt>
        <dd className="mono">{selected.dbUser}</dd>
        <dt>Access</dt>
        <dd className="mono">{selected.socketOrPath}</dd>
      </dl>

      <div className="stack">
        <div className="row" style={{ justifyContent: "space-between" }}>
          <strong className="row" style={{ gap: 6 }}>
            <Glyph icon={KeyRound} />
            Rotate database password
          </strong>
          {selected.canRotatePassword ? (
            <CopyButton text={rotateCmd} label="Copy password rotation command" />
          ) : null}
        </div>
        {selected.canRotatePassword ? (
          <>
            <p className="cap">
              {selected.isAppDatabase ? (
                <>
                  Generates a fresh password locally on the server, atomically updates{" "}
                  <span className="mono">DATABASE_URL</span> in{" "}
                  <span className="mono">private/app.env</span> (mode 0400), and restarts the app
                  unit.
                </>
              ) : (
                <>
                  Generates a new password locally on the server, atomically swaps{" "}
                  <span className="mono">db.cnf</span>, and restarts the site PHP pool.
                </>
              )}
            </p>
            <pre className="code signed-bytes">{rotateCmd}</pre>
          </>
        ) : (
          <p className="muted">
            SQLite databases use Linux file ownership and SELinux confinement instead of network
            passwords.
          </p>
        )}
      </div>

      <div className="stack">
        <div className="row" style={{ justifyContent: "space-between" }}>
          <strong className="row" style={{ gap: 6 }}>
            <Glyph icon={Download} />
            Export database dump safely
          </strong>
          <CopyButton text={exportCmd} label="Copy database export command" />
        </div>
        <div className="form-row">
          <label htmlFor="db-snap">Snapshot ID (optional — defaults to latest)</label>
          <input
            id="db-snap"
            className="input mono"
            placeholder="snap_..."
            value={snapshotId}
            onChange={(e) => setSnapshotId(e.target.value)}
          />
        </div>
        <pre className="code signed-bytes">{exportCmd}</pre>
      </div>

      {selected.canRotatePassword ? (
        <details className="disclose">
          <summary>
            <Glyph icon={ShieldCheck} />
            <span>Submit signed password rotation plan</span>
            <Glyph icon={ChevronDown} className="chev" />
          </summary>
          <div className="d-body">
            <SeparateCustodyApplyPanel />
          </div>
        </details>
      ) : null}

      <div className="insp-actions">
        <Link className="btn sm" to="/sites/$siteId" params={{ siteId: selected.siteId }}>
          Open website
        </Link>
      </div>
    </InspectorPanel>
  );
}

function dbExposureLabel(
  isLive: boolean,
  mariaListeners: number | null | undefined,
  pgListeners: number | null | undefined,
): { value: string; detail: string } {
  const totalExternal = (mariaListeners ?? 0) + (pgListeners ?? 0);
  if (!isLive || (mariaListeners === 0 && (pgListeners === 0 || pgListeners == null))) {
    return { value: "Local only", detail: "Loopback/socket verified (3306 & 5432)" };
  }
  if (totalExternal > 0) {
    return {
      value: `${totalExternal} external`,
      detail: "Exposed listener on MariaDB :3306 or PostgreSQL :5432",
    };
  }
  return { value: "Not observed", detail: "Verify MariaDB / PostgreSQL 18 listeners on host" };
}

export function DatabasesPage() {
  const data = useData();
  const isLive = isRealHost(data.source);
  const apps = isLive ? (data.observation ? liveApps(data.observation) : []) : fixtureApps;
  const entries = buildDatabaseEntries(data.sites, apps);
  const [selectedId, setSelectedId] = useDrawerSelection<string>();
  const [engineFilter, setEngineFilter] = useState<"all" | DatabaseEngineLabel>("all");
  const visible =
    engineFilter === "all" ? entries : entries.filter((e) => e.engine === engineFilter);
  const selected = visible.find((e) => e.id === selectedId) ?? null;

  const mariaCount = entries.filter((e) => e.engine === "MariaDB").length;
  const pgCount = entries.filter((e) => e.engine === "PostgreSQL 18").length;
  const sqliteCount = entries.filter((e) => e.engine === "SQLite").length;
  const exposure = dbExposureLabel(
    isLive,
    data.machine?.database?.listeners_beyond_loopback,
    data.machine?.postgresql?.installed
      ? data.machine.postgresql.listeners_beyond_loopback
      : undefined,
  );

  return (
    <Page live>
      <Crumbs items={[{ href: "/", label: "Overview" }, { label: "Databases" }]} />
      <div className="page-head">
        <div>
          <h1>Databases</h1>
          <p className="sub">
            Per-site MariaDB, PostgreSQL 18 (18.7+), and SQLite databases on this server. Every
            database runs with its own least-privilege role and local-only loopback or socket
            access.
          </p>
        </div>
        <Link className="btn primary sm" to="/sites/new">
          Add website &amp; database
        </Link>
      </div>

      <section className="grid g4" aria-label="Database summary">
        <article className="panel metric">
          <div className="m-head">Total databases</div>
          <div className="m-val">{entries.length}</div>
          <div className="m-detail">Managed across sites &amp; modern apps</div>
        </article>
        <article className="panel metric">
          <div className="m-head">MariaDB 10.11</div>
          <div className="m-val">{mariaCount}</div>
          <div className="m-detail">WordPress &amp; opt-in app accounts</div>
        </article>
        <article className="panel metric">
          <div className="m-head">PostgreSQL 18</div>
          <div className="m-val">{pgCount}</div>
          <div className="m-detail">SCRAM-SHA-256 · {sqliteCount} SQLite WAL</div>
        </article>
        <article className="panel metric">
          <div className="m-head">Network exposure</div>
          <div className="m-val" style={{ fontSize: 20 }}>
            {exposure.value}
          </div>
          <div className="m-detail">{exposure.detail}</div>
        </article>
      </section>

      {entries.length === 0 ? (
        <EmptyState
          icon={Database}
          title="No databases registered on this server yet"
          description="Provision a WordPress site or modern app with SQLite, MariaDB, or PostgreSQL 18 and its isolated database will appear here automatically."
          action={
            <Link className="btn primary sm" to="/sites/new">
              Add website
            </Link>
          }
        />
      ) : (
        <div className="stack">
          <section className="panel flush" aria-label="Databases table">
            <div className="panel-head" style={{ padding: "14px 16px 10px" }}>
              <div className="row" style={{ gap: 8 }}>
                <Glyph icon={Database} />
                <h2>Registered databases</h2>
              </div>
              <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
                {(["all", "MariaDB", "PostgreSQL 18", "SQLite"] as const).map((f) => (
                  <button
                    key={f}
                    type="button"
                    className={engineFilter === f ? "btn primary sm" : "btn quiet sm"}
                    onClick={() => setEngineFilter(f)}
                  >
                    {f === "all" ? "All" : f}
                  </button>
                ))}
              </div>
            </div>
            <TableScroll label="Databases table">
              <table className="data">
                <thead>
                  <tr>
                    <th>Website</th>
                    <th>Engine</th>
                    <th>Database</th>
                    <th>User</th>
                    <th>Access</th>
                    <th>Manage</th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map((entry) => (
                    <tr
                      key={entry.id}
                      className={selected?.id === entry.id ? "selected" : undefined}
                    >
                      <td className="mono">{entry.domain}</td>
                      <td>
                        <span className="pill">{entry.engine}</span>
                      </td>
                      <td className="mono">{entry.dbName}</td>
                      <td className="mono">{entry.dbUser}</td>
                      <td className="muted">{entry.socketOrPath}</td>
                      <td>
                        <button
                          type="button"
                          className="btn quiet sm"
                          onClick={() =>
                            setSelectedId((cur) => (cur === entry.id ? null : entry.id))
                          }
                        >
                          {selected?.id === entry.id ? "Close" : "Manage"}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableScroll>
          </section>

          {selected ? (
            <DatabaseActionDrawer selected={selected} onClose={() => setSelectedId(null)} />
          ) : null}
        </div>
      )}
    </Page>
  );
}

type SiteOpKind = "php" | "update" | "quota" | "clone" | "restore" | "eject" | "delete";

const siteOpList: [SiteOpKind, string, string][] = [
  ["php", "PHP & Cache", "Tune PHP worker limit and LiteSpeed Page Cache"],
  ["update", "WordPress Updates", "Update WordPress core, plugins, or themes with rollback"],
  ["quota", "Disk Quota", "Adjust per-site storage limit (MiB)"],
  ["clone", "Staging Clone", "Clone website from a backup into an isolated staging domain"],
  ["restore", "Restore Backup", "Restore files and database from an encrypted snapshot"],
  ["eject", "Eject Website", "Hand over standalone config without stopping serving"],
  ["delete", "Delete Website", "Take offline and remove files, database, and account"],
];

type SiteOpParams = {
  kind: SiteOpKind;
  siteId: string;
  domain: string;
  workers: string;
  cache: string;
  updateScope: "core" | "plugins" | "themes";
  quotaMib: string;
  cloneHost: string;
  snapshotId: string;
};

const siteOpCmdMap: Record<SiteOpKind, (p: SiteOpParams) => string> = {
  php: (p) =>
    buildConfigActivateCmd({
      siteId: p.siteId,
      note: `Requested PHP workers ${p.workers}, cache ${p.cache}`,
    }),
  update: (p) =>
    buildManualVerbPlanNote({
      verb: "site_update",
      runbook: "Runbook 35",
      summary: `WordPress ${p.updateScope} update for ${p.siteId} (${p.domain})`,
    }),
  quota: (p) =>
    buildManualVerbPlanNote({
      verb: "site_quota",
      runbook: "Runbook 35",
      summary: `Adjust hard disk quota for ${p.siteId} to ${p.quotaMib} MiB`,
    }),
  clone: (p) =>
    buildManualVerbPlanNote({
      verb: "site_clone",
      runbook: "Runbook 35",
      summary: `Staging clone of ${p.siteId} -> ${p.cloneHost || `staging.${p.domain}`}${p.snapshotId ? ` (snapshot ${p.snapshotId})` : ""}`,
    }),
  restore: (p) =>
    buildManualVerbPlanNote({
      verb: "site_restore",
      runbook: "Runbook 26",
      summary: `Guided live restore for ${p.siteId}${p.snapshotId ? ` from snapshot ${p.snapshotId}` : ""}`,
    }),
  eject: (p) => buildSiteEjectCmd({ siteId: p.siteId }),
  delete: (p) =>
    buildManualVerbPlanNote({
      verb: "site_delete",
      runbook: "Runbook 35",
      summary: `Destructive site removal for ${p.siteId} (${p.domain}) with recent safety backup${p.snapshotId ? ` (${p.snapshotId})` : ""}`,
    }),
};

function SiteOpInputs({
  params,
  patch,
}: {
  params: SiteOpParams;
  patch: (p: Partial<SiteOpParams>) => void;
}) {
  if (params.kind === "php") {
    return (
      <>
        <div className="form-row">
          <label htmlFor="so-workers">PHP worker limit (1–16)</label>
          <input
            id="so-workers"
            className="input tnum"
            type="number"
            min={1}
            max={16}
            value={params.workers}
            onChange={(e) => patch({ workers: e.target.value })}
          />
        </div>
        <div className="form-row">
          <label htmlFor="so-cache">LiteSpeed Page Cache</label>
          <select
            id="so-cache"
            className="input"
            value={params.cache}
            onChange={(e) => patch({ cache: e.target.value })}
          >
            <option value="litespeed_cache_793_cache_on_v1">Enabled (LiteSpeed Cache)</option>
            <option value="none">Disabled</option>
          </select>
        </div>
      </>
    );
  }
  if (params.kind === "update") {
    return (
      <div className="form-row">
        <label htmlFor="so-upd">Update target</label>
        <select
          id="so-upd"
          className="input"
          value={params.updateScope}
          onChange={(e) => patch({ updateScope: e.target.value as "core" | "plugins" | "themes" })}
        >
          <option value="core">WordPress Core</option>
          <option value="plugins">Installed Plugins</option>
          <option value="themes">Installed Themes</option>
        </select>
      </div>
    );
  }
  if (params.kind === "quota") {
    return (
      <div className="form-row">
        <label htmlFor="so-quota">Disk quota (MiB, 256–65536)</label>
        <input
          id="so-quota"
          className="input tnum"
          type="number"
          min={256}
          max={65536}
          value={params.quotaMib}
          onChange={(e) => patch({ quotaMib: e.target.value })}
        />
      </div>
    );
  }
  if (params.kind === "clone") {
    return (
      <>
        <div className="form-row">
          <label htmlFor="so-clone">Staging domain name</label>
          <input
            id="so-clone"
            className="input mono"
            value={params.cloneHost}
            onChange={(e) => patch({ cloneHost: e.target.value })}
          />
        </div>
        <div className="form-row">
          <label htmlFor="so-snap">Source backup snapshot ID (optional)</label>
          <input
            id="so-snap"
            className="input mono"
            placeholder="snap_..."
            value={params.snapshotId}
            onChange={(e) => patch({ snapshotId: e.target.value })}
          />
        </div>
      </>
    );
  }
  if (params.kind === "restore" || params.kind === "delete") {
    return (
      <div className="form-row">
        <label htmlFor="so-snap2">
          {params.kind === "delete"
            ? "Safety backup snapshot ID (< 24 h)"
            : "Snapshot ID to restore"}
        </label>
        <input
          id="so-snap2"
          className="input mono"
          placeholder="snap_..."
          value={params.snapshotId}
          onChange={(e) => patch({ snapshotId: e.target.value })}
        />
      </div>
    );
  }
  return null;
}

export function SiteActionsConsole({ siteId, domain }: { siteId: string; domain: string }) {
  const [params, setParams] = useState<SiteOpParams>({
    kind: "php",
    siteId,
    domain,
    workers: "4",
    cache: "litespeed_cache_793_cache_on_v1",
    updateScope: "plugins",
    quotaMib: "4096",
    cloneHost: `staging.${domain}`,
    snapshotId: "",
  });

  const patch = (p: Partial<SiteOpParams>) => setParams((prev) => ({ ...prev, ...p }));
  const cmd = `${siteOpCmdMap[params.kind]({ ...params, siteId, domain })}\n${INSPECT_AND_SIGN_STEPS}`;
  const destructive = params.kind === "delete" || params.kind === "eject";

  return (
    <section className="panel stack" aria-labelledby="site-ctrl-t">
      <div className="panel-head">
        <div className="row" style={{ gap: 8 }}>
          <Glyph icon={Wrench} />
          <h2 id="site-ctrl-t">Website controls</h2>
        </div>
        <CopyButton text={cmd} label="Copy website action command" />
      </div>

      <div
        className="row"
        style={{ gap: 6, flexWrap: "wrap" }}
        role="group"
        aria-label="Choose website action"
      >
        {siteOpList.map(([id, label]) => (
          <button
            key={id}
            type="button"
            className={params.kind === id ? "btn primary sm" : "btn quiet sm"}
            onClick={() => patch({ kind: id })}
          >
            {label}
          </button>
        ))}
      </div>

      <p className="muted">{siteOpList.find(([id]) => id === params.kind)?.[2]}</p>

      {destructive ? (
        <div className="attention warn" role="alert">
          <Glyph icon={TriangleAlert} />
          <div className="att-body">
            <strong>
              {params.kind === "delete"
                ? "Destructive action: deleting a website requires taking it offline first and binding a backup snapshot taken within 24 hours."
                : "Ejecting hands control of OpenLiteSpeed and HTTPS certificates back to standalone host files without interrupting traffic."}
            </strong>
          </div>
        </div>
      ) : null}

      <div className="form-grid">
        <SiteOpInputs params={params} patch={patch} />
      </div>

      <div className="row" style={{ gap: 10 }}>
        <Glyph icon={params.kind === "quota" ? HardDrive : Layers} className="list-muted" />
        <span className="cap">Sign on your operator workstation and submit below when ready.</span>
      </div>

      <pre className="code signed-bytes">{cmd}</pre>

      <details className="disclose">
        <summary>
          <Glyph icon={ShieldCheck} />
          <span>Submit signed plan for {domain}</span>
          <Glyph icon={ChevronDown} className="chev" />
        </summary>
        <div className="d-body">
          <SeparateCustodyApplyPanel />
        </div>
      </details>
    </section>
  );
}
