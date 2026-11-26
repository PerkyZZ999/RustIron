import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { toastManager } from "@/components/ui/toast";
import { MotionBeat } from "@/components/console/motion";
import { Link } from "@tanstack/react-router";
import {
  Activity,
  ListChecks,
  ShieldCheck,
  type LucideIcon,
  Globe,
  BookOpen,
  ChevronDown,
  Download,
  Filter,
  FileCode,
  FileText,
  Lock,
  Signature,
  CircleAlert,
  CircleCheck,
  CircleDashed,
  CircleMinus,
  CircleX,
  Clock,
  LoaderCircle,
  Plus,
  ClockAlert,
  Cpu,
  HardDrive,
  Info,
  KeyRound,
  MemoryStick,
  RefreshCw,
  Search,
  Server,
  TriangleAlert,
} from "lucide-react";
import { Fragment, type ReactNode, useState } from "react";

import { type ThemePreference, useThemePreference } from "./shell";
import { BackupRestoreActionsPanel } from "./backup-migration-wizards";
import { useData } from "./data";
import {
  type ConsolePreferences,
  type MetricsRange,
  type RowsPerPage,
  type TimeDisplay,
  type TransparencyPref,
  usePreferences,
} from "./prefs";
import {
  LiveOperationEvidenceBar,
  LiveSiteCoordinatorPanel,
  triggerCsvDownload,
} from "./live-coordinator";
import { InspectorPanel, OverviewFindingsPanel } from "./platform-pages";
import { RecoveryTabs, SiteInspector } from "./platform-subviews";
import { ReceiptAttestationPanel, SignedBytesPanel } from "./signed-panel";
import {
  clockSyncText,
  sshPolicyText,
  databaseText,
  stackText,
  executorSelinuxText,
  failedUnitsText,
  olsMapText,
  firewallText,
  tlsListenerText,
  enrolledRetentionText,
  inodeUseText,
  hostHistoryCaption,
  liveHostHistory,
  liveOperation,
  liveOverviewMetrics,
  liveReceipt,
  liveSnapshot,
  type Observation,
  type LiveOperation,
  type Machine,
  type LiveReceipt,
  type LiveSnapshot,
  type OverviewMetrics,
  packagePins,
  type PackagePin,
  signerFacts,
  type SignerFacts,
} from "./live";
import {
  type HostService,
  type Mark,
  type OperationRow,
  type RecoveryState,
  type ServiceState,
  type Site,
  type SiteJournal,
  type SiteSnapshot,
  sites,
} from "./fixture";
import {
  CopyId,
  Crumbs,
  EvidenceStrip,
  Glyph,
  Legend,
  Page,
  ResourceChart,
  Sparkline,
  TableScroll,
} from "./ui";

const ranges = ["1 hour", "6 hours", "24 hours", "7 days"] as const;

function Range({ extra = false }: { extra?: boolean }) {
  const [current, setCurrent] = useState("24 hours");
  const items = extra ? [...ranges, "30 days" as const] : ranges;
  return (
    <div className="seg" role="group" aria-label="Time range">
      {items.map((item) => (
        <button
          key={item}
          type="button"
          aria-pressed={current === item}
          onClick={() => setCurrent(item)}
        >
          {item}
        </button>
      ))}
    </div>
  );
}

const fixtureOverviewMetrics: OverviewMetrics = {
  cpu: { value: "24", unit: "%", detail: "5-min average · 4 vCPU", width: "24%" },
  memory: { value: "56", unit: "%", detail: "4.5 GiB of 8 GiB in use", width: "56%" },
  disk: {
    extra: "/var",
    value: "71",
    unit: "%",
    detail: "113 GiB of 160 GiB · inodes 18%",
    width: "71%",
  },
  uptime: {
    value: "23",
    unit: " days",
    detail: "Booted 1 Oct 2026, 09:12 UTC",
    kernel: "Kernel 6.12.0-55",
  },
};

function HostContext() {
  const { source, machine, refresh } = useData();
  const hostId = source.kind === "live" ? source.host.host_id : "lab-01";
  const stale = source.kind === "live" && source.stale;
  return (
    <div className="host-ctx" aria-label="Host context">
      <div className="hc-id">
        <Glyph icon={Server} />
        <div>
          <strong>{hostId}</strong>
          <small>{hostSubtitle(machine)}</small>
        </div>
      </div>
      <span className="sep" />
      <div>
        <span className={stale ? "state warn" : "state ok"}>
          <Glyph icon={stale ? ClockAlert : CircleCheck} />
          {stale ? "Stale" : "Connected"}
        </span>
        <small>
          {source.kind === "live" ? <SourceNote /> : "Observed 24 Oct 2026, 16:42 UTC · 38 s ago"}
        </small>
      </div>
      <button
        className="icon-btn"
        type="button"
        aria-label="Refresh observation"
        onClick={() => void refresh()}
      >
        <Glyph icon={RefreshCw} />
      </button>
    </div>
  );
}

function OverviewAttention() {
  return (
    <div className="attention err" role="status">
      <Glyph icon={TriangleAlert} />
      <div className="att-body">
        <strong>Operation needs attention.</strong> Configuration activation for{" "}
        <Link to="/sites/$siteId" params={{ siteId: "site_8KD2QW" }}>
          shop.lab.test
        </Link>{" "}
        stopped at the all-site probe; effect on 2 sites is uncertain. New operations on the global
        OpenLiteSpeed configuration are blocked.
        <div className="att-meta">
          Since 16:07 UTC · operation op_7Q2KX9 · read-only diagnosis remains available
        </div>
      </div>
      <Link className="btn sm" to="/operations/$operationId" params={{ operationId: "op_7Q2KX9" }}>
        Inspect operation
      </Link>
    </div>
  );
}

function OverviewMetricsRow({ metrics, foot }: { metrics: OverviewMetrics; foot: string }) {
  return (
    <section className="grid g4" aria-label="Current metrics">
      <Metric
        icon={Cpu}
        tone="c-cpu"
        bar="bg-cpu"
        label="CPU"
        value={metrics.cpu.value}
        unit={metrics.cpu.unit}
        detail={metrics.cpu.detail}
        width={metrics.cpu.width}
        href="/host/metrics#cpu"
        foot={foot}
      />
      <Metric
        icon={MemoryStick}
        tone="c-mem"
        bar="bg-mem"
        label="Memory"
        value={metrics.memory.value}
        unit={metrics.memory.unit}
        detail={metrics.memory.detail}
        width={metrics.memory.width}
        href="/host/metrics#memory"
        foot={foot}
      />
      <Metric
        icon={HardDrive}
        tone="c-disk"
        bar="bg-disk"
        label="Disk"
        extra={metrics.disk.extra}
        value={metrics.disk.value}
        unit={metrics.disk.unit}
        detail={metrics.disk.detail}
        width={metrics.disk.width}
        href="/host/metrics#disk"
        foot={foot}
      />
      <article className="panel metric">
        <div className="m-head">
          <span className="m-icon" style={{ color: "var(--muted)" }}>
            <Glyph icon={Clock} />
          </span>
          Uptime
        </div>
        <div className="m-val">
          {metrics.uptime.value}
          {metrics.uptime.unit ? <small>{metrics.uptime.unit}</small> : null}
        </div>
        <div className="m-detail">{metrics.uptime.detail}</div>
        <div className="bar" style={{ visibility: "hidden" }}>
          <i />
        </div>
        <div className="m-foot">
          <span>{metrics.uptime.kernel}</span>
          <Link to="/host/metrics">Inspect</Link>
        </div>
      </article>
    </section>
  );
}

const fixtureSummaryServices = [
  { name: "OpenLiteSpeed", kind: "ok", state: "Running", note: "38 s" },
  { name: "LSPHP 8.4", kind: "ok", state: "Running", note: "38 s" },
  { name: "MariaDB 11.4", kind: "ok", state: "Running", note: "38 s" },
  { name: "Executor", kind: "ok", state: "Running", note: "38 s" },
  { name: "firewalld", kind: "unknown", state: "Not checked", note: "—" },
];

function overviewServices(isLive: boolean, services: HostService[]) {
  if (!isLive) return fixtureSummaryServices;
  return services.slice(0, 5).map((service) => {
    const kind =
      service.state === "Running" || service.state === "Synced"
        ? "ok"
        : service.state === "Failed"
          ? "err"
          : "unknown";
    return {
      name: service.name,
      kind,
      state: service.state,
      note: service.since === "—" ? "—" : service.since.replace(" UTC", ""),
    };
  });
}

function adoptedCount(list: Site[]) {
  const count = list.filter((site) => site.ownership === "Adopted").length;
  return count ? [{ count, label: "Adopted (serving not observed)", dot: "unknown" }] : [];
}

function overviewSiteCounts(isLive: boolean, list: Site[]) {
  if (!isLive) {
    return [
      { count: 6, label: "Serving", dot: "ok" },
      { count: 1, label: "Blocked by operation", dot: "err" },
      { count: 1, label: "Observed only", dot: "unknown" },
      { count: 8, label: "Registered sites", dot: null },
    ];
  }
  return [
    {
      count: list.filter((site) => site.ownership === "Created" && site.serving !== "Ejected")
        .length,
      label: "Created (serving not observed)",
      dot: "unknown",
    },
    // W372: adopted sites are listed only when the journal holds one.
    ...adoptedCount(list),
    {
      count: list.filter((site) => site.serving === "Quarantined").length,
      label: "Quarantined",
      dot: "err",
    },
    {
      count: list.filter((site) => site.serving === "Ejected").length,
      label: "Ejected",
      dot: "unknown",
    },
    { count: list.length, label: "Registered sites", dot: null },
  ];
}

function OverviewRecentOps({
  isLive,
  operations,
}: {
  isLive: boolean;
  operations: OperationRow[];
}) {
  if (isLive) {
    return (
      <ul className="list">
        {operations.slice(0, 4).map((row) => (
          <li key={`${row.action}-${row.id}`}>
            <Glyph icon={row.icon} />
            <span className="grow">
              <span className="t">
                {row.linked ? (
                  <Link to="/operations/$operationId" params={{ operationId: row.id }}>
                    {row.action}
                  </Link>
                ) : (
                  row.action
                )}
              </span>
              <span className="s">
                {row.resources} · {row.outcome.toLowerCase()}
              </span>
            </span>
            <span className="r">
              {row.started === "—" ? row.id : (row.started.split(", ")[1] ?? row.started)}
            </span>
          </li>
        ))}
      </ul>
    );
  }
  return (
    <ul className="list">
      <li>
        <Glyph icon={CircleAlert} />
        <span className="grow">
          <span className="t">Config activation</span>
          <span className="s">shop.lab.test · needs attention</span>
        </span>
        <span className="r">35m</span>
      </li>
      <li>
        <Glyph icon={CircleCheck} />
        <span className="grow">
          <span className="t">Backup capture</span>
          <span className="s">blog.lab.test · succeeded</span>
        </span>
        <span className="r">2h</span>
      </li>
      <li>
        <Glyph icon={CircleCheck} />
        <span className="grow">
          <span className="t">Restore probe</span>
          <span className="s">docs.lab.test · succeeded</span>
        </span>
        <span className="r">5h</span>
      </li>
      <li>
        <Glyph icon={CircleX} />
        <span className="grow">
          <span className="t">Site provision</span>
          <span className="s">news.lab.test · failed, partial</span>
        </span>
        <span className="r">1d</span>
      </li>
    </ul>
  );
}

const unobservedOverviewMetrics: OverviewMetrics = {
  cpu: { value: "—", unit: "", detail: "Not observed in this snapshot", width: "0%" },
  memory: { value: "—", unit: "", detail: "Not observed in this snapshot", width: "0%" },
  disk: {
    extra: "/var",
    value: "—",
    unit: "",
    detail: "Not observed in this snapshot",
    width: "0%",
  },
  uptime: {
    value: "—",
    unit: "",
    detail: "Run rustiron-control --host-status",
    kernel: "Not observed",
  },
};

function resolveOverviewMetrics(isLive: boolean, machine: Machine | null): OverviewMetrics {
  if (machine) return liveOverviewMetrics(machine);
  return isLive ? unobservedOverviewMetrics : fixtureOverviewMetrics;
}

export function Overview() {
  const data = useData();
  const isLive = data.source.kind === "live";
  const metrics = resolveOverviewMetrics(isLive, data.machine);
  const history = data.machine ? liveHostHistory(data.machine) : null;
  const foot = data.source.kind === "live" ? (data.source.stale ? "stale" : "live") : "38 s ago";
  const summaryServices = overviewServices(isLive, data.services);
  const siteCounts = overviewSiteCounts(isLive, data.sites);
  const chartSubtitle = !isLive
    ? "5-minute averages · UTC · disk is /var"
    : history
      ? "Collected host samples · UTC"
      : "Collecting host samples · history appears after the next observation";
  const chartLabel = history
    ? "Live CPU, memory and disk samples from the host"
    : "CPU, memory and disk usage over the last 24 hours, with a 25-minute gap in samples around 08:00";

  return (
    <Page live>
      <MotionBeat beat={0}>
        <div className="page-head">
          <div>
            <h1>Host overview</h1>
            <p className="sub">
              Server health, hosted websites, resource usage, and quick actions.
            </p>
          </div>
          <HostContext />
        </div>
      </MotionBeat>
      {isLive ? null : (
        <MotionBeat beat={1}>
          <OverviewAttention />
        </MotionBeat>
      )}
      <MotionBeat beat={2}>
        <OverviewMetricsRow metrics={metrics} foot={foot} />
      </MotionBeat>
      <MotionBeat beat={3}>
        <nav className="quick-actions" aria-label="Quick actions">
          <Link className="qa-card" to="/sites/new">
            <span className="qa-icon">
              <Glyph icon={Globe} />
            </span>
            <span className="qa-text">
              <strong>Add website</strong>
              <span>Provision a WordPress site or app</span>
            </span>
          </Link>
          <Link className="qa-card" to="/domains/new">
            <span className="qa-icon">
              <Glyph icon={Server} />
            </span>
            <span className="qa-text">
              <strong>Add domain &amp; DNS</strong>
              <span>Create DNS zones &amp; SSL certs</span>
            </span>
          </Link>
          <Link className="qa-card" to="/mail">
            <span className="qa-icon">
              <Glyph icon={Info} />
            </span>
            <span className="qa-text">
              <strong>Email &amp; relay</strong>
              <span>Configure outbound mail &amp; DNS</span>
            </span>
          </Link>
          <Link className="qa-card" to="/recovery">
            <span className="qa-icon">
              <Glyph icon={ShieldCheck} />
            </span>
            <span className="qa-text">
              <strong>Backups &amp; restore</strong>
              <span>Snapshots &amp; recovery checks</span>
            </span>
          </Link>
        </nav>
      </MotionBeat>
      <MotionBeat beat={4}>
        <div className="aside-grid">
          <section className="panel" aria-labelledby="hist-title">
            <div className="panel-head">
              <div>
                <h2 id="hist-title">Resource history</h2>
                <p className="cap">{chartSubtitle}</p>
              </div>
              <div className="row">
                {isLive ? null : <Range />}
                <Link className="btn quiet sm" to="/host/metrics">
                  View as table
                </Link>
              </div>
            </div>
            <ResourceChart live={isLive} history={history} label={chartLabel} />
            {!isLive || history ? <Legend /> : null}
          </section>
          <OverviewFindingsPanel />
        </div>
      </MotionBeat>
      <MotionBeat beat={5}>
        <section className="grid g2" aria-label="Summaries">
          <article className="panel">
            <div className="panel-head">
              <h2>Services</h2>
              <Link to="/host/services">View all</Link>
            </div>
            <ul className="list">
              {summaryServices.map((service) => (
                <li key={service.name}>
                  <span className={`dot ${service.kind}`} />
                  <span className="grow t">{service.name}</span>
                  <span className={`state ${service.kind}`}>{service.state}</span>
                  <span className="r">{service.note}</span>
                </li>
              ))}
            </ul>
          </article>
          <article className="panel">
            <div className="panel-head">
              <h2>Sites</h2>
              <Link to="/sites">View all</Link>
            </div>
            <ul className="list tnum">
              {siteCounts.map((item) => (
                <li key={item.label}>
                  <strong style={{ width: 28 }}>{item.count}</strong>
                  <span className={item.dot ? "grow" : "grow muted"}>{item.label}</span>
                  {item.dot ? <span className={`dot ${item.dot}`} /> : null}
                </li>
              ))}
            </ul>
          </article>
          <article className="panel">
            <div className="panel-head">
              <h2>Recent operations</h2>
              <Link to="/operations">View all</Link>
            </div>
            <OverviewRecentOps isLive={isLive} operations={data.operations} />
          </article>
          <article className="panel">
            <div className="panel-head">
              <h2>Recovery evidence</h2>
              <Link to="/recovery">View all</Link>
            </div>
            <ul className="list">
              {(isLive ? data.sites : sites).slice(0, 4).map((site) => (
                <li key={site.id}>
                  <span className="grow">
                    <span className="t">{site.domain}</span>
                    <span className="s">{site.operationDetail || site.operation}</span>
                  </span>
                  <EvidenceStrip marks={site.marks} />
                </li>
              ))}
            </ul>
          </article>
        </section>
      </MotionBeat>
    </Page>
  );
}

function Metric({
  icon,
  tone,
  bar,
  label,
  extra,
  value,
  unit,
  detail,
  width,
  href,
  foot,
}: {
  icon: typeof Cpu;
  tone: string;
  bar: string;
  label: string;
  extra?: string;
  value: string;
  unit: string;
  detail: string;
  width: string;
  href: string;
  foot: string;
}) {
  return (
    <article className="panel metric">
      <div className="m-head">
        <span className={`m-icon ${tone}`}>
          <Glyph icon={icon} />
        </span>
        {label} {extra ? <span className="cap">{extra}</span> : null}
      </div>
      <div className="m-val">
        {value}
        <small>{unit}</small>
      </div>
      <div className="m-detail tnum">{detail}</div>
      <div className="bar">
        <i className={bar} style={{ width }} />
      </div>
      <div className="m-foot">
        <span>{foot}</span>
        <Link to={href}>Inspect</Link>
      </div>
    </article>
  );
}

function InodeMeta({ disk }: { disk: Machine["disk"] | undefined }) {
  if (!disk) return null;
  return <span className="meta">{inodeUseText(disk) ?? "Inodes not observed"}</span>;
}

function exportMetricsCsv(hostId: string, history: ReturnType<typeof liveHostHistory>) {
  if (!history) return;
  const rows: string[][] = [["timestamp_utc", "cpu_pct", "memory_pct", "disk_pct"]];
  for (const s of history.samples) {
    rows.push([
      new Date(s.t * 1000).toISOString(),
      s.cpu === null ? "" : String(s.cpu),
      s.mem === null ? "" : String(s.mem),
      s.disk === null ? "" : String(s.disk),
    ]);
  }
  triggerCsvDownload(`rustiron-metrics-${hostId}.csv`, rows);
}

export function HostMetrics() {
  const data = useData();
  const isLive = data.source.kind === "live";
  const history = data.machine ? liveHostHistory(data.machine) : null;
  const hostId = data.source.kind === "live" ? data.source.host.host_id : "lab-01";
  const diskPath = data.machine?.disk.path ?? "/var";

  return (
    <Page live>
      <Crumbs items={[{ href: "/", label: "Overview" }, { label: "Host metrics" }]} />
      <div className="page-head">
        <div>
          <h1>Host metrics</h1>
          <p className="sub">
            CPU, memory, and disk history collected for {hostId}. Export raw samples as CSV at any
            time.
          </p>
        </div>
        <div className="head-actions">
          {isLive ? null : <Range extra />}
          <button
            className="btn sm"
            type="button"
            disabled={!history}
            onClick={() => exportMetricsCsv(hostId, history)}
          >
            <Glyph icon={Download} />
            Export CSV
          </button>
        </div>
      </div>
      {isLive ? (
        <div className="attention info">
          <Glyph icon={Info} />
          <div className="att-body">
            <strong>{history ? hostHistoryCaption(history) : "Collecting host samples."}</strong>{" "}
            {history
              ? "Gaps stay as gaps, not zeros."
              : "History appears after the next observation."}
            <div className="att-meta">Source: rustiron-control on the host</div>
          </div>
        </div>
      ) : (
        <div className="attention info">
          <Glyph icon={Info} />
          <div className="att-body">
            <strong>25-minute collection gap.</strong> No samples between 07:55 and 08:20 UTC while
            the observer restarted after a package update. Gaps are shown as gaps, not zeros.
            <div className="att-meta">Source: rustiron-observer journal · 24 Oct 2026</div>
          </div>
        </div>
      )}
      <section className="panel" id="cpu">
        <div className="panel-head">
          <div>
            <h2 className="c-cpu">CPU</h2>
            <p className="cap">
              {isLive
                ? "5-minute load as a percent of vCPU · UTC"
                : "5-minute average of all 4 vCPU · UTC"}
            </p>
          </div>
        </div>
        <ResourceChart
          live={isLive}
          history={history}
          label={
            history
              ? "Live CPU samples from the host"
              : "CPU usage over 24 hours with a collection gap"
          }
          height={180}
          only="cpu"
        />
      </section>
      <section className="panel" id="memory">
        <div className="panel-head">
          <h2 className="c-mem">Memory</h2>
        </div>
        <ResourceChart
          live={isLive}
          history={history}
          label={
            history
              ? "Live memory samples from the host"
              : "Memory usage over 24 hours with a collection gap"
          }
          height={180}
          only="mem"
        />
      </section>
      <section className="panel" id="disk">
        <div className="panel-head">
          <h2 className="c-disk">Disk {diskPath}</h2>
          <InodeMeta disk={data.machine?.disk} />
        </div>
        <ResourceChart
          live={isLive}
          history={history}
          label={
            history
              ? "Live disk samples from the host"
              : "Disk usage over 24 hours with a collection gap"
          }
          height={180}
          only="disk"
        />
      </section>
      {history ? (
        <details className="disclose">
          <summary>
            <Glyph icon={ListChecks} />
            <span>Sample data table ({history.samples.length} observations)</span>
            <Glyph icon={ChevronDown} className="chev" />
          </summary>
          <div className="d-body">
            <TableScroll label="Collected host metric samples">
              <table className="data tnum">
                <thead>
                  <tr>
                    <th scope="col">Timestamp (UTC)</th>
                    <th scope="col">CPU %</th>
                    <th scope="col">Memory %</th>
                    <th scope="col">Disk %</th>
                  </tr>
                </thead>
                <tbody>
                  {history.samples
                    .slice(-50)
                    .reverse()
                    .map((s) => (
                      <tr key={s.t}>
                        <td className="mono">
                          {new Date(s.t * 1000).toISOString().replace("T", " ").slice(0, 19)}
                        </td>
                        <td>{s.cpu === null ? "—" : `${s.cpu}%`}</td>
                        <td>{s.mem === null ? "—" : `${s.mem}%`}</td>
                        <td>{s.disk === null ? "—" : `${s.disk}%`}</td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </TableScroll>
          </div>
        </details>
      ) : null}
    </Page>
  );
}

function serviceStateClass(state: ServiceState) {
  if (state === "Not checked") return "state unknown";
  if (state === "Stale" || state === "Starting") return "state warn";
  if (state === "Failed") return "state err";
  if (state === "Stopped") return "state notrun";
  return "state ok";
}

function serviceStateIcon(state: ServiceState) {
  if (state === "Not checked") return CircleDashed;
  if (state === "Stale" || state === "Starting") return ClockAlert;
  if (state === "Failed") return CircleX;
  if (state === "Stopped") return CircleMinus;
  return CircleCheck;
}

function hostSubtitle(machine: ReturnType<typeof useData>["machine"]) {
  if (!machine) return "Profile almalinux10-ols-lsphp84 · rev 3";
  const os = `${machine.os.name ?? "Unknown OS"} ${machine.os.version ?? ""}`.trim();
  return `${os} · SELinux ${machine.selinux ?? "not checked"} · ${clockSyncText(machine.clock)}`;
}

function SshPolicyLine({ ssh }: { ssh: Machine["ssh"] }) {
  if (!ssh) return null;
  return <p className="cap">{sshPolicyText(ssh)}</p>;
}

function TlsListenerLine({ tls }: { tls: Machine["tls"] }) {
  if (!tls) return null;
  return <p className="cap">{tlsListenerText(tls)}</p>;
}

function FirewallLine({ firewall }: { firewall: Machine["firewall"] }) {
  if (!firewall) return null;
  return <p className="cap">{firewallText(firewall)}</p>;
}

function DatabaseLine({ database }: { database: Machine["database"] }) {
  if (!database) return null;
  return <p className="cap">{databaseText(database)}</p>;
}

function StackLine({ stack }: { stack: Machine["stack"] }) {
  if (!stack) return null;
  return <p className="cap">{stackText(stack)}</p>;
}

function ExecutorSelinuxLine({ value }: { value: Machine["executor_selinux"] }) {
  if (!value) return null;
  return <p className="cap">{executorSelinuxText(value)}</p>;
}

function FailedUnitsLine({ value }: { value: Machine["failed_units"] }) {
  if (!value) return null;
  return <p className="cap">{failedUnitsText(value)}</p>;
}

function OlsMapLine({
  map,
  journalSites,
}: {
  map: Machine["ols_map"];
  journalSites: Observation["sites"] | undefined;
}) {
  const text = olsMapText(map, journalSites);
  if (!text) return null;
  return <p className="cap">{text}</p>;
}

function ServicePolicyLines({ data }: { data: ReturnType<typeof useData> }) {
  return (
    <>
      <SshPolicyLine ssh={data.machine?.ssh} />
      <TlsListenerLine tls={data.machine?.tls} />
      <FirewallLine firewall={data.machine?.firewall} />
      <DatabaseLine database={data.machine?.database} />
    </>
  );
}

function ServiceStackLines({ data }: { data: ReturnType<typeof useData> }) {
  return (
    <>
      <StackLine stack={data.machine?.stack} />
      <ExecutorSelinuxLine value={data.machine?.executor_selinux} />
      <FailedUnitsLine value={data.machine?.failed_units} />
      <OlsMapLine map={data.machine?.ols_map} journalSites={data.observation?.sites} />
    </>
  );
}

function ServiceHostFacts({ data }: { data: ReturnType<typeof useData> }) {
  const hostId = data.source.kind === "live" ? data.source.host.host_id : "lab-01";
  return (
    <div className="page-head">
      <div>
        <h1>Services</h1>
        <p className="sub">
          Supported host profile services and their observed state. Restart and configuration
          changes require a reviewed plan.
        </p>
        <ServicePolicyLines data={data} />
        <ServiceStackLines data={data} />
      </div>
      <div className="host-ctx">
        <div className="hc-id">
          <Glyph icon={Server} />
          <div>
            <strong>{hostId}</strong>
            <small>{hostSubtitle(data.machine)}</small>
          </div>
        </div>
      </div>
    </div>
  );
}

function matchingServices(services: HostService[], query: string, stateFilter: string) {
  const needle = query.trim().toLowerCase();
  return services.filter((service) => {
    const matchesState = stateFilter === "All states" || service.state === stateFilter;
    const haystack = `${service.name} ${service.unit} ${service.role}`.toLowerCase();
    return matchesState && (needle === "" || haystack.includes(needle));
  });
}

function UnitSelinux({ context }: { context: string | null | undefined }) {
  if (context === undefined) return null;
  return (
    <>
      <dt>SELinux</dt>
      <dd>{context ? <code translate="no">{context}</code> : "No process label"}</dd>
    </>
  );
}

function ObservedServiceFacts({ service }: { service: HostService }) {
  return (
    <dl className="kv">
      <dt>Unit</dt>
      <dd>
        <code translate="no">{service.unit}</code>
      </dd>
      <dt>Role</dt>
      <dd>{service.role}</dd>
      <dt>Since</dt>
      <dd>{service.since}</dd>
      <dt>Management</dt>
      <dd>{service.management}</dd>
      <UnitSelinux context={service.selinux} />
    </dl>
  );
}

export function HostServices() {
  const data = useData();
  const hostServices = data.services;
  const [query, setQuery] = useState("");
  const [stateFilter, setStateFilter] = useState("All states");
  const [selectedName, setSelectedName] = useState<string | null>(null);
  const visible = matchingServices(hostServices, query, stateFilter);
  const selected = visible.find((service) => service.name === selectedName) ?? null;

  return (
    <Page live>
      <Crumbs items={[{ href: "/", label: "Overview" }, { label: "Services" }]} />
      <ServiceHostFacts data={data} />
      <section className="panel flush" aria-label="Services table">
        <div className="toolbar">
          <label className="input search-input">
            <Glyph icon={Search} />
            <input
              aria-label="Filter services"
              placeholder="Filter services"
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
              value={stateFilter}
              onChange={(event) => setStateFilter(event.target.value)}
            >
              <option>All states</option>
              <option>Running</option>
              <option>Synced</option>
              <option>Not checked</option>
              <option>Stale</option>
              <option>Starting</option>
              <option>Stopped</option>
              <option>Failed</option>
            </select>
          </label>
          <span className="muted" style={{ marginLeft: "auto", fontSize: 13 }}>
            {visible.length === hostServices.length
              ? `${hostServices.length} services`
              : `${visible.length} of ${hostServices.length} services`}{" "}
            · <SourceNote />
          </span>
        </div>
        <TableScroll label="Services">
          <table className="data">
            <thead>
              <tr>
                <th>Service</th>
                <th>Role</th>
                <th>State</th>
                <th>Since</th>
                <th>Management</th>
              </tr>
            </thead>
            <tbody>
              {visible.length === 0 ? (
                <tr>
                  <td colSpan={5}>No services match this filter.</td>
                </tr>
              ) : (
                visible.map((service) => (
                  <tr
                    key={service.name}
                    className={selected?.name === service.name ? "selected" : undefined}
                  >
                    <td className="primary-cell">
                      <button
                        type="button"
                        aria-pressed={selected?.name === service.name}
                        onClick={() =>
                          setSelectedName((cur) => (cur === service.name ? null : service.name))
                        }
                      >
                        {service.name}
                      </button>
                      <small className="mono" translate="no">
                        {service.unit}
                      </small>
                    </td>
                    <td>{service.role}</td>
                    <td>
                      <span className={serviceStateClass(service.state)}>
                        <Glyph icon={serviceStateIcon(service.state)} />
                        {service.state}
                      </span>
                    </td>
                    <td className="muted">{service.since}</td>
                    <td>{service.management}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </TableScroll>
      </section>
      {data.source.kind === "live" ? null : (
        <section className="panel">
          <div className="panel-head">
            <h2>Why “Not checked”?</h2>
          </div>
          <p className="muted">
            The observer runs unprivileged and cannot read firewalld state on this profile. It
            reports Not checked rather than assuming the firewall is active.
          </p>
          <p style={{ marginTop: 8 }}>
            <Link to="/help/$slug" params={{ slug: "security-and-diagnoses" }}>
              Read the observer permissions runbook
            </Link>
          </p>
        </section>
      )}
      {selected ? (
        <InspectorPanel
          ariaLabel="Selected service"
          title={selected.name}
          subtitle={selected.unit}
          closeLabel="Close service details"
          onClose={() => setSelectedName(null)}
        >
          <div className="row" style={{ gap: 8 }}>
            <span className={serviceStateClass(selected.state)}>
              <Glyph icon={serviceStateIcon(selected.state)} />
              {selected.state}
            </span>
            <span className="cap">{selected.role}</span>
          </div>
          {selected.name === "OpenLiteSpeed 1.9.3" ? (
            <dl className="kv">
              <dt>Unit</dt>
              <dd>
                <code translate="no">lshttpd.service</code>
              </dd>
              <dt>Listeners</dt>
              <dd>:80, :443</dd>
              <dt>Workers</dt>
              <dd>2 · user nobody</dd>
              <dt>Config generation</dt>
              <dd>
                41 active · 42{" "}
                <Link to="/operations/$operationId" params={{ operationId: "op_7Q2KX9" }}>
                  uncertain
                </Link>
              </dd>
              <dt>Last restart</dt>
              <dd>16:07 UTC by op_7Q2KX9</dd>
              <dt>Observed</dt>
              <dd>16:42 UTC · 38 s ago</dd>
            </dl>
          ) : (
            <ObservedServiceFacts service={selected} />
          )}
          {selected.name === "OpenLiteSpeed 1.9.3" ? (
            <div className="stack">
              <h3 style={{ fontSize: 14, fontWeight: 600 }}>Recent events</h3>
              <ul className="list">
                <li>
                  <Glyph className="list-muted" icon={RefreshCw} />
                  <span className="grow">
                    <span className="t">Graceful restart</span>
                    <span className="s">op_7Q2KX9 · config activation</span>
                  </span>
                  <span className="r">16:07</span>
                </li>
                <li>
                  <Glyph className="list-ok" icon={CircleCheck} />
                  <span className="grow">
                    <span className="t">Health probe passed</span>
                    <span className="s">6 of 8 sites answered</span>
                  </span>
                  <span className="r">16:08</span>
                </li>
                <li>
                  <Glyph className="list-muted" icon={RefreshCw} />
                  <span className="grow">
                    <span className="t">Graceful restart</span>
                    <span className="s">op_4MN2P1 · config activation</span>
                  </span>
                  <span className="r">Tue</span>
                </li>
              </ul>
            </div>
          ) : null}
        </InspectorPanel>
      ) : null}
    </Page>
  );
}

function matchesSiteFilter(site: Site, needle: string, stateFilter: string): boolean {
  if (stateFilter !== "all" && site.servingKind !== stateFilter) return false;
  if (!needle) return true;
  return `${site.domain} ${site.id} ${site.runtime}`.toLowerCase().includes(needle);
}

export function SitesPage() {
  const data = useData();
  const [query, setQuery] = useState("");
  const [stateFilter, setStateFilter] = useState("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);
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

/** How old the shown data is, in words. */
function SourceNote() {
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

function SiteHead({ site }: { site: Site }) {
  const http = httpState[site.httpKind];
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
            <span className={site.servingKind === "err" ? "pill err" : "pill"}>{site.serving}</span>
          )}
          <span className="pill">{site.runtime}</span>
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
          <small>
            {site.httpKind === "muted"
              ? "No HTTP observation"
              : "HTTP observed 16:41 UTC · 1 min ago"}
          </small>
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
            ? "From the executor journal: ownership, operations and recovery. Serving, HTTP and runtime are not observed yet."
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

function matchesOutcome(outcome: string, filter: string) {
  if (filter === "All outcomes") return true;
  if (filter === "Running") return outcome.startsWith("Running");
  if (filter === "Failed") return outcome.startsWith("Failed ·");
  return outcome === filter;
}

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
            {data.source.kind === "live"
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
            {data.source.kind === "live"
              ? "Recorded, not finished"
              : "Backup capture · wiki.lab.test"}
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
            {data.source.kind === "live"
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
            {data.source.kind === "live"
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
              : data.source.kind === "live"
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

const recoveryStateIcon = {
  ok: CircleCheck,
  err: CircleX,
  notrun: CircleMinus,
  unknown: CircleDashed,
} as const;

function RecoveryStateLabel({ state }: { state: RecoveryState }) {
  return (
    <span className={`state ${state.kind}`}>
      <Glyph icon={recoveryStateIcon[state.kind]} />
      {state.label}
    </span>
  );
}

function EvidenceKey() {
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

const recoveryFilters = ["All sites", "Any field not passing"] as const;

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

export function RecoveryPage() {
  const [query, setQuery] = useState("");
  const [show, setShow] = useState<(typeof recoveryFilters)[number]>("All sites");
  const needle = query.trim().toLowerCase();
  const data = useData();
  const rows = data.recovery.flatMap((row) => {
    const site = data.sites.find((candidate) => candidate.id === row.siteId);
    if (!site) return [];
    if (show === "Any field not passing" && site.marks.every((mark) => mark === "pass")) return [];
    const haystack = `${site.domain} ${row.snapshot ?? ""} ${row.receipt ?? ""}`.toLowerCase();
    return needle && !haystack.includes(needle) ? [] : [{ row, site }];
  });
  return (
    <Page live>
      <div className="page-head">
        <div>
          <h1>Recovery</h1>
          <p className="sub">
            Recovery evidence for each site, field by field. A captured backup is not counted as
            recoverable until a restore is tested.
          </p>
        </div>
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
      </div>
      <RecoveryTabs current="/recovery" />
      <BackupRestoreActionsPanel />
      {data.source.kind === "live" ? null : (
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
      <section className="panel">
        <div className="panel-head">
          <h2>Seven evidence fields</h2>
          <span className="meta">
            Each is recorded separately; there is no combined &ldquo;backup healthy&rdquo; score
          </span>
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
      </section>
      <section className="panel flush" aria-label="Recovery by site">
        <div className="toolbar">
          <label className="input search-input">
            <Glyph icon={Search} />
            <input
              aria-label="Site or snapshot ID"
              placeholder="Site or snapshot ID"
              autoComplete="off"
              spellCheck={false}
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
          </label>
          <label className="field">
            Show
            <select
              className="input"
              value={show}
              onChange={(event) => setShow(event.target.value as typeof show)}
            >
              {recoveryFilters.map((filter) => (
                <option key={filter}>{filter}</option>
              ))}
            </select>
          </label>
          <div className="toolbar-end">
            <EvidenceKey />
          </div>
        </div>
        <TableScroll label="Recovery by site">
          <table className="data">
            <thead>
              <tr>
                <th scope="col">Site</th>
                <th scope="col">Latest snapshot</th>
                <th scope="col">Evidence (latest receipt)</th>
                <th scope="col">Last restore test</th>
                <th scope="col">Independent copy</th>
                <th scope="col">Receipt</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ row, site }) => (
                <tr key={site.id}>
                  <td className="primary-cell">
                    <Link to="/sites/$siteId/recovery" params={{ siteId: site.id }}>
                      {site.domain}
                    </Link>
                  </td>
                  <td className={row.snapshot ? "tnum" : "muted"}>
                    <div>{row.snapshot ?? row.snapshotNote}</div>
                    {row.snapshot && row.exposure ? (
                      <div className="cap">{row.exposure}</div>
                    ) : null}
                  </td>
                  <td>
                    <EvidenceStrip marks={site.marks} />
                  </td>
                  <td>
                    {row.restore ? (
                      <RecoveryStateLabel state={row.restore} />
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </td>
                  <td>
                    {typeof row.copy === "string" ? (
                      row.copy
                    ) : row.copy ? (
                      <RecoveryStateLabel state={row.copy} />
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </td>
                  <td>
                    <ReceiptCell receipt={row.receipt} live={data.source.kind === "live"} />
                  </td>
                </tr>
              ))}
              {rows.length === 0 ? (
                <tr>
                  <td colSpan={6} className="muted">
                    No site matches this filter.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </TableScroll>
        <div className="pager">
          <span>
            {rows.length} of {data.recovery.length} sites
            {data.source.kind === "live" ? " · in recorded order" : " · sorted by weakest evidence"}
          </span>
          <span>
            {data.source.kind === "live"
              ? `Repository: ${data.source.host.backup_destination ?? "none enrolled"} (lab store on the operator PC, not independent)`
              : "Repositories: offsite-b2 (independent provider) · local-stage"}
          </span>
        </div>
      </section>
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
          { href: "/recovery", label: "Recovery" },
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
          { href: "/recovery", label: "Recovery" },
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
          { href: "/recovery", label: "Recovery" },
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
          { href: "/recovery", label: "Recovery" },
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

const themeChoices: { value: ThemePreference; label: string }[] = [
  { value: "system", label: "Match system" },
  { value: "light", label: "Light" },
  { value: "dark", label: "Dark" },
];

const signers = [
  ["Operator key", "SHA256:Qm4…f2c · ed25519", "Active", "ok"],
  ["Break-glass key", "SHA256:Wd1…07a · offline", "Active", "ok"],
  ["Old operator key", "SHA256:Bz8…c13", "Revoked 3 Oct", "muted"],
] as const;

function observedFact(value: string | null | undefined): [string, string] {
  return value ? [value, "Observed"] : ["Not in this observation", "Not checked"];
}

function settingsProfileRows(
  live: boolean,
  osName: string | null | undefined,
  osVersion: string | null | undefined,
  kernel: string | null | undefined,
  selinux: string | null | undefined,
  listener: string | null | undefined,
  backup: string | null | undefined,
): [string, string, string][] {
  if (!live) {
    return [
      ["AlmaLinux", "10.0", "Matches"],
      ["OpenLiteSpeed", "1.9.3", "Matches"],
      ["LSPHP", "8.4.13", "Matches"],
      ["MariaDB", "11.4.8", "Matches"],
      ["SELinux", "Not readable by observer", "Not checked"],
    ];
  }
  const os = osName && osVersion ? `${osName} ${osVersion}` : null;
  return [
    ["OS", ...observedFact(os)],
    ["Kernel", ...observedFact(kernel)],
    ["SELinux", ...observedFact(selinux)],
    ["OLS listener", ...observedFact(listener)],
    ["Backup destination", ...observedFact(backup)],
  ];
}

/** One row per observed package, or one row saying the pins are missing. */
export function packageRows(pins: PackagePin[] | null): [string, string, string][] {
  if (!pins) return [["Package pins", "Not in this observation", "Not checked"]];
  return pins.map((pin) => [
    pin.name,
    pin.version
      ? `${pin.version} · ${pin.signing_key ? `signed, key ${pin.signing_key}` : "unsigned"}`
      : "Not installed",
    pin.version ? "Observed" : "Not checked",
  ]);
}

function profileCaption(live: boolean, pins: PackagePin[] | null): string {
  if (!live) return "almalinux10-ols-lsphp84 · revision 3 · digest ";
  return pins
    ? "Facts from this observation only. Package pins come from the host RPM database."
    : "Facts from this observation only. Package pins are not in this observation.";
}

function SettingsProfile({ live }: { live: boolean }) {
  const data = useData();
  const machine = data.machine;
  const host = data.source.kind === "live" ? data.source.host : null;
  const rows = settingsProfileRows(
    live,
    machine?.os.name,
    machine?.os.version,
    machine?.os.kernel,
    machine?.selinux,
    host?.ols_listener,
    host?.backup_destination,
  );
  const pins = live ? packagePins(host) : null;
  if (live) rows.push(...packageRows(pins));
  return (
    <section className="panel flush" aria-labelledby="prof-t">
      <div className="panel-head">
        <div>
          <h2 id="prof-t">Supported host profile</h2>
          <p className="cap">
            {profileCaption(live, pins)}
            {live ? null : <code>sha256:a2f0…31bd</code>}
          </p>
        </div>
        <span className="pill">Read-only</span>
      </div>
      <TableScroll label="Supported host profile">
        <table className="data">
          <thead>
            <tr>
              <th scope="col">Component</th>
              <th scope="col">{live ? "Observed" : "Pinned / observed"}</th>
              <th scope="col">State</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(([component, value, state]) => (
              <tr key={component}>
                <td>{component}</td>
                <td className={state === "Not checked" ? "muted" : undefined}>{value}</td>
                <td>
                  <span
                    className={`state ${state === "Observed" || state === "Matches" ? "ok" : "unknown"}`}
                  >
                    <Glyph
                      icon={
                        state === "Observed" || state === "Matches" ? CircleCheck : CircleDashed
                      }
                    />
                    {state}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableScroll>
    </section>
  );
}

type ObservedHost = {
  host_id: string;
  host_epoch: string;
  issuer: string;
  signer_policy_epoch: string;
  backup_retention_days?: number | null;
};

export function signerRows(facts: SignerFacts | null): [string, string][] {
  if (!facts) return [["Signer key", "Not in this observation"]];
  return [
    ["Key", `${facts.algorithm} ${facts.fingerprint}`],
    ["Namespace", facts.namespace],
    [
      "Revocations",
      facts.revocations_bytes === 0
        ? "Empty list"
        : `${facts.revocations_bytes} bytes · sha256 ${facts.revocations_sha256.slice(0, 12)}`,
    ],
  ];
}

function SettingsSigners({ host }: { host: ObservedHost }) {
  const rows = signerRows(signerFacts(host as Observation["host"]));
  return (
    <dl className="kv">
      <dt>Issuer</dt>
      <dd translate="no">{host.issuer}</dd>
      <dt>Signer epoch</dt>
      <dd translate="no">{host.signer_policy_epoch}</dd>
      <dt>Host epoch</dt>
      <dd translate="no">{host.host_epoch}</dd>
      {rows.map(([label, value]) => (
        <Fragment key={label}>
          <dt>{label}</dt>
          <dd translate="no" className={label === "Key" ? "mono" : undefined}>
            {value}
          </dd>
        </Fragment>
      ))}
    </dl>
  );
}

function SettingsFixtureSigners() {
  return (
    <ul className="list">
      {signers.map(([name, fingerprint, state, kind]) => (
        <li key={name}>
          <Glyph icon={KeyRound} className="list-muted" />
          <span className="grow">
            <span className="t">{name}</span>
            <span className="s mono">{fingerprint}</span>
          </span>
          <span className={`state ${kind}`}>{state}</span>
        </li>
      ))}
    </ul>
  );
}

function SettingsAbout({ live, host }: { live: boolean; host: ObservedHost | null }) {
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>About</h2>
      </div>
      <dl className="kv">
        <dt>Console</dt>
        <dd>{live ? "0.1.0 · read-only" : "0.1.0 · fixture preview, read-only"}</dd>
        {host ? (
          <>
            <dt>Host</dt>
            <dd translate="no">{host.host_id}</dd>
            <dt>Host epoch</dt>
            <dd translate="no">{host.host_epoch}</dd>
          </>
        ) : live ? (
          <>
            <dt>Host</dt>
            <dd>Not in this observation</dd>
          </>
        ) : (
          <>
            <dt>Coordinator</dt>
            <dd>0.4.0</dd>
            <dt>Executor</dt>
            <dd>0.4.0 · host epoch 3</dd>
          </>
        )}
        <dt>Observation retention</dt>
        <dd>{live ? enrolledRetentionText(host?.backup_retention_days) : "30 days"}</dd>
      </dl>
    </section>
  );
}

function SettingsAuthority({ live }: { live: boolean }) {
  const data = useData();
  const host = data.source.kind === "live" ? data.source.host : null;
  return (
    <>
      <section className="panel">
        <div className="panel-head">
          <h2>Approval authority</h2>
          <span className="pill">Read-only</span>
        </div>
        {host ? (
          <SettingsSigners host={host} />
        ) : live ? (
          <p className="muted">No observation is available to show enrolled signers.</p>
        ) : (
          <SettingsFixtureSigners />
        )}
        <p className="cap" style={{ marginTop: 12 }}>
          Signers are enrolled and revoked with the root CLI on the host. The console never stores
          private keys.
        </p>
      </section>
      <section className="panel">
        <div className="panel-head">
          <h2>Agents</h2>
        </div>
        <p className="muted">
          {live
            ? "Agent identities are not in this observation. Agents cannot approve."
            : "1 agent identity (maint-bot) may request plans. Agents cannot approve; every plan still needs a human signature."}
        </p>
      </section>
      <SettingsAbout live={live} host={host} />
    </>
  );
}

function SettingsPreferencesForm() {
  const { prefs, savePrefs } = usePreferences();
  const [draft, setDraft] = useState<ConsolePreferences>(prefs);
  const [saved, setSaved] = useState(false);

  function updateDraft(patch: Partial<ConsolePreferences>) {
    setDraft((prev) => ({ ...prev, ...patch }));
    setSaved(false);
  }

  return (
    <>
      <div className="form-grid">
        <div className="form-row">
          <label htmlFor="s-tz">Time display</label>
          <select
            id="s-tz"
            className="input"
            name="time-display"
            autoComplete="off"
            value={draft.timeDisplay}
            onChange={(e) => updateDraft({ timeDisplay: e.target.value as TimeDisplay })}
          >
            <option value="utc">UTC (host time)</option>
            <option value="local">Browser local time</option>
          </select>
          <span className="hint">Exports always use UTC</span>
        </div>
        <div className="form-row">
          <label htmlFor="s-range">Default metrics range</label>
          <select
            id="s-range"
            className="input"
            name="metrics-range"
            autoComplete="off"
            value={draft.metricsRange}
            onChange={(e) => updateDraft({ metricsRange: e.target.value as MetricsRange })}
          >
            <option value="1h">1 hour</option>
            <option value="6h">6 hours</option>
            <option value="24h">24 hours</option>
            <option value="7d">7 days</option>
          </select>
        </div>
        <div className="form-row">
          <label htmlFor="s-tr">Transparency</label>
          <select
            id="s-tr"
            className="input"
            name="transparency"
            autoComplete="off"
            value={draft.transparency}
            onChange={(e) => updateDraft({ transparency: e.target.value as TransparencyPref })}
          >
            <option value="system">Match system</option>
            <option value="reduce">Reduce (opaque chrome)</option>
          </select>
        </div>
        <div className="form-row">
          <label htmlFor="s-rows">Table rows per page</label>
          <select
            id="s-rows"
            className="input"
            name="rows-per-page"
            autoComplete="off"
            value={String(draft.rowsPerPage)}
            onChange={(e) => updateDraft({ rowsPerPage: Number(e.target.value) as RowsPerPage })}
          >
            <option value="10">10</option>
            <option value="25">25</option>
            <option value="50">50</option>
            <option value="100">100</option>
          </select>
        </div>
        <div className="form-row">
          <div className="flex items-center justify-between gap-3 pt-1">
            <div>
              <label htmlFor="s-motion">Reduced motion</label>
              <span className="hint block">
                Disable entrance animations and chart draw transitions
              </span>
            </div>
            <Switch
              id="s-motion"
              checked={draft.motion === "reduce"}
              onCheckedChange={(checked) => updateDraft({ motion: checked ? "reduce" : "system" })}
            />
          </div>
        </div>
      </div>
      <div className="row end">
        {saved ? (
          <span className="saved" role="status">
            Preferences saved in this browser.
          </span>
        ) : null}
        <Button
          variant="default"
          onClick={() => {
            savePrefs(draft);
            setSaved(true);
            toastManager.add({
              id: "prefs-saved",
              type: "success",
              title: "Preferences saved",
              description: "Stored locally in this browser.",
            });
          }}
        >
          Save preferences
        </Button>
      </div>
    </>
  );
}

function AutomationBoundariesCard() {
  return (
    <section className="panel" aria-labelledby="automation-t">
      <div className="panel-head">
        <h2 id="automation-t">Automation &amp; remote access</h2>
        <span className="pill">Explicit approval</span>
      </div>
      <dl className="kv">
        <dt>Local MCP server</dt>
        <dd>
          <span className="mono">rustiron-mcp</span> runs read-only by default; opt-in write mode
          refuses self-approval, blanket tokens, and destructive actions
        </dd>
        <dt>Remote SSH gateway</dt>
        <dd>
          Forced-command allowlist with no interactive shell, sudo, or signing-agent forwarding
        </dd>
        <dt>Background scheduling</dt>
        <dd>Traffic-aware job deferral with automatic backup deadline protection</dd>
        <dt>Multi-host inventory</dt>
        <dd>Read-only fleet aggregation with isolated per-server approval keys and locks</dd>
      </dl>
    </section>
  );
}

export function SettingsPage() {
  const { preference, mode, setPreference } = useThemePreference();
  const data = useData();
  const live = data.source.kind === "live" || data.source.kind === "unavailable";
  return (
    <Page live={live}>
      <div className="page-head">
        <div>
          <h1>Settings</h1>
          <p className="sub">
            Console preferences, and read-only views of the host profile and approval authority.
            Host security policy is not changed from here.
          </p>
        </div>
      </div>
      <div className="grid g-main-side">
        <div className="stack">
          <section className="panel" aria-labelledby="pref-t">
            <div className="panel-head">
              <h2 id="pref-t">Preferences</h2>
              <span className="meta">Stored in this browser only</span>
            </div>
            <div className="stack" style={{ gap: 20 }}>
              <fieldset className="plain">
                <legend>Theme</legend>
                <div className="grid g3 tight">
                  {themeChoices.map((choice) => (
                    <label
                      key={choice.value}
                      className={preference === choice.value ? "radio-card selected" : "radio-card"}
                    >
                      <input
                        type="radio"
                        name="theme"
                        className="sr-only"
                        value={choice.value}
                        checked={preference === choice.value}
                        onChange={() => setPreference(choice.value)}
                      />
                      <span className="rc-dot" aria-hidden="true" />
                      <strong>{choice.label}</strong>
                      {choice.value === "system" ? (
                        <span className="cap">Currently {mode}</span>
                      ) : null}
                    </label>
                  ))}
                </div>
                <p className="cap" style={{ marginTop: 8 }}>
                  Applies immediately, like the toggle in the top bar.
                </p>
              </fieldset>
              <SettingsPreferencesForm />
            </div>
          </section>
          <SettingsProfile live={live} />
        </div>
        <aside className="stack">
          <SettingsAuthority live={live} />
          <section className="panel" aria-labelledby="backend-t">
            <div className="panel-head">
              <h2 id="backend-t">Backend connection</h2>
              <span className="pill ok">Hardened</span>
            </div>
            <dl className="kv">
              <dt>Console mode</dt>
              <dd>
                {data.backend?.write_workflows_enabled
                  ? "Separate-custody write opt-in"
                  : "Read-only loopback"}
              </dd>
              <dt>Observation feed</dt>
              <dd>
                {data.backend?.observation_configured
                  ? "Configured (/api/observation)"
                  : "Preview data"}
              </dd>
              <dt>Coordinator IPC</dt>
              <dd>
                {data.backend?.coordinator_configured
                  ? data.backend.coordinator_reachable
                    ? "Connected (Unix socket)"
                    : "Configured, unreachable"
                  : "Not configured (observation-only)"}
              </dd>
              <dt>Write workflows</dt>
              <dd>
                {data.backend?.write_workflows_enabled
                  ? "Enabled via external SSHSIG only"
                  : "Disabled (read-only default)"}
              </dd>
              {data.observation?.authority_budget?.consumed ? (
                <>
                  <dt>Authority budget</dt>
                  <dd className="tnum">
                    {data.observation.authority_budget.consumed.total_admissions ?? 0} admissions ·{" "}
                    {data.observation.authority_budget.consumed.total_ols_reloads ?? 0} OLS reloads
                  </dd>
                </>
              ) : null}
            </dl>
          </section>
          <AutomationBoundariesCard />
        </aside>
      </div>
    </Page>
  );
}

const stateLabels: [string, LucideIcon, string][] = [
  ["ok", CircleCheck, "Pass / Running / Verified"],
  ["err", CircleX, "Fail"],
  ["err", CircleAlert, "Needs attention"],
  ["warn", TriangleAlert, "Drift / Warning"],
  ["info", LoaderCircle, "Running"],
  ["unknown", CircleDashed, "Unknown / Not checked"],
  ["notrun", CircleMinus, "Not run"],
  ["stale", ClockAlert, "Stale"],
];

export function StatesPage() {
  const { source } = useData();
  const live = source.kind === "live" || source.kind === "unavailable";
  return (
    <Page live={live}>
      <div className="page-head">
        <div>
          <h1>Shared states</h1>
          <p className="sub">
            Reference sheet for feedback states reused across views: loading, empty, no match,
            unavailable, stale, permission and error. The controls here are samples.
          </p>
        </div>
      </div>
      <div className="grid g3">
        <section className="panel" aria-busy="true">
          <div className="panel-head">
            <h2>Loading</h2>
            <span className="meta">Localized skeleton</span>
          </div>
          <div className="stack" style={{ gap: 10 }}>
            <span className="skeleton" style={{ width: "40%", height: 28 }} />
            <span className="skeleton" style={{ width: "70%" }} />
            <span className="skeleton" style={{ width: "90%" }} />
            <span className="skeleton" style={{ width: "55%" }} />
          </div>
          <p className="cap" style={{ marginTop: 12 }}>
            Only the loading panel shows a skeleton; the rest of the page stays usable.
          </p>
        </section>
        <section className="panel">
          <div className="panel-head">
            <h2>Empty</h2>
          </div>
          <div className="empty-sample">
            <Glyph icon={ListChecks} />
            <p className="t">No operations yet</p>
            <p className="muted">
              Operations appear here once an approved plan is admitted by the executor.
            </p>
            <p style={{ marginTop: 8 }}>
              <Link to="/help/$slug" params={{ slug: "signing-and-plans" }}>
                How operations work
              </Link>
            </p>
          </div>
        </section>
        <section className="panel">
          <div className="panel-head">
            <h2>No match</h2>
          </div>
          <div className="empty-sample">
            <Glyph icon={Filter} />
            <p className="t">No sites match &ldquo;Blocked&rdquo; + &ldquo;Observed only&rdquo;</p>
            <p className="muted">8 sites are hidden by filters.</p>
            <div style={{ marginTop: 8 }}>
              <Button variant="outline" size="sm">
                Clear filters
              </Button>
            </div>
          </div>
        </section>
        <section className="panel">
          <div className="panel-head">
            <h2>Unavailable</h2>
          </div>
          <div className="metric" style={{ padding: 0 }}>
            <div className="m-head">
              <span className="m-icon c-disk">
                <Glyph icon={HardDrive} />
              </span>
              Disk <span className="cap">/srv/backup-stage</span>
            </div>
            <div className="m-val muted">—</div>
            <div className="m-detail">Not mounted. No value is shown rather than 0%.</div>
            <div className="m-foot">
              <span>Checked 38 s ago</span>
              <Link to="/help/$slug" params={{ slug: "security-and-diagnoses" }}>
                Why?
              </Link>
            </div>
          </div>
        </section>
        <section className="panel">
          <div className="panel-head">
            <h2>Stale</h2>
            <span className="state stale">
              <Glyph icon={ClockAlert} />
              Stale · 12 min
            </span>
          </div>
          <div className="metric" style={{ padding: 0 }}>
            <div className="m-head">
              <span className="m-icon c-cpu">
                <Glyph icon={Cpu} />
              </span>
              CPU
            </div>
            <div className="m-val">
              24<small>%</small>
            </div>
            <div className="m-detail">Last value kept, marked stale while reconnecting</div>
            <div className="m-foot">
              <span>Observed 16:30 UTC</span>
              <Button variant="ghost" size="sm">
                <Glyph icon={RefreshCw} />
                Retry now
              </Button>
            </div>
          </div>
        </section>
        <section className="panel">
          <div className="panel-head">
            <h2>Error</h2>
          </div>
          <div className="attention err" style={{ margin: 0 }}>
            <Glyph icon={CircleX} />
            <div className="att-body">
              <strong>Could not load the selected operation.</strong> The coordinator did not
              respond within 10 s. The operation itself is unaffected.
              <div className="att-meta">COORDINATOR_TIMEOUT · 16:44:02 UTC</div>
            </div>
          </div>
          <div className="row" style={{ marginTop: 12 }}>
            <Button variant="outline" size="sm">
              Try again
            </Button>
            <Link
              className="btn quiet sm"
              to="/help/$slug"
              params={{ slug: "troubleshooting-and-recovery" }}
            >
              Troubleshooting guide
            </Link>
          </div>
        </section>
      </div>
      <section className="panel">
        <div className="panel-head">
          <h2>State labels</h2>
          <span className="meta">Text and shape, never colour alone</span>
        </div>
        <div className="row" style={{ gap: 20 }}>
          {stateLabels.map(([kind, icon, label]) => (
            <span key={label} className={`state ${kind}`}>
              <Glyph icon={icon} />
              {label}
            </span>
          ))}
        </div>
        <div style={{ marginTop: 16 }}>
          <EvidenceKey />
        </div>
      </section>
      <section className="panel">
        <div className="panel-head">
          <h2>Buttons</h2>
        </div>
        <div className="row">
          <Button variant="default">Primary action</Button>
          <Button variant="outline">Secondary</Button>
          <Button variant="ghost">Quiet</Button>
          <Button variant="destructive">Discard plan</Button>
          <Button variant="outline" disabled>
            Disabled
          </Button>
        </div>
        <p className="cap" style={{ marginTop: 12 }}>
          Press Tab to see the focus ring on any of these buttons.
        </p>
      </section>
    </Page>
  );
}

function Missing({
  name,
  back = "/sites",
}: {
  name: string;
  back?: "/sites" | "/operations" | "/recovery";
}) {
  const { source } = useData();
  const live = source.kind === "live" || source.kind === "unavailable";
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
