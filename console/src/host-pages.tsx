// W714 (pass 33, fix 7): Host overview, metrics, and services pages. Split from `pages.tsx`.
import { MotionBeat } from "@/components/console/motion";
import { Link } from "@tanstack/react-router";
import {
  ListChecks,
  ShieldCheck,
  Globe,
  ChevronDown,
  Download,
  CircleAlert,
  CircleCheck,
  CircleDashed,
  CircleMinus,
  CircleX,
  Clock,
  ClockAlert,
  Cpu,
  HardDrive,
  Info,
  MemoryStick,
  RefreshCw,
  Search,
  Server,
  TriangleAlert,
} from "lucide-react";
import { useState } from "react";
import { hostLabel, isRealHost, useData } from "./data";
import { triggerCsvDownload } from "./live-coordinator";
import { OverviewFindingsPanel } from "./findings-panel";
import { InspectorPanel, useDrawerSelection } from "./inspector";
import {
  clockSyncText,
  inodeUseText,
  serviceFactLines,
  hostHistoryCaption,
  liveHostHistory,
  liveOverviewMetrics,
  type Machine,
  type OverviewMetrics,
} from "./live";
import {
  type HostService,
  type OperationRow,
  type ServiceState,
  type Site,
  sites,
} from "./fixture";
import { Crumbs, EvidenceStrip, Glyph, Legend, Page, ResourceChart, TableScroll } from "./ui";
import { SourceNote } from "./page-parts";

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

type DataSource = ReturnType<typeof useData>["source"];

/**
 * W732 (QA-01): the host status chip. Only a live or sample source may claim a
 * connection; loading and unavailable sources say so.
 */
function hostStatus(source: DataSource) {
  if (source.kind === "loading") {
    return {
      tone: "muted",
      icon: CircleX,
      label: "Checking",
      note: "Reading the host observation",
    };
  }
  if (source.kind === "unavailable") {
    return {
      tone: "err",
      icon: CircleX,
      label: "Unavailable",
      note: "No observation of this host",
    };
  }
  if (source.kind === "live" && source.stale) {
    return { tone: "warn", icon: ClockAlert, label: "Stale", note: "" };
  }
  return {
    tone: "ok",
    icon: CircleCheck,
    label: "Connected",
    note: "Observed 24 Oct 2026, 16:42 UTC · 38 s ago",
  };
}

/** The footer of the Overview metric cards. */
function metricFoot(source: DataSource): string {
  if (source.kind === "live") return source.stale ? "stale" : "live";
  return isRealHost(source) ? "not observed" : "38 s ago";
}

function HostContext() {
  const { source, machine, refresh } = useData();
  const hostId = hostLabel(source);
  const status = hostStatus(source);
  return (
    <div className="host-ctx" aria-label="Host context">
      <div className="hc-id">
        <Glyph icon={Server} />
        <div>
          <strong>{hostId}</strong>
          <small>{hostSubtitle(machine, source)}</small>
        </div>
      </div>
      <span className="sep" />
      <div>
        <span className={`state ${status.tone}`}>
          <Glyph icon={status.icon} />
          {status.label}
        </span>
        <small>{source.kind === "live" ? <SourceNote /> : status.note} </small>
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
  const isLive = isRealHost(data.source);
  const metrics = resolveOverviewMetrics(isLive, data.machine);
  const history = data.machine ? liveHostHistory(data.machine) : null;
  const foot = metricFoot(data.source);
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
  const isLive = isRealHost(data.source);
  const history = data.machine ? liveHostHistory(data.machine) : null;
  const hostId = hostLabel(data.source);
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

function hostSubtitle(
  machine: ReturnType<typeof useData>["machine"],
  source: ReturnType<typeof useData>["source"],
) {
  if (!machine) {
    return isRealHost(source)
      ? "Host status not observed"
      : "Profile almalinux10-ols-lsphp84 · rev 3";
  }
  const os = `${machine.os.name ?? "Unknown OS"} ${machine.os.version ?? ""}`.trim();
  return `${os} · SELinux ${machine.selinux ?? "not checked"} · ${clockSyncText(machine.clock)}`;
}

function ServiceFactLines({ data }: { data: ReturnType<typeof useData> }) {
  return serviceFactLines(data.machine, data.observation?.sites).map((line) => (
    <p key={line} className="cap">
      {line}
    </p>
  ));
}

function ServiceHostFacts({ data }: { data: ReturnType<typeof useData> }) {
  const hostId = hostLabel(data.source);
  return (
    <div className="page-head">
      <div>
        <h1>Services</h1>
        <p className="sub">
          Supported host profile services and their observed state. Restart and configuration
          changes require a reviewed plan.
        </p>
        <ServiceFactLines data={data} />
      </div>
      <div className="host-ctx">
        <div className="hc-id">
          <Glyph icon={Server} />
          <div>
            <strong>{hostId}</strong>
            <small>{hostSubtitle(data.machine, data.source)}</small>
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
  const [selectedName, setSelectedName] = useDrawerSelection<string>();
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
