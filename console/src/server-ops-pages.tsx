// W632 / W650: Server Operations — Interactive Firewall Rule Builder,
// Scheduled Jobs & Timers (/host/cron), and Redacted Server Logs Viewer (/host/logs).
import { consoleRequest } from "./console-request";
import { Link } from "@tanstack/react-router";
import {
  Clock,
  Download,
  FileText,
  Plus,
  RefreshCw,
  Shield,
  Trash2,
  TriangleAlert,
  WrapText,
} from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { toastManager } from "@/components/ui/toast";
import { isRealHost, useData } from "./data";
import { CopyButton, Crumbs, EmptyState, Glyph, Page, TableScroll } from "./ui";

type StagedFwRule = {
  id: string;
  action: "add" | "remove";
  port: string;
  proto: "tcp" | "udp";
  source: string;
};

const BLOCKED_EXTERNAL_PORTS = new Set(["2019", "3306", "4319", "5432", "7080"]);

function renderFirewallCmds(rules: StagedFwRule[]): string {
  const cmds = rules.map((r) => {
    if (r.source.trim() && r.source.trim() !== "0.0.0.0/0") {
      const rich = `rule family="ipv4" source address="${r.source.trim()}" port port="${r.port}" protocol="${r.proto}" accept`;
      return `sudo firewall-cmd --zone=rustiron --permanent --${r.action}-rich-rule='${rich}'`;
    }
    return `sudo firewall-cmd --zone=rustiron --permanent --${r.action}-port=${r.port}/${r.proto}`;
  });
  return `${cmds.join("\n")}\nsudo firewall-cmd --reload`;
}

export function FirewallRuleBuilderPanel() {
  const [rules, setRules] = useState<StagedFwRule[]>([]);
  const [action, setAction] = useState<"add" | "remove">("add");
  const [port, setPort] = useState("993");
  const [proto, setProto] = useState<"tcp" | "udp">("tcp");
  const [source, setSource] = useState("0.0.0.0/0");
  const [err, setErr] = useState<string | null>(null);

  const riskyPort = rules.some((r) => r.action === "add" && BLOCKED_EXTERNAL_PORTS.has(r.port));
  const cmd = rules.length > 0 ? renderFirewallCmds(rules) : "";

  function handleAddRule() {
    const n = Number(port);
    if (!Number.isInteger(n) || n < 1 || n > 65535) {
      setErr("Port must be an integer between 1 and 65535.");
      return;
    }
    setErr(null);
    setRules((prev) => [
      ...prev,
      { id: `fw_${Date.now()}_${prev.length}`, action, port: String(n), proto, source },
    ]);
    toastManager.add({
      id: "fw-rule-staged",
      type: BLOCKED_EXTERNAL_PORTS.has(String(n)) && action === "add" ? "warning" : "info",
      title: `Staged ${action === "add" ? "allow" : "remove"} ${n}/${proto}`,
      description: "Copy the firewalld commands below and review before applying on the server.",
    });
  }

  return (
    <section className="panel stack" aria-labelledby="fw-builder-t">
      <div className="panel-head">
        <div>
          <h2 id="fw-builder-t">Manage firewall rules</h2>
          <p className="cap">
            Stage port or rich-rule changes for the <span className="mono">rustiron</span> firewalld
            zone (for example, IMAPS 993 or Submission 587 for self-hosted mail).
          </p>
        </div>
        {rules.length > 0 ? (
          <CopyButton
            text={cmd}
            label="Copy firewall commands"
            toastTitle="Firewall commands copied"
          />
        ) : null}
      </div>

      <div className="form-grid">
        <div className="form-row">
          <label htmlFor="fw-act">Action</label>
          <select
            id="fw-act"
            className="input"
            value={action}
            onChange={(e) => setAction(e.target.value as "add" | "remove")}
          >
            <option value="add">Allow port</option>
            <option value="remove">Remove port</option>
          </select>
        </div>
        <div className="form-row">
          <label htmlFor="fw-port">Port (1–65535)</label>
          <input
            id="fw-port"
            className="input tnum"
            type="number"
            min={1}
            max={65535}
            value={port}
            onChange={(e) => setPort(e.target.value)}
          />
        </div>
        <div className="form-row">
          <label htmlFor="fw-proto">Protocol</label>
          <select
            id="fw-proto"
            className="input"
            value={proto}
            onChange={(e) => setProto(e.target.value as "tcp" | "udp")}
          >
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
          </select>
        </div>
        <div className="form-row">
          <label htmlFor="fw-src">Source CIDR</label>
          <input
            id="fw-src"
            className="input mono"
            value={source}
            placeholder="0.0.0.0/0 or 100.64.0.0/10"
            onChange={(e) => setSource(e.target.value)}
          />
        </div>
      </div>

      {err ? <span className="err-msg">{err}</span> : null}

      <div className="row" style={{ gap: 8 }}>
        <button type="button" className="btn primary sm" onClick={handleAddRule}>
          <Glyph icon={Plus} />
          Add rule to change set
        </button>
        {rules.length > 0 ? (
          <button
            type="button"
            className="btn quiet sm"
            onClick={() => {
              setRules([]);
              toastManager.add({ id: "fw-clear", type: "info", title: "Staged rules cleared" });
            }}
          >
            Clear all
          </button>
        ) : null}
      </div>

      {riskyPort ? (
        <div className="attention err" role="alert">
          <Glyph icon={TriangleAlert} />
          <div className="att-body">
            <strong>
              Warning: sensitive local port selected (2019 / 3306 / 4319 / 5432 / 7080).
            </strong>{" "}
            Caddy Admin, MariaDB, Console loopback, PostgreSQL 18, and OLS WebAdmin must stay
            restricted to localhost or a private VPN CIDR.
          </div>
        </div>
      ) : null}

      {rules.length > 0 ? (
        <>
          <TableScroll label="Staged firewall rules">
            <table className="data">
              <thead>
                <tr>
                  <th>Action</th>
                  <th>Port / Protocol</th>
                  <th>Source</th>
                  <th>Remove</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((r) => (
                  <tr key={r.id}>
                    <td>
                      <span className={r.action === "add" ? "pill ok" : "pill warn"}>
                        {r.action === "add" ? "Allow" : "Remove"}
                      </span>
                    </td>
                    <td className="mono">
                      {r.port}/{r.proto}
                    </td>
                    <td className="mono">{r.source || "0.0.0.0/0"}</td>
                    <td>
                      <button
                        type="button"
                        className="icon-btn"
                        aria-label={`Remove rule ${r.port}/${r.proto}`}
                        onClick={() => setRules((prev) => prev.filter((item) => item.id !== r.id))}
                      >
                        <Glyph icon={Trash2} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableScroll>
          <pre className="code signed-bytes">{cmd}</pre>
        </>
      ) : null}
    </section>
  );
}

const managedTimers = [
  {
    unit: "rustiron-site-cron.timer",
    schedule: "Every 5 min",
    purpose: "Triggers WordPress scheduled events inside each site's isolated PHP pool",
  },
  {
    unit: "rustiron-scheduled-capture.timer",
    schedule: "Scheduled window",
    purpose: "Runs approved standing backup captures with traffic-budget deferral",
  },
  {
    unit: "rustiron-alert-checkin.timer",
    schedule: "Every 2 min",
    purpose: "Pushes redacted server health heartbeat to Uptime Kuma",
  },
  {
    unit: "rustiron-observe.timer",
    schedule: "Every 1 min",
    purpose: "Collects live host status and metric samples for the Console",
  },
];

export function HostCronPage() {
  const data = useData();
  const isLive = isRealHost(data.source);
  const services = data.machine?.services ?? [];

  function timerStatus(unit: string): string {
    if (!isLive) return "Scheduled";
    return services.find((s) => s.unit === unit)?.active ?? "Not observed";
  }

  return (
    <Page live>
      <Crumbs items={[{ href: "/", label: "Overview" }, { label: "Cron jobs" }]} />
      <div className="page-head">
        <div>
          <h1>Cron jobs &amp; timers</h1>
          <p className="sub">
            Managed systemd timers and per-site WordPress cron execution schedules with
            traffic-aware load gating.
          </p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <Link className="btn quiet sm" to="/recovery/schedules">
            Backup schedules
          </Link>
          <Link className="btn quiet sm" to="/help/$slug" params={{ slug: "firewall-and-network" }}>
            Timers &amp; budget guide
          </Link>
        </div>
      </div>

      <section className="panel flush" aria-label="System timers">
        <div className="panel-head" style={{ padding: "14px 16px 10px" }}>
          <div className="row" style={{ gap: 8 }}>
            <Glyph icon={Clock} />
            <h2>Server timers</h2>
          </div>
          <span className="meta">Managed via systemd timers</span>
        </div>
        <TableScroll label="System timers">
          <table className="data">
            <thead>
              <tr>
                <th>Timer unit</th>
                <th>Schedule</th>
                <th>Status</th>
                <th>Purpose</th>
              </tr>
            </thead>
            <tbody>
              {managedTimers.map((t) => {
                const st = timerStatus(t.unit);
                return (
                  <tr key={t.unit}>
                    <td className="mono">{t.unit}</td>
                    <td>{t.schedule}</td>
                    <td>
                      <span className={st === "active" || st === "Active" ? "pill ok" : "pill"}>
                        {st}
                      </span>
                    </td>
                    <td className="muted">{t.purpose}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </TableScroll>
      </section>

      <section className="panel flush" aria-label="Per-site WordPress cron jobs">
        <div className="panel-head" style={{ padding: "14px 16px 10px" }}>
          <div className="row" style={{ gap: 8 }}>
            <Glyph icon={Shield} />
            <h2>Website scheduled jobs</h2>
          </div>
          <span className="meta">Each site runs inside its own confined PHP pool</span>
        </div>
        {data.sites.length === 0 ? (
          <div style={{ padding: 16 }}>
            <EmptyState
              icon={Clock}
              title="No hosted websites registered yet"
              description="WordPress cron entries appear automatically for each registered website."
            />
          </div>
        ) : (
          <TableScroll label="Per-site WordPress cron jobs">
            <table className="data">
              <thead>
                <tr>
                  <th>Website</th>
                  <th>Schedule</th>
                  <th>Traffic budget check</th>
                </tr>
              </thead>
              <tbody>
                {data.sites.map((s) => (
                  <tr key={s.id}>
                    <td>
                      <Link className="mono" to="/sites/$siteId" params={{ siteId: s.id }}>
                        {s.domain}
                      </Link>
                    </td>
                    <td>Every 5 min (/wp-cron.php)</td>
                    <td className="mono">
                      rustiron-control --background-budget ./merged.json --job site_cron --site{" "}
                      {s.id}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableScroll>
        )}
      </section>
    </Page>
  );
}

type LogApiReply = {
  unitKey: string;
  unit: string;
  available: boolean;
  truncated?: boolean;
  fetchedAt?: number;
  reason: string | null;
  lines: string[];
};

type LogSeverity = "all" | "error" | "warn" | "info";

type ParsedLogEntry = {
  index: number;
  timestamp: string | null;
  message: string;
  severity: "error" | "warn" | "info";
  raw: string;
};

const logUnits = [
  ["executor", "RustIron Executor (rustiron-executor.service)"],
  ["coordinator", "RustIron Coordinator (rustiron-coordinator.service)"],
  ["admin", "RustIron Admin Helper (rustiron-admin-helper.service)"],
  ["console", "RustIron Console (rustiron-console.service)"],
  ["caddy", "Caddy Edge Ingress (rustiron-caddy.service)"],
  ["ols", "OpenLiteSpeed (lshttpd.service)"],
  ["mariadb", "MariaDB (mariadb.service)"],
  ["postgresql", "PostgreSQL 18 (postgresql-18.service)"],
  ["sitecron", "Site Cron (rustiron-site-cron.service)"],
  ["pdns", "PowerDNS (pdns.service)"],
  ["postfix", "Postfix Mail (postfix.service)"],
  ["dovecot", "Dovecot IMAP (dovecot.service)"],
] as const;

const ISO_PREFIX_RE = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{4})\s+(.*)$/;
const LOG_ERROR_RE = /\b(error|failed|fatal|denied|panic|crit)\b/i;
const LOG_WARN_RE = /\b(warn|warning|timeout|deprecated)\b/i;

function classifyLogSeverity(line: string): "error" | "warn" | "info" {
  if (LOG_ERROR_RE.test(line)) return "error";
  if (LOG_WARN_RE.test(line)) return "warn";
  return "info";
}

function parseLogEntry(raw: string, index: number): ParsedLogEntry {
  const match = ISO_PREFIX_RE.exec(raw);
  const timestamp = match?.[1] ? match[1].replace("T", " ").slice(0, 19) : null;
  const message = match?.[2] ?? raw;
  return {
    index: index + 1,
    timestamp,
    message,
    severity: classifyLogSeverity(message),
    raw,
  };
}

function downloadLogsFile(unitName: string, lines: string[]) {
  const blob = new Blob([`${lines.join("\n")}\n`], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${unitName.replace(/[^a-z0-9.-]/gi, "_")}.log`;
  a.click();
  URL.revokeObjectURL(url);
}

async function fetchUnitLogs(unit: string, lines: number): Promise<LogApiReply | null> {
  const reply = await consoleRequest<Partial<LogApiReply> | null>(
    `/api/host/logs?unit=${encodeURIComponent(unit)}&lines=${lines}`,
  );
  const body = reply.ok ? reply.data : null;
  if (!body || typeof body.unit !== "string" || !Array.isArray(body.lines)) return null;
  return {
    unitKey: body.unitKey ?? unit,
    unit: body.unit,
    available: Boolean(body.available),
    truncated: Boolean(body.truncated),
    fetchedAt: typeof body.fetchedAt === "number" ? body.fetchedAt : Date.now(),
    reason: body.reason ?? null,
    lines: body.lines,
  };
}

const LOG_SEVERITY_TABS: readonly [LogSeverity, string][] = [
  ["all", "All"],
  ["error", "Errors"],
  ["warn", "Warnings"],
  ["info", "Info"],
];

function filterLogEntries(
  entries: ParsedLogEntry[],
  severity: LogSeverity,
  filterText: string,
): ParsedLogEntry[] {
  const needle = filterText.trim().toLowerCase();
  return entries.filter((entry) => {
    const sevMatch = severity === "all" || entry.severity === severity;
    const textMatch = !needle || entry.raw.toLowerCase().includes(needle);
    return sevMatch && textMatch;
  });
}

function LogStreamBody({
  entries,
  wrap,
  loading,
}: {
  entries: ParsedLogEntry[];
  wrap: boolean;
  loading: boolean;
}) {
  if (loading && entries.length === 0) {
    return (
      <div className="log-skeleton" aria-busy="true">
        <div className="skeleton-shimmer h-4 w-3/4 rounded" />
        <div className="skeleton-shimmer h-4 w-full rounded" />
        <div className="skeleton-shimmer h-4 w-5/6 rounded" />
      </div>
    );
  }
  if (entries.length === 0) {
    return (
      <div className="p-5 text-sm text-muted-foreground">
        No log lines match the current severity or text filter.
      </div>
    );
  }
  return (
    <div className={wrap ? "log-viewer wrap" : "log-viewer"} role="log" aria-live="off">
      {entries.map((entry) => (
        <div key={entry.index} className={`log-line log-sev-${entry.severity}`}>
          <span className="log-num tnum">{entry.index}</span>
          {entry.timestamp ? <span className="log-ts tnum">{entry.timestamp}</span> : null}
          <span className="log-msg">{entry.message}</span>
        </div>
      ))}
    </div>
  );
}

function LogStreamCard({
  unitName,
  entries,
  totalCount,
  severity,
  onSeverity,
  wrap,
  onToggleWrap,
  loading,
  autoRefreshSec,
  truncated,
  onDownload,
}: {
  unitName: string;
  entries: ParsedLogEntry[];
  totalCount: number;
  severity: LogSeverity;
  onSeverity: (next: LogSeverity) => void;
  wrap: boolean;
  onToggleWrap: () => void;
  loading: boolean;
  autoRefreshSec: number;
  truncated: boolean;
  onDownload: () => void;
}) {
  const rawText = entries.map((e) => e.raw).join("\n");
  return (
    <section className="panel flush" aria-label={`Journal output for ${unitName}`}>
      <div className="log-card-head">
        <div className="row" style={{ gap: 10 }}>
          <Glyph icon={FileText} />
          <h2 className="mono" style={{ fontSize: 15 }}>
            {unitName}
          </h2>
          <span className="pill ok">
            {autoRefreshSec > 0 ? <span className="dot ok live-dot-pulse" /> : null}
            {entries.length} of {totalCount} lines
          </span>
          {truncated ? <span className="pill warn">Truncated at 128 KiB</span> : null}
        </div>
        <div className="row" style={{ gap: 6 }}>
          <button
            type="button"
            className={wrap ? "btn sm" : "btn quiet sm"}
            aria-pressed={wrap}
            onClick={onToggleWrap}
          >
            <Glyph icon={WrapText} />
            Wrap
          </button>
          <CopyButton text={rawText} label="Copy visible log lines" toastTitle="Log lines copied" />
          <button type="button" className="btn quiet sm" onClick={onDownload}>
            <Glyph icon={Download} />
            Download
          </button>
        </div>
      </div>

      <div className="log-toolbar">
        <div className="filter-pills" role="group" aria-label="Filter logs by severity">
          {LOG_SEVERITY_TABS.map(([id, label]) => (
            <button
              key={id}
              type="button"
              aria-pressed={severity === id}
              onClick={() => onSeverity(id)}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      <LogStreamBody entries={entries} wrap={wrap} loading={loading} />
    </section>
  );
}

function LogFiltersCard({
  unit,
  onUnit,
  lineCount,
  onLineCount,
  autoRefreshSec,
  onAutoRefreshSec,
  filter,
  onFilter,
}: {
  unit: string;
  onUnit: (v: string) => void;
  lineCount: number;
  onLineCount: (v: number) => void;
  autoRefreshSec: number;
  onAutoRefreshSec: (v: number) => void;
  filter: string;
  onFilter: (v: string) => void;
}) {
  return (
    <section className="panel stack" aria-label="Log filters">
      <div className="form-grid">
        <div className="form-row">
          <label htmlFor="log-unit">Service unit</label>
          <select
            id="log-unit"
            className="input"
            value={unit}
            onChange={(e) => onUnit(e.target.value)}
          >
            {logUnits.map(([key, label]) => (
              <option key={key} value={key}>
                {label}
              </option>
            ))}
          </select>
        </div>
        <div className="form-row">
          <label htmlFor="log-lines">Lines</label>
          <select
            id="log-lines"
            className="input tnum"
            value={lineCount}
            onChange={(e) => onLineCount(Number(e.target.value))}
          >
            <option value={30}>Last 30 lines</option>
            <option value={60}>Last 60 lines</option>
            <option value={120}>Last 120 lines</option>
            <option value={200}>Last 200 lines</option>
          </select>
        </div>
        <div className="form-row">
          <label htmlFor="log-refresh">Auto-refresh</label>
          <select
            id="log-refresh"
            className="input"
            value={autoRefreshSec}
            onChange={(e) => onAutoRefreshSec(Number(e.target.value))}
          >
            <option value={0}>Off</option>
            <option value={5}>Every 5 s</option>
            <option value={15}>Every 15 s</option>
          </select>
        </div>
        <div className="form-row">
          <label htmlFor="log-filter">Filter text</label>
          <input
            id="log-filter"
            className="input"
            placeholder="error, warn, site_id…"
            value={filter}
            onChange={(e) => onFilter(e.target.value)}
          />
        </div>
      </div>
    </section>
  );
}

function useUnitLogStream(unit: string, lineCount: number, autoRefreshSec: number) {
  const [reply, setReply] = useState<LogApiReply | null>(null);
  const [loading, setLoading] = useState(false);

  const reload = useCallback(async (nextUnit: string, nextLines: number, notify = false) => {
    setLoading(true);
    const data = await fetchUnitLogs(nextUnit, nextLines);
    setReply(data);
    setLoading(false);
    if (!notify) return;
    // W682: a failed read (null) is not "no new entries".
    if (!data) {
      toastManager.add({ id: "logs-refresh", type: "warning", title: "Could not load logs" });
      return;
    }
    toastManager.add({
      id: "logs-refresh",
      type: data.available ? "success" : "info",
      title: data.available
        ? `Loaded ${data.lines.length} lines from ${data.unit}`
        : `No new entries for ${data.unit}`,
    });
  }, []);

  useEffect(() => {
    let active = true;
    void fetchUnitLogs(unit, lineCount).then((data) => {
      if (!active) return;
      setReply(data);
      setLoading(false);
    });
    return () => {
      active = false;
    };
  }, [unit, lineCount]);

  useEffect(() => {
    if (autoRefreshSec <= 0) return undefined;
    let active = true;
    const timer = setInterval(() => {
      void fetchUnitLogs(unit, lineCount).then((data) => {
        // A reply for a unit the viewer has left must not overwrite the current one.
        if (active && data) setReply(data);
      });
    }, autoRefreshSec * 1000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [unit, lineCount, autoRefreshSec]);

  return { reply, loading, reload };
}

export function HostLogsPage() {
  const [unit, setUnit] = useState<string>("executor");
  const [lineCount, setLineCount] = useState(60);
  const [filter, setFilter] = useState("");
  const [severity, setSeverity] = useState<LogSeverity>("all");
  const [autoRefreshSec, setAutoRefreshSec] = useState<number>(0);
  const [wrap, setWrap] = useState(true);
  const { reply, loading, reload } = useUnitLogStream(unit, lineCount, autoRefreshSec);

  const activeUnitName = reply?.unit ?? `${unit}.service`;
  const cliCmd = `sudo journalctl -u ${activeUnitName} -n ${lineCount} --no-pager`;
  const parsedEntries = (reply?.lines ?? []).map(parseLogEntry);
  const visibleEntries = filterLogEntries(parsedEntries, severity, filter);
  const hasLogs = Boolean(reply?.available && parsedEntries.length > 0);
  const handleDownload = () => {
    downloadLogsFile(
      activeUnitName,
      visibleEntries.map((e) => e.raw),
    );
    toastManager.add({
      id: "logs-download",
      type: "success",
      title: `Downloaded ${activeUnitName}.log`,
    });
  };

  return (
    <Page live>
      <Crumbs items={[{ href: "/", label: "Overview" }, { label: "Server logs" }]} />
      <div className="page-head">
        <div>
          <h1>Server logs</h1>
          <p className="sub">
            Redacted, read-only systemd journal viewer for core hosting services. Sensitive tokens,
            keys, and cookies are automatically stripped.
          </p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <button
            type="button"
            className="btn sm"
            disabled={loading}
            onClick={() => void reload(unit, lineCount, true)}
          >
            <Glyph icon={RefreshCw} className={loading ? "animate-spin" : undefined} />
            {loading ? "Refreshing…" : "Refresh"}
          </button>
          <CopyButton
            text={cliCmd}
            label="Copy journalctl command"
            toastTitle="journalctl command copied"
          />
          <Link
            className="btn quiet sm"
            to="/help/$slug"
            params={{ slug: "security-and-diagnoses" }}
          >
            Logs guide
          </Link>
        </div>
      </div>

      <LogFiltersCard
        unit={unit}
        onUnit={setUnit}
        lineCount={lineCount}
        onLineCount={setLineCount}
        autoRefreshSec={autoRefreshSec}
        onAutoRefreshSec={setAutoRefreshSec}
        filter={filter}
        onFilter={setFilter}
      />

      {hasLogs ? (
        <LogStreamCard
          unitName={activeUnitName}
          entries={visibleEntries}
          totalCount={parsedEntries.length}
          severity={severity}
          onSeverity={setSeverity}
          wrap={wrap}
          onToggleWrap={() => setWrap((prev) => !prev)}
          loading={loading}
          autoRefreshSec={autoRefreshSec}
          truncated={Boolean(reply?.truncated)}
          onDownload={handleDownload}
        />
      ) : (
        <EmptyState
          icon={FileText}
          title={`No log lines returned for ${activeUnitName}`}
          description={
            reply?.reason ??
            "Connect the Console on a live Linux server with journald read access, or run the command below directly on the server."
          }
          command={cliCmd}
        />
      )}
    </Page>
  );
}
