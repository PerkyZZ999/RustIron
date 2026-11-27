// W624: Delivered v1.0 read-only views ported from docs/mockup/screens/
// (Host Alerts P05/D-083, Host Firewall CP08/D-095, Outbound Mail Relay P07/D-071,
// and Site Maintenance P13/D-100). Strictly read-only; mutates nothing.
import { Link } from "@tanstack/react-router";
import {
  Bell,
  CircleCheck,
  CircleDashed,
  KeyRound,
  Shield,
  ShieldCheck,
  Wrench,
} from "lucide-react";

import { isRealHost, useData } from "./data";
import { SiteActionsConsole } from "./databases-and-site-ops";
import { FirewallRuleBuilderPanel } from "./server-ops-pages";
import { CopyId, Crumbs, Glyph, Page, TableScroll } from "./ui";

function findServiceActive(
  services: { unit: string | null; active: string | null }[] | undefined,
  unit: string,
): string | null {
  return services?.find((s) => s.unit === unit)?.active ?? null;
}

export function HostAlertsPage() {
  const data = useData();
  const isLive = isRealHost(data.source);
  const timerState = findServiceActive(data.machine?.services, "rustiron-alert-checkin.timer");

  return (
    <Page live>
      <Crumbs
        items={[
          { href: "/", label: "Overview" },
          { href: "/host/metrics", label: "Host" },
          { label: "Alerts" },
        ]}
      />
      <div className="page-head">
        <div>
          <h1>Alerts</h1>
          <p className="sub">
            Automated server heartbeat monitoring and health notifications. If the server stops
            checking in, your monitoring endpoint alerts you automatically.
          </p>
        </div>
        <Link className="btn sm" to="/help/$slug" params={{ slug: "security-and-diagnoses" }}>
          Alert setup guide
        </Link>
      </div>

      <section className="grid g4" aria-label="Alert check-in summary">
        <article className="panel metric">
          <div className="m-head">Delivery channel</div>
          <div className="m-val" style={{ fontSize: 20 }}>
            Uptime Kuma
          </div>
          <div className="m-detail">Push heartbeat &amp; email notifications</div>
        </article>
        <article className="panel metric">
          <div className="m-head">Check-in timer</div>
          <div className="m-val" style={{ fontSize: 20 }}>
            {isLive ? (timerState ?? "Not observed") : "Every 2 min"}
          </div>
          <div className="m-detail">rustiron-alert-checkin.timer</div>
        </article>
        <article className="panel metric">
          <div className="m-head">Failure detection</div>
          <div className="m-val" style={{ fontSize: 20 }}>
            Dead-man switch
          </div>
          <div className="m-detail">Alerts automatically if the server stops responding</div>
        </article>
        <article className="panel metric">
          <div className="m-head">Payload privacy</div>
          <div className="m-val" style={{ fontSize: 20 }}>
            Redacted codes
          </div>
          <div className="m-detail">No secrets, logs, or site data sent externally</div>
        </article>
      </section>

      <div className="grid g2">
        <section className="panel">
          <div className="panel-head">
            <div className="row" style={{ gap: 8 }}>
              <Glyph icon={Bell} />
              <h2>Monitored health signals</h2>
            </div>
            <span className={timerState === "active" ? "pill ok" : "pill"}>
              {isLive ? (timerState ?? "Not observed") : "Scheduled"}
            </span>
          </div>
          <dl className="kv">
            <dt>Heartbeat format</dt>
            <dd className="mono">status=up|down&amp;msg=summary&amp;ping=ms</dd>
            <dt>Critical triggers</dt>
            <dd>
              SELinux non-enforcing, clock drift, database down, failed services, disk below 10%, or
              backup and restore verification failures
            </dd>
            <dt>Webhook secret</dt>
            <dd>Stored root-only on the server; hidden from the web console</dd>
            <dt>Test check-in</dt>
            <dd className="mono">rustiron-control --diagnose --alert-line</dd>
          </dl>
        </section>

        <section className="panel">
          <div className="panel-head">
            <h2>Quick links</h2>
          </div>
          <p className="muted" style={{ marginBottom: 12 }}>
            Review current server health checks or inspect the alert timer service status.
          </p>
          <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
            <Link className="btn sm" to="/host/diagnoses">
              View health checks
            </Link>
            <Link className="btn quiet sm" to="/host/services">
              Check timer service
            </Link>
          </div>
        </section>
      </div>
    </Page>
  );
}

function formatDbAccess(isLive: boolean, dbListeners: number | null | undefined): string {
  if (dbListeners === 0 || !isLive) return "Local only";
  if (dbListeners == null) return "Not observed";
  return `${dbListeners} external`;
}

function formatFirewallCards(
  isLive: boolean,
  fwReadable: boolean,
  defaultZone: string | null | undefined,
  fwState: string | null | undefined,
  dbListeners: number | null | undefined,
) {
  if (!isLive) {
    return {
      zone: "rustiron",
      status: "Active",
      db: "Local only",
      admin: "Protected",
      adminDetail: "WebAdmin disabled · Console local-only",
    };
  }
  return {
    zone: defaultZone ?? "Not readable",
    status: fwReadable ? (fwState ?? "Active") : "Not checked",
    db: formatDbAccess(true, dbListeners),
    admin: fwReadable ? "Observed" : "Not observed",
    adminDetail: fwReadable
      ? "WebAdmin disabled · Console local-only"
      : "Run root firewall-cmd check to verify live rules",
  };
}

function FirewallSummaryCards({
  isLive,
  fwReadable,
  defaultZone,
  fwState,
  dbListeners,
}: {
  isLive: boolean;
  fwReadable: boolean;
  defaultZone: string | null | undefined;
  fwState: string | null | undefined;
  dbListeners: number | null | undefined;
}) {
  const cards = formatFirewallCards(isLive, fwReadable, defaultZone, fwState, dbListeners);
  return (
    <section className="grid g4" aria-label="Firewall summary">
      <article className="panel metric">
        <div className="m-head">Active zone</div>
        <div className="m-val mono" style={{ fontSize: 20 }}>
          {cards.zone}
        </div>
        <div className="m-detail">Managed firewalld zone</div>
      </article>
      <article className="panel metric">
        <div className="m-head">Status</div>
        <div className="m-val" style={{ fontSize: 20 }}>
          {cards.status}
        </div>
        <div className="m-detail">Firewall daemon state</div>
      </article>
      <article className="panel metric">
        <div className="m-head">MariaDB access</div>
        <div className="m-val" style={{ fontSize: 20 }}>
          {cards.db}
        </div>
        <div className="m-detail">zz-rustiron-loopback.cnf</div>
      </article>
      <article className="panel metric">
        <div className="m-head">Admin ports</div>
        <div className="m-val" style={{ fontSize: 20 }}>
          {cards.admin}
        </div>
        <div className="m-detail">{cards.adminDetail}</div>
      </article>
    </section>
  );
}

export function HostFirewallPage() {
  const data = useData();
  const isLive = isRealHost(data.source);
  const fw = data.machine?.firewall;
  const dbListeners = data.machine?.database?.listeners_beyond_loopback;
  const fwReadable = fw?.readable === true;
  const unverifiedLive = isLive && !fwReadable;

  return (
    <Page live>
      <Crumbs items={[{ href: "/", label: "Overview" }, { label: "Firewall" }]} />
      <div className="page-head">
        <div>
          <h1>Firewall</h1>
          <p className="sub">
            Network firewall zone and allowed server ports. Database and admin ports remain blocked
            from public traffic.
          </p>
        </div>
        <Link className="btn sm" to="/help/$slug" params={{ slug: "firewall-and-network" }}>
          Firewall guide
        </Link>
      </div>

      {unverifiedLive ? (
        <div className="attention info" role="status">
          <Glyph icon={CircleDashed} />
          <div className="att-body">
            <strong>Live firewalld rules require root inspection.</strong> Run{" "}
            <span className="mono">sudo firewall-cmd --zone=rustiron --list-all</span> on the server
            to inspect active rules.
          </div>
        </div>
      ) : null}

      <FirewallSummaryCards
        isLive={isLive}
        fwReadable={fwReadable}
        defaultZone={fw?.default_zone}
        fwState={fw?.state}
        dbListeners={dbListeners}
      />

      <section className="panel flush" aria-label="Managed firewall service rules">
        <div className="panel-head" style={{ padding: "14px 16px 10px" }}>
          <div className="row" style={{ gap: 8 }}>
            <Glyph icon={Shield} />
            <h2>
              {unverifiedLive ? "Expected managed policy (unverified)" : "Allowed ports & services"}
            </h2>
          </div>
          <span className="meta">
            {unverifiedLive ? "Verify live host rules as root" : "Managed server firewall policy"}
          </span>
        </div>
        <TableScroll label="Managed firewall service rules">
          <table className="data">
            <thead>
              <tr>
                <th>Service / Port</th>
                <th>Protocol</th>
                <th>Policy</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td className="mono">ssh (22)</td>
                <td>TCP</td>
                <td>
                  <span className="pill ok">Allowed</span>
                </td>
                <td>SSH administration and secure console tunnel</td>
              </tr>
              <tr>
                <td className="mono">http (80) / https (443)</td>
                <td>TCP</td>
                <td>
                  <span className="pill ok">Allowed</span>
                </td>
                <td>Web traffic for hosted websites and modern apps</td>
              </tr>
              <tr>
                <td className="mono">dns (53)</td>
                <td>UDP / TCP</td>
                <td>
                  <span className="pill">When DNS enabled</span>
                </td>
                <td>Authoritative PowerDNS server and zone transfers</td>
              </tr>
              <tr>
                <td className="mono">mariadb (3306) · webadmin (7080)</td>
                <td>TCP</td>
                <td>
                  <span className="pill err">Blocked</span>
                </td>
                <td>Restricted to local loopback connections only</td>
              </tr>
            </tbody>
          </table>
        </TableScroll>
      </section>
      <FirewallRuleBuilderPanel />
    </Page>
  );
}

const maintenanceActions = [
  {
    verb: "site_credential_rotate",
    scope: "Rotate database password, update wp-config/db.cnf atomically, and restart PHP pool",
    custody: "Generated locally on the server; password never appears in plans or browser",
    status: "Available",
  },
  {
    verb: "site_update",
    scope: "Update WordPress core, plugins, or themes with automatic code and database rollback",
    custody: "Requires a fresh backup snapshot taken within the last 24 hours",
    status: "Available",
  },
  {
    verb: "site_quota",
    scope: "Adjust per-site disk storage and file count limits",
    custody: "Applies within server quota policy limits",
    status: "Available",
  },
  {
    verb: "site_clone / clone_scrub",
    scope: "Create an isolated staging clone from a backup snapshot with URL rewriting",
    custody: "Stays isolated until explicitly published",
    status: "Available",
  },
  {
    verb: "site_restore",
    scope: "Restore a website from an encrypted backup snapshot with safety rollback",
    custody: "Verifies manifest integrity before replacing live files or database",
    status: "Available",
  },
  {
    verb: "site_delete / site_retire",
    scope: "Take a website offline and cleanly remove its files, database, and account",
    custody: "Requires a recent backup snapshot and explicit operator approval",
    status: "Available",
  },
] as const;

export function SiteMaintenancePage({ siteId }: { siteId: string }) {
  const data = useData();
  const site = data.sites.find((s) => s.id === siteId) ?? data.sites[0];
  const domain = site?.domain ?? siteId;
  const resolvedId = site?.id ?? siteId;

  return (
    <Page live>
      <Crumbs
        items={[
          { href: "/", label: "Overview" },
          { href: "/sites", label: "Sites" },
          { href: `/sites/${resolvedId}`, label: domain },
          { label: "Maintenance" },
        ]}
      />
      <div className="page-head">
        <div>
          <div className="row" style={{ gap: 10, flexWrap: "wrap" }}>
            <h1 translate="no">{domain}</h1>
            <CopyId id={resolvedId} label="site ID" />
          </div>
          <p className="sub">
            Database credential rotation, scheduled WordPress jobs, and approved site maintenance
            actions.
          </p>
        </div>
        <Link className="btn primary sm" to="/plans/new">
          Run maintenance action
        </Link>
      </div>

      <nav className="tabs" aria-label="Site sections">
        <Link to="/sites/$siteId" params={{ siteId: resolvedId }}>
          Overview
        </Link>
        <Link to="/sites/$siteId/configuration" params={{ siteId: resolvedId }}>
          Configuration
        </Link>
        <Link to="/sites/$siteId/maintenance" params={{ siteId: resolvedId }} aria-current="page">
          Maintenance
        </Link>
        <Link to="/sites/$siteId/operations" params={{ siteId: resolvedId }}>
          Operations
        </Link>
        <Link to="/sites/$siteId/recovery" params={{ siteId: resolvedId }}>
          Recovery
        </Link>
      </nav>

      <SiteActionsConsole siteId={resolvedId} domain={domain} />

      <div className="grid g2">
        <section className="panel">
          <div className="panel-head">
            <div className="row" style={{ gap: 8 }}>
              <Glyph icon={KeyRound} />
              <h2>Database password rotation</h2>
            </div>
            <span className="pill ok">
              <Glyph icon={CircleCheck} />
              Ready
            </span>
          </div>
          <p className="muted" style={{ marginBottom: 12 }}>
            Generates a new MariaDB password on the server, swaps{" "}
            <span className="mono">private/db.cnf</span> atomically, restarts the site PHP pool, and
            verifies the website responds cleanly.
          </p>
          <pre className="code" style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>
            {`rustiron plan create site-credential-rotate --site ${resolvedId} --hostname ${domain}`}
          </pre>
        </section>

        <section className="panel">
          <div className="panel-head">
            <div className="row" style={{ gap: 8 }}>
              <Glyph icon={ShieldCheck} />
              <h2>Scheduled jobs &amp; background load</h2>
            </div>
            <span className="pill">Traffic-aware</span>
          </div>
          <dl className="kv">
            <dt>WordPress cron</dt>
            <dd>Server timer triggers wp-cron.php every 5 minutes inside this site&apos;s pool</dd>
            <dt>Load check</dt>
            <dd className="mono">
              rustiron-control --background-budget --job site_cron --site {resolvedId}
            </dd>
            <dt>Outbound mail</dt>
            <dd className="mono">/run/rustiron-mail-relay/rs_{resolvedId}.sock</dd>
          </dl>
        </section>
      </div>

      <section className="panel flush" aria-label="Approved site maintenance catalogue">
        <div className="panel-head" style={{ padding: "14px 16px 10px" }}>
          <div className="row" style={{ gap: 8 }}>
            <Glyph icon={Wrench} />
            <h2>Available maintenance actions</h2>
          </div>
          <span className="meta">Requires operator approval before execution</span>
        </div>
        <TableScroll label="Approved site maintenance catalogue">
          <table className="data">
            <thead>
              <tr>
                <th>Action</th>
                <th>What it does</th>
                <th>Safety requirements</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {maintenanceActions.map((item) => (
                <tr key={item.verb}>
                  <td className="mono">{item.verb}</td>
                  <td>{item.scope}</td>
                  <td className="muted">{item.custody}</td>
                  <td>
                    <span className="pill ok">{item.status}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableScroll>
      </section>
    </Page>
  );
}
