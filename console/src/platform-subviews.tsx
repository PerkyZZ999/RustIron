// W605 (P29 Slice 2): Read-only console subviews ported from docs/mockup/screens/
// (Sites inspector, Recovery schedules & backup store, Domain overview & PowerDNS
// records). Strictly read-only: no host mutation or backend write endpoints.
import { Link } from "@tanstack/react-router";
import { ArrowLeft, ChevronDown, ChevronRight, Copy, Globe, Layers, Lock } from "lucide-react";
import { useState } from "react";

import { BackupScheduleWizard } from "./backup-migration-wizards";
import { useData } from "./data";
import { DnsRecordEditorPanel, SslActionPanel } from "./hosting-wizards";
import type { Site } from "./fixture";
import { type DomainRecord, fixtureDomains, liveApps, liveDomains } from "./platform-data";
import { InspectorPanel } from "./platform-pages";
import { Crumbs, EmptyState, Glyph, Page, TableScroll } from "./ui";

const recoveryTabItems = [
  { to: "/recovery", label: "Overview" },
  { to: "/recovery/schedules", label: "Scheduled capture" },
  { to: "/recovery/store", label: "Backup store" },
] as const;

export function RecoveryTabs({ current }: { current: (typeof recoveryTabItems)[number]["to"] }) {
  return (
    <nav className="host-tabs" aria-label="Recovery sections">
      {recoveryTabItems.map((tab) => (
        <Link key={tab.to} to={tab.to} aria-current={tab.to === current ? "page" : undefined}>
          {tab.label}
        </Link>
      ))}
    </nav>
  );
}

type StandingGrantCard = {
  id: string;
  schedule: string;
  state: "active" | "expired";
  sites: string;
  windows: string;
  missed: string;
  newest: string;
  expires: string;
};

const fixtureGrants: StandingGrantCard[] = [
  {
    id: "sg_03",
    schedule: "Daily at 02:58 UTC · signed 8 Oct",
    state: "active",
    sites: "blog, shop, portfolio, emdash, api",
    windows: "41 used · 49 remaining of 90",
    missed: "1 · 2 Nov (executor stopped)",
    newest: "15 h ago · next window tonight 02:58",
    expires: "6 Jan 2027 · 50 days",
  },
  {
    id: "sg_02",
    schedule: "Every 6 h · signed 1 Aug",
    state: "expired",
    sites: "blog, shop",
    windows: "268 used · 0 remaining of 268",
    missed: "4",
    newest: "Covered by sg_03 now",
    expires: "Expired 8 Oct 2026",
  },
];

export function RecoverySchedulesPage() {
  const data = useData();

  return (
    <Page live>
      <Crumbs
        items={[
          { href: "/", label: "Overview" },
          { href: "/recovery", label: "Recovery" },
          { label: "Scheduled capture" },
        ]}
      />
      <div className="page-head">
        <div>
          <h1>Scheduled capture</h1>
          <p className="sub">
            Recurring backup schedules for up to 16 websites with fixed capture windows and
            encrypted off-host storage.
          </p>
        </div>
        <Link className="btn sm" to="/help/$slug" params={{ slug: "backups-and-recovery" }}>
          Schedule guide
        </Link>
      </div>
      <RecoveryTabs current="/recovery/schedules" />
      <BackupScheduleWizard />

      {data.source.kind === "live" ? (
        <section className="panel">
          <div className="panel-head">
            <h2>Live host observation</h2>
            <span className="pill">Read-only summary</span>
          </div>
          <p className="muted">
            Observed host <span className="mono">{data.source.host.host_id}</span> has{" "}
            {data.sites.length} registered site(s) and destination{" "}
            <span className="mono">
              {data.observation?.host.backup_destination ?? "not enrolled"}
            </span>
            . Standing-grant window counters stay in the host journal and are inspected on the host
            with <span className="mono">rustiron-control --diagnose</span> or{" "}
            <span className="mono">rustiron backup retention-plan</span>.
          </p>
        </section>
      ) : (
        <>
          <div className="grid g2">
            {fixtureGrants.map((grant) => (
              <section className="panel" key={grant.id}>
                <div className="panel-head">
                  <div>
                    <h2 className="mono">{grant.id}</h2>
                    <span className="cap">{grant.schedule}</span>
                  </div>
                  <span className={grant.state === "active" ? "pill ok" : "pill"}>
                    {grant.state}
                  </span>
                </div>
                <dl className="kv">
                  <dt>Named sites</dt>
                  <dd className="mono">{grant.sites}</dd>
                  <dt>Capture windows</dt>
                  <dd>{grant.windows}</dd>
                  <dt>Missed windows</dt>
                  <dd>{grant.missed}</dd>
                  <dt>Newest snapshot</dt>
                  <dd>{grant.newest}</dd>
                  <dt>Validity</dt>
                  <dd>{grant.expires}</dd>
                </dl>
              </section>
            ))}
          </div>
          <div className="attention warn">
            <div className="att-body">
              <strong>Sites outside any standing grant.</strong> Quarantined sites (
              <span className="mono">news.lab.test</span>) and newly created sites require a new
              signed standing grant or a one-off signed capture.
            </div>
            <Link className="btn sm" to="/plans/new">
              Review offline CLI flow
            </Link>
          </div>
        </>
      )}

      <p className="cap">
        Captures in each window run with the site&apos;s scoped identity (PHP + MariaDB or modern
        app SQLite + uploads). Missed windows are recorded honestly, never silently caught up.
      </p>
    </Page>
  );
}

export function RecoveryStorePage() {
  const data = useData();
  const obs = data.source.kind === "live" ? data.observation : null;
  const destination = obs
    ? (obs.host.backup_destination ?? "Not enrolled")
    : "s3://rustiron-vps1@s3.store.lab.test";
  const retentionDays = obs ? obs.host.backup_retention_days : 30;
  const enrolled = obs ? Boolean(obs.host.backup_destination) : true;
  const captureCount = obs ? obs.captures.length : 14;

  return (
    <Page live>
      <Crumbs
        items={[
          { href: "/", label: "Overview" },
          { href: "/recovery", label: "Recovery" },
          { label: "Backup store" },
        ]}
      />
      <div className="page-head">
        <div>
          <div className="row" style={{ gap: 10 }}>
            <h1>Backup store</h1>
            <span className={enrolled ? "pill ok" : "pill warn"}>
              {enrolled ? "Enrolled" : "Not enrolled"}
            </span>
          </div>
          <p className="sub">
            Connected S3-compatible destination for encrypted backups with Object Lock protection.
            Access keys stay strictly on the server.
          </p>
        </div>
      </div>
      <RecoveryTabs current="/recovery/store" />

      <div className="grid g2">
        <section className="panel">
          <div className="panel-head">
            <h2>Destination</h2>
          </div>
          <dl className="kv">
            <dt>Endpoint & bucket</dt>
            <dd className="mono">{destination}</dd>
            <dt>Transport</dt>
            <dd>HTTPS, certificate pinned at enrollment</dd>
            <dt>Enrollment authority</dt>
            <dd>
              Root procedure on the host (
              <Link to="/help/$slug" params={{ slug: "backups-and-recovery" }}>
                Backups &amp; recovery guide
              </Link>
              )
            </dd>
          </dl>
        </section>

        <section className="panel">
          <div className="panel-head">
            <h2>Retention lock</h2>
          </div>
          <dl className="kv">
            <dt>Object lock</dt>
            <dd>
              <span className="pill ok">COMPLIANCE mode</span>
            </dd>
            <dt>Enrolled retention</dt>
            <dd>{retentionDays ? `${retentionDays} days` : "Not reported in observation"}</dd>
            <dt>Retention authority</dt>
            <dd>Separate operator workstation principal</dd>
            <dt>Worker deletes / prune</dt>
            <dd>Refused by store policy; server cannot erase backup history</dd>
          </dl>
        </section>

        <section className="panel">
          <div className="panel-head">
            <h2>Observed usage</h2>
          </div>
          <dl className="kv">
            <dt>Recorded captures</dt>
            <dd>{captureCount} capture record(s) in observation</dd>
            <dt>Site namespaces</dt>
            <dd>{data.sites.length} registered workload(s)</dd>
            <dt>Consistency model</dt>
            <dd>WordPress &amp; WAL-safe SQLite consistency checks</dd>
          </dl>
        </section>

        <section className="panel">
          <div className="panel-head">
            <h2>Independent off-site copy</h2>
            <span className="pill">Not configured</span>
          </div>
          <p className="muted">
            Secondary off-site replication and offline key escrow are not yet configured. Until
            connected, the independent copy verification check remains{" "}
            <span className="mono">not_run</span>.
          </p>
        </section>
      </div>

      <p className="cap">
        To enroll or rotate a backup destination, follow the Backup Store guide on the server CLI.
      </p>
    </Page>
  );
}

function DomainTabs({ hostname, current }: { hostname: string; current: "overview" | "dns" }) {
  return (
    <nav className="host-tabs" aria-label="Domain sections">
      <Link
        to="/domains/$hostname"
        params={{ hostname }}
        aria-current={current === "overview" ? "page" : undefined}
      >
        Overview
      </Link>
      <Link
        to="/domains/$hostname/dns"
        params={{ hostname }}
        aria-current={current === "dns" ? "page" : undefined}
      >
        DNS
      </Link>
    </nav>
  );
}

function resolveDomain(
  hostname: string,
  sourceKind: string,
  sites: Site[],
  observation: ReturnType<typeof useData>["observation"],
): DomainRecord {
  const list =
    sourceKind === "live" && observation ? liveDomains(sites, observation) : fixtureDomains;
  return (
    list.find((d) => d.hostname === hostname) ?? {
      hostname,
      serves: "Unregistered hostname",
      siteHref: null,
      certificate: "not_issued",
      certificateLabel: "Not observed",
      notAfter: "—",
      renewedBy: "—",
      issuer: "—",
      chainDigest: "—",
      renewUntil: "—",
      lastResult: "Hostname not present in current observation",
      dnsZone: "Not observed",
      dnsMode: "Read-only",
    }
  );
}

export function DomainDetailPage({ hostname }: { hostname: string }) {
  const data = useData();
  const domain = resolveDomain(hostname, data.source.kind, data.sites, data.observation);
  const [detailsOpen, setDetailsOpen] = useState(true);
  const [copied, setCopied] = useState(false);

  function copyDigest() {
    void navigator.clipboard?.writeText(domain.chainDigest).then(() => setCopied(true));
  }

  return (
    <Page live>
      <Crumbs
        items={[
          { href: "/", label: "Overview" },
          { href: "/domains", label: "Domains" },
          { label: hostname },
        ]}
      />
      <div className="page-head">
        <div>
          <div className="row" style={{ gap: 10, flexWrap: "wrap" }}>
            <h1 className="mono">{domain.hostname}</h1>
            <span
              className={
                domain.certificate === "valid"
                  ? "pill ok"
                  : domain.certificate === "not_issued"
                    ? "pill"
                    : "pill warn"
              }
            >
              {domain.certificateLabel}
            </span>
          </div>
          <p className="sub">Serves {domain.serves} · HTTPS certificate and DNS overview.</p>
        </div>
        <Link className="btn quiet sm" to="/domains">
          <Glyph icon={ArrowLeft} />
          All domains
        </Link>
      </div>
      <DomainTabs hostname={hostname} current="overview" />

      <div className="aside-grid">
        <section className="panel">
          <div className="panel-head">
            <h2>Certificate</h2>
            <span className={domain.certificate === "valid" ? "pill ok" : "pill warn"}>
              {domain.certificateLabel}
            </span>
          </div>
          <dl className="kv">
            <dt>Hostname</dt>
            <dd className="mono">{domain.hostname}</dd>
            <dt>Not after</dt>
            <dd>{domain.notAfter}</dd>
            <dt>renew_until</dt>
            <dd>{domain.renewUntil}</dd>
            <dt>Renewed by</dt>
            <dd>{domain.renewedBy}</dd>
            <dt>Last result</dt>
            <dd>{domain.lastResult}</dd>
          </dl>
          <button
            type="button"
            className="disc-btn"
            aria-expanded={detailsOpen}
            onClick={() => setDetailsOpen((prev) => !prev)}
          >
            <span>Cryptographic & listener details</span>
            <Glyph icon={detailsOpen ? ChevronDown : ChevronRight} />
          </button>
          {detailsOpen ? (
            <dl className="kv" style={{ marginTop: 12 }}>
              <dt>Issuer</dt>
              <dd>{domain.issuer}</dd>
              <dt>Chain digest</dt>
              <dd className="row" style={{ gap: 8 }}>
                <span className="mono">{domain.chainDigest}</span>
                <button type="button" className="btn quiet sm" onClick={copyDigest}>
                  <Glyph icon={Copy} />
                  {copied ? "Copied" : "Copy"}
                </button>
              </dd>
              <dt>Key</dt>
              <dd>ECDSA P-256 · private key never leaves the host</dd>
              <dt>Challenge</dt>
              <dd>Confined HTTP-01 on the site webroot</dd>
              <dt>Listener reload</dt>
              <dd>Graceful OpenLiteSpeed reload applies across all hosted websites</dd>
            </dl>
          ) : null}
        </section>

        <aside style={{ display: "grid", gap: 16, alignContent: "start" }}>
          <section className="panel">
            <div className="panel-head">
              <h2>TLS probe</h2>
            </div>
            <dl className="kv">
              <dt>Served chain</dt>
              <dd>{domain.certificate === "valid" ? "Matches issued leaf" : "See last result"}</dd>
              <dt>Protocol</dt>
              <dd>TLS 1.3 (OLS SNI listener)</dd>
              <dt>Workload</dt>
              <dd>
                {domain.siteHref ? (
                  <Link to={domain.siteHref}>{domain.serves}</Link>
                ) : (
                  domain.serves
                )}
              </dd>
            </dl>
          </section>

          <section className="panel">
            <div className="panel-head">
              <h2>DNS zone</h2>
            </div>
            <p className="muted">
              Zone <span className="mono">{domain.dnsZone}</span> ({domain.dnsMode}).
            </p>
            <Link className="btn sm" to="/domains/$hostname/dns" params={{ hostname }}>
              Manage DNS records
            </Link>
          </section>
          <SslActionPanel hostname={domain.hostname} />
        </aside>
      </div>
    </Page>
  );
}

export function DomainDnsPage({ hostname }: { hostname: string }) {
  const data = useData();
  const isLive = data.source.kind === "live";
  const domain = resolveDomain(hostname, data.source.kind, data.sites, data.observation);
  const label = hostname.split(".")[0] ?? hostname;
  const liveDnsOps =
    isLive && data.observation
      ? data.observation.operations.filter(
          (op) => op.kind === "dns_zone_import" || op.kind === "dns_change",
        )
      : [];

  return (
    <Page live>
      <Crumbs
        items={[
          { href: "/", label: "Overview" },
          { href: "/domains", label: "Domains" },
          { href: `/domains/${hostname}`, label: hostname },
          { label: "DNS" },
        ]}
      />
      <div className="page-head">
        <div>
          <h1 className="mono">{hostname}</h1>
          <p className="sub">
            Authoritative DNS zone and resource records served by PowerDNS 5.1 with secondary zone
            transfers.
          </p>
        </div>
        <Link className="btn quiet sm" to="/domains/$hostname" params={{ hostname }}>
          <Glyph icon={ArrowLeft} />
          Domain overview
        </Link>
      </div>
      <DomainTabs hostname={hostname} current="dns" />

      <DnsRecordEditorPanel hostname={hostname} />

      <section className="grid g4" aria-label="Zone summary">
        <article className="panel metric">
          <div className="m-head">Authority</div>
          <div className="m-val" style={{ fontSize: 20 }}>
            PowerDNS 5.1
          </div>
          <div className="m-detail">SQLite backend · authoritative primary</div>
        </article>
        <article className="panel metric">
          <div className="m-head">Transfer</div>
          <div className="m-val" style={{ fontSize: 20 }}>
            TSIG AXFR
          </div>
          <div className="m-detail">Signed transfer authority to secondary</div>
        </article>
        <article className="panel metric">
          <div className="m-head">DNSSEC</div>
          <div className="m-val" style={{ fontSize: 20 }}>
            Disabled
          </div>
          <div className="m-detail">Unsigned primary zone</div>
        </article>
        <article className="panel metric">
          <div className="m-head">Zone</div>
          <div className="m-val mono" style={{ fontSize: 18 }}>
            {domain.dnsZone.split(" ")[0]}
          </div>
          <div className="m-detail">Compare-and-set serial increment</div>
        </article>
      </section>

      {isLive ? (
        liveDnsOps.length > 0 ? (
          <section className="panel flush" aria-label="Recorded DNS operations">
            <div className="panel-head" style={{ padding: "14px 16px 10px" }}>
              <h2>Recorded DNS journal operations</h2>
              <span className="meta">Live host journal · inspect RRsets via pdnsutil</span>
            </div>
            <TableScroll label="Recorded DNS journal operations">
              <table className="data">
                <thead>
                  <tr>
                    <th>Operation</th>
                    <th>Kind</th>
                    <th>State</th>
                    <th>Zone / subject</th>
                  </tr>
                </thead>
                <tbody>
                  {liveDnsOps.map((op) => (
                    <tr key={op.operation_id}>
                      <td>
                        <Link
                          className="mono"
                          to="/operations/$operationId"
                          params={{ operationId: op.operation_id }}
                        >
                          {op.operation_id}
                        </Link>
                      </td>
                      <td className="mono">{op.kind}</td>
                      <td>
                        <span className={op.state === "succeeded" ? "pill ok" : "pill warn"}>
                          {op.state}
                        </span>
                      </td>
                      <td className="mono">{op.site_id}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableScroll>
          </section>
        ) : (
          <EmptyState
            icon={Globe}
            title={`No live RRset export in observation for ${hostname}`}
            description="Inspect live PowerDNS 5.1 RRsets directly on the host or submit a signed dns_zone_import / dns_change plan."
            command={`sudo pdnsutil list-zone ${hostname}`}
            action={
              <>
                <Link className="btn primary sm" to="/plans/new">
                  Prepare plan
                </Link>
                <Link
                  className="btn quiet sm"
                  to="/help/$slug"
                  params={{ slug: "domains-ssl-and-dns" }}
                >
                  Domains &amp; DNS guide
                </Link>
              </>
            }
          />
        )
      ) : (
        <section className="panel flush" aria-label="Zone records grouped by ownership">
          <div className="panel-head" style={{ padding: "14px 16px 10px" }}>
            <h2>Records for {hostname}</h2>
            <span className="meta">Grouped by Rustiron ownership boundary</span>
          </div>
          <TableScroll label={`DNS records for ${hostname}`}>
            <table className="data">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Type</th>
                  <th>Value</th>
                  <th>TTL</th>
                  <th>Ownership</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td className="mono">{label}</td>
                  <td className="mono">A</td>
                  <td className="mono">192.0.2.10</td>
                  <td className="tnum">300</td>
                  <td>
                    <span className="owner-badge">Managed</span>
                  </td>
                </tr>
                <tr>
                  <td className="mono">{label}</td>
                  <td className="mono">AAAA</td>
                  <td className="mono">2001:db8::10</td>
                  <td className="tnum">300</td>
                  <td>
                    <span className="owner-badge">Managed</span>
                  </td>
                </tr>
                <tr>
                  <td className="mono">{label}</td>
                  <td className="mono">MX</td>
                  <td className="mono">10 mail.external.example.</td>
                  <td className="tnum">3600</td>
                  <td>
                    <span className="owner-badge host">
                      <Glyph icon={Lock} /> Protected mail
                    </span>
                  </td>
                </tr>
                <tr>
                  <td className="mono">{label}</td>
                  <td className="mono">TXT</td>
                  <td className="mono">&quot;v=spf1 include:mail.external.example -all&quot;</td>
                  <td className="tnum">3600</td>
                  <td>
                    <span className="owner-badge host">
                      <Glyph icon={Lock} /> Protected mail
                    </span>
                  </td>
                </tr>
                <tr>
                  <td className="mono">_dmarc.{label}</td>
                  <td className="mono">TXT</td>
                  <td className="mono">&quot;v=DMARC1; p=quarantine&quot;</td>
                  <td className="tnum">3600</td>
                  <td>
                    <span className="owner-badge host">
                      <Glyph icon={Lock} /> Protected mail
                    </span>
                  </td>
                </tr>
              </tbody>
            </table>
          </TableScroll>
        </section>
      )}

      <p className="cap">
        Mail records (MX, SPF, DKIM, DMARC) stay untouched by site changes and require explicit
        signed <span className="mono">dns_change</span> plans (
        <Link to="/help/$slug" params={{ slug: "domains-ssl-and-dns" }}>
          Domains &amp; DNS guide
        </Link>
        ).
      </p>
    </Page>
  );
}

export function SiteInspector({ site, onClose }: { site: Site; onClose: () => void }) {
  const passedMarks = site.marks.filter((m) => m === "pass").length;
  return (
    <InspectorPanel
      ariaLabel={`Details for ${site.domain}`}
      title={site.domain}
      subtitle={`Site ${site.id}`}
      monoTitle
      closeLabel="Close site details"
      onClose={onClose}
    >
      <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
        <span className={`state ${site.servingKind}`}>{site.serving}</span>
        <span className="owner-badge">{site.ownership}</span>
      </div>
      <dl className="kv">
        <dt>Runtime</dt>
        <dd>{site.runtime}</dd>
        <dt>Last HTTP</dt>
        <dd className="mono">{site.http}</dd>
        <dt>Page cache</dt>
        <dd>{site.journal?.pageCache ?? "See site configuration"}</dd>
        <dt>Quotas</dt>
        <dd>
          {site.journal
            ? `${site.journal.quotaUsage} of ${site.journal.quotaLimit}`
            : "Per-site XFS project quota"}
        </dd>
        <dt>Last operation</dt>
        <dd>
          {site.operation}
          {site.operationDetail ? ` · ${site.operationDetail}` : ""}
        </dd>
        <dt>Recovery fields</dt>
        <dd>{passedMarks} of 7 passing</dd>
      </dl>
      <div className="insp-actions">
        <Link className="btn sm" to="/sites/$siteId" params={{ siteId: site.id }}>
          Open site
        </Link>
        <Link className="btn quiet sm" to="/sites/$siteId/recovery" params={{ siteId: site.id }}>
          Recovery evidence
        </Link>
      </div>
    </InspectorPanel>
  );
}

const emdashMigrationChecks = [
  [
    "Published posts & pages",
    "42 published WordPress items",
    "42 imported in EmDash SQLite",
    "Matched",
    "ok",
  ],
  [
    "Captured media assets",
    "wp-content/uploads (14 files)",
    "data/uploads (14 SHA-256 verified)",
    "Verified",
    "ok",
  ],
  [
    "Internal links & permalinks",
    "/2026/09/hello-world/",
    "301 → /posts/hello-world",
    "301 verified",
    "ok",
  ],
  ["Draft isolation", "3 unpublished drafts", "Public GET → 404 (not leaked)", "Isolated", "ok"],
  [
    "Full-text search (FTS5)",
    "WordPress ?s=query",
    "SQLite FTS5 /_emdash/api/content/",
    "Matched",
    "ok",
  ],
  [
    "DNS, TLS & mail cutover",
    "Incumbent WordPress serving 200",
    "Staged at emdash.lab.test",
    "Operator gate",
    "muted",
  ],
] as const;

export function EmDashMigrationDetailPage({ migrationId }: { migrationId: string }) {
  const data = useData();
  const isLive = data.source.kind === "live";
  const liveEmDash =
    isLive && data.observation
      ? liveApps(data.observation).find(
          (app) =>
            app.kind === "EmDash CMS" &&
            (`emdash_${app.siteId}` === migrationId || app.id === migrationId),
        )
      : null;

  if (isLive) {
    return (
      <Page live>
        <Crumbs
          items={[
            { href: "/", label: "Overview" },
            { href: "/migration", label: "Migration" },
            { label: migrationId },
          ]}
        />
        <div className="page-head">
          <div>
            <h1>WordPress → EmDash CMS</h1>
            <p className="sub">
              {liveEmDash
                ? `Observed EmDash site ${liveEmDash.hostname} (${liveEmDash.currentRelease}) on this host.`
                : `Rehearsal ${migrationId} is not recorded in this live host observation.`}
            </p>
          </div>
          <Link className="btn quiet sm" to="/migration">
            <Glyph icon={ArrowLeft} />
            All migrations
          </Link>
        </div>
        {liveEmDash ? (
          <section className="panel">
            <div className="panel-head">
              <h2>Observed EmDash workload</h2>
              <span className={`pill ${liveEmDash.servingKind}`}>{liveEmDash.serving}</span>
            </div>
            <dl className="kv">
              <dt>Hostname</dt>
              <dd className="mono">{liveEmDash.hostname}</dd>
              <dt>Runtime profile</dt>
              <dd className="mono">{liveEmDash.runtimeProfile}</dd>
              <dt>Active release</dt>
              <dd className="mono">{liveEmDash.currentRelease}</dd>
              <dt>Backup model</dt>
              <dd>{liveEmDash.sqliteBackup}</dd>
            </dl>
          </section>
        ) : (
          <EmptyState
            icon={Layers}
            title="Offline WXR parity report stays on the operator workstation"
            description="Run packaging/wordpress-to-emdash.py on your workstation to generate and verify a WordPress-to-EmDash migration bundle."
            command="python3 packaging/wordpress-to-emdash.py plan --wxr ./export.xml --media ./uploads --out ./emdash-migration"
            action={
              <Link
                className="btn quiet sm"
                to="/help/$slug"
                params={{ slug: "modern-apps-and-emdash" }}
              >
                EmDash CMS guide
              </Link>
            }
          />
        )}
      </Page>
    );
  }

  return (
    <Page live>
      <Crumbs
        items={[
          { href: "/", label: "Overview" },
          { href: "/migration", label: "Migration" },
          { label: migrationId },
        ]}
      />
      <div className="page-head">
        <div>
          <div className="row" style={{ gap: 10, flexWrap: "wrap" }}>
            <h1>WordPress → EmDash CMS rehearsal</h1>
            <span className="pill ok">Verified</span>
          </div>
          <p className="sub">
            Rehearsal <span className="mono">{migrationId}</span> from{" "}
            <span className="mono">blog.lab.test</span> (WordPress) into{" "}
            <span className="mono">emdash.lab.test</span> (EmDash 1.6.0 Node.js Starter). Incumbent
            WordPress stays untouched until explicit operator retirement.
          </p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <Link className="btn sm" to="/apps/$appId" params={{ appId: "app_emdash" }}>
            Open EmDash app
          </Link>
          <Link className="btn quiet sm" to="/migration">
            <Glyph icon={ArrowLeft} />
            All rehearsals
          </Link>
        </div>
      </div>

      <section className="grid g4" aria-label="EmDash migration summary">
        <article className="panel metric">
          <div className="m-head">Incumbent WordPress</div>
          <div className="m-val" style={{ fontSize: 20 }}>
            200 OK · untouched
          </div>
          <div className="m-detail">Source blog.lab.test continues serving</div>
        </article>
        <article className="panel metric">
          <div className="m-head">Content &amp; media</div>
          <div className="m-val" style={{ fontSize: 20 }}>
            42 posts · 14 media
          </div>
          <div className="m-detail">Every media SHA-256 verified</div>
        </article>
        <article className="panel metric">
          <div className="m-head">Links &amp; redirects</div>
          <div className="m-val" style={{ fontSize: 20 }}>
            100% rewritten
          </div>
          <div className="m-detail">301 redirect rules verified live</div>
        </article>
        <article className="panel metric">
          <div className="m-head">Drafts &amp; FTS5</div>
          <div className="m-val" style={{ fontSize: 20 }}>
            Drafts 404 · FTS5 ok
          </div>
          <div className="m-detail">No private draft exposed publicly</div>
        </article>
      </section>

      <section className="panel flush" aria-label="Side-by-side verification checks">
        <div className="panel-head" style={{ padding: "14px 16px 10px" }}>
          <h2>Side-by-side verification (packaging/wordpress-to-emdash.py)</h2>
          <span className="meta">Read-only migration parity evidence</span>
        </div>
        <TableScroll label="WordPress to EmDash verification checks">
          <table className="data">
            <thead>
              <tr>
                <th>Check</th>
                <th>Source (WordPress)</th>
                <th>Target (EmDash 1.6.0)</th>
                <th>Verification</th>
              </tr>
            </thead>
            <tbody>
              {emdashMigrationChecks.map(([check, src, dst, result, kind]) => (
                <tr key={check}>
                  <td>{check}</td>
                  <td className="mono">{src}</td>
                  <td className="mono">{dst}</td>
                  <td>
                    <span className={kind === "ok" ? "pill ok" : "owner-badge host"}>{result}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableScroll>
      </section>

      <div className="attention warn">
        <div className="att-body">
          <strong>Operator sign-off required before retiring WordPress.</strong> Verify pages,
          media, and redirects on <span className="mono">emdash.lab.test</span>. Retiring{" "}
          <span className="mono">blog.lab.test</span> requires a separate signed offline activation
          and <span className="mono">site_delete</span> behind a fresh 24 h capture.
        </div>
        <Link className="btn sm" to="/help/$slug" params={{ slug: "modern-apps-and-emdash" }}>
          EmDash CMS guide
        </Link>
      </div>
    </Page>
  );
}
