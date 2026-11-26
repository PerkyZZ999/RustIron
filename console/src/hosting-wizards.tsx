// W628 (P29 Slice 8): CyberPanel-grade interactive hosting workflows —
// Create Website (/sites/new), Add Domain & DNS Zone (/domains/new),
// Interactive DNS Record Manager (Create/Edit/Delete RRsets on /domains/:hostname/dns),
// and SSL/TLS Certificate Manager panel.
import { Link } from "@tanstack/react-router";
import {
  AlertCircle,
  ArrowLeft,
  Check,
  ChevronDown,
  Copy,
  Download,
  Globe,
  Layers,
  Pencil,
  Plus,
  Server,
  ShieldCheck,
  Trash2,
  TriangleAlert,
} from "lucide-react";
import { useEffect, useState } from "react";

import {
  buildAppProvisionCmd,
  buildDnsChangeCmd,
  buildDnsZoneImportCmd,
  buildManualVerbPlanNote,
  buildSiteProvisionCmd,
  INSPECT_AND_SIGN_STEPS,
  renderCanonicalZone,
  renderDnsOperationsJson,
} from "./cli-commands";
import { toastManager } from "./components/ui/toast";
import { useData } from "./data";
import { Crumbs, Glyph, Page, TableScroll } from "./ui";
import { SeparateCustodyApplyPanel } from "./write-panel";

type WebsiteKind = "wordpress" | "emdash" | "app" | "proxy";

const websiteKinds: [WebsiteKind, string, string][] = [
  ["wordpress", "WordPress", "Isolated PHP 8.4 pool, MariaDB database, and LiteSpeed Cache."],
  ["emdash", "EmDash CMS", "Node.js 22 CMS with native SQLite FTS5 behind OpenLiteSpeed."],
  ["app", "Node.js / Bun app", "Prebuilt Node.js 22 or Bun 1.4 service on a local loopback port."],
  ["proxy", "Reverse proxy", "HTTPS reverse proxy with WebSocket support to a local backend port."],
];

const HOSTNAME_RE =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i;
const SITE_ID_RE = /^[a-z][a-z0-9]{2,15}$/;
const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;

function slugFromDomain(domain: string): string {
  const clean = domain.toLowerCase().replace(/[^a-z0-9]+/g, "");
  const prefixed = /^[a-z]/.test(clean) ? clean : `s${clean}`;
  const trimmed = prefixed.slice(0, 16);
  return trimmed.length >= 3 ? trimmed : `${trimmed}site`.slice(0, 16);
}

function downloadTextFile(filename: string, content: string, mime = "text/plain;charset=utf-8") {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function CopySnippetButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return undefined;
    const t = setTimeout(() => setCopied(false), 2000);
    return () => clearTimeout(t);
  }, [copied]);
  return (
    <button
      type="button"
      className="btn quiet sm"
      aria-label={label}
      onClick={() =>
        void navigator.clipboard?.writeText(text).then(() => {
          setCopied(true);
          toastManager.add({ id: `copy-${label}`, type: "success", title: "Command copied" });
        })
      }
    >
      <Glyph icon={copied ? Check : Copy} className={copied ? "check-pop" : undefined} />
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

function InlineErr({ id, message }: { id: string; message: string | null }) {
  if (!message) return null;
  return (
    <span id={id} className="err-msg" role="alert">
      <Glyph icon={AlertCircle} />
      {message}
    </span>
  );
}

function SignedApplyDisclosure({ title }: { title: string }) {
  return (
    <details className="disclose">
      <summary>
        <Glyph icon={ShieldCheck} />
        <span>{title}</span>
        <Glyph icon={ChevronDown} className="chev" />
      </summary>
      <div className="d-body">
        <SeparateCustodyApplyPanel />
      </div>
    </details>
  );
}

type WebsiteFormState = {
  kind: WebsiteKind;
  siteId: string;
  hostname: string;
  quotaMib: string;
  runtime: "node_22_v1" | "bun_1_v1";
  port: string;
  healthPath: string;
};

const websiteCmdMap: Record<WebsiteKind, (f: WebsiteFormState, s: string, h: string) => string> = {
  wordpress: (f, s, h) =>
    buildSiteProvisionCmd({ siteId: s, hostname: h, quotaMib: f.quotaMib || "2048" }),
  emdash: (f, s, h) =>
    buildAppProvisionCmd({
      siteId: s,
      hostname: h,
      runtime: "node_22_v1",
      port: f.port || "3401",
      healthPath: f.healthPath || "/_emdash/api/health",
      entrypoint: "dist/server/entry.mjs",
    }),
  app: (f, s, h) =>
    buildAppProvisionCmd({
      siteId: s,
      hostname: h,
      runtime: f.runtime,
      port: f.port || "3210",
      healthPath: f.healthPath || "/healthz",
    }),
  proxy: (f, s, h) =>
    buildManualVerbPlanNote({
      verb: "proxy_site_provision",
      runbook: "Runbook 34",
      summary: `Loopback reverse proxy site ${s} (${h}) -> 127.0.0.1:${Number.parseInt(f.port, 10) || 8080}`,
    }),
};

function buildWebsiteCommand(form: WebsiteFormState): string {
  return websiteCmdMap[form.kind](
    form,
    form.siteId.trim() || "sitenew",
    form.hostname.trim() || "example.com",
  );
}

function validateHost(hostname: string, existingHosts: Set<string>): string | null {
  const h = hostname.trim().toLowerCase();
  if (!h) return "Enter a valid domain name (for example, blog.example.com).";
  if (!HOSTNAME_RE.test(h)) return "Domain must be a valid hostname like example.com.";
  if (existingHosts.has(h)) return `${h} is already registered on this server.`;
  return null;
}

function validateIntRange(raw: string, min: number, max: number, label: string): string | null {
  const n = Number(raw);
  return Number.isInteger(n) && n >= min && n <= max
    ? null
    : `${label} must be between ${min} and ${max}.`;
}

type WebsiteErrors = {
  hostErr: string | null;
  idErr: string | null;
  quotaErr: string | null;
  portErr: string | null;
};

function WebsiteRuntimeFields({
  form,
  errs,
  patch,
}: {
  form: WebsiteFormState;
  errs: WebsiteErrors;
  patch: (p: Partial<WebsiteFormState>) => void;
}) {
  if (form.kind === "wordpress") {
    return (
      <div className="form-row">
        <label htmlFor="ws-quota">Disk quota (MiB)</label>
        <input
          id="ws-quota"
          className="input tnum"
          type="number"
          min={256}
          max={65536}
          value={form.quotaMib}
          aria-invalid={errs.quotaErr ? "true" : "false"}
          aria-describedby={errs.quotaErr ? "ws-quota-err" : undefined}
          onChange={(e) => patch({ quotaMib: e.target.value })}
        />
        <InlineErr id="ws-quota-err" message={errs.quotaErr} />
      </div>
    );
  }
  return (
    <>
      {form.kind === "app" ? (
        <div className="form-row">
          <label htmlFor="ws-runtime">Runtime</label>
          <select
            id="ws-runtime"
            className="input"
            value={form.runtime}
            onChange={(e) => patch({ runtime: e.target.value as "node_22_v1" | "bun_1_v1" })}
          >
            <option value="node_22_v1">Node.js 22 LTS</option>
            <option value="bun_1_v1">Bun 1.4</option>
          </select>
        </div>
      ) : null}
      <div className="form-row">
        <label htmlFor="ws-port">Local loopback port (1024–65535)</label>
        <input
          id="ws-port"
          className="input tnum"
          type="number"
          min={1024}
          max={65535}
          value={form.port}
          aria-invalid={errs.portErr ? "true" : "false"}
          aria-describedby={errs.portErr ? "ws-port-err" : undefined}
          onChange={(e) => patch({ port: e.target.value })}
        />
        <InlineErr id="ws-port-err" message={errs.portErr} />
      </div>
      {form.kind !== "proxy" ? (
        <div className="form-row">
          <label htmlFor="ws-health">Health check path</label>
          <input
            id="ws-health"
            className="input mono"
            value={form.healthPath}
            onChange={(e) => patch({ healthPath: e.target.value })}
          />
        </div>
      ) : null}
    </>
  );
}

function WebsiteSummaryAside({
  form,
  valid,
  signCmd,
  draftPayload,
}: {
  form: WebsiteFormState;
  valid: boolean;
  signCmd: string;
  draftPayload: string;
}) {
  const kindTitle = websiteKinds.find(([id]) => id === form.kind)?.[1] ?? form.kind;
  const runtimeNote =
    form.kind === "wordpress"
      ? `MariaDB + LSPHP 8.4 · ${form.quotaMib} MiB quota`
      : `Loopback 127.0.0.1:${form.port} behind OpenLiteSpeed`;

  return (
    <aside className="stack">
      <section className="panel">
        <div className="panel-head">
          <h2>Provision summary</h2>
          <span className={valid ? "pill ok" : "pill warn"}>
            {valid ? "Ready to sign" : "Check inputs"}
          </span>
        </div>
        <ul className="list">
          <li>
            <Glyph icon={Globe} className="list-muted" />
            <span className="grow">
              <span className="t mono">{form.hostname.trim() || "—"}</span>
              <span className="s">Account: rs_{form.siteId.trim() || "site"}</span>
            </span>
          </li>
          <li>
            <Glyph icon={Layers} className="list-muted" />
            <span className="grow">
              <span className="t">{kindTitle}</span>
              <span className="s">{runtimeNote}</span>
            </span>
          </li>
        </ul>
        <p className="cap" style={{ marginTop: 10 }}>
          New sites stay unserved until you activate OpenLiteSpeed configuration and issue an SSL
          certificate.
        </p>
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>Create &amp; sign command</h2>
          <div className="row" style={{ gap: 6 }}>
            <CopySnippetButton text={signCmd} label="Copy create website commands" />
            <button
              type="button"
              className="btn quiet sm"
              onClick={() =>
                downloadTextFile(
                  `${form.siteId.trim() || "website"}-draft.json`,
                  draftPayload,
                  "application/json;charset=utf-8",
                )
              }
            >
              <Glyph icon={Download} />
              JSON
            </button>
          </div>
        </div>
        <pre className="code signed-bytes">{signCmd}</pre>
      </section>
    </aside>
  );
}

export function CreateWebsitePage() {
  const data = useData();
  const [form, setForm] = useState<WebsiteFormState>({
    kind: "wordpress",
    hostname: "newsite.example.com",
    siteId: "newsite_example",
    quotaMib: "2048",
    runtime: "node_22_v1",
    port: "3210",
    healthPath: "/healthz",
  });
  const [siteIdEdited, setSiteIdEdited] = useState(false);

  const patch = (p: Partial<WebsiteFormState>) => setForm((prev) => ({ ...prev, ...p }));
  const existingHosts = new Set(data.sites.map((s) => s.domain.toLowerCase()));
  const errs: WebsiteErrors = {
    hostErr: validateHost(form.hostname, existingHosts),
    idErr: SITE_ID_RE.test(form.siteId.trim())
      ? null
      : "Use 2–24 lowercase letters, digits, or underscores starting with a letter.",
    quotaErr:
      form.kind === "wordpress" ? validateIntRange(form.quotaMib, 256, 65536, "Quota (MiB)") : null,
    portErr:
      form.kind !== "wordpress" ? validateIntRange(form.port, 1024, 65535, "Loopback port") : null,
  };
  const valid = !errs.hostErr && !errs.idErr && !errs.quotaErr && !errs.portErr;
  const signCmd = `${buildWebsiteCommand(form)}\n${INSPECT_AND_SIGN_STEPS}`;
  const draftPayload = JSON.stringify(form, null, 2);

  return (
    <Page live>
      <Crumbs
        items={[
          { href: "/", label: "Overview" },
          { href: "/sites", label: "Sites" },
          { label: "Add website" },
        ]}
      />
      <div className="page-head">
        <div>
          <h1>Add website</h1>
          <p className="sub">
            Create an isolated WordPress site, EmDash CMS, Node.js/Bun application, or reverse proxy
            on this server.
          </p>
        </div>
        <Link className="btn quiet sm" to="/sites">
          <Glyph icon={ArrowLeft} />
          All sites
        </Link>
      </div>

      <div className="grid g-main-side">
        <div className="stack">
          <fieldset className="panel">
            <div className="panel-head">
              <legend>
                <h2>Website type</h2>
              </legend>
              <span className="meta">Isolated per-site Linux account &amp; SELinux context</span>
            </div>
            <div className="grid g2 tight">
              {websiteKinds.map(([id, title, detail]) => (
                <label key={id} className={form.kind === id ? "radio-card selected" : "radio-card"}>
                  <input
                    type="radio"
                    name="website-kind"
                    className="sr-only"
                    value={id}
                    checked={form.kind === id}
                    onChange={() => patch({ kind: id })}
                  />
                  <span className="rc-dot" aria-hidden="true" />
                  <strong>{title}</strong>
                  <span className="cap">{detail}</span>
                </label>
              ))}
            </div>
          </fieldset>

          <section className="panel" aria-labelledby="ws-details-t">
            <div className="panel-head">
              <h2 id="ws-details-t">Website details</h2>
            </div>
            <div className="form-grid">
              <div className="form-row">
                <label htmlFor="ws-host">Domain name</label>
                <input
                  id="ws-host"
                  className="input mono"
                  value={form.hostname}
                  aria-invalid={errs.hostErr ? "true" : "false"}
                  aria-describedby={errs.hostErr ? "ws-host-err" : undefined}
                  placeholder="shop.example.com"
                  onChange={(e) => {
                    const next = e.target.value;
                    patch(
                      siteIdEdited
                        ? { hostname: next }
                        : { hostname: next, siteId: slugFromDomain(next) },
                    );
                  }}
                />
                <InlineErr id="ws-host-err" message={errs.hostErr} />
              </div>
              <div className="form-row">
                <label htmlFor="ws-id">Site identifier</label>
                <input
                  id="ws-id"
                  className="input mono"
                  value={form.siteId}
                  aria-invalid={errs.idErr ? "true" : "false"}
                  aria-describedby={errs.idErr ? "ws-id-err" : undefined}
                  onChange={(e) => {
                    setSiteIdEdited(true);
                    patch({ siteId: e.target.value });
                  }}
                />
                <InlineErr id="ws-id-err" message={errs.idErr} />
              </div>
              <WebsiteRuntimeFields form={form} errs={errs} patch={patch} />
            </div>
          </section>

          <SignedApplyDisclosure title="Submit signed plan to server" />
        </div>

        <WebsiteSummaryAside
          form={form}
          valid={valid}
          signCmd={signCmd}
          draftPayload={draftPayload}
        />
      </div>
    </Page>
  );
}

type DomainMode = "zone" | "ssl";

type DomainFormState = {
  mode: DomainMode;
  zone: string;
  primaryNs: string;
  secondaryNs: string;
  ipv4: string;
  ipv6: string;
  includeWww: boolean;
  mailHost: string;
  aliasHost: string;
};

function DomainZoneFields({
  form,
  ipErr,
  patch,
}: {
  form: DomainFormState;
  ipErr: string | null;
  patch: (p: Partial<DomainFormState>) => void;
}) {
  if (form.mode === "ssl") {
    return (
      <div className="form-row">
        <label htmlFor="dom-alias">Alias hostname (optional, e.g. www.example.com)</label>
        <input
          id="dom-alias"
          className="input mono"
          placeholder="www.example.com"
          value={form.aliasHost}
          onChange={(e) => patch({ aliasHost: e.target.value })}
        />
      </div>
    );
  }
  return (
    <>
      <div className="form-row">
        <label htmlFor="dom-ip4">Server IPv4 address (A record)</label>
        <input
          id="dom-ip4"
          className="input mono"
          value={form.ipv4}
          aria-invalid={ipErr ? "true" : "false"}
          aria-describedby={ipErr ? "dom-ip4-err" : undefined}
          onChange={(e) => patch({ ipv4: e.target.value })}
        />
        <InlineErr id="dom-ip4-err" message={ipErr} />
      </div>
      <div className="form-row">
        <label htmlFor="dom-ns1">Primary nameserver</label>
        <input
          id="dom-ns1"
          className="input mono"
          value={form.primaryNs}
          onChange={(e) => patch({ primaryNs: e.target.value })}
        />
      </div>
      <div className="form-row">
        <label htmlFor="dom-ns2">Secondary nameserver</label>
        <input
          id="dom-ns2"
          className="input mono"
          value={form.secondaryNs}
          onChange={(e) => patch({ secondaryNs: e.target.value })}
        />
      </div>
      <div className="form-row">
        <label htmlFor="dom-ip6">Server IPv6 address (optional)</label>
        <input
          id="dom-ip6"
          className="input mono"
          placeholder="2001:db8::10"
          value={form.ipv6}
          onChange={(e) => patch({ ipv6: e.target.value })}
        />
      </div>
      <div className="form-row">
        <label htmlFor="dom-mx">External mail server MX (optional)</label>
        <input
          id="dom-mx"
          className="input mono"
          placeholder="mx.provider.example"
          value={form.mailHost}
          onChange={(e) => patch({ mailHost: e.target.value })}
        />
      </div>
      <div className="form-row" style={{ gridColumn: "1 / -1" }}>
        <label className="row" style={{ gap: 8 }}>
          <input
            type="checkbox"
            checked={form.includeWww}
            onChange={(e) => patch({ includeWww: e.target.checked })}
          />
          <span>Also create www A/AAAA records pointing to the same IP</span>
        </label>
      </div>
    </>
  );
}

export function AddDomainPage() {
  const [form, setForm] = useState<DomainFormState>({
    mode: "zone",
    zone: "example.com",
    primaryNs: "ns1.example.com",
    secondaryNs: "ns2.example.com",
    ipv4: "203.0.113.10",
    ipv6: "",
    includeWww: true,
    mailHost: "",
    aliasHost: "",
  });
  const patch = (p: Partial<DomainFormState>) => setForm((prev) => ({ ...prev, ...p }));
  const cleanZone = form.zone.trim().toLowerCase().replace(/\.$/, "");
  const zoneErr = HOSTNAME_RE.test(cleanZone) ? null : "Enter a valid domain such as example.com.";
  const ipErr =
    form.mode === "zone" && form.ipv4.trim() && !IPV4_RE.test(form.ipv4.trim())
      ? "Enter a valid IPv4 address (for example, 203.0.113.10)."
      : null;

  const zoneText = renderCanonicalZone(form);
  const safeZone = cleanZone || "example.com";
  const cli =
    form.mode === "zone"
      ? buildDnsZoneImportCmd({ zone: safeZone, zoneFile: `./${safeZone}.zone` })
      : buildManualVerbPlanNote({
          verb: "certificate_issue",
          runbook: "Runbook 22",
          summary: `HTTP-01 TLS certificate for ${safeZone}${form.aliasHost.trim() ? ` + alias ${form.aliasHost.trim()}` : ""}`,
        });
  const signCmd = `${cli}\n${INSPECT_AND_SIGN_STEPS}`;

  return (
    <Page live>
      <Crumbs
        items={[
          { href: "/", label: "Overview" },
          { href: "/domains", label: "Domains" },
          { label: "Add domain" },
        ]}
      />
      <div className="page-head">
        <div>
          <h1>Add domain</h1>
          <p className="sub">
            Create an authoritative PowerDNS zone with starter records or request an SSL/TLS
            certificate for a hosted domain.
          </p>
        </div>
        <Link className="btn quiet sm" to="/domains">
          <Glyph icon={ArrowLeft} />
          All domains
        </Link>
      </div>

      <div className="grid g-main-side">
        <div className="stack">
          <fieldset className="panel">
            <div className="panel-head">
              <legend>
                <h2>Domain action</h2>
              </legend>
            </div>
            <div className="grid g2 tight">
              <label className={form.mode === "zone" ? "radio-card selected" : "radio-card"}>
                <input
                  type="radio"
                  name="domain-mode"
                  className="sr-only"
                  checked={form.mode === "zone"}
                  onChange={() => patch({ mode: "zone" })}
                />
                <span className="rc-dot" aria-hidden="true" />
                <strong>Create DNS zone</strong>
                <span className="cap">
                  Import an authoritative PowerDNS zone with A/NS/MX records.
                </span>
              </label>
              <label className={form.mode === "ssl" ? "radio-card selected" : "radio-card"}>
                <input
                  type="radio"
                  name="domain-mode"
                  className="sr-only"
                  checked={form.mode === "ssl"}
                  onChange={() => patch({ mode: "ssl" })}
                />
                <span className="rc-dot" aria-hidden="true" />
                <strong>Issue SSL certificate</strong>
                <span className="cap">
                  Request an ACME HTTPS certificate for a domain or alias pair.
                </span>
              </label>
            </div>
          </fieldset>

          <section className="panel" aria-labelledby="dom-in-t">
            <div className="panel-head">
              <h2 id="dom-in-t">
                {form.mode === "zone" ? "Zone settings" : "Certificate settings"}
              </h2>
            </div>
            <div className="form-grid">
              <div className="form-row">
                <label htmlFor="dom-name">Domain name</label>
                <input
                  id="dom-name"
                  className="input mono"
                  value={form.zone}
                  aria-invalid={zoneErr ? "true" : "false"}
                  aria-describedby={zoneErr ? "dom-name-err" : undefined}
                  onChange={(e) => patch({ zone: e.target.value })}
                />
                <InlineErr id="dom-name-err" message={zoneErr} />
              </div>
              <DomainZoneFields form={form} ipErr={ipErr} patch={patch} />
            </div>
          </section>

          <SignedApplyDisclosure title="Submit signed plan to server" />
        </div>

        <aside className="stack">
          {form.mode === "zone" ? (
            <section className="panel">
              <div className="panel-head">
                <h2>Canonical zone file</h2>
                <button
                  type="button"
                  className="btn quiet sm"
                  onClick={() => downloadTextFile(`${safeZone}.zone`, zoneText)}
                >
                  <Glyph icon={Download} />
                  Download .zone
                </button>
              </div>
              <pre className="code signed-bytes">{zoneText}</pre>
            </section>
          ) : null}

          <section className="panel">
            <div className="panel-head">
              <h2>Sign &amp; apply command</h2>
              <CopySnippetButton text={signCmd} label="Copy domain setup commands" />
            </div>
            <pre className="code signed-bytes">{signCmd}</pre>
          </section>
        </aside>
      </div>
    </Page>
  );
}

type DnsRecordType = "A" | "AAAA" | "CNAME" | "MX" | "TXT" | "CAA" | "SRV" | "NS";
type DnsOpAction = "upsert" | "delete";

type StagedDnsOp = {
  id: string;
  action: DnsOpAction;
  type: DnsRecordType;
  name: string;
  ttl: number;
  priority?: number;
  value: string;
};

type DnsDraftState = {
  action: DnsOpAction;
  type: DnsRecordType;
  name: string;
  ttl: number;
  priority: string;
  value: string;
};

const dnsTypes: DnsRecordType[] = ["A", "AAAA", "CNAME", "MX", "TXT", "CAA", "SRV", "NS"];
const ttlOptions = [300, 600, 3600, 14400, 86400];

const dnsPlaceholders: Record<DnsRecordType, string> = {
  A: "203.0.113.10",
  AAAA: "2001:db8::10",
  CNAME: "target.example.com.",
  MX: "mx.mailprovider.example.",
  TXT: '"v=spf1 include:_spf.provider.example -all"',
  CAA: '0 issue "letsencrypt.org"',
  SRV: "5 443 sip.example.com.",
  NS: "ns1.example.com.",
};

function isMailSensitive(op: Pick<StagedDnsOp, "type" | "name" | "value">): boolean {
  if (op.type === "MX") return true;
  const n = op.name.toLowerCase();
  const v = op.value.toLowerCase();
  return (
    n.includes("_dmarc") ||
    n.includes("_domainkey") ||
    n === "mail" ||
    v.includes("v=spf1") ||
    v.includes("v=dkim1") ||
    v.includes("v=dmarc1")
  );
}

function validateDnsDraft(type: DnsRecordType, value: string): string | null {
  const v = value.trim();
  if (!v) return "Enter a record value.";
  if (type === "A" && !IPV4_RE.test(v)) return "A records require a valid IPv4 address.";
  if (type === "AAAA" && !v.includes(":")) return "AAAA records require a valid IPv6 address.";
  return null;
}

function DnsFormFields({
  draft,
  error,
  patch,
}: {
  draft: DnsDraftState;
  error: string | null;
  patch: (p: Partial<DnsDraftState>) => void;
}) {
  return (
    <div className="form-grid" style={{ marginBottom: 14 }}>
      <div className="form-row">
        <label htmlFor="dns-act">Change</label>
        <select
          id="dns-act"
          className="input"
          value={draft.action}
          onChange={(e) => patch({ action: e.target.value as DnsOpAction })}
        >
          <option value="upsert">Add / Update record</option>
          <option value="delete">Delete record set</option>
        </select>
      </div>
      <div className="form-row">
        <label htmlFor="dns-type">Record type</label>
        <select
          id="dns-type"
          className="input mono"
          value={draft.type}
          onChange={(e) => patch({ type: e.target.value as DnsRecordType })}
        >
          {dnsTypes.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
      </div>
      <div className="form-row">
        <label htmlFor="dns-name">Host / Name</label>
        <input
          id="dns-name"
          className="input mono"
          value={draft.name}
          placeholder="@ or www"
          onChange={(e) => patch({ name: e.target.value })}
        />
      </div>
      <div className="form-row">
        <label htmlFor="dns-ttl">TTL (seconds)</label>
        <select
          id="dns-ttl"
          className="input tnum"
          value={draft.ttl}
          onChange={(e) => patch({ ttl: Number(e.target.value) })}
        >
          {ttlOptions.map((sec) => (
            <option key={sec} value={sec}>
              {sec} s
            </option>
          ))}
        </select>
      </div>
      {draft.type === "MX" || draft.type === "SRV" ? (
        <div className="form-row">
          <label htmlFor="dns-prio">Priority</label>
          <input
            id="dns-prio"
            className="input tnum"
            type="number"
            min={0}
            max={65535}
            value={draft.priority}
            onChange={(e) => patch({ priority: e.target.value })}
          />
        </div>
      ) : null}
      {draft.action === "upsert" ? (
        <div className="form-row" style={{ gridColumn: "1 / -1" }}>
          <label htmlFor="dns-val">Value / Target</label>
          <input
            id="dns-val"
            className="input mono"
            value={draft.value}
            aria-invalid={error ? "true" : "false"}
            aria-describedby={error ? "dns-val-err" : undefined}
            placeholder={dnsPlaceholders[draft.type]}
            onChange={(e) => patch({ value: e.target.value })}
          />
          <InlineErr id="dns-val-err" message={error} />
        </div>
      ) : null}
    </div>
  );
}

function StagedDnsSection({
  hostname,
  ops,
  onEdit,
  onRemove,
  onClear,
}: {
  hostname: string;
  ops: StagedDnsOp[];
  onEdit: (op: StagedDnsOp) => void;
  onRemove: (id: string) => void;
  onClear: () => void;
}) {
  const opsJson = renderDnsOperationsJson(hostname, ops);
  const cli = `${buildDnsChangeCmd({ zone: hostname, operationsFile: `./${hostname}-dns-ops.json` })}\n${INSPECT_AND_SIGN_STEPS}`;

  return (
    <div className="stack">
      <TableScroll label="Staged DNS changes">
        <table className="data">
          <thead>
            <tr>
              <th>Action</th>
              <th>Type</th>
              <th>Name</th>
              <th>TTL</th>
              <th>Value</th>
              <th>Edit</th>
            </tr>
          </thead>
          <tbody>
            {ops.map((op) => (
              <tr key={op.id}>
                <td>
                  <span className={op.action === "delete" ? "pill err" : "pill ok"}>
                    {op.action === "delete" ? "Delete" : "Upsert"}
                  </span>
                </td>
                <td className="mono">{op.type}</td>
                <td className="mono">{op.name}</td>
                <td className="tnum">{op.ttl} s</td>
                <td className="mono">
                  {op.priority !== undefined ? `${op.priority} ` : ""}
                  {op.value}
                </td>
                <td>
                  <div className="row" style={{ gap: 4 }}>
                    <button
                      type="button"
                      className="icon-btn"
                      aria-label={`Edit ${op.type} ${op.name}`}
                      onClick={() => onEdit(op)}
                    >
                      <Glyph icon={Pencil} />
                    </button>
                    <button
                      type="button"
                      className="icon-btn"
                      aria-label={`Remove ${op.type} ${op.name}`}
                      onClick={() => onRemove(op.id)}
                    >
                      <Glyph icon={Trash2} />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableScroll>

      <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
        <button
          type="button"
          className="btn sm"
          onClick={() =>
            downloadTextFile(`${hostname}-dns-ops.json`, opsJson, "application/json;charset=utf-8")
          }
        >
          <Glyph icon={Download} />
          Download operations JSON
        </button>
        <CopySnippetButton text={cli} label="Copy DNS change commands" />
        <button type="button" className="btn quiet sm" onClick={onClear}>
          Clear all
        </button>
      </div>

      <pre className="code signed-bytes">{cli}</pre>
      <SignedApplyDisclosure title="Submit signed DNS plan" />
    </div>
  );
}

export function DnsRecordEditorPanel({ hostname }: { hostname: string }) {
  const [ops, setOps] = useState<StagedDnsOp[]>([]);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [draft, setDraft] = useState<DnsDraftState>({
    action: "upsert",
    type: "A",
    name: "@",
    ttl: 3600,
    priority: "10",
    value: "",
  });
  const [error, setError] = useState<string | null>(null);

  const patch = (p: Partial<DnsDraftState>) => setDraft((prev) => ({ ...prev, ...p }));
  const hasMailChange = ops.some(isMailSensitive);

  function handleSaveRecord() {
    if (draft.action === "upsert") {
      const err = validateDnsDraft(draft.type, draft.value);
      if (err) {
        setError(err);
        return;
      }
    }
    setError(null);
    const nextOp: StagedDnsOp = {
      id: editingId ?? `dns_${Date.now()}_${ops.length}`,
      action: draft.action,
      type: draft.type,
      name: draft.name.trim() || "@",
      ttl: draft.ttl,
      priority:
        draft.type === "MX" || draft.type === "SRV" ? Number(draft.priority) || 10 : undefined,
      value: draft.action === "delete" ? "(delete entire RRset)" : draft.value.trim(),
    };
    setOps((prev) =>
      editingId ? prev.map((item) => (item.id === editingId ? nextOp : item)) : [...prev, nextOp],
    );
    setEditingId(null);
    patch({ value: "" });
  }

  function startEdit(op: StagedDnsOp) {
    setEditingId(op.id);
    setDraft({
      action: op.action,
      type: op.type,
      name: op.name,
      ttl: op.ttl,
      priority: String(op.priority ?? 10),
      value: op.action === "delete" ? "" : op.value,
    });
    setError(null);
  }

  return (
    <section className="panel" aria-labelledby="dns-editor-t">
      <div className="panel-head">
        <div>
          <h2 id="dns-editor-t">Manage DNS records</h2>
          <p className="cap">
            Add, edit, or remove records for <span className="mono">{hostname}</span>, then export
            the operations file to sign and apply.
          </p>
        </div>
        {ops.length > 0 ? <span className="pill ok">{ops.length} staged</span> : null}
      </div>

      <DnsFormFields draft={draft} error={error} patch={patch} />

      <div className="row" style={{ gap: 8, marginBottom: ops.length > 0 ? 16 : 0 }}>
        <button type="button" className="btn primary sm" onClick={handleSaveRecord}>
          <Glyph icon={Plus} />
          {editingId ? "Update staged record" : "Add record to change set"}
        </button>
        {editingId ? (
          <button
            type="button"
            className="btn quiet sm"
            onClick={() => {
              setEditingId(null);
              patch({ value: "" });
              setError(null);
            }}
          >
            Cancel edit
          </button>
        ) : null}
      </div>

      {hasMailChange ? (
        <div className="attention warn" role="alert" style={{ marginBottom: 14 }}>
          <Glyph icon={TriangleAlert} />
          <div className="att-body">
            <strong>Mail-sensitive DNS change staged.</strong> Modifying MX, SPF, DKIM, or DMARC
            records can affect email delivery. Double-check your mail provider values before
            signing.
          </div>
        </div>
      ) : null}

      {ops.length > 0 ? (
        <StagedDnsSection
          hostname={hostname}
          ops={ops}
          onEdit={startEdit}
          onRemove={(id) => setOps((prev) => prev.filter((item) => item.id !== id))}
          onClear={() => setOps([])}
        />
      ) : null}
    </section>
  );
}

export function SslActionPanel({ hostname }: { hostname: string }) {
  const [alias, setAlias] = useState("");
  const cmd = `${buildManualVerbPlanNote({
    verb: "certificate_issue",
    runbook: "Runbook 22",
    summary: `HTTP-01 TLS certificate for ${hostname}${alias.trim() ? ` + alias ${alias.trim()}` : ""}`,
  })}\n${INSPECT_AND_SIGN_STEPS}`;
  return (
    <section className="panel">
      <div className="panel-head">
        <div className="row" style={{ gap: 8 }}>
          <Glyph icon={Server} />
          <h2>Issue or renew SSL</h2>
        </div>
        <CopySnippetButton text={cmd} label="Copy SSL certificate command" />
      </div>
      <div className="form-row" style={{ marginBottom: 10 }}>
        <label htmlFor="ssl-alias">Optional alias hostname</label>
        <input
          id="ssl-alias"
          className="input mono"
          placeholder={`www.${hostname}`}
          value={alias}
          onChange={(e) => setAlias(e.target.value)}
        />
      </div>
      <pre className="code signed-bytes">{cmd}</pre>
    </section>
  );
}
