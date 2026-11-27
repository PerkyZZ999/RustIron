// W628 (P29 Slice 8): CyberPanel-grade interactive hosting workflows —
// Create Website (/sites/new), Add Domain & DNS Zone (/domains/new),
// Interactive DNS Record Manager (Create/Edit/Delete RRsets on /domains/:hostname/dns),
// and SSL/TLS Certificate Manager panel.
import { Link } from "@tanstack/react-router";
import {
  AlertCircle,
  ArrowLeft,
  ChevronDown,
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
import { type ReactNode, useRef, useState } from "react";

import {
  type AppDatabaseEngine,
  type AppIngressEngine,
  type AppRuntimeProfile,
  type AppTopologyKind,
  buildAppPackCmd,
  buildAppProvisionCmd,
  buildDnsChangeCmd,
  buildDnsZoneImportCmd,
  buildManualVerbPlanNote,
  buildSiteProvisionCmd,
  INSPECT_AND_SIGN_STEPS,
  renderCanonicalZone,
  renderDnsOperationsJson,
} from "./cli-commands";
import { useData } from "./data";
import { CopyButton, Crumbs, Glyph, Page, TableScroll } from "./ui";
import { SeparateCustodyApplyPanel } from "./write-panel";

type WebsiteKind = "wordpress" | "emdash" | "app" | "proxy";

const websiteKinds: [WebsiteKind, string, string][] = [
  ["wordpress", "WordPress", "Isolated PHP 8.4 pool, MariaDB database, and LiteSpeed Cache."],
  ["emdash", "EmDash CMS", "Node.js 22 CMS with native SQLite FTS5 behind OpenLiteSpeed."],
  [
    "app",
    "Modern full-stack app",
    "Vite/React/Next/Astro/TanStack front-end + Bun/Node back-end behind Caddy HTTP/3 & selectable DB.",
  ],
  ["proxy", "Reverse proxy", "HTTPS reverse proxy with WebSocket support to a local backend port."],
];

const RESERVED_INFRA_PORTS = new Set([2019, 3306, 4319, 5432, 7080]);
// W664: common framework defaults that SELinux gives their own port type.
// shortcut: a partial list for early feedback; `rustiron plan create` checks the full AlmaLinux 10 table.
const SELINUX_NAMED_APP_PORTS = new Set([
  3000, 3001, 3401, 4101, 4200, 4321, 5000, 8000, 8080, 9000,
]);

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
  runtime: AppRuntimeProfile;
  ingress: AppIngressEngine;
  topology: AppTopologyKind;
  database: AppDatabaseEngine;
  blueGreen: boolean;
  port: string;
  standbyPort: string;
  spaFallback: boolean;
  frontendDir: string;
  frontendRuntime: "node_22_v1" | "bun_1_v1";
  frontendEntrypoint: string;
  frontendPort: string;
  frontendStandbyPort: string;
  entrypoint: string;
  routePrefix: string;
  websocketPrefix: string;
  ssePrefix: string;
  stripApiPrefix: boolean;
  healthPath: string;
};

type AppPresetDef = {
  id: string;
  label: string;
  patch: Partial<WebsiteFormState>;
};

const APP_PRESETS: readonly AppPresetDef[] = [
  {
    id: "vite-elysia",
    label: "Vite + Elysia (Bun)",
    patch: {
      topology: "fullstack_split",
      ingress: "caddy",
      runtime: "bun_1_v1",
      database: "postgresql_18",
      blueGreen: true,
      port: "3301",
      standbyPort: "3302",
      frontendDir: "web",
      spaFallback: true,
      entrypoint: "api/server.js",
      routePrefix: "/api/",
      websocketPrefix: "/ws/",
      ssePrefix: "",
      stripApiPrefix: true,
      healthPath: "/api/health",
    },
  },
  {
    id: "react-hono",
    label: "React + Hono (Bun)",
    patch: {
      topology: "fullstack_split",
      ingress: "caddy",
      runtime: "bun_1_v1",
      database: "postgresql_18",
      blueGreen: true,
      port: "3301",
      standbyPort: "3302",
      frontendDir: "web",
      spaFallback: true,
      entrypoint: "api/index.js",
      routePrefix: "/api/",
      websocketPrefix: "",
      ssePrefix: "",
      stripApiPrefix: false,
      healthPath: "/api/health",
    },
  },
  {
    id: "nextjs-standalone",
    label: "Next.js Standalone",
    patch: {
      topology: "backend_api",
      ingress: "caddy",
      runtime: "node_22_v1",
      database: "postgresql_18",
      blueGreen: true,
      port: "3301",
      standbyPort: "3302",
      spaFallback: false,
      entrypoint: "server.js",
      routePrefix: "/",
      websocketPrefix: "",
      ssePrefix: "",
      stripApiPrefix: false,
      healthPath: "/api/health",
    },
  },
  {
    id: "astro-ssr",
    label: "Astro SSR",
    patch: {
      topology: "backend_api",
      ingress: "caddy",
      runtime: "node_22_v1",
      database: "sqlite",
      blueGreen: true,
      port: "3301",
      standbyPort: "3302",
      spaFallback: false,
      entrypoint: "dist/server/entry.mjs",
      routePrefix: "/",
      websocketPrefix: "",
      ssePrefix: "",
      stripApiPrefix: false,
      healthPath: "/healthz",
    },
  },
  {
    id: "tanstack-start",
    label: "TanStack Dual SSR",
    patch: {
      topology: "fullstack_dual_ssr",
      ingress: "caddy",
      runtime: "bun_1_v1",
      database: "postgresql_18",
      blueGreen: true,
      frontendRuntime: "bun_1_v1",
      frontendEntrypoint: "web/server.js",
      frontendPort: "3301",
      frontendStandbyPort: "3302",
      port: "3303",
      standbyPort: "3304",
      spaFallback: false,
      entrypoint: "api/server.js",
      routePrefix: "/api/",
      websocketPrefix: "",
      ssePrefix: "",
      stripApiPrefix: false,
      healthPath: "/api/health",
    },
  },
  {
    id: "static-spa",
    label: "Static SPA",
    patch: {
      topology: "static_spa",
      ingress: "caddy",
      runtime: "static_v1",
      database: "none",
      blueGreen: false,
      port: "0",
      standbyPort: "",
      frontendDir: "dist",
      spaFallback: true,
      entrypoint: "",
      routePrefix: "",
      websocketPrefix: "",
      ssePrefix: "",
      stripApiPrefix: false,
      healthPath: "/",
    },
  },
];

function splitPrefixes(raw: string): string[] {
  return raw
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean);
}

function effectiveAppRuntime(f: WebsiteFormState): AppRuntimeProfile {
  if (f.topology === "static_spa") return "static_v1";
  return f.runtime === "static_v1" ? "bun_1_v1" : f.runtime;
}

function buildDualSsrOpts(f: WebsiteFormState, useBg: boolean) {
  if (f.topology !== "fullstack_dual_ssr") return {};
  return {
    frontendRuntime: f.frontendRuntime,
    frontendEntrypoint: f.frontendEntrypoint,
    frontendPort: f.frontendPort,
    frontendStandbyPort: useBg ? f.frontendStandbyPort : undefined,
  };
}

function buildStaticAppProvisionCmd(f: WebsiteFormState, s: string, h: string): string {
  return buildAppProvisionCmd({
    siteId: s,
    hostname: h,
    runtime: "static_v1",
    port: 0,
    ingress: "caddy",
    topology: "static_spa",
    database: "none",
    spaFallback: f.spaFallback,
    frontendDir: f.frontendDir || "dist",
    healthPath: "/",
  });
}

function buildCaddyPrefixOpts(f: WebsiteFormState, routes: string[]) {
  if (f.ingress !== "caddy") return {};
  const isSplit = f.topology === "fullstack_split";
  return {
    spaFallback: isSplit && f.spaFallback,
    frontendDir: isSplit ? f.frontendDir || "web" : undefined,
    ssePrefixes: splitPrefixes(f.ssePrefix),
    stripApiPrefixes: f.stripApiPrefix ? routes : [],
  };
}

function buildModernAppProvisionCmd(f: WebsiteFormState, s: string, h: string): string {
  if (f.topology === "static_spa") return buildStaticAppProvisionCmd(f, s, h);
  const useBg = f.ingress === "caddy" && f.blueGreen;
  const routes = splitPrefixes(f.routePrefix);
  return buildAppProvisionCmd({
    siteId: s,
    hostname: h,
    runtime: effectiveAppRuntime(f),
    port: f.port || "3301",
    ingress: f.ingress,
    topology: f.topology,
    database: f.database,
    blueGreen: useBg,
    standbyPort: useBg ? f.standbyPort : undefined,
    entrypoint: f.entrypoint || "api/server.js",
    routePrefixes: routes,
    websocketPrefixes: splitPrefixes(f.websocketPrefix),
    healthPath: f.healthPath || "/api/health",
    ...buildDualSsrOpts(f, useBg),
    ...buildCaddyPrefixOpts(f, routes),
  });
}

const websiteCmdMap: Record<WebsiteKind, (f: WebsiteFormState, s: string, h: string) => string> = {
  wordpress: (f, s, h) =>
    buildSiteProvisionCmd({ siteId: s, hostname: h, quotaMib: f.quotaMib || "2048" }),
  emdash: (f, s, h) =>
    buildAppProvisionCmd({
      siteId: s,
      hostname: h,
      runtime: "node_22_v1",
      port: f.port || "3402",
      healthPath: f.healthPath || "/_emdash/api/health",
      entrypoint: "dist/server/entry.mjs",
    }),
  app: buildModernAppProvisionCmd,
  proxy: (f, s, h) =>
    buildManualVerbPlanNote({
      verb: "proxy_site_provision",
      runbook: "Runbook 34",
      summary: `Loopback reverse proxy site ${s} (${h}) -> 127.0.0.1:${Number.parseInt(f.port, 10) || 8080}`,
    }),
};

/**
 * W749 (QA-18): a command is shown only for valid input. Before that the
 * builders fill in defaults or drop characters, so the text would not match
 * the form.
 */
function SignCommandPanel({
  title,
  copyLabel,
  valid,
  text,
  extra,
}: {
  title: string;
  copyLabel: string;
  valid: boolean;
  text: string;
  extra?: ReactNode;
}) {
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>{title}</h2>
        {valid ? (
          <div className="row" style={{ gap: 6 }}>
            <CopyButton text={text} label={copyLabel} />
            {extra}
          </div>
        ) : null}
      </div>
      {valid ? (
        <pre className="code signed-bytes">{text}</pre>
      ) : (
        <p className="cap">Fix the highlighted fields to see the command.</p>
      )}
    </section>
  );
}

function buildWebsiteCommand(form: WebsiteFormState): string {
  return websiteCmdMap[form.kind](
    form,
    form.siteId.trim() || "sitenew",
    form.hostname.trim() || "example.com",
  );
}

function buildAppPackSnippet(form: WebsiteFormState): string | null {
  if (form.kind !== "app") return null;
  const s = form.siteId.trim() || "sitenew";
  const isStatic = form.topology === "static_spa";
  const runtime: AppRuntimeProfile = isStatic
    ? "static_v1"
    : form.runtime === "static_v1"
      ? "bun_1_v1"
      : form.runtime;
  return buildAppPackCmd({
    siteId: s,
    releaseId: "rel-20261126-01",
    topology: form.topology,
    runtime,
    database: isStatic ? "none" : form.database,
    frontendDir: form.frontendDir,
    entrypoint: form.entrypoint,
    frontendRuntime: form.frontendRuntime,
    frontendEntrypoint: form.frontendEntrypoint,
    blueGreen: form.ingress === "caddy" && form.blueGreen,
  });
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

function validateAppPort(raw: string, label: string): string | null {
  const rangeErr = validateIntRange(raw, 1024, 65535, label);
  if (rangeErr) return rangeErr;
  const n = Number(raw);
  if (RESERVED_INFRA_PORTS.has(n)) {
    return `${label} ${n} is reserved for host infrastructure (2019/3306/4319/5432/7080).`;
  }
  if (SELINUX_NAMED_APP_PORTS.has(n) || (n >= 32768 && n <= 60999)) {
    return `${label} ${n} has its own SELinux port type, so a confined app cannot bind it. Choose another port (for example 3402 or 5173).`;
  }
  return null;
}

function collectAppPorts(form: WebsiteFormState): [string, string][] {
  const useBg = form.ingress === "caddy" && form.blueGreen;
  const ports: [string, string][] = [["Backend port", form.port]];
  if (useBg) ports.push(["Standby port", form.standbyPort]);
  if (form.topology === "fullstack_dual_ssr") {
    ports.push(["Frontend SSR port", form.frontendPort]);
    if (useBg) ports.push(["Frontend standby port", form.frontendStandbyPort]);
  }
  return ports;
}

function validateUniquePorts(ports: [string, string][]): string | null {
  const seen = new Set<number>();
  for (const [label, raw] of ports) {
    const err = validateAppPort(raw, label);
    if (err) return err;
    const n = Number(raw);
    if (seen.has(n)) {
      return `Port ${n} is used twice; every active and standby slot needs a unique port.`;
    }
    seen.add(n);
  }
  return null;
}

function validateAppPorts(form: WebsiteFormState): string | null {
  if (form.kind === "wordpress") return null;
  if (form.kind !== "app") return validateAppPort(form.port, "Loopback port");
  if (form.topology === "static_spa") return null;
  return validateUniquePorts(collectAppPorts(form));
}

type WebsiteErrors = {
  hostErr: string | null;
  idErr: string | null;
  quotaErr: string | null;
  portErr: string | null;
};

function AppPresetStrip({ patch }: { patch: (p: Partial<WebsiteFormState>) => void }) {
  return (
    <div className="form-row" style={{ gridColumn: "1 / -1" }}>
      <span className="cap">Quick-fill preset (matches packaging/rustiron-app-pack.py)</span>
      <div className="row" style={{ gap: 6, flexWrap: "wrap", marginTop: 4 }}>
        {APP_PRESETS.map((preset) => (
          <button
            key={preset.id}
            type="button"
            className="btn quiet sm"
            onClick={() => patch(preset.patch)}
          >
            {preset.label}
          </button>
        ))}
      </div>
    </div>
  );
}

function AppDualSsrFields({
  form,
  useBg,
  patch,
}: {
  form: WebsiteFormState;
  useBg: boolean;
  patch: (p: Partial<WebsiteFormState>) => void;
}) {
  return (
    <>
      <div className="form-row">
        <label htmlFor="ws-frt">Frontend SSR runtime</label>
        <select
          id="ws-frt"
          className="input"
          value={form.frontendRuntime}
          onChange={(e) => patch({ frontendRuntime: e.target.value as "node_22_v1" | "bun_1_v1" })}
        >
          <option value="bun_1_v1">Bun 1.4</option>
          <option value="node_22_v1">Node.js 22 LTS</option>
        </select>
      </div>
      <div className="form-row">
        <label htmlFor="ws-fentry">Frontend SSR entrypoint</label>
        <input
          id="ws-fentry"
          className="input mono"
          value={form.frontendEntrypoint}
          onChange={(e) => patch({ frontendEntrypoint: e.target.value })}
        />
      </div>
      <div className="form-row">
        <label htmlFor="ws-fport">Frontend SSR port (Slot A)</label>
        <input
          id="ws-fport"
          className="input tnum"
          type="number"
          min={1024}
          max={65535}
          value={form.frontendPort}
          onChange={(e) => patch({ frontendPort: e.target.value })}
        />
      </div>
      {useBg ? (
        <div className="form-row">
          <label htmlFor="ws-fstandby">Frontend standby port (Slot B)</label>
          <input
            id="ws-fstandby"
            className="input tnum"
            type="number"
            min={1024}
            max={65535}
            value={form.frontendStandbyPort}
            onChange={(e) => patch({ frontendStandbyPort: e.target.value })}
          />
        </div>
      ) : null}
    </>
  );
}

function AppBackendFields({
  form,
  errs,
  patch,
}: {
  form: WebsiteFormState;
  errs: WebsiteErrors;
  patch: (p: Partial<WebsiteFormState>) => void;
}) {
  const isCaddy = form.ingress === "caddy";
  const runtimeVal = form.runtime === "static_v1" ? "bun_1_v1" : form.runtime;
  return (
    <>
      <div className="form-row">
        <label htmlFor="ws-runtime">Backend runtime</label>
        <select
          id="ws-runtime"
          className="input"
          value={runtimeVal}
          onChange={(e) => patch({ runtime: e.target.value as "node_22_v1" | "bun_1_v1" })}
        >
          <option value="bun_1_v1">Bun 1.4 (bun_1_v1)</option>
          <option value="node_22_v1">Node.js 22 LTS (node_22_v1)</option>
        </select>
      </div>
      <div className="form-row">
        <label htmlFor="ws-database">Database engine</label>
        <select
          id="ws-database"
          className="input"
          value={form.database}
          onChange={(e) => patch({ database: e.target.value as AppDatabaseEngine })}
        >
          <option value="postgresql_18">PostgreSQL 18 (18.7+, SCRAM-SHA-256)</option>
          <option value="mariadb">MariaDB 10.11 (local 127.0.0.1:3306)</option>
          <option value="sqlite">SQLite (WAL mode in site data/)</option>
          <option value="none">None (stateless / external API)</option>
        </select>
      </div>
      <div className="form-row">
        <label htmlFor="ws-entry">Backend entrypoint</label>
        <input
          id="ws-entry"
          className="input mono"
          value={form.entrypoint}
          onChange={(e) => patch({ entrypoint: e.target.value })}
        />
      </div>
      <div className="form-row">
        <label htmlFor="ws-port">Backend loopback port (Slot A)</label>
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
      {isCaddy && form.blueGreen ? (
        <div className="form-row">
          <label htmlFor="ws-standby">Backend standby port (Slot B)</label>
          <input
            id="ws-standby"
            className="input tnum"
            type="number"
            min={1024}
            max={65535}
            value={form.standbyPort}
            onChange={(e) => patch({ standbyPort: e.target.value })}
          />
        </div>
      ) : null}
      <div className="form-row">
        <label htmlFor="ws-routes">API route prefix(es)</label>
        <input
          id="ws-routes"
          className="input mono"
          value={form.routePrefix}
          placeholder="/api/"
          onChange={(e) => patch({ routePrefix: e.target.value })}
        />
      </div>
      <div className="form-row">
        <label htmlFor="ws-ws">WebSocket prefix (optional)</label>
        <input
          id="ws-ws"
          className="input mono"
          value={form.websocketPrefix}
          placeholder="/ws/"
          onChange={(e) => patch({ websocketPrefix: e.target.value })}
        />
      </div>
      {isCaddy ? (
        <div className="form-row">
          <label htmlFor="ws-sse">SSE prefix (optional, unbuffered)</label>
          <input
            id="ws-sse"
            className="input mono"
            value={form.ssePrefix}
            placeholder="/events/"
            onChange={(e) => patch({ ssePrefix: e.target.value })}
          />
        </div>
      ) : null}
      <div className="form-row">
        <label htmlFor="ws-health">Health check path</label>
        <input
          id="ws-health"
          className="input mono"
          value={form.healthPath}
          onChange={(e) => patch({ healthPath: e.target.value })}
        />
      </div>
    </>
  );
}

function AppOptionCheckboxes({
  form,
  patch,
}: {
  form: WebsiteFormState;
  patch: (p: Partial<WebsiteFormState>) => void;
}) {
  if (form.ingress !== "caddy") return null;
  const isStatic = form.topology === "static_spa";
  const isSplit = form.topology === "fullstack_split";
  return (
    <div className="form-row" style={{ gridColumn: "1 / -1" }}>
      <div className="row" style={{ gap: 16, flexWrap: "wrap" }}>
        {!isStatic ? (
          <label className="row" style={{ gap: 6, cursor: "pointer" }}>
            <input
              type="checkbox"
              checked={form.blueGreen}
              onChange={(e) => patch({ blueGreen: e.target.checked })}
            />
            <span>Zero-downtime blue/green cutover</span>
          </label>
        ) : null}
        {isStatic || isSplit ? (
          <label className="row" style={{ gap: 6, cursor: "pointer" }}>
            <input
              type="checkbox"
              checked={form.spaFallback}
              onChange={(e) => patch({ spaFallback: e.target.checked })}
            />
            <span>SPA index.html fallback</span>
          </label>
        ) : null}
        {isSplit ? (
          <label className="row" style={{ gap: 6, cursor: "pointer" }}>
            <input
              type="checkbox"
              checked={form.stripApiPrefix}
              onChange={(e) => patch({ stripApiPrefix: e.target.checked })}
            />
            <span>Strip API prefix before upstream</span>
          </label>
        ) : null}
      </div>
    </div>
  );
}

function topologyPatch(form: WebsiteFormState, next: AppTopologyKind): Partial<WebsiteFormState> {
  if (next === "static_spa") {
    return {
      topology: next,
      ingress: "caddy",
      runtime: "static_v1",
      database: "none",
      blueGreen: false,
      spaFallback: true,
      frontendDir: form.frontendDir || "dist",
      healthPath: "/",
    };
  }
  const forceCaddy = next !== "backend_api";
  return {
    topology: next,
    runtime: form.runtime === "static_v1" ? "bun_1_v1" : form.runtime,
    ingress: forceCaddy ? "caddy" : form.ingress,
    routePrefix: next === "backend_api" ? "/" : "/api/",
    healthPath: next === "backend_api" ? "/healthz" : "/api/health",
  };
}

function AppFullstackFields({
  form,
  errs,
  patch,
}: {
  form: WebsiteFormState;
  errs: WebsiteErrors;
  patch: (p: Partial<WebsiteFormState>) => void;
}) {
  const isStatic = form.topology === "static_spa";
  const hasFrontendDir = isStatic || form.topology === "fullstack_split";
  return (
    <>
      <AppPresetStrip patch={patch} />
      <div className="form-row">
        <label htmlFor="ws-topology">App topology</label>
        <select
          id="ws-topology"
          className="input"
          value={form.topology}
          onChange={(e) => patch(topologyPatch(form, e.target.value as AppTopologyKind))}
        >
          <option value="fullstack_split">Full-stack split (Static SPA + API backend)</option>
          <option value="backend_api">Backend / Full-stack SSR single process</option>
          <option value="fullstack_dual_ssr">Full-stack dual SSR (SSR web + API backend)</option>
          <option value="static_spa">Static SPA (zero daemon, Caddy file server)</option>
        </select>
      </div>
      <div className="form-row">
        <label htmlFor="ws-ingress">Edge ingress</label>
        <select
          id="ws-ingress"
          className="input"
          value={form.ingress}
          disabled={form.topology !== "backend_api"}
          onChange={(e) => patch({ ingress: e.target.value as AppIngressEngine })}
        >
          <option value="caddy">Caddy (HTTP/3, zero-downtime, SPA fallback)</option>
          <option value="ols">OpenLiteSpeed (legacy v1 proxy)</option>
        </select>
      </div>
      {hasFrontendDir ? (
        <div className="form-row">
          <label htmlFor="ws-fdir">Static frontend directory (in bundle)</label>
          <input
            id="ws-fdir"
            className="input mono"
            value={form.frontendDir}
            placeholder="web"
            onChange={(e) => patch({ frontendDir: e.target.value })}
          />
        </div>
      ) : null}
      {form.topology === "fullstack_dual_ssr" ? (
        <AppDualSsrFields
          form={form}
          useBg={form.ingress === "caddy" && form.blueGreen}
          patch={patch}
        />
      ) : null}
      {!isStatic ? <AppBackendFields form={form} errs={errs} patch={patch} /> : null}
      <AppOptionCheckboxes form={form} patch={patch} />
    </>
  );
}

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
  if (form.kind === "app") {
    return <AppFullstackFields form={form} errs={errs} patch={patch} />;
  }
  return (
    <>
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

function runtimeSummaryText(form: WebsiteFormState): string {
  if (form.kind === "wordpress") return `MariaDB + LSPHP 8.4 · ${form.quotaMib} MiB quota`;
  if (form.kind !== "app") return `Loopback 127.0.0.1:${form.port} behind OpenLiteSpeed`;
  const edge = form.ingress === "caddy" ? "Caddy HTTP/3" : "OpenLiteSpeed";
  if (form.topology === "static_spa") return `Static SPA (${form.frontendDir || "dist"}) · ${edge}`;
  const dbMap: Record<AppDatabaseEngine, string> = {
    none: "No DB",
    sqlite: "SQLite WAL",
    mariadb: "MariaDB",
    postgresql_18: "PostgreSQL 18",
  };
  const bg = form.ingress === "caddy" && form.blueGreen ? ` · blue/green :${form.standbyPort}` : "";
  return `${form.topology} · ${edge} · ${dbMap[form.database]}${bg}`;
}

function summaryIngressNote(form: WebsiteFormState): string {
  if (form.kind === "app" && form.ingress === "caddy") {
    return "Confined Caddy reloads atomically without touching OpenLiteSpeed or WordPress pools.";
  }
  return "New sites stay unserved until you activate ingress configuration and issue an SSL certificate.";
}

function WebsiteSummaryAside({
  form,
  valid,
  signCmd,
  packCmd,
  draftPayload,
}: {
  form: WebsiteFormState;
  valid: boolean;
  signCmd: string;
  packCmd: string | null;
  draftPayload: string;
}) {
  const kindTitle = websiteKinds.find(([id]) => id === form.kind)?.[1] ?? form.kind;
  const hostDisplay = form.hostname.trim() || "—";
  const accountId = form.siteId.trim() || "site";

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
              <span className="t mono">{hostDisplay}</span>
              <span className="s">Account: rs_{accountId}</span>
            </span>
          </li>
          <li>
            <Glyph icon={Layers} className="list-muted" />
            <span className="grow">
              <span className="t">{kindTitle}</span>
              <span className="s">{runtimeSummaryText(form)}</span>
            </span>
          </li>
        </ul>
        <p className="cap" style={{ marginTop: 10 }}>
          {summaryIngressNote(form)}
        </p>
      </section>

      <SignCommandPanel
        title="Create & sign command"
        copyLabel="Copy create website commands"
        valid={valid}
        text={signCmd}
        extra={
          <button
            type="button"
            className="btn quiet sm"
            onClick={() =>
              downloadTextFile(
                `${accountId}-draft.json`,
                draftPayload,
                "application/json;charset=utf-8",
              )
            }
          >
            <Glyph icon={Download} />
            JSON
          </button>
        }
      />

      {packCmd && valid ? (
        <section className="panel">
          <div className="panel-head">
            <h2>Off-host release pack command</h2>
            <CopyButton text={packCmd} label="Copy app pack command" />
          </div>
          <p className="cap" style={{ marginBottom: 8 }}>
            Build locally or in CI, then pack a deterministic tarball with SHA-256 manifest before
            running <span className="mono">app-deploy</span>.
          </p>
          <pre className="code signed-bytes">{packCmd}</pre>
        </section>
      ) : null}
    </aside>
  );
}

export function CreateWebsitePage() {
  const data = useData();
  const [form, setForm] = useState<WebsiteFormState>({
    kind: "wordpress",
    hostname: "newsite.example.com",
    siteId: "newsite",
    quotaMib: "2048",
    runtime: "bun_1_v1",
    ingress: "caddy",
    topology: "fullstack_split",
    database: "postgresql_18",
    blueGreen: true,
    port: "3301",
    standbyPort: "3302",
    spaFallback: true,
    frontendDir: "web",
    frontendRuntime: "bun_1_v1",
    frontendEntrypoint: "web/server.js",
    frontendPort: "3301",
    frontendStandbyPort: "3302",
    entrypoint: "api/server.js",
    routePrefix: "/api/",
    websocketPrefix: "/ws/",
    ssePrefix: "",
    stripApiPrefix: true,
    healthPath: "/api/health",
  });
  // Read only in handlers: a ref avoids a re-render when it flips.
  const siteIdEdited = useRef(false);

  const patch = (p: Partial<WebsiteFormState>) => setForm((prev) => ({ ...prev, ...p }));
  const existingHosts = new Set(data.sites.map((s) => s.domain.toLowerCase()));
  const errs: WebsiteErrors = {
    hostErr: validateHost(form.hostname, existingHosts),
    idErr: SITE_ID_RE.test(form.siteId.trim())
      ? null
      : "Use 3–16 lowercase letters or digits starting with a letter.",
    quotaErr:
      form.kind === "wordpress" ? validateIntRange(form.quotaMib, 256, 65536, "Quota (MiB)") : null,
    portErr: validateAppPorts(form),
  };
  const valid = !errs.hostErr && !errs.idErr && !errs.quotaErr && !errs.portErr;
  const signCmd = `${buildWebsiteCommand(form)}\n${INSPECT_AND_SIGN_STEPS}`;
  const packCmd = buildAppPackSnippet(form);
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
                      siteIdEdited.current
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
                    siteIdEdited.current = true;
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
          packCmd={packCmd}
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
  const valid = !zoneErr && !ipErr;

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

          <SignCommandPanel
            title="Sign & apply command"
            copyLabel="Copy domain setup commands"
            valid={valid}
            text={signCmd}
          />
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
        <CopyButton text={cli} label="Copy DNS change commands" />
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
        <CopyButton text={cmd} label="Copy SSL certificate command" />
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
