// W612 (P29 Slice 4 / CP04): D-090 hardened loopback HTTP read-only backend
// adapter for the Rustiron Console. Enforces loopback Host allowlist against
// DNS rebinding, zero CORS, GET/HEAD-only methods, strict CSP, and bounded
// error responses without data leaks.
import { existsSync, lstatSync, readFileSync } from "node:fs";
import { extname, join, resolve, sep } from "node:path";
import {
  type CoordinatorErrorCode,
  type CoordinatorResult,
  coordinatorDoctor,
  coordinatorEvidenceExport,
  coordinatorOperationStatus,
  coordinatorSiteInspect,
  coordinatorSiteList,
} from "./coordinator-client";
import { observationResponse } from "./observation-route";

export const D090_CSP =
  "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";

export const D090_SECURITY_HEADERS: Record<string, string> = {
  "content-security-policy": D090_CSP,
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "cache-control": "no-store",
};

const HSTS_HEADER = "max-age=31536000; includeSubDomains";

export type BackendStatus = {
  schema: "rustiron-console-backend/1";
  mode: "read_only" | "write_opt_in";
  d090_hardened: true;
  write_workflows_enabled: boolean;
  observation_configured: boolean;
  coordinator_configured: boolean;
  coordinator_reachable: boolean;
  doctor: unknown;
};

export function allowedLoopbackHosts(port: number): Set<string> {
  return new Set([`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`]);
}

/**
 * Builds the D-090 Host allowlist: always includes the loopback listener hosts, plus
 * the exact hostname[:port] from an explicitly configured `RUSTIRON_CONSOLE_ORIGIN`
 * when serving behind a TLS reverse proxy (Runbook 38).
 */
export function allowedConsoleHosts(port: number, origin?: string): Set<string> {
  const hosts = allowedLoopbackHosts(port);
  if (!origin?.trim()) return hosts;
  try {
    const parsed = new URL(origin.trim());
    if (parsed.protocol === "https:" || parsed.protocol === "http:") {
      hosts.add(parsed.host.toLowerCase());
    }
  } catch {
    // Ignore malformed origin; fail closed to loopback-only hosts.
  }
  return hosts;
}

export function jsonReply(
  status: number,
  body: unknown,
  extraHeaders?: Record<string, string>,
): Response {
  return Response.json(body, {
    status,
    headers: { ...D090_SECURITY_HEADERS, ...extraHeaders },
  });
}

export function withD090Headers(
  response: Response,
  options?: { hsts?: boolean; preserveCacheControl?: boolean },
): Response {
  const headers = new Headers(response.headers);
  const existingCache = options?.preserveCacheControl ? headers.get("cache-control") : null;
  for (const [key, value] of Object.entries(D090_SECURITY_HEADERS)) {
    headers.set(key, value);
  }
  if (existingCache) {
    headers.set("cache-control", existingCache);
  }
  if (options?.hsts) {
    headers.set("strict-transport-security", HSTS_HEADER);
  }
  // D-090 explicitly forbids CORS headers on the loopback console listener.
  headers.delete("access-control-allow-origin");
  headers.delete("access-control-allow-credentials");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function originMatchesHost(origin: string, allowedHosts: ReadonlySet<string>): boolean {
  try {
    return allowedHosts.has(new URL(origin).host.toLowerCase());
  } catch {
    return false;
  }
}

/** W635 (M-02): shared loopback Host + same-origin Origin + Sec-Fetch-Site write guard. */
export function checkSameOriginMutation(
  req: Request,
  allowedHosts: ReadonlySet<string>,
): Response | null {
  const host = req.headers.get("host")?.toLowerCase() ?? "";
  if (!allowedHosts.has(host)) return jsonReply(421, { error: "MISDIRECTED_HOST" });
  const origin = req.headers.get("origin");
  if (origin && !originMatchesHost(origin, allowedHosts)) {
    return jsonReply(403, { error: "CROSS_ORIGIN_DENIED" });
  }
  const fetchSite = req.headers.get("sec-fetch-site");
  if (fetchSite && fetchSite !== "same-origin" && fetchSite !== "none") {
    return jsonReply(403, { error: "CROSS_SITE_DENIED" });
  }
  const mutating = req.method !== "GET" && req.method !== "HEAD";
  if (mutating && !origin && fetchSite !== "same-origin") {
    return jsonReply(403, { error: "ORIGIN_REQUIRED" });
  }
  return null;
}

/** Enforces D-090 Host allowlist, zero-CORS same-origin check, and GET/HEAD-only methods. */
export function checkD090Request(
  request: Request,
  allowedHosts: ReadonlySet<string>,
): Response | null {
  const host = request.headers.get("host")?.trim().toLowerCase() ?? "";
  if (!host || !allowedHosts.has(host)) {
    return jsonReply(421, { error: "HOST_NOT_ALLOWED" });
  }
  const origin = request.headers.get("origin");
  if (origin !== null) {
    const normalized = origin.trim().toLowerCase();
    if (normalized !== `http://${host}` && normalized !== `https://${host}`) {
      return jsonReply(403, { error: "CROSS_ORIGIN_FORBIDDEN" });
    }
  }
  if (request.method !== "GET" && request.method !== "HEAD") {
    return jsonReply(405, { error: "METHOD_NOT_ALLOWED" }, { allow: "GET, HEAD" });
  }
  return null;
}

function mapCoordinatorErrorStatus(code: CoordinatorErrorCode): number {
  switch (code) {
    case "INVALID_ID":
    case "INVALID_REQUEST":
      return 400;
    case "UNAUTHORIZED_PEER":
      return 403;
    case "RESPONSE_TOO_LARGE":
    case "INVALID_RESPONSE":
      return 502;
    case "COORDINATOR_NOT_CONFIGURED":
    case "DEPENDENCY_UNAVAILABLE":
      return 503;
  }
}

function mapCoordinatorResult(result: CoordinatorResult): Response {
  if (!result.ok) {
    return jsonReply(mapCoordinatorErrorStatus(result.code), { error: result.code });
  }
  if (result.response.status === "error") {
    const code = result.response.error?.code ?? "COORDINATOR_ERROR";
    const status = code === "NOT_FOUND" || code === "CURSOR_EXPIRED" ? 404 : 400;
    return jsonReply(status, { error: code, response: result.response });
  }
  return jsonReply(200, result.response);
}

export type BackendConfig = {
  observationPath?: string;
  coordinatorSocket?: string;
  writeWorkflowsEnabled?: boolean;
  allowFixture?: boolean;
  getAllowedHosts: () => ReadonlySet<string>;
};

function guard(
  config: BackendConfig,
  handler: (request: Request) => Promise<Response>,
): (request: Request) => Promise<Response> {
  return async (request) => {
    const refused = checkD090Request(request, config.getAllowedHosts());
    if (refused) return refused;
    return withD090Headers(await handler(request));
  };
}

type CoordinatorSiteEntry = {
  site_id?: string;
  name?: string;
  hostname?: string;
  ownership?: string;
  state?: string;
  operation_id?: string;
  account?: string;
  site_kind?: string;
};

const validSiteStates = new Set([
  "running",
  "quarantined",
  "adopted",
  "succeeded",
  "unknown",
  "not_observed",
]);

function asString(value: unknown, fallback: string): string {
  return typeof value === "string" && value.length > 0 ? value : fallback;
}

// W635 (H-03): never fabricate `"succeeded"`, `"coordinator"`, or `"rs_<id>"` when
// the coordinator SiteSummary omits journal/host facts; report unknown/not_observed truthfully.
function toObservedSiteFromCoordinator(raw: CoordinatorSiteEntry) {
  const siteId = asString(raw.site_id, "");
  const state =
    typeof raw.state === "string" && validSiteStates.has(raw.state)
      ? (raw.state as "running" | "quarantined" | "adopted" | "succeeded" | "unknown")
      : "unknown";
  return {
    site_id: siteId,
    operation_id: asString(raw.operation_id, "not_observed"),
    hostname: asString(raw.hostname, asString(raw.name, siteId)),
    account: asString(raw.account, "not_observed"),
    state,
    site_kind: typeof raw.site_kind === "string" ? raw.site_kind : undefined,
    ejected: false,
  };
}

function extractCoordinatorSites(value: unknown): CoordinatorSiteEntry[] {
  if (!value || typeof value !== "object") return [];
  const obj = value as { items?: unknown; sites?: unknown };
  const list = Array.isArray(obj.items) ? obj.items : obj.sites;
  return Array.isArray(list) ? (list as CoordinatorSiteEntry[]) : [];
}

function buildCoordinatorObservation(doctorVal: unknown, sitesVal: unknown) {
  const doc = (doctorVal && typeof doctorVal === "object" ? doctorVal : {}) as Record<
    string,
    unknown
  >;
  const hostId = typeof doc.host_id === "string" && doc.host_id ? doc.host_id : "not_observed";
  const siteList = extractCoordinatorSites(sitesVal)
    .filter((entry) => typeof entry.site_id === "string" && entry.site_id.length > 0)
    .map(toObservedSiteFromCoordinator);
  return {
    schema: "rustiron-lab-observation/1",
    host: {
      host_id: hostId,
      host_epoch: typeof doc.host_epoch === "string" ? doc.host_epoch : "not_observed",
      issuer: typeof doc.issuer === "string" ? doc.issuer : "not_observed",
      signer_policy_epoch: typeof doc.signer_epoch === "string" ? doc.signer_epoch : "not_observed",
      ols_listener: null,
      backup_destination: null,
      backup_retention_days: null,
    },
    sites: siteList,
    operations: [],
    captures: [],
    probes: [],
    generations: [],
  };
}

const DIST_MIME_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".json": "application/json; charset=utf-8",
  ".webmanifest": "application/manifest+json",
  ".woff2": "font/woff2",
};

function isSafeRelativeAsset(rel: string): boolean {
  return Boolean(rel) && !rel.includes("\0") && !rel.includes("..");
}

function resolveDistFile(
  distDir: string,
  pathname: string,
): { filePath: string; immutable: boolean } | null {
  const rel = pathname.replace(/^\/+/, "");
  if (!isSafeRelativeAsset(rel)) return null;
  const candidate = resolve(distDir, rel);
  if (!candidate.startsWith(`${distDir}${sep}`) || !existsSync(candidate)) return null;
  const info = lstatSync(candidate);
  if (!info.isFile() || info.isSymbolicLink()) return null;
  return { filePath: candidate, immutable: /^chunk-[a-z0-9]+\.(js|css)$/i.test(rel) };
}

/** W651: serves built production SPA & hashed assets with full D-090 Host + CSP/HSTS headers. */
export function createProdDistHandler(options: {
  distDir: string;
  getAllowedHosts: () => ReadonlySet<string>;
  hsts?: boolean;
}) {
  const distRoot = resolve(options.distDir);
  const indexPath = join(distRoot, "index.html");
  const hsts = Boolean(options.hsts);

  return (req: Request): Response => {
    const refused = checkD090Request(req, options.getAllowedHosts());
    if (refused) return refused;
    const pathname = new URL(req.url).pathname;
    if (pathname.startsWith("/api/")) {
      return withD090Headers(new Response("Not Found", { status: 404 }), { hsts });
    }
    const hit = resolveDistFile(distRoot, pathname);
    if (hit) {
      const mime =
        DIST_MIME_TYPES[extname(hit.filePath).toLowerCase()] ?? "application/octet-stream";
      const headers: Record<string, string> = { "content-type": mime };
      if (hit.immutable) headers["cache-control"] = "public, max-age=31536000, immutable";
      return withD090Headers(new Response(readFileSync(hit.filePath), { headers }), {
        hsts,
        preserveCacheControl: hit.immutable,
      });
    }
    return withD090Headers(
      new Response(readFileSync(indexPath), {
        headers: { "content-type": "text/html; charset=utf-8" },
      }),
      { hsts },
    );
  };
}

export function createReadOnlyBackendHandlers(config: BackendConfig) {
  const allowFixture =
    config.allowFixture ?? (!config.observationPath && !config.coordinatorSocket);

  async function buildStatusResponse(includeDoctor: boolean): Promise<Response> {
    const doctorResult =
      includeDoctor && config.coordinatorSocket
        ? await coordinatorDoctor(config.coordinatorSocket)
        : null;
    const coordinatorReachable =
      doctorResult !== null && doctorResult.ok && doctorResult.response.status === "ok";
    const writeEnabled = Boolean(config.writeWorkflowsEnabled);
    const body: BackendStatus = {
      schema: "rustiron-console-backend/1",
      mode: writeEnabled ? "write_opt_in" : "read_only",
      d090_hardened: true,
      write_workflows_enabled: writeEnabled,
      observation_configured: Boolean(config.observationPath),
      coordinator_configured: Boolean(config.coordinatorSocket),
      coordinator_reachable: coordinatorReachable,
      doctor: coordinatorReachable ? (doctorResult.response.data?.value ?? null) : null,
    };
    return jsonReply(200, body);
  }

  return {
    observation: guard(config, () => observationResponse(config.observationPath, { allowFixture })),
    status: guard(config, () => buildStatusResponse(true)),
    // W635 (M-17): unauthenticated capability flags only; never calls coordinator doctor.
    publicStatus: guard(config, () => buildStatusResponse(false)),
    coordinatorLive: guard(config, async () => {
      if (!config.coordinatorSocket) {
        return jsonReply(503, { error: "COORDINATOR_NOT_CONFIGURED" });
      }
      const [docRes, sitesRes] = await Promise.all([
        coordinatorDoctor(config.coordinatorSocket),
        coordinatorSiteList(config.coordinatorSocket, 100, null),
      ]);
      if (!docRes.ok) {
        return jsonReply(mapCoordinatorErrorStatus(docRes.code), { error: docRes.code });
      }
      if (docRes.response.status !== "ok") {
        return mapCoordinatorResult(docRes);
      }
      // W635 (H-03): fail closed when site_list fails instead of returning 200 with empty sites.
      if (!sitesRes.ok) {
        return jsonReply(mapCoordinatorErrorStatus(sitesRes.code), { error: sitesRes.code });
      }
      if (sitesRes.response.status !== "ok") {
        return mapCoordinatorResult(sitesRes);
      }
      return jsonReply(200, {
        source: "coordinator",
        observed_at: Date.now(),
        observation: buildCoordinatorObservation(
          docRes.response.data?.value,
          sitesRes.response.data?.value,
        ),
      });
    }),
    coordinatorDoctor: guard(config, async () =>
      mapCoordinatorResult(await coordinatorDoctor(config.coordinatorSocket)),
    ),
    coordinatorSites: guard(config, async (request) => {
      const url = new URL(request.url);
      const limitParam = url.searchParams.get("limit");
      const cursorParam = url.searchParams.get("cursor");
      const parsedLimit = limitParam === null ? 25 : Number(limitParam);
      if (!Number.isInteger(parsedLimit) || parsedLimit < 1 || parsedLimit > 100) {
        return jsonReply(400, { error: "INVALID_REQUEST" });
      }
      return mapCoordinatorResult(
        await coordinatorSiteList(config.coordinatorSocket, parsedLimit, cursorParam),
      );
    }),
    coordinatorSiteInspect: guard(config, async (request) => {
      const url = new URL(request.url);
      const siteId = decodeURIComponent(url.pathname.replace(/^\/api\/coordinator\/sites\//, ""));
      return mapCoordinatorResult(await coordinatorSiteInspect(config.coordinatorSocket, siteId));
    }),
    coordinatorOperationStatus: guard(config, async (request) => {
      const url = new URL(request.url);
      const operationId = decodeURIComponent(
        url.pathname.replace(/^\/api\/coordinator\/operations\//, ""),
      );
      return mapCoordinatorResult(
        await coordinatorOperationStatus(config.coordinatorSocket, operationId),
      );
    }),
    coordinatorEvidenceExport: guard(config, async (request) => {
      const url = new URL(request.url);
      const operationId = decodeURIComponent(
        url.pathname.replace(/^\/api\/coordinator\/evidence\//, ""),
      );
      return mapCoordinatorResult(
        await coordinatorEvidenceExport(config.coordinatorSocket, operationId),
      );
    }),
  };
}
