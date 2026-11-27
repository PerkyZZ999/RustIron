import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import index from "../index.html";
import { consoleApiRoutes } from "./api-routes";
import { createConsoleAuthBackend } from "./auth-backend";
import {
  allowedConsoleHosts,
  checkD090Request,
  consolePort,
  createProdDistHandler,
  createReadOnlyBackendHandlers,
  withD090Headers,
} from "./backend-server";
import { createHostLogsHandler } from "./logs-backend";
import { createMailBackend } from "./mail-backend";
import { createWriteBackendHandlers } from "./write-backend";

const port = consolePort(process.env.RUSTIRON_CONSOLE_PORT);
const isProd = process.env.NODE_ENV === "production";
const writeEnabled = process.env.RUSTIRON_CONSOLE_WRITE_WORKFLOWS === "1";
const mailWritesEnabled = process.env.RUSTIRON_CONSOLE_MAIL_WRITES === "1" || writeEnabled;
const noFixture = process.env.RUSTIRON_CONSOLE_NO_FIXTURE === "1";
const configuredOrigin = process.env.RUSTIRON_CONSOLE_ORIGIN?.trim() || undefined;
const isHttpsOrigin = configuredOrigin?.toLowerCase().startsWith("https://") ?? false;

let hosts = allowedConsoleHosts(port, configuredOrigin);
const loopbackOrigin = `http://127.0.0.1:${port}`;
const baseURL = configuredOrigin ?? loopbackOrigin;
const trustedOrigins = Array.from(
  new Set([
    loopbackOrigin,
    `http://localhost:${port}`,
    ...(configuredOrigin ? [configuredOrigin] : []),
  ]),
);

const PUBLIC_DIR = join(import.meta.dir, "..", "public");
const DIST_DIR = resolve(import.meta.dir, "..", "dist");
const DIST_INDEX = join(DIST_DIR, "index.html");
const hasProdDist = isProd && existsSync(DIST_INDEX);
const STATIC_ASSETS: Record<string, { file: string; contentType: string }> = {
  "/favicon.svg": { file: "favicon.svg", contentType: "image/svg+xml" },
  "/favicon.ico": { file: "favicon.ico", contentType: "image/x-icon" },
  "/favicon-16x16.png": { file: "favicon-16x16.png", contentType: "image/png" },
  "/favicon-32x32.png": { file: "favicon-32x32.png", contentType: "image/png" },
  "/favicon-48x48.png": { file: "favicon-48x48.png", contentType: "image/png" },
  "/apple-touch-icon.png": { file: "apple-touch-icon.png", contentType: "image/png" },
  "/android-chrome-192x192.png": { file: "android-chrome-192x192.png", contentType: "image/png" },
  "/android-chrome-512x512.png": { file: "android-chrome-512x512.png", contentType: "image/png" },
  "/open-graph-1200x630.png": { file: "open-graph-1200x630.png", contentType: "image/png" },
  "/site.webmanifest": { file: "site.webmanifest", contentType: "application/manifest+json" },
};

function servePublicAsset(assetPath: string): (req: Request) => Response {
  const entry = STATIC_ASSETS[assetPath];
  return (req) => {
    const guard = checkD090Request(req, hosts);
    if (guard) return guard;
    if (!entry)
      return withD090Headers(new Response("Not Found", { status: 404 }), { hsts: isHttpsOrigin });
    const bytes = readFileSync(join(PUBLIC_DIR, entry.file));
    return withD090Headers(
      new Response(bytes, {
        headers: {
          "content-type": entry.contentType,
          "cache-control": "public, max-age=86400",
        },
      }),
      { hsts: isHttpsOrigin, preserveCacheControl: true },
    );
  };
}

const serveProdDist = createProdDistHandler({
  distDir: DIST_DIR,
  getAllowedHosts: () => hosts,
  hsts: isHttpsOrigin,
});
// W663-C2: production never runs with authentication turned off.
if (isProd && process.env.RUSTIRON_CONSOLE_AUTH_DISABLED === "1") {
  console.error("RUSTIRON_CONSOLE_AUTH_DISABLED=1 is refused when NODE_ENV=production.");
  process.exit(1);
}
const authApi = createConsoleAuthBackend({
  dbPath: process.env.RUSTIRON_CONSOLE_AUTH_DB,
  secret: process.env.RUSTIRON_CONSOLE_AUTH_SECRET,
  setupToken: process.env.RUSTIRON_CONSOLE_SETUP_TOKEN,
  requireSetupToken: isProd,
  baseURL,
  trustedOrigins,
  forceRequired: process.env.RUSTIRON_CONSOLE_AUTH_REQUIRED === "1",
  disableEnforcement: process.env.RUSTIRON_CONSOLE_AUTH_DISABLED === "1",
  getAllowedHosts: () => hosts,
});
const api = createReadOnlyBackendHandlers({
  observationPath: process.env.RUSTIRON_OBSERVATION,
  coordinatorSocket: process.env.RUSTIRON_COORDINATOR_SOCKET,
  writeWorkflowsEnabled: writeEnabled,
  allowFixture:
    !noFixture && !process.env.RUSTIRON_OBSERVATION && !process.env.RUSTIRON_COORDINATOR_SOCKET,
  getAllowedHosts: () => hosts,
});
const writeApi = createWriteBackendHandlers({
  enabled: writeEnabled,
  coordinatorSocket: process.env.RUSTIRON_COORDINATOR_SOCKET,
  getAllowedHosts: () => hosts,
});
const mailApi = createMailBackend({
  dbPath: process.env.RUSTIRON_CONSOLE_MAIL_DB,
  writesEnabled: mailWritesEnabled,
  getAllowedHosts: () => hosts,
});
const hostLogsHandler = createHostLogsHandler({ getAllowedHosts: () => hosts });

const server = Bun.serve({
  hostname: "127.0.0.1",
  port,
  // W665: refuse bodies before buffering them; the largest route body (P15 apply) is 256 KiB.
  maxRequestBodySize: 1_048_576,
  routes: {
    ...consoleApiRoutes(
      { auth: authApi, readOnly: api, write: writeApi, mail: mailApi, hostLogs: hostLogsHandler },
      { production: isProd },
    ),
    "/favicon.svg": servePublicAsset("/favicon.svg"),
    "/favicon.ico": servePublicAsset("/favicon.ico"),
    "/favicon-16x16.png": servePublicAsset("/favicon-16x16.png"),
    "/favicon-32x32.png": servePublicAsset("/favicon-32x32.png"),
    "/favicon-48x48.png": servePublicAsset("/favicon-48x48.png"),
    "/apple-touch-icon.png": servePublicAsset("/apple-touch-icon.png"),
    "/android-chrome-192x192.png": servePublicAsset("/android-chrome-192x192.png"),
    "/android-chrome-512x512.png": servePublicAsset("/android-chrome-512x512.png"),
    "/open-graph-1200x630.png": servePublicAsset("/open-graph-1200x630.png"),
    "/site.webmanifest": servePublicAsset("/site.webmanifest"),
    "/*": hasProdDist ? serveProdDist : index,
  },
  // W635 (M-16) / W651: in production serve built dist/ with full D-090 Host + CSP/HSTS headers.
  fetch(req) {
    if (hasProdDist) return serveProdDist(req);
    const guard = checkD090Request(req, hosts);
    if (guard) return guard;
    return withD090Headers(new Response("Not Found", { status: 404 }), { hsts: isHttpsOrigin });
  },
  development: isProd
    ? false
    : {
        hmr: true,
        console: true,
      },
});

hosts = allowedConsoleHosts(server.port ?? port, configuredOrigin);
const modeLabel = writeEnabled
  ? "P15 write opt-in loopback"
  : mailWritesEnabled
    ? "D-090 loopback · mail catalog opt-in"
    : "D-090 read-only loopback";
console.log(`Rustiron console ${server.url} (${modeLabel} · Better Auth)`);
