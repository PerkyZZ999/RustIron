// Real-browser gate: every route, both themes, desktop and phone widths.
// Fails on axe WCAG 2.2 AA violations, horizontal page scroll, console
// errors, a missing h1, or a broken keyboard path. W379 adds two synthetic
// passes (console/e2e/states): every new journal state, and EXECUTOR_NOT_ENROLLED.
import { readFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import AxeBuilder from "@axe-core/playwright";
import { type Browser, chromium, type Page } from "playwright";

import index from "../index.html";
import { consoleApiRoutes } from "../src/api-routes";
import { createConsoleAuthBackend } from "../src/auth-backend";
import {
  allowedLoopbackHosts,
  createReadOnlyBackendHandlers,
  D090_CSP,
} from "../src/backend-server";
import { isObservation, type Observation } from "../src/live";
import { createHostLogsHandler } from "../src/logs-backend";
import { createMailBackend } from "../src/mail-backend";
import { observationRoute } from "../src/observation-route";
import { createWriteBackendHandlers } from "../src/write-backend";

function liveObservation(): Observation | undefined {
  const path = process.env.RUSTIRON_OBSERVATION;
  if (!path) return undefined;
  try {
    const value = JSON.parse(readFileSync(path, "utf8")) as unknown;
    return isObservation(value) ? value : undefined;
  } catch {
    return undefined;
  }
}

const live = liveObservation();
const siteId = live?.sites[0]?.site_id ?? "site_8KD2QW";
const domainHost = live?.sites[0]?.hostname ?? "blog.lab.test";
const operationId =
  live?.captures[0]?.operation_id ??
  live?.probes[0]?.operation_id ??
  live?.operations[0]?.operation_id ??
  live?.sites[0]?.operation_id ??
  "op_7Q2KX9";
const receiptId =
  live?.probes.find((probe) => probe.fields && Object.keys(probe.fields).length > 0)
    ?.operation_id ?? "rcpt_2YB7";
const artifactId =
  live?.captures.find((capture) => capture.snapshot_id)?.snapshot_id ?? "snap_P8Q1";

const routes = [
  "/",
  "/host/metrics",
  "/host/services",
  "/host/diagnoses",
  "/host/updates",
  "/host/alerts",
  "/host/firewall",
  "/host/cron",
  "/host/logs",
  "/sites",
  "/sites/new",
  `/sites/${siteId}`,
  `/sites/${siteId}/configuration`,
  `/sites/${siteId}/maintenance`,
  `/sites/${siteId}/operations`,
  `/sites/${siteId}/recovery`,
  "/sites/site_4HX9KC",
  "/apps",
  "/databases",
  "/apps/app_emdash",
  "/domains",
  "/domains/new",
  `/domains/${domainHost}`,
  `/domains/${domainHost}/dns`,
  "/mail",
  "/migration",
  "/migration/emdash/wxr_emdash_01",
  "/operations",
  `/operations/${operationId}`,
  "/plans/plan_3HV8RA",
  "/plans/new",
  "/plans/new/review",
  "/recovery",
  "/recovery/schedules",
  "/recovery/store",
  `/recovery/artifacts/${artifactId}`,
  `/recovery/evidence/${receiptId}`,
  "/users",
  "/login",
  "/settings",
  "/help",
  "/help/how-rustiron-works",
  "/help/fullstack-caddy",
  "/help/postgresql-18",
  "/help/updates-and-releases",
  "/states",
];

const viewports = [
  { name: "desktop", width: 1440, height: 900 },
  { name: "phone", width: 375, height: 812 },
] as const;

const themes = ["light", "dark"] as const;

let serverHosts = allowedLoopbackHosts(0);
const backendApi = createReadOnlyBackendHandlers({
  observationPath: process.env.RUSTIRON_OBSERVATION,
  coordinatorSocket: process.env.RUSTIRON_COORDINATOR_SOCKET,
  getAllowedHosts: () => serverHosts,
});

const authApi = createConsoleAuthBackend({
  dbPath: ":memory:",
  baseURL: "http://127.0.0.1:4319",
  disableEnforcement: true,
  getAllowedHosts: () => serverHosts,
});

const writeApi = createWriteBackendHandlers({
  enabled: false,
  coordinatorSocket: process.env.RUSTIRON_COORDINATOR_SOCKET,
  getAllowedHosts: () => serverHosts,
});
const mailApi = createMailBackend({
  dbPath: ":memory:",
  getAllowedHosts: () => serverHosts,
});
const hostLogsHandler = createHostLogsHandler({
  getAllowedHosts: () => serverHosts,
  disableSpawn: true,
});

const server = Bun.serve({
  hostname: "127.0.0.1",
  port: 0,
  routes: {
    ...consoleApiRoutes(
      {
        auth: authApi,
        readOnly: backendApi,
        write: writeApi,
        mail: mailApi,
        hostLogs: hostLogsHandler,
      },
      { production: false },
    ),
    "/*": index,
  },
  development: false,
});
serverHosts = allowedLoopbackHosts(server.port ?? 0);

/** With RUSTIRON_OBSERVATION the gate checks the live console, otherwise the fixture one. */
const expectedSource = process.env.RUSTIRON_OBSERVATION ? "Live" : "Fixture data";
const failures: string[] = [];
let checks = 0;

/** Names the outermost elements that stick out, skipping content inside scroll containers. */
function overflowCulprits() {
  const limit = document.documentElement.clientWidth;
  const extra = document.documentElement.scrollWidth - limit;
  if (extra <= 0) return null;
  const sticksOut = (element: Element | null) =>
    element !== null && element.getBoundingClientRect().right > limit + 1;
  const culprits = [...document.querySelectorAll("main *")]
    .filter((element) => sticksOut(element) && !sticksOut(element.parentElement))
    .filter((element) => !element.closest(".table-scroll, .chart, .tabs, pre"))
    .slice(0, 3)
    .map((element) => `${element.tagName.toLowerCase()}.${[...element.classList].join(".")}`);
  return { extra, culprits: culprits.join(", ") };
}

type Violation = Awaited<ReturnType<AxeBuilder["analyze"]>>["violations"][number];

function describeViolation(violation: Violation) {
  const targets = violation.nodes
    .slice(0, 3)
    .map((node) => node.target.join(" "))
    .join(", ");
  const data = violation.nodes[0]?.any[0]?.data as { contrastRatio?: number } & Record<
    string,
    unknown
  >;
  const contrast = data?.contrastRatio
    ? ` ${data.fgColor} on ${data.bgColor} = ${data.contrastRatio}:1`
    : "";
  return `${violation.id} (${violation.impact}) ${targets}${contrast}`;
}

async function checkPage(page: Page, label: string) {
  const h1 = await page.locator("h1").count();
  if (h1 !== 1) failures.push(`${label}: expected one h1, found ${h1}`);
  const overflow = await page.evaluate(overflowCulprits);
  if (overflow) {
    failures.push(
      `${label}: page scrolls horizontally by ${overflow.extra}px (${overflow.culprits})`,
    );
  }
  const result = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
  for (const violation of result.violations)
    failures.push(`${label}: ${describeViolation(violation)}`);
}

async function checkKeyboard(page: Page) {
  await page.goto(`${server.url}plans/new`);
  await page.locator("h1").waitFor();
  await page.keyboard.press("Tab");
  const skip = await page.evaluate(() => document.activeElement?.textContent?.trim());
  if (skip !== "Skip to content") failures.push(`keyboard: first Tab reached "${skip}"`);
  await page.getByRole("radio", { name: /Config activation/ }).focus();
  await page.keyboard.press("ArrowDown");
  const checked = await page.getByRole("radio", { name: /Backup capture/ }).isChecked();
  if (!checked) failures.push("keyboard: arrow key did not move the plan action selection");
  const ring = await page.evaluate(() => {
    const card = document.activeElement?.closest(".radio-card");
    return card ? getComputedStyle(card).outlineStyle : "none";
  });
  if (ring === "none") failures.push("keyboard: focused action card has no visible focus ring");
  checks += 1;
}

type Pass = {
  name: string;
  url: URL;
  routes: string[];
  badge: string;
  /** Text each route must show; a state the console fails to render is a failure. */
  expect: Record<string, string[]>;
};

async function checkRoute(page: Page, pass: Pass, route: string, theme: string, label: string) {
  await page.goto(`${pass.url}${route.slice(1)}`);
  await page.locator("h1").first().waitFor();
  await page
    .locator(".sidebar-foot .fixture")
    .filter({ hasText: pass.badge })
    .waitFor({ timeout: 5000 })
    .catch(() => {
      failures.push(`${label}: data source badge is not "${pass.badge}"`);
    });
  const applied = await page.evaluate(() => document.documentElement.dataset.theme);
  if (applied !== theme) failures.push(`${label}: theme applied as ${applied}`);
  // W396: the browser hashes signed bytes asynchronously; check the settled page.
  await page
    .waitForFunction(() => !document.querySelector("main")?.textContent?.includes("Checking…"), {
      timeout: 5000,
    })
    .catch(() => {
      failures.push(`${label}: signed-byte check did not settle`);
    });
  const text = await page.locator("main").innerText();
  const absent = (pass.expect[route] ?? []).filter((wanted) => !text.includes(wanted));
  for (const wanted of absent) failures.push(`${label}: state text "${wanted}" absent`);
  await checkPage(page, label);
}

/** Console errors and page errors raised since the last drain. */
function errorLog(page: Page): string[] {
  const errors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  page.on("pageerror", (error) => errors.push(error.message));
  return errors;
}

const PAGES_PER_CONTEXT = Math.max(
  1,
  Math.min(4, Number.parseInt(process.env.RUSTIRON_BROWSER_CONCURRENCY ?? "2", 10) || 2),
);

async function checkWorkerRoutes(
  page: Page,
  pass: Pass,
  theme: string,
  width: string,
  nextIndex: () => number,
) {
  const errors = errorLog(page);
  for (;;) {
    const idx = nextIndex();
    const route = pass.routes[idx];
    if (!route) break;
    const label = `${pass.name}${route} [${theme}, ${width}]`;
    await checkRoute(page, pass, route, theme, label);
    failures.push(...errors.splice(0).map((error) => `${label}: console error ${error}`));
    checks += 1;
  }
}

async function checkContextPass(
  browser: Browser,
  pass: Pass,
  theme: (typeof themes)[number],
  viewport: (typeof viewports)[number],
) {
  const context = await browser.newContext({
    viewport: { width: viewport.width, height: viewport.height },
    colorScheme: theme,
  });
  let cursor = 0;
  const nextIndex = () => cursor++;
  const workerCount = Math.min(PAGES_PER_CONTEXT, Math.max(1, pass.routes.length));
  try {
    const pages = await Promise.all(Array.from({ length: workerCount }, () => context.newPage()));
    await Promise.all(
      pages.map((page) => checkWorkerRoutes(page, pass, theme, viewport.name, nextIndex)),
    );
  } finally {
    await context.close();
  }
}

async function checkPass(browser: Browser, pass: Pass) {
  const pairs = themes.flatMap((theme) => viewports.map((viewport) => ({ theme, viewport })));
  await Promise.all(
    pairs.map(({ theme, viewport }) => checkContextPass(browser, pass, theme, viewport)),
  );
}

/** W379: synthetic observations of the states the backend produces, checked in every mode. */
const STATES = new URL("./states/", import.meta.url).pathname;

function stateServer(file: string) {
  return Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    routes: { "/api/observation": observationRoute(`${STATES}${file}`), "/*": index },
    development: false,
  });
}

const statesExpect: Record<string, string[]> = {
  "/": ["Adopted (serving not observed)"],
  "/sites": ["1–4 of 4", "Adopted", "Failed · unclaimed snapshot"],
  // W382: the empty snapshot table of a settled capture names its unclaimed snapshot.
  "/sites/w379d/recovery": ["0 recorded in journal", "1 unclaimed, not a backup of record"],
  "/sites/w379a": ["Opted in", "5 GiB, 500,000 inodes", "export SITE"],
  "/sites/w379a/configuration": ["Page cache", "Disk quota usage"],
  "/sites/w379b": ["Opted out", "1 GiB, 100,000 inodes"],
  "/sites/w379c": ["Adopted by re-adoption", "op_w379_readopt", "256 MiB"],
  "/sites/w379c/configuration": ["Adopted by re-adoption", "Re-adoption"],
  "/operations": [
    "Page cache opt-out",
    "Site re-adoption",
    "Failed · unclaimed snapshot",
    "Failed · refused READOPT_MISMATCH",
    "17 recorded",
  ],
  "/operations/op_w379_cap_1": [
    "Matched: the database marker",
    "30 days recorded",
    "Digest mismatch",
    "do not match the recorded SHA-256",
  ],
  "/operations/op_w379_cap_2": [
    "Refusal code",
    "Not recorded in the journal",
    "Not recorded: admitted before journal v20",
  ],
  "/operations/op_w379_cap_3": ["is not a backup of record", "Unclaimed snapshot"],
  "/operations/op_w379_cap_4": ["Outcome uncertain"],
  // W391 (journal v18): per-version retention evidence and a stored refusal code.
  "/operations/op_w391_cap_1": [
    "7 object versions read back, COMPLIANCE",
    "Retained until",
    "COMPLIANCE 30 days before, 30 days after",
    "Digests match",
    "Self-attested, signed",
  ],
  "/operations/op_w391_cap_2": ["Refusal code", "RETENTION_LOCK_UNVERIFIED"],
  // W396 (journal v20): signed bytes hashed in the browser, and the receipt attestation.
  "/operations/op_w379_act": ["Signed plan and grant", "Digests match", "SSHSIG verified"],
  "/operations/op_w379_probe_1": ["Digests match", "Self-attested, signed", "SHA256:W396"],
  "/operations/op_w379_probe_2": ["NOT_ADMITTED_FOR_EFFECT"],
  "/operations/op_w379_readopt": ["Re-adoption adopted", "Bytes not kept"],
  "/operations/op_w379_readopt_gen": ["READOPT_MISMATCH", "generation", "Not in this observation"],
  "/recovery": ["unclaimed, not a backup of record"],
  "/recovery/evidence/op_w379_probe_1": ["D-026 defers independent"],
};

const notEnrolledRoutes = ["/", "/sites", "/operations", "/recovery", "/host/metrics"];

const browser = await chromium.launch({
  executablePath: process.env.RUSTIRON_CHROMIUM ?? "/usr/bin/chromium",
});
const states = stateServer("w396-observation.json");
const notEnrolled = stateServer("not-enrolled.json");
try {
  await checkPass(browser, {
    name: "",
    url: server.url,
    routes,
    badge: expectedSource,
    expect: {},
  });
  await checkPass(browser, {
    name: "states:",
    url: states.url,
    routes: Object.keys(statesExpect),
    badge: "Live",
    expect: statesExpect,
  });
  await checkPass(browser, {
    name: "not-enrolled:",
    url: notEnrolled.url,
    routes: notEnrolledRoutes,
    badge: "executor not enrolled",
    expect: Object.fromEntries(
      notEnrolledRoutes.map((route) => [route, ["Executor not enrolled"]]),
    ),
  });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  await checkKeyboard(await context.newPage());
  await context.close();

  // W612 (CP04 / D-090): verify loopback Host allowlist, zero CORS, GET/HEAD-only, and CSP live.
  const rawGet = (method: string, headers?: Record<string, string>) =>
    new Promise<{ status: number; headers: Record<string, string | string[] | undefined> }>(
      (resolve, reject) => {
        const req = httpRequest(
          {
            host: "127.0.0.1",
            port: server.port ?? 0,
            path: "/api/backend/status",
            method,
            headers,
          },
          (res) => {
            res.resume();
            res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers }));
          },
        );
        req.on("error", reject);
        req.end();
      },
    );
  checks += 1;
  const statusRes = await rawGet("GET");
  if (
    statusRes.status !== 200 ||
    statusRes.headers["content-security-policy"] !== D090_CSP ||
    statusRes.headers["x-frame-options"] !== "DENY" ||
    statusRes.headers["access-control-allow-origin"] !== undefined
  ) {
    failures.push(`d090 /api/backend/status headers/status invalid (${statusRes.status})`);
  }
  checks += 1;
  const badHost = await rawGet("GET", { host: "evil.example:4319" });
  if (badHost.status !== 421) {
    failures.push(`d090 DNS-rebinding host expected 421, got ${badHost.status}`);
  }
  checks += 1;
  const badOrigin = await rawGet("GET", { origin: "https://evil.example" });
  if (badOrigin.status !== 403 || badOrigin.headers["access-control-allow-origin"] !== undefined) {
    failures.push(`d090 cross-origin expected 403 without CORS, got ${badOrigin.status}`);
  }
  checks += 1;
  const badMethod = await rawGet("POST");
  if (badMethod.status !== 405 || badMethod.headers.allow !== "GET, HEAD") {
    failures.push(`d090 POST expected 405 Allow: GET, HEAD, got ${badMethod.status}`);
  }
  // W613 (P15): verify write endpoints stay disabled (405) under D-090 default mode.
  checks += 1;
  const writeDisabled = await new Promise<{ status: number }>((resolve, reject) => {
    const req = httpRequest(
      {
        host: "127.0.0.1",
        port: server.port ?? 0,
        path: "/api/write/plan/apply",
        method: "POST",
        headers: { "content-type": "application/json" },
      },
      (res) => {
        res.resume();
        res.on("end", () => resolve({ status: res.statusCode ?? 0 }));
      },
    );
    req.on("error", reject);
    req.end("{}");
  });
  if (writeDisabled.status !== 405) {
    failures.push(
      `p15 default-disabled POST /api/write/plan/apply expected 405, got ${writeDisabled.status}`,
    );
  }
} finally {
  await browser.close();
  await server.stop(true);
  await states.stop(true);
  await notEnrolled.stop(true);
}

const stateRoutes = Object.keys(statesExpect).length + notEnrolledRoutes.length;
for (const failure of failures) console.error(`FAIL ${failure}`);
console.log(
  `${checks} browser checks on ${expectedSource.toLowerCase()} and W379 states, ${failures.length} failures ((${routes.length} routes + ${stateRoutes} state routes) × ${themes.length} themes × ${viewports.length} widths + keyboard)`,
);
process.exit(failures.length ? 1 : 0);
