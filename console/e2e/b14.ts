// B14 evidence (W195): on the live lab observation, checks that sample plan
// screens never issue a write, that fixture facts do not leak into live
// pages, that missing facts are labelled as missing, and records each
// route's accessibility tree as a screen-reader proxy. Run:
//   RUSTIRON_OBSERVATION=.live/observation.json bun e2e/b14.ts OUTDIR
import { mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { chromium, type Page } from "playwright";

import index from "../index.html";
import { observationRoute } from "../src/observation-route";

const path = process.env.RUSTIRON_OBSERVATION;
const out = process.argv[2];
if (!path || !out) {
  console.error("usage: RUSTIRON_OBSERVATION=FILE bun e2e/b14.ts OUTDIR");
  process.exit(2);
}
mkdirSync(`${out}/aria`, { recursive: true });
const obs = JSON.parse(readFileSync(path, "utf8")) as {
  sites: { site_id: string }[];
  operations: { operation_id: string }[];
  captures: { operation_id: string; snapshot_id?: string }[];
  probes: { operation_id: string }[];
};
const mtime = statSync(path).mtimeMs;
const site =
  obs.sites.find((s) => s.site_id === "blog13")?.site_id ?? obs.sites[0]?.site_id ?? "none";
const op = obs.operations[0]?.operation_id ?? "none";
const snap = obs.captures.find((c) => c.snapshot_id)?.snapshot_id ?? "none";
const probe = obs.probes[0]?.operation_id ?? "none";

/** Plan screens are documented samples; the others must show only live facts. */
const SAMPLE = new Set([
  "/plans/plan_3HV8RA",
  "/plans/new",
  "/plans/new/review",
  "/states",
  "/help",
]);
const routes = [
  "/",
  "/host/metrics",
  "/host/services",
  "/sites",
  `/sites/${site}`,
  `/sites/${site}/configuration`,
  `/sites/${site}/operations`,
  `/sites/${site}/recovery`,
  "/operations",
  `/operations/${op}`,
  "/recovery",
  `/recovery/artifacts/${snap}`,
  `/recovery/evidence/${probe}`,
  "/settings",
  ...SAMPLE,
];
const FIXTURE_MARKERS = [
  "shop.lab.test",
  "site_8KD2QW",
  "op_7Q2KX9",
  "SHA256:Qm4",
  "SHA256:Wd1",
  "sha256:a2f0",
  "sha256:71ac",
  "almalinux10-ols-lsphp84 · revision 3",
  "rcpt_2YB7",
  "snap_P8Q1",
];
const MISSING_LABELS: Record<string, string[]> = {
  "/settings": [
    (obs as { host?: { packages?: unknown } }).host?.packages
      ? "Package pins come from the host RPM database"
      : "Package pins are not in this observation",
  ],
  [`/recovery/artifacts/${snap}`]: ["Artifact file list, sizes and digests"],
};

const server = Bun.serve({
  hostname: "127.0.0.1",
  port: 0,
  routes: { "/api/observation": observationRoute(path), "/*": index },
  development: false,
});
const failures: string[] = [];
const report: Record<string, unknown> = {};
const writes: string[] = [];

async function a11y(page: Page) {
  return page.evaluate(() => {
    const levels = [...document.querySelectorAll("h1,h2,h3,h4,h5,h6")].map((h) =>
      Number(h.tagName[1]),
    );
    const skips = levels.filter((l, i) => i > 0 && l > (levels[i - 1] ?? l) + 1).length;
    return {
      main: document.querySelectorAll("main").length,
      nav: document.querySelectorAll("nav").length,
      headings: levels.length,
      heading_skips: skips,
      tables_without_th: [...document.querySelectorAll("table")].filter(
        (t) => !t.querySelector("th"),
      ).length,
      unnamed_buttons: [...document.querySelectorAll("button")].filter(
        (b) =>
          !(
            b.textContent?.trim() ||
            b.getAttribute("aria-label") ||
            b.getAttribute("aria-labelledby")
          ),
      ).length,
      img_without_alt: [...document.querySelectorAll("img:not([alt])")].length,
      live_regions: document.querySelectorAll("[aria-live],[role=status],[role=alert]").length,
    };
  });
}

const browser = await chromium.launch({
  executablePath: process.env.RUSTIRON_CHROMIUM ?? "/usr/bin/chromium",
});
try {
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();
  page.on("request", (r) => {
    const url = new URL(r.url());
    if (r.method() !== "GET" || url.origin !== server.url.origin)
      writes.push(`${r.method()} ${r.url()}`);
  });
  for (const route of routes) {
    await page.goto(`${server.url}${route.slice(1)}`);
    await page.locator("h1").first().waitFor();
    await page
      .locator(".sidebar-foot .fixture")
      .filter({ hasText: "Live" })
      .waitFor({ timeout: 5000 });
    const text = await page.locator("main").innerText();
    const leaks = FIXTURE_MARKERS.filter((m) => text.includes(m));
    const sample = SAMPLE.has(route);
    if (leaks.length && !sample)
      failures.push(`${route}: fixture facts on a live page: ${leaks.join(", ")}`);
    const sampleLabelled = sample ? /sample|fixture|example|preview/i.test(text) : null;
    if (sample && leaks.length && !sampleLabelled)
      failures.push(`${route}: sample values without a sample label`);
    for (const label of MISSING_LABELS[route] ?? [])
      if (!text.includes(label)) failures.push(`${route}: missing-fact label "${label}" absent`);
    let clicked = 0;
    if (sample) {
      const main = page.locator("main");
      const radios = main.getByRole("radio");
      for (let i = 0; i < (await radios.count()); i += 1) {
        await radios
          .nth(i)
          .check({ timeout: 2000 })
          .catch(() => undefined);
        clicked += 1;
      }
      const boxes = main.getByRole("textbox");
      for (let i = 0; i < (await boxes.count()); i += 1) {
        const box = boxes.nth(i);
        await box.fill("1", { timeout: 2000 }).catch(() => undefined);
        await box.press("Enter").catch(() => undefined);
        clicked += 1;
      }
      const buttons = main.locator("button:enabled");
      for (let i = 0; i < (await buttons.count()); i += 1) {
        await buttons
          .nth(i)
          .click({ timeout: 2000 })
          .catch(() => undefined);
        clicked += 1;
      }
      const actions = main.getByRole("link", {
        name: /continue|review|submit|approve|apply|sign|create|discard/i,
      });
      const n = await actions.count();
      for (let i = 0; i < n; i += 1) {
        await page.goto(`${server.url}${route.slice(1)}`);
        await page
          .locator("main")
          .getByRole("link", { name: /continue|review|submit|approve|apply|sign|create|discard/i })
          .nth(i)
          .click({ timeout: 2000 })
          .catch(() => undefined);
        clicked += 1;
      }
      await page.goto(`${server.url}${route.slice(1)}`);
      await page.locator("h1").first().waitFor();
      await page.waitForTimeout(300);
    }
    const tree = a11y(page);
    const aria = await page.locator("body").ariaSnapshot();
    writeFileSync(`${out}/aria/${route.replaceAll("/", "_") || "_"}.yaml`, aria);
    const facts = await tree;
    if (facts.main !== 1) failures.push(`${route}: ${facts.main} main landmarks`);
    if (facts.unnamed_buttons || facts.img_without_alt || facts.tables_without_th)
      failures.push(`${route}: unnamed controls/images/tables ${JSON.stringify(facts)}`);
    report[route] = { leaks, sample, sampleLabelled, clicked, ...facts };
  }
  await context.close();
} finally {
  await browser.close();
}
const post = await fetch(`${server.url}api/observation`, { method: "POST", body: "{}" });
if (post.status !== 405) failures.push(`POST /api/observation returned ${post.status}`);
await server.stop(true);
if (writes.length) failures.push(`non-GET or cross-origin requests: ${writes.join("; ")}`);
if (statSync(path).mtimeMs !== mtime) failures.push("observation file changed");
writeFileSync(
  `${out}/b14.json`,
  `${JSON.stringify({ routes: report, writes, post_api_status: post.status, failures }, null, 1)}\n`,
);
for (const f of failures) console.error(`FAIL ${f}`);
console.log(
  `${routes.length} live routes, ${writes.length} write requests, ${failures.length} failures; POST /api/observation -> ${post.status}`,
);
process.exit(failures.length ? 1 : 0);
