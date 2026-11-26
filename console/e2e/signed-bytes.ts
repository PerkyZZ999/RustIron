// B14 evidence (W429): on a product host's observation, the operation page of
// OP shows the exact plan and grant bytes that were signed on the operator
// PC. Passes when the browser's own digest check settles to "Digests match",
// the page states the SSHSIG verification, and the text of each signed-bytes
// block equals the signed file byte for byte. Run:
//   RUSTIRON_OBSERVATION=FILE OP=op_id PLAN=plan.json GRANT=grant.json bun e2e/signed-bytes.ts
import { readFileSync } from "node:fs";
import { chromium } from "playwright";

import index from "../index.html";
import { observationRoute } from "../src/observation-route";

const { RUSTIRON_OBSERVATION: path, OP: op, PLAN: plan, GRANT: grant } = process.env;
if (!path || !op || !plan || !grant) {
  console.error(
    "usage: RUSTIRON_OBSERVATION=FILE OP=ID PLAN=FILE GRANT=FILE bun e2e/signed-bytes.ts",
  );
  process.exit(2);
}
const expected: Record<string, string> = {
  plan: readFileSync(plan, "utf8"),
  grant: readFileSync(grant, "utf8"),
};

const server = Bun.serve({
  hostname: "127.0.0.1",
  port: 0,
  routes: { "/api/observation": observationRoute(path), "/*": index },
  development: false,
});
const failures: string[] = [];
const browser = await chromium.launch();
try {
  const page = await browser.newPage();
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(String(error)));
  await page.goto(`http://127.0.0.1:${server.port}/operations/${op}`);
  await page.locator("h1").first().waitFor();
  await page
    .waitForFunction(() => !document.querySelector("main")?.textContent?.includes("Checking…"), {
      timeout: 5000,
    })
    .catch(() => failures.push("signed-byte check did not settle"));
  const text = await page.locator("main").innerText();
  for (const wanted of ["Signed plan and grant", "Digests match", "SSHSIG verified at admission"]) {
    if (!text.includes(wanted)) failures.push(`text "${wanted}" absent`);
  }
  // Each kept object has its own state; any mismatch fails the check.
  if (text.includes("Digest mismatch")) failures.push(`the page shows "Digest mismatch"`);
  for (const part of ["plan", "grant"]) {
    const shown = await page
      .locator(`pre.signed-bytes[data-part="${part}"]`)
      .textContent()
      .catch(() => null);
    if (shown !== expected[part])
      failures.push(`${part} bytes on the page differ from the signed file`);
    else console.log(`${part}: ${shown.length} bytes on the page equal the signed file`);
  }
  failures.push(...errors.map((error) => `page error: ${error}`));
  if (process.env.SHOT) {
    await page.locator("#signed-bytes-heading").scrollIntoViewIfNeeded();
    await page.screenshot({ path: process.env.SHOT });
  }
} finally {
  await browser.close();
  server.stop(true);
}
if (failures.length) {
  for (const failure of failures) console.error(`FAIL ${failure}`);
  process.exit(1);
}
console.log(`PASS ${op}: signed bytes shown exactly, digests match, SSHSIG verification stated`);
