import { afterEach, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CircleCheck, RotateCcw } from "lucide-react";
import { act, cleanup, render, screen } from "@testing-library/react";
import { createMemoryHistory, createRouter, RouterProvider } from "@tanstack/react-router";

import {
  serviceFactLines,
  signerFacts,
  captureRetentionEvidence,
  consistencyText,
  enrolledRetentionText,
  isExecutorRefusal,
  quotaLimitText,
  liveAttention,
  liveCaptureExposure,
  clockSyncText,
  sshPolicyText,
  databaseText,
  stackText,
  executorSelinuxText,
  failedUnitsText,
  olsMapText,
  firewallText,
  tlsListenerText,
  inodeUseText,
  liveHelpItems,
  liveHostHistory,
  liveOperation,
  liveOperations,
  liveReceipt,
  liveRecovery,
  liveSearchTargets,
  resourcePressure,
  liveServices,
  liveSiteSnapshots,
  liveSnapshot,
  liveSites,
  type Observation,
  packagePins,
} from "./live";
import { packageRows, signerRows } from "./settings-pages";
import { observationResponse, observationRoute } from "./observation-route";
import { routeTree } from "./router";

const pass = { status: "pass" };
const observation: Observation = {
  schema: "rustiron-lab-observation/1",
  machine: {
    schema: "rustiron-host-status/1",
    observed_at: 1793046400,
    os: { name: "AlmaLinux", version: "10.2", kernel: "6.12.0-211.7.3.el10_2.x86_64" },
    uptime_seconds: 172800,
    cpu: { count: 4, load: [0.2, 1.0, 0.5] },
    memory: { total_bytes: 8 * 1073741824, available_bytes: 6 * 1073741824 },
    disk: { path: "/", total_bytes: 40 * 1073741824, available_bytes: 30 * 1073741824 },
    selinux: "enforcing",
    samples: [
      { t: 1793046325, cpu: 10, mem: 20, disk: 20 },
      { t: 1793046340, cpu: 15, mem: 22, disk: 22 },
      { t: 1793046355, cpu: 20, mem: 24, disk: 24 },
      { t: 1793046400, cpu: 25, mem: 25, disk: 25 },
    ],
    services: [
      {
        unit: "lshttpd.service",
        label: "OpenLiteSpeed web server",
        active: "active",
        sub: "running",
        since: 1793000000,
      },
      {
        unit: "rustiron-s02-lab-executor.service",
        label: "Rustiron executor (lab)",
        active: "active",
        sub: "running",
        since: 1793040000,
      },
    ],
  },
  host: {
    host_id: "rustiron_alma10_lab",
    host_epoch: "epoch_test",
    issuer: "lab_agent",
    signer_policy_epoch: "policy_3",
    ols_listener: "192.168.122.186:8090",
    backup_destination: "lab_pc_store",
    backup_retention_days: 30,
  },
  journal_last_time: 1793046321,
  sites: [
    {
      site_id: "blog13",
      hostname: "blog13.example.test",
      operation_id: "prov_blog13",
      state: "succeeded",
      steps_done: 8,
      steps_recorded: 8,
      http_status: 200,
      ejected: false,
    },
    {
      site_id: "blog7",
      hostname: "blog7.example.test",
      operation_id: "prov_blog7",
      state: "quarantined",
      steps_done: 0,
      steps_recorded: 1,
      failed_step: "account",
      host_account: "absent",
      host_directory: "absent",
      ejected: false,
    },
  ],
  operations: [
    {
      operation_id: "op_ej1",
      kind: "site_eject",
      resource_id: "ols_lab_listener",
      site_id: "blog9",
      state: "failed_compensated",
      effect_attempted: true,
    },
  ],
  captures: [
    {
      operation_id: "op_cap1",
      site_id: "blog13",
      state: "succeeded",
      snapshot_id: "05810d1450fd4377bea966dbc1c159609a191bd943abe952c3b39867880876a2",
      started_at: 1793046319,
      finished_at: 1793046321,
      fields: {
        artifacts_complete: { status: "unknown", observed_at: 1793046321, evidence_refs: [] },
        repository_integrity_checked: {
          status: "pass",
          observed_at: 1793046321,
          evidence_refs: [],
        },
        decryption_tested: { status: "not_run", observed_at: 1793046321, evidence_refs: [] },
        application_consistency_assessed: {
          status: "unknown",
          observed_at: 1793046321,
          evidence_refs: [],
        },
        restored_in_isolation: { status: "not_run", observed_at: 1793046321, evidence_refs: [] },
        health_checks_passed: { status: "not_run", observed_at: 1793046321, evidence_refs: [] },
        independent_copy_confirmed: {
          status: "unknown",
          observed_at: 1793046321,
          evidence_refs: [],
        },
      },
    },
    {
      operation_id: "op_cap2",
      site_id: "blog13",
      state: "running",
      snapshot_id: null,
      started_at: 1793046400,
      finished_at: null,
    },
  ],
  probes: [
    {
      operation_id: "op_pr1",
      site_id: "blog13",
      snapshot_id: "05810d1450fd4377bea966dbc1c159609a191bd943abe952c3b39867880876a2",
      state: "passed",
      started_at: 1793046330,
      finished_at: 1793046390,
      fields: {
        artifacts_complete: pass,
        repository_integrity_checked: pass,
        decryption_tested: pass,
        application_consistency_assessed: pass,
        restored_in_isolation: pass,
        health_checks_passed: pass,
        independent_copy_confirmed: {
          status: "fail",
          scope: "local-PC lab destination, not an independent off-host copy",
        },
      },
    },
    {
      operation_id: "op_pr2",
      site_id: "blog13",
      snapshot_id: "05810d1450fd4377bea966dbc1c159609a191bd943abe952c3b39867880876a2",
      state: "failed",
      started_at: 1793046395,
      finished_at: 1793046399,
      fields: null,
    },
  ],
};

afterEach(cleanup);

function only<T>(rows: T[], index: number): T {
  const row = rows[index];
  if (row === undefined) throw new Error(`missing row ${index}`);
  return row;
}

/** The fixture observation's machine block, which these tests require. */
function fixtureMachine() {
  if (!observation.machine) throw new Error("fixture observation has no machine block");
  return observation.machine;
}

test("host history needs two timed samples and keeps them in order", () => {
  const machine = observation.machine;
  if (!machine) throw new Error("test observation must include host status");
  expect(liveHostHistory({ ...machine, samples: [{ t: 10, cpu: 1, mem: 1, disk: 1 }] })).toBeNull();
  const history = liveHostHistory(machine);
  expect(history?.samples).toHaveLength(4);
  expect(history?.from).toBe(1793046325);
  expect(history?.to).toBe(1793046400);
});

test("live sites show only what the journal records", () => {
  const sites = liveSites(observation);
  const blog13 = only(sites, 0);
  expect([blog13.serving, blog13.http, blog13.operation]).toEqual([
    "Not observed",
    "200",
    "Backup capture",
  ]);
  // A later failed probe without fields does not erase the last recorded evidence.
  expect(blog13.marks).toEqual(["pass", "pass", "pass", "pass", "pass", "pass", "fail"]);
  const blog7 = only(sites, 1);
  expect(blog7.serving).toBe("Quarantined");
  expect(blog7.ownership).toBe("No account or directory");
  expect(blog7.runtime).toBe("Not observed");
  expect(blog13.http).toBe("200");
  expect(blog7.http).toBe("Not observed");
  expect(new Set(blog7.marks)).toEqual(new Set(["not_run"]));
  expect(blog13.operationHref).toBe("/operations/op_cap2");
});

test("live operations keep running, failed and compensated outcomes distinct", () => {
  const rows = liveOperations(observation);
  const outcome = (id: string) => rows.find((row) => row.id === id)?.outcome;
  expect([only(rows, 0).id, only(rows, 0).outcome, only(rows, 0).duration]).toEqual([
    "op_cap2",
    "Running",
    "—",
  ]);
  expect(outcome("op_pr2")).toBe("Failed · probe did not pass");
  expect(outcome("op_ej1")).toBe("Failed, compensated");
  expect(outcome("prov_blog7")).toBe("Failed · partial effects");
  expect(rows.every((row) => row.linked)).toBe(true);
});

test("a finished capture shows its seven derived evidence marks", () => {
  const finished = liveOperation(observation, "op_cap1");
  expect(finished?.marks).toEqual([
    "unknown",
    "pass",
    "not_run",
    "unknown",
    "not_run",
    "not_run",
    "unknown",
  ]);
  expect(finished?.observed).toContain("Seven-field capture evidence is recorded");
  expect(finished?.facts).toContainEqual({
    label: "Evidence recorded",
    value: "26 Oct, 20:25 UTC",
  });
  expect(finished?.unknown).toContain("No evidence refs are recorded for these fields");
  const running = liveOperation(observation, "op_cap2");
  expect(running?.unknown).toContain("Seven-field capture evidence is not in this observation");
});

test("live operation detail records journal facts and omits plans", () => {
  expect(liveOperation(observation, "missing")).toBeNull();
  const capture = liveOperation(observation, "op_cap2");
  expect(capture?.title).toBe("Backup capture · blog13.example.test");
  expect(capture?.observed).toContain("Backup capture running");
  expect(capture?.unknown).toContain("No snapshot id is recorded yet");
  expect(capture?.unknown).toContain(
    "The detached signature and any approval review are not in this observation",
  );
  const probe = liveOperation(observation, "op_pr1");
  expect(probe?.marks).toEqual(["pass", "pass", "pass", "pass", "pass", "pass", "fail"]);
  expect(probe?.observed).toContain("Seven-field restore evidence is recorded");
  const eject = liveOperation(observation, "op_ej1");
  expect(eject?.title).toBe("Site eject · blog9");
  expect(eject?.hostname).toBeNull();
});

test("live recovery never counts the lab store as an independent copy", () => {
  const recovery = liveRecovery(observation);
  const recovery13 = only(recovery, 0);
  const recovery7 = only(recovery, 1);
  expect(recovery13.snapshot).toStartWith("05810d14 ·");
  expect(recovery13.exposure).toContain("within the 24 h D-010 target");
  expect(recovery13.exposure).toContain("not an independent-copy RPO");
  expect(liveCaptureExposure(observation, "blog13").seconds).toBe(0);
  expect(liveCaptureExposure(observation, "blog7").withinTarget).toBeNull();
  expect(recovery7.exposure).toContain("unmeasured");
  expect(recovery13.copy).toEqual({ label: "Not independent (lab store)", kind: "err" });
  expect(recovery13.receipt).toBe("op_pr1");
  expect(recovery7.receipt).toBeNull();
  expect(liveReceipt(observation, "op_pr2")).toBeNull();
  expect(liveReceipt(observation, "op_pr1")?.fields.at(-1)).toEqual({
    name: "Independent copy confirmed",
    mark: "fail",
    scope: "local-PC lab destination, not an independent off-host copy",
  });
  expect(recovery7.snapshot).toBeNull();

  const snapshots = liveSiteSnapshots(observation);
  const snap13 = only(snapshots.blog13 ?? [], 0);
  expect(snap13.id).toBe("05810d14");
  expect(snap13.artifactId).toStartWith("05810d14");
  const snapshot = liveSnapshot(observation, "05810d14");
  expect(snapshot?.hostname).toBe("blog13.example.test");
  expect(snapshot?.receiptId).toBe("op_pr1");
  expect(snapshot?.repository).toBe("lab_pc_store · not independent");
  expect(liveSnapshot(observation, "missing")).toBeNull();
  expect(snap13.repository).toBe("lab_pc_store · not independent");
  expect(snap13.marks).toEqual(["pass", "pass", "pass", "pass", "pass", "pass", "fail"]);
  expect(snap13.restore.kind).toBe("err");
  expect(snapshots.blog7).toEqual([]);
});

test("the observation route serves the file read-only and says when there is none", async () => {
  const none = await observationResponse(undefined);
  expect(await none.json()).toEqual({ source: "fixture" });
  const directory = await mkdtemp(join(tmpdir(), "ri-observation-"));
  try {
    const path = join(directory, "observation.json");
    expect((await observationResponse(path)).status).toBe(503);
    await writeFile(path, "{not json");
    expect((await observationResponse(path)).status).toBe(503);
    await writeFile(path, JSON.stringify(observation));
    const response = await observationResponse(path);
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const body = (await response.json()) as { observed_at: number; observation: Observation };
    expect(body.observation.sites).toHaveLength(2);
    expect(body.observed_at).toBeGreaterThan(0);
  } finally {
    await rm(directory, { recursive: true });
  }
});

test("package pins are shown only when every observed pin is well formed", () => {
  const pins = [
    { name: "openlitespeed", version: "0:1.9.3-1.el10.x86_64", signing_key: null },
    {
      name: "mariadb-server",
      version: "3:10.11.18-1.el10_2.alma.2.x86_64",
      signing_key: "dee5c11cc2a1e572",
    },
    { name: "restic", version: null, signing_key: null },
  ];
  const host = { ...observation.host, packages: pins };
  expect(packagePins(host)).toEqual(pins);
  expect(packagePins(observation.host)).toBeNull();
  expect(packagePins({ ...host, packages: null })).toBeNull();
  expect(packagePins({ ...host, packages: [] })).toBeNull();
  expect(packagePins({ ...host, packages: [{ ...pins[0], version: "1.9 3;rm" }] })).toBeNull();
  expect(packagePins({ ...host, packages: [{ ...pins[1], signing_key: "zz" }] })).toBeNull();
  expect(
    packagePins({ ...host, packages: [{ name: "<b>", version: null, signing_key: null }] }),
  ).toBeNull();
  expect(packageRows(packagePins(host))).toEqual([
    ["openlitespeed", "0:1.9.3-1.el10.x86_64 · unsigned", "Observed"],
    [
      "mariadb-server",
      "3:10.11.18-1.el10_2.alma.2.x86_64 · signed, key dee5c11cc2a1e572",
      "Observed",
    ],
    ["restic", "Not installed", "Not checked"],
  ]);
  expect(packageRows(null)).toEqual([["Package pins", "Not in this observation", "Not checked"]]);
});

test("the observation route refuses every method that is not a read", async () => {
  const route = observationRoute(undefined);
  for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
    const response = await route(new Request("http://127.0.0.1/api/observation", { method }));
    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("GET, HEAD");
  }
  expect((await route(new Request("http://127.0.0.1/api/observation"))).status).toBe(200);
});

test("with a live source the sites screen shows the host and labels sample screens", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = (async () =>
    Response.json({ observed_at: Date.now(), observation })) as unknown as typeof fetch;
  try {
    const router = createRouter({
      routeTree,
      history: createMemoryHistory({ initialEntries: ["/sites"] }),
    });
    render(<RouterProvider router={router} />);
    expect(await screen.findByRole("link", { name: "blog13.example.test" })).toBeTruthy();
    expect(screen.queryByRole("link", { name: "shop.lab.test" })).toBeNull();
    expect(screen.getByRole("status").textContent).toContain("Live · rustiron_alma10_lab");
    expect(screen.queryByText(/Sample screen/)).toBeNull();
    await act(() => router.navigate({ to: "/" }));
    expect(await screen.findByRole("heading", { level: 1, name: "Host overview" })).toBeTruthy();
    expect(screen.queryByText(/Sample screen/)).toBeNull();
    expect(screen.queryByText(/Operation needs attention/)).toBeNull();
    expect(screen.getAllByText("25")).toHaveLength(3);
    expect(screen.getByText(/5-min load 1\.00 · 4 vCPU/)).toBeTruthy();
    expect(screen.getByText(/2\.0 GiB of 8\.0 GiB in use/)).toBeTruthy();
    expect(screen.getByText(/10\.0 GiB of 40\.0 GiB in use/)).toBeTruthy();
    expect(screen.getByText(/OpenLiteSpeed web server/)).toBeTruthy();
    expect(screen.getAllByRole("link", { name: "Backup capture" }).length).toBeGreaterThan(0);

    await act(() =>
      router.navigate({ to: "/sites/$siteId/recovery", params: { siteId: "blog13" } }),
    );
    expect(await screen.findByRole("heading", { level: 2, name: "Snapshots" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "05810d14" })).toBeTruthy();
    expect(screen.getByText("lab_pc_store · not independent")).toBeTruthy();
    await act(() =>
      router.navigate({
        to: "/recovery/artifacts/$artifactId",
        params: { artifactId: "05810d14" },
      }),
    );
    expect(
      await screen.findByRole("heading", { level: 1, name: "Snapshot 05810d14" }),
    ).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "Snapshot snap_P8Q1" })).toBeNull();
    expect(screen.queryByText(/1\.9 GiB/)).toBeNull();
    expect(screen.getByText("Artifact manifest is not in this observation")).toBeTruthy();
    expect(screen.getByRole("link", { name: "op_pr1" })).toBeTruthy();

    await act(() => router.navigate({ to: "/host/metrics" }));
    expect(screen.queryByText(/Sample screen/)).toBeNull();
    expect(await screen.findByText(/4 samples/)).toBeTruthy();
    expect(screen.getByRole("img", { name: "Live CPU samples from the host" })).toBeTruthy();
    expect(screen.getByRole("heading", { level: 2, name: "Disk /" })).toBeTruthy();

    await act(() => router.navigate({ to: "/operations" }));
    expect(screen.queryByText(/Sample screen/)).toBeNull();
    expect(screen.getAllByRole("link", { name: "Backup capture" }).length).toBeGreaterThan(0);

    await act(() =>
      router.navigate({ to: "/operations/$operationId", params: { operationId: "op_pr1" } }),
    );
    expect(
      await screen.findByRole("heading", { level: 1, name: "Restore probe · blog13.example.test" }),
    ).toBeTruthy();
    expect(screen.queryByText(/Sample screen/)).toBeNull();
    expect(screen.getByText("Seven-field restore evidence is recorded")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Open blog13.example.test" })).toBeTruthy();

    await act(() =>
      router.navigate({ to: "/operations/$operationId", params: { operationId: "op_7Q2KX9" } }),
    );
    expect(
      await screen.findByRole("heading", { level: 1, name: "Not in this observation" }),
    ).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "Config activation · shop.lab.test" })).toBeNull();

    await act(() => router.navigate({ to: "/recovery" }));
    expect(await screen.findByRole("link", { name: "op_pr1" })).toBeTruthy();
    await act(() =>
      router.navigate({ to: "/recovery/evidence/$receiptId", params: { receiptId: "op_pr1" } }),
    );
    expect(
      await screen.findByRole("heading", { level: 1, name: "Recovery receipt op_pr1" }),
    ).toBeTruthy();
    expect(
      screen.getByText("local-PC lab destination, not an independent off-host copy"),
    ).toBeTruthy();
    expect(screen.queryByText(/portfolio\.lab\.test/)).toBeNull();
    expect(screen.queryByText(/lab-02/)).toBeNull();
    expect(screen.getByText("Signed receipt bytes are not in this observation")).toBeTruthy();

    await act(() =>
      router.navigate({ to: "/recovery/evidence/$receiptId", params: { receiptId: "op_pr2" } }),
    );
    expect(
      await screen.findByRole("heading", { level: 1, name: "Not in this observation" }),
    ).toBeTruthy();
    expect(screen.getByRole("link", { name: "Back to recovery" })).toBeTruthy();

    await act(() => router.navigate({ to: "/settings" }));
    expect(screen.queryByText(/Sample screen/)).toBeNull();
    expect((await screen.findAllByText("rustiron_alma10_lab")).length).toBeGreaterThan(0);
    expect(screen.getByText("lab_agent")).toBeTruthy();
    expect(
      screen.getByText(
        "30 days enrolled on the backup policy. D-010 target is 30 days. Older captures do not gain this number.",
      ),
    ).toBeTruthy();
    expect(screen.getByText("policy_3")).toBeTruthy();
    expect(screen.getByText(/Package pins are not in this observation/)).toBeTruthy();
    expect(screen.getByText("Package pins")).toBeTruthy();
    expect(screen.queryByText(/sha256:a2f0/)).toBeNull();
    expect(screen.getByText("AlmaLinux 10.2")).toBeTruthy();
    expect(screen.getByText("enforcing")).toBeTruthy();
    expect(screen.queryByText("maint-bot")).toBeNull();
    expect(screen.getByText(/Local session/).textContent).toContain("rustiron_alma10_lab");
    expect(screen.getByRole("button", { name: /Notifications, \d+ need attention/ })).toBeTruthy();
    const liveBody = document.body.textContent ?? "";
    expect(liveBody).not.toContain("shop.lab.test");
    expect(liveBody).not.toContain("Operation op_7Q2KX9");

    await act(() => router.navigate({ to: "/help" }));
    expect(screen.queryByText(/Sample screen/)).toBeNull();
    expect(
      await screen.findByText(/Runbooks for the current state of rustiron_alma10_lab/),
    ).toBeTruthy();
    const helpMain = document.querySelector("#main")?.textContent ?? "";
    expect(helpMain).toContain("Quarantined site blog7.example.test");
    expect(helpMain).not.toContain("lab-01");
    expect(helpMain).not.toContain("op_7Q2KX9");
    expect(helpMain).not.toContain("portfolio.lab.test");

    await act(() => router.navigate({ to: "/states" }));
    expect(screen.queryByText(/Sample screen/)).toBeNull();
    expect(await screen.findByRole("heading", { level: 1, name: "Shared states" })).toBeTruthy();

    await act(() => router.navigate({ to: "/plans/$planId", params: { planId: "plan_3HV8RA" } }));
    expect(await screen.findByRole("heading", { level: 1, name: "Plan plan_3HV8RA" })).toBeTruthy();
    expect(screen.queryByText(/Sample screen/)).toBeNull();
    expect(screen.getByText(/Plans are not listed by plan ID in this observation/)).toBeTruthy();
    expect(screen.queryByRole("heading", { name: /shop\.lab\.test/ })).toBeNull();

    await act(() =>
      router.navigate({ to: "/sites/$siteId/configuration", params: { siteId: "blog7" } }),
    );
    expect(
      await screen.findByRole("heading", { level: 1, name: "blog7.example.test" }),
    ).toBeTruthy();
    expect(screen.queryByText("Blocked by operation")).toBeNull();
    expect(screen.queryByText("LSPHP 8.4")).toBeNull();
    expect(screen.getAllByText("Quarantined").length).toBeGreaterThan(0);
    expect(
      screen.getByText(/Managed OLS and PHP settings are not in this observation/),
    ).toBeTruthy();

    await act(() => router.navigate({ to: "/plans/new" }));
    expect(await screen.findByRole("heading", { level: 1, name: "New plan" })).toBeTruthy();
    expect(screen.queryByText(/Sample screen/)).toBeNull();
    expect(screen.getAllByText(/blog13\.example\.test/).length).toBeGreaterThan(0);
    expect(screen.queryByText(/shop\.lab\.test/)).toBeNull();

    screen.getByRole("button", { name: /Notifications, \d+ need attention/ }).click();
    expect(await screen.findByRole("heading", { name: "Needs attention" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "Quarantined site blog7.example.test" })).toBeTruthy();
  } finally {
    globalThis.fetch = original;
  }
});

test("help items come from quarantined sites and failed operations", () => {
  const items = liveHelpItems(observation);
  expect(items[0]?.title).toBe("Quarantined site blog7.example.test");
  expect(items[0]?.detail).toContain("Stopped at account");
  expect(items.some((item) => item.href.startsWith("/operations/"))).toBe(true);
});

test("attention groups quarantined sites and failed operations", () => {
  const attention = liveAttention(observation);
  expect(attention.count).toBeGreaterThan(1);
  expect(attention.items.some((item) => item.label.includes("blog7.example.test"))).toBe(true);
  expect(
    attention.items.some(
      (item) => item.href === "/operations" || item.href.startsWith("/operations/"),
    ),
  ).toBe(true);
});

test("a capture older than 24 h is attention, still not an independent-copy RPO", () => {
  const stale = {
    ...observation,
    journal_last_time: 1793046321 + 90_000,
  };
  const exposure = liveCaptureExposure(stale, "blog13");
  expect(exposure.withinTarget).toBe(false);
  expect(exposure.seconds).toBe(90_000);
  expect(exposure.text).toContain("past the 24 h D-010 target");
  expect(exposure.text).toContain("not an independent-copy RPO");
  const attention = liveAttention(stale);
  expect(
    attention.items.some((item) => item.label.includes("past the 24 h local capture gap")),
  ).toBe(true);
  const early = { ...observation, journal_last_time: 1793046321 - 10 };
  expect(liveCaptureExposure(early, "blog13").text).toContain("Age is not computed");
});

test("a log timer shows its last trigger and an unset trigger stays unrecorded", () => {
  const timer = liveServices({
    ...fixtureMachine(),
    services: [
      {
        unit: "logrotate.timer",
        label: "Log rotation",
        active: "active",
        sub: "waiting",
        since: 1793040000,
        last_trigger: 1793228407,
      },
    ],
  });
  expect(timer[0]?.since).toBe("Last trigger 28 Oct, 23:00 UTC");
  expect(timer[0]?.role).toBe("Log rotation");
  const unset = liveServices({
    ...fixtureMachine(),
    services: [
      {
        unit: "logrotate.timer",
        label: "Log rotation",
        active: "active",
        sub: "waiting",
        since: 1793040000,
        last_trigger: null,
      },
    ],
  });
  expect(unset[0]?.since).toBe("No trigger recorded");
});

test("an unconfined executor type is attention and a missing context stays unread", () => {
  expect(executorSelinuxText(undefined)).toBe("Executor SELinux context was not read");
  expect(
    executorSelinuxText({
      unit: "rustiron-s02-lab-executor.service",
      readable: false,
      context: null,
    }),
  ).toBe("Executor SELinux context is not readable by this observer");
  const unconfined = {
    ...observation,
    machine: observation.machine
      ? {
          ...observation.machine,
          selinux: "enforcing",
          executor_selinux: {
            unit: "rustiron-s02-lab-executor.service",
            readable: true,
            context: "system_u:system_r:unconfined_service_t:s0",
          },
        }
      : observation.machine,
  };
  expect(executorSelinuxText(unconfined.machine?.executor_selinux)).toContain(
    "unconfined_service_t",
  );
  expect(
    liveAttention(unconfined).items.some(
      (item) => item.label === "Executor SELinux type is unconfined",
    ),
  ).toBe(true);
  const permissive = {
    ...observation,
    machine: observation.machine
      ? { ...observation.machine, selinux: "permissive" }
      : observation.machine,
  };
  expect(
    liveAttention(permissive).items.some((item) => item.label === "SELinux is permissive"),
  ).toBe(true);
});

test("a site PHP pool outside rustiron_php_t is attention and a matching type is quiet", () => {
  const confined = {
    ...observation,
    machine: observation.machine
      ? {
          ...observation.machine,
          services: [
            ...observation.machine.services,
            {
              unit: "rustiron-site-php@rs_blog13.service",
              label: "Site PHP pool",
              active: "active",
              sub: "running",
              since: 1793040000,
              selinux_context: "system_u:system_r:rustiron_php_t:s0:c201",
            },
          ],
        }
      : observation.machine,
  };
  expect(liveAttention(confined).items.some((item) => item.label.includes("PHP pool"))).toBe(false);
  const drifted = {
    ...observation,
    machine: observation.machine
      ? {
          ...observation.machine,
          services: [
            {
              unit: "rustiron-site-php@rs_blog13.service",
              label: "Site PHP pool",
              active: "active",
              sub: "running",
              since: 1793040000,
              selinux_context: "system_u:system_r:unconfined_service_t:s0",
            },
            {
              unit: "rustiron-site-php@site_a.service",
              label: "Site PHP pool",
              active: "active",
              sub: "running",
              since: 1793040000,
              selinux_context: "system_u:system_r:unconfined_service_t:s0",
            },
          ],
        }
      : observation.machine,
  };
  const attention = liveAttention(drifted);
  expect(
    attention.items.some((item) => item.label === "2 PHP pools are outside rustiron_php_t"),
  ).toBe(true);
  expect(attention.count).toBeGreaterThanOrEqual(2);
});

test("stack versions omit anything that was not read", () => {
  expect(stackText(undefined)).toBe("Stack versions were not read");
  expect(stackText({ openlitespeed: null, mariadb: null, php: [] })).toBe(
    "Stack versions were not read",
  );
  expect(
    stackText({ openlitespeed: "1.9.3", mariadb: "10.11.18", php: ["8.4.27", "8.3.36"] }),
  ).toBe("OpenLiteSpeed 1.9.3 · MariaDB 10.11.18 · PHP 8.4.27, 8.3.36");
});

test("a MariaDB response is not a query and silence is attention", () => {
  expect(databaseText(undefined)).toBe("MariaDB ping was not run");
  expect(databaseText({ socket: "/var/lib/mysql/mysql.sock", ping: "unknown" })).toBe(
    "MariaDB ping was not run",
  );
  expect(databaseText({ socket: "/var/lib/mysql/mysql.sock", ping: "responding" })).toContain(
    "not a query",
  );
  const down = {
    ...observation,
    machine: observation.machine
      ? {
          ...observation.machine,
          database: {
            socket: "/var/lib/mysql/mysql.sock",
            ping: "not_responding" as const,
          },
        }
      : observation.machine,
  };
  expect(liveAttention(down).items.some((item) => item.label === "MariaDB did not respond")).toBe(
    true,
  );
});

test("an unreadable firewall stays unknown and a stopped firewall is attention", () => {
  expect(firewallText(undefined)).toBe("Firewall policy was not read");
  expect(firewallText({ readable: false, state: null, default_zone: null, services: null })).toBe(
    "Firewall policy not readable by this observer",
  );
  expect(
    firewallText({
      readable: true,
      state: "running",
      default_zone: "public",
      services: ["ssh"],
    }),
  ).toBe("Firewall running · zone public · services ssh");
  const stopped = {
    ...observation,
    machine: observation.machine
      ? {
          ...observation.machine,
          firewall: {
            readable: true,
            state: "not running",
            default_zone: "public",
            services: [],
          },
        }
      : observation.machine,
  };
  expect(
    liveAttention(stopped).items.some((item) => item.label === "Firewall is not running"),
  ).toBe(true);
});

test("resource pressure starts at 90 percent and ignores a missing count", () => {
  expect(resourcePressure(observation.machine)).toEqual([]);
  const tight = observation.machine
    ? {
        ...observation.machine,
        memory: { total_bytes: 100, available_bytes: 5 },
        disk: {
          ...observation.machine.disk,
          total_bytes: 100,
          available_bytes: 11,
          inode_total: 100,
          inode_available: 4,
        },
      }
    : undefined;
  expect(resourcePressure(tight).map((item) => item.resource)).toEqual(["Memory", "Inodes"]);
  const pressured = { ...observation, machine: tight };
  expect(liveAttention(pressured).items.some((item) => item.label.includes("past 90%"))).toBe(true);
});

test("a missing port 443 listener does not claim a certificate expiry", () => {
  expect(tlsListenerText(undefined)).toBe(
    "TLS listeners not observed. Certificate expiry was not read.",
  );
  expect(tlsListenerText({ listeners_443: null })).toBe(
    "TLS listeners not observed. Certificate expiry was not read.",
  );
  expect(tlsListenerText({ listeners_443: 0 })).toBe(
    "No TLS listener on port 443. Certificate expiry was not read.",
  );
  expect(tlsListenerText({ listeners_443: 2 })).toBe(
    "2 TLS listeners on port 443. Certificate expiry was not read.",
  );
});

test("an unreadable SSH policy stays unknown and a password yes is attention", () => {
  expect(sshPolicyText(undefined)).toBe("SSH policy was not read");
  expect(sshPolicyText({ ...unreadSsh(), readable: false })).toBe(
    "SSH policy not readable by this observer",
  );
  const open = {
    ...observation,
    machine: observation.machine
      ? {
          ...observation.machine,
          ssh: {
            readable: true,
            permit_root_login: "no",
            password_authentication: "yes",
            pubkey_authentication: "yes",
            kbd_interactive_authentication: "no",
          },
        }
      : observation.machine,
  };
  expect(sshPolicyText(open.machine?.ssh)).toContain("password yes");
  expect(
    liveAttention(open).items.some(
      (item) => item.label === "SSH password authentication is enabled",
    ),
  ).toBe(true);
});

function unreadSsh() {
  return {
    readable: false,
    permit_root_login: null,
    password_authentication: null,
    pubkey_authentication: null,
    kbd_interactive_authentication: null,
  };
}

test("clock sync stays unobserved until timedatectl says yes or no", () => {
  expect(clockSyncText(undefined)).toBe("Clock sync not observed");
  expect(clockSyncText({ synchronized: null })).toBe("Clock sync not observed");
  expect(clockSyncText({ synchronized: true })).toBe("NTP synchronized");
  expect(clockSyncText({ synchronized: false })).toBe("NTP not synchronized");
  const unsynced = {
    ...observation,
    machine: observation.machine
      ? { ...observation.machine, clock: { synchronized: false } }
      : observation.machine,
  };
  expect(
    liveAttention(unsynced).items.some((item) => item.label === "NTP is not synchronized"),
  ).toBe(true);
});

test("a succeeded site missing from the OLS map is attention and an ejected mapped site stays quiet", () => {
  const sites = [
    {
      site_id: "blog13",
      hostname: "blog13.example.test",
      operation_id: "prov_blog13",
      state: "succeeded" as const,
      steps_done: 8,
      steps_recorded: 8,
      ejected: false,
    },
    {
      site_id: "blog9",
      hostname: "blog9.example.test",
      operation_id: "op_eject9",
      state: "succeeded" as const,
      steps_done: 8,
      steps_recorded: 8,
      ejected: true,
    },
  ];
  const map = { readable: true, hosts: ["blog9.example.test", "blog5.example.test"] };
  expect(olsMapText(map, sites)).toBe("Not in the active OLS map: blog13.example.test");
  const drifted = {
    ...observation,
    sites,
    machine: observation.machine ? { ...observation.machine, ols_map: map } : observation.machine,
  };
  const labels = liveAttention(drifted).items.map((item) => item.label);
  expect(labels).toContain("blog13.example.test is not in the active OLS map");
  expect(labels).not.toContain("blog9.example.test is ejected but still mapped");
  expect(olsMapText({ readable: false, hosts: null }, sites)).toBe(
    "Active OLS map was not readable",
  );
});

test("a failed unit is attention and an empty list stays quiet", () => {
  expect(failedUnitsText(undefined)).toBe("Failed units were not read");
  expect(failedUnitsText({ readable: false, units: null })).toBe(
    "Failed units were not readable by this observer",
  );
  expect(failedUnitsText({ readable: true, units: [] })).toBe("No failed units");
  const failed = {
    ...observation,
    machine: observation.machine
      ? {
          ...observation.machine,
          failed_units: { readable: true, units: ["rustiron-observe-local.service"] },
        }
      : observation.machine,
  };
  expect(failedUnitsText(failed.machine?.failed_units)).toBe(
    "Failed unit rustiron-observe-local.service",
  );
  expect(
    liveAttention(failed).items.some(
      (item) => item.label === "rustiron-observe-local.service failed",
    ),
  ).toBe(true);
  const quiet = {
    ...observation,
    machine: observation.machine
      ? { ...observation.machine, failed_units: { readable: true, units: [] } }
      : observation.machine,
  };
  expect(
    liveAttention(quiet).items.some(
      (item) => item.label.endsWith(" units failed") || item.label.endsWith(".service failed"),
    ),
  ).toBe(false);
});

test("a chrony offset is shown and a 1 s gap is attention", () => {
  expect(clockSyncText({ synchronized: true, offset_us: -302 })).toBe(
    "NTP synchronized · 302 µs slow of NTP",
  );
  expect(clockSyncText({ synchronized: true, offset_us: 0 })).toBe(
    "NTP synchronized · offset 0 µs",
  );
  expect(clockSyncText({ synchronized: true, offset_us: null })).toBe("NTP synchronized");
  const skewed = {
    ...observation,
    machine: observation.machine
      ? { ...observation.machine, clock: { synchronized: true, offset_us: -1_000_000 } }
      : observation.machine,
  };
  expect(
    liveAttention(skewed).items.some((item) => item.label === "Clock offset is at least 1 s"),
  ).toBe(true);
  const small = {
    ...observation,
    machine: observation.machine
      ? { ...observation.machine, clock: { synchronized: true, offset_us: 999_999 } }
      : observation.machine,
  };
  expect(
    liveAttention(small).items.some((item) => item.label === "Clock offset is at least 1 s"),
  ).toBe(false);
});

test("inode use stays unobserved until both counts are consistent", () => {
  const disk = observation.machine?.disk;
  if (!disk) throw new Error("missing disk");
  expect(inodeUseText(disk)).toBeNull();
  expect(inodeUseText({ ...disk, inode_total: 1000, inode_available: 750 })).toBe(
    "250 of 1000 inodes in use (25%)",
  );
  expect(inodeUseText({ ...disk, inode_total: 10, inode_available: 11 })).toBeNull();
  expect(inodeUseText({ ...disk, inode_total: 0, inode_available: 0 })).toBeNull();
});

test("a capture stores its own retention and a blank row stays blank", () => {
  const stored = {
    ...observation,
    captures: observation.captures.map((item, index) =>
      index === 0 ? { ...item, retention_days: 30 } : { ...item, retention_days: null },
    ),
  };
  const first = liveOperation(stored, stored.captures[0]?.operation_id ?? "");
  const second = liveOperation(stored, stored.captures[1]?.operation_id ?? "");
  expect(first?.facts.some((fact) => fact.value === "30 days recorded on this capture")).toBe(true);
  expect(second?.facts.some((fact) => fact.value === "Not recorded on this capture")).toBe(true);
});

test("a capture shows its artifact manifest as recorded or not recorded", () => {
  const sha = "ab".repeat(32);
  const shaped = (manifest: unknown) => ({
    ...observation,
    captures: observation.captures.map((item, index) =>
      index === 0 ? { ...item, manifest } : item,
    ),
  });
  const fact = (manifest: unknown) => {
    const stored = shaped(manifest);
    const view = liveOperation(stored, stored.captures[0]?.operation_id ?? "");
    return view?.facts.find((item) => item.label === "Artifact manifest")?.value;
  };
  expect(fact({ sha256: sha, entries: 12, regular_bytes: 3400, truncated: false })).toBe(
    `Recorded: sha256 ${sha.slice(0, 12)}, 12 entries, 3400 bytes`,
  );
  expect(fact({ sha256: sha, entries: 5, regular_bytes: 9, truncated: true })).toBe(
    `Recorded (truncated at a bound): sha256 ${sha.slice(0, 12)}, 5 entries, 9 bytes`,
  );
  const missing = "Not recorded (captured before schema 10 or the listing was refused)";
  for (const bad of [
    null,
    undefined,
    { sha256: "short", entries: 1, regular_bytes: 1, truncated: false },
    { sha256: sha, entries: -1, regular_bytes: 1, truncated: false },
    { sha256: sha, entries: 1, regular_bytes: 1.5, truncated: false },
    { sha256: sha, entries: 1, regular_bytes: 1, truncated: "no" },
    "recorded",
  ]) {
    expect(fact(bad)).toBe(missing);
  }
});

test("missing retention stays unobserved", () => {
  expect(enrolledRetentionText(undefined)).toBe("Target 30 days (D-010). Not in this observation.");
  expect(enrolledRetentionText(0)).toBe("Target 30 days (D-010). Not in this observation.");
});

test("live search lists observed sites and omits fixture shop stories", () => {
  const targets = liveSearchTargets(observation);
  expect(targets.some((item) => item.label === "blog13.example.test")).toBe(true);
  expect(targets.some((item) => item.href === "/operations/op_pr1")).toBe(true);
  expect(targets.some((item) => item.label === "Receipt op_pr1")).toBe(true);
  expect(targets.every((item) => !item.label.includes("shop.lab.test"))).toBe(true);
  expect(targets.every((item) => !item.href.includes("plan_3HV8RA"))).toBe(true);
  expect(targets.every((item) => !item.href.includes("snap_P8Q1"))).toBe(true);
});

test("signer facts are shown only when the observed shape is exact", () => {
  const signer = {
    principal: "lab_agent",
    namespace: "rustiron-plan-v1",
    algorithm: "ssh-ed25519",
    fingerprint: "SHA256:1qxNSGzuxAUJztinl6g7k5tlkJccQie3h6fdhLFn05U",
    revocations_bytes: 0,
    revocations_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  };
  const host = { ...observation.host, signer };
  expect(signerFacts(host)).toEqual(signer);
  expect(signerFacts(observation.host)).toBeNull();
  expect(signerFacts({ ...host, signer: null })).toBeNull();
  expect(signerFacts({ ...host, signer: { ...signer, fingerprint: "MD5:aa" } })).toBeNull();
  expect(signerFacts({ ...host, signer: { ...signer, principal: "<b>" } })).toBeNull();
  expect(signerFacts({ ...host, signer: { ...signer, revocations_bytes: -1 } })).toBeNull();
  expect(signerFacts({ ...host, signer: { ...signer, extra: 1 } })).toBeNull();
  expect(signerRows(signerFacts(host))).toEqual([
    ["Key", "ssh-ed25519 SHA256:1qxNSGzuxAUJztinl6g7k5tlkJccQie3h6fdhLFn05U"],
    ["Namespace", "rustiron-plan-v1"],
    ["Revocations", "Empty list"],
  ]);
  expect(
    signerRows(signerFacts({ ...host, signer: { ...signer, revocations_bytes: 120 } }))[2],
  ).toEqual(["Revocations", "120 bytes · sha256 e3b0c44298fc"]);
  expect(signerRows(null)).toEqual([["Signer key", "Not in this observation"]]);
});

/** W379: the synthetic state observation the browser gate also renders. */
const states = JSON.parse(
  readFileSync(new URL("../e2e/states/w391-observation.json", import.meta.url), "utf8"),
) as Observation;

function must<T>(value: T | null | undefined): T {
  if (value === null || value === undefined) throw new Error("expected a value");
  return value;
}

function journalOf(source: Observation, id: string) {
  return must(must(liveSites(source).find((item) => item.id === id)).journal);
}

function rowOf(source: Observation, id: string) {
  return must(liveOperations(source).find((row) => row.id === id));
}

function detailOf(source: Observation, id: string) {
  return must(liveOperation(source, id));
}

test("an adopted site says adopted, links its re-adoption and is not a provision", () => {
  const site = must(liveSites(states).find((item) => item.id === "w379c"));
  expect(site.ownership).toBe("Adopted");
  expect(site.operation).toBe("Site re-adoption");
  expect(journalOf(states, "w379c").adoption).toEqual({
    operationId: "op_w379_readopt",
    previousEpoch: "epoch_w379_0",
    evidence: "sha256 cccccccccccc",
  });
  expect(journalOf(states, "w379c").quotaLimit).toBe(
    "256 MiB, 20,000 inodes · verified by re-adoption",
  );
  expect(liveOperations(states).filter((row) => row.id === "op_w379_readopt")).toHaveLength(1);
  expect(rowOf(states, "op_w379_readopt").action).toBe("Site re-adoption");
  expect(rowOf(states, "op_w379_readopt").outcome).toBe("Succeeded");
  expect(rowOf(states, "op_w379_readopt_gen").outcome).toBe("Failed · refused READOPT_MISMATCH");
  expect(detailOf(states, "op_w379_readopt_gen").facts).toContainEqual({
    label: "First failed rule",
    value: "generation",
  });
  // An older observation without the re-adoption list still labels the provision.
  const older = { ...states, readoptions: undefined };
  expect(rowOf(older, "op_w379_readopt").outcome).toBe("Succeeded");
});

test("page-cache changes are their own operations and each site states its latest", () => {
  expect(journalOf(states, "w379a").pageCache).toBe("Opted in");
  expect(journalOf(states, "w379b").pageCache).toBe("Opted out");
  expect(journalOf(states, "w379d").pageCache).toBe("Not opted in (no change recorded)");
  expect(rowOf(states, "op_w379_pc_out").action).toBe("Page cache opt-out");
  expect(rowOf(states, "op_w379_pc_in").resources).toBe("w379a · global OLS");
  const pending = {
    ...states,
    operations: states.operations.map((item) =>
      item.operation_id === "op_w379_pc_out" ? { ...item, state: "needs_attention" } : item,
    ),
  };
  expect(journalOf(pending, "w379b").pageCache).toBe(
    "Opted out · latest change op_w379_pc_out is needs_attention",
  );
  const older = {
    ...states,
    sites: states.sites.map((site) => ({ ...site, page_cache: undefined })),
  };
  expect(journalOf(older, "w379a").pageCache).toBe("Not in this observation");
  // W395: an opt-in with the cache-on recipe states that the cache is on.
  const cacheOn = {
    ...states,
    sites: states.sites.map((site) =>
      site.site_id === "w379a" ? { ...site, page_cache: "cache_on" as const } : site,
    ),
  };
  expect(journalOf(cacheOn, "w379a").pageCache).toBe(
    "Opted in · page cache on for anonymous visitors",
  );
});

test("recorded quota limits are stated and usage is never guessed", () => {
  expect(journalOf(states, "w379a").quotaLimit).toBe("5 GiB, 500,000 inodes · signed site plan");
  expect(journalOf(states, "w379a").quotaUsage).toContain("export SITE");
  expect(quotaLimitText(undefined)).toBe("Not in this observation");
  expect(quotaLimitText({ state: "not_enforced", source: "policy" })).toContain("Not enforced");
  expect(quotaLimitText({ state: "not_recorded" })).toContain("before per-site quotas");
  expect(quotaLimitText({ state: "not_attempted" })).toContain("never began");
  expect(quotaLimitText({ state: "malformed" })).toContain("malformed");
  expect(quotaLimitText({ state: "enforced", block_hard_kib: 0, inode_hard: 1 })).toContain(
    "malformed",
  );
  expect(quotaLimitText({ state: "enforced", block_hard_kib: 512, inode_hard: 9 })).toBe(
    "512 KiB, 9 inodes",
  );
});

test("a capture's label, refusal and running state say what the journal records", () => {
  const matched = detailOf(states, "op_w379_cap_1");
  expect(matched.facts).toContainEqual({
    label: "Consistency label",
    value:
      "Matched: the database marker read before the dump equals the one after the snapshot check",
  });
  expect(matched.notice).toBeNull();
  const refused = detailOf(states, "op_w379_cap_2");
  expect(refused.outcome).toBe("Failed · no snapshot");
  expect(refused.facts).toContainEqual({
    label: "Refusal code",
    value: "Not recorded in the journal",
  });
  const running = detailOf(states, "op_w379_cap_4");
  expect(running.notice).toContain("Outcome uncertain");
  expect(running.unknown).toContain("No snapshot id is recorded yet");
  expect(consistencyText(undefined)).toBeNull();
  expect(consistencyText(null)).toBe("Not recorded for this capture");
  expect(consistencyText({ label: "unmatched", reason: "not_checked" })).toBe(
    "Unmatched: no marker check is recorded",
  );
  expect(consistencyText({ label: "unmatched", reason: "freeze_not_held" })).toBe(
    "Unmatched: the freeze was not proved to hold",
  );
  expect(consistencyText({ label: "other", reason: null })).toContain("not recognised");
});

test("W391: stored retention evidence and a refusal code are stated as recorded", () => {
  const evidenced = detailOf(states, "op_w391_cap_1");
  expect(evidenced.facts).toContainEqual({
    label: "Retention evidence",
    value: "7 object versions read back, COMPLIANCE",
  });
  expect(evidenced.facts).toContainEqual({
    label: "Bucket lock",
    value: "COMPLIANCE 30 days before, 30 days after",
  });
  expect(evidenced.facts.find((fact) => fact.label === "Retained until")?.value).toContain(" to ");
  expect(
    evidenced.unknown.some((line) => line.includes("after the postcheck is not observed")),
  ).toBe(true);
  const coded = detailOf(states, "op_w391_cap_2");
  expect(coded.outcome).toBe("Failed · no snapshot");
  expect(coded.facts).toContainEqual({ label: "Refusal code", value: "RETENTION_LOCK_UNVERIFIED" });
  expect(coded.observed).toContain(
    "Refused with RETENTION_LOCK_UNVERIFIED before the snapshot step; no snapshot was written",
  );
  // An older succeeded row without the field shows nothing new; a null reads not recorded.
  const base = must(states.captures.find((item) => item.operation_id === "op_w379_cap_1"));
  expect(captureRetentionEvidence(base)).toBeNull();
  expect(captureRetentionEvidence({ ...base, retention: null })?.facts).toContainEqual({
    label: "Retention evidence",
    value: "Not recorded on this capture",
  });
  // A malformed summary is never shown as recorded.
  const recorded = must(
    states.captures.find((item) => item.operation_id === "op_w391_cap_1")?.retention,
  );
  expect(
    captureRetentionEvidence({ ...base, retention: { ...recorded, objects: 0 } })?.facts[0]?.value,
  ).toBe("Not recorded on this capture");
});

test("an unclaimed snapshot is named as evidence and never as a backup of record", () => {
  const settled = detailOf(states, "op_w379_cap_3");
  expect(settled.outcome).toBe("Failed · unclaimed snapshot");
  expect(settled.notice).toContain("is not a backup of record");
  expect(settled.facts).toContainEqual({
    label: "Unclaimed snapshot",
    value: "f184d11a · not a backup of record",
  });
  expect(settled.facts).toContainEqual({ label: "Snapshot", value: "None recorded" });
  const recovery = must(liveRecovery(states).find((row) => row.siteId === "w379d"));
  expect(recovery.snapshot).toBeNull();
  expect(recovery.snapshotNote).toBe("No snapshot of record · 1 unclaimed, not a backup of record");
  expect(liveSiteSnapshots(states).w379d).toEqual([]);
  expect(liveSnapshot(states, "f184d11a")).toBeNull();
});

test("a refused probe names its code and a passed probe explains D-026", () => {
  expect(detailOf(states, "op_w379_probe_2").facts).toContainEqual({
    label: "Refusal code",
    value: "NOT_ADMITTED_FOR_EFFECT",
  });
  expect(liveReceipt(states, "op_w379_probe_2")).toBeNull();
  const receipt = must(liveReceipt(states, "op_w379_probe_1"));
  expect(receipt.stateLabel).toBe("Passed");
  expect(receipt.fields).toHaveLength(7);
  expect(receipt.fields[6]).toEqual({
    name: "Independent copy confirmed",
    mark: "not_run",
    scope:
      "D-026: the probe restores from the enrolled store only; no independent or off-site copy is checked",
  });
  expect(receipt.independence).toContain("D-026 defers independent and off-site copies");
});

test("only the exact not-enrolled refusal document is recognised", () => {
  const document = JSON.parse(
    readFileSync(new URL("../e2e/states/not-enrolled.json", import.meta.url), "utf8"),
  ) as unknown;
  expect(isExecutorRefusal(document)).toBe(true);
  expect(isExecutorRefusal({ schema: "rustiron-executor-refusal/1", error: "OTHER" })).toBe(false);
  expect(
    isExecutorRefusal({
      schema: "rustiron-executor-refusal/1",
      error: "EXECUTOR_NOT_ENROLLED",
      sites: [],
    }),
  ).toBe(false);
  expect(isExecutorRefusal(null)).toBe(false);
});

test("a not-enrolled executor is its own empty state, not a fault or stale data", async () => {
  const directory = await mkdtemp(join(tmpdir(), "ri-not-enrolled-"));
  const file = join(directory, "observation.json");
  await writeFile(
    file,
    JSON.stringify({ schema: "rustiron-executor-refusal/1", error: "EXECUTOR_NOT_ENROLLED" }),
  );
  const route = observationRoute(file);
  const original = globalThis.fetch;
  globalThis.fetch = (async () =>
    route(new Request("http://console.test/api/observation"))) as unknown as typeof fetch;
  try {
    const router = createRouter({
      routeTree,
      history: createMemoryHistory({ initialEntries: ["/sites"] }),
    });
    render(<RouterProvider router={router} />);
    expect(await screen.findByText("Executor not enrolled")).toBeDefined();
    expect(screen.getByText("Live · executor not enrolled")).toBeDefined();
    expect(screen.queryByText("shop.lab.test")).toBeNull();
    expect(screen.queryByText(/Live data unavailable/)).toBeNull();
  } finally {
    globalThis.fetch = original;
    await rm(directory, { recursive: true });
  }
});

test("a site's last capture says what the journal records, the unclaimed snapshot included", () => {
  // W382: a settled capture (W366) keeps an unclaimed snapshot. The site row
  // names it as W379 does on the operations page, never as "no snapshot".
  const sites = liveSites(states);
  const settled = must(sites.find((site) => site.id === "w379d"));
  expect(settled.operation).toBe("Backup capture");
  expect(settled.operationDetail).toMatch(/^Failed · unclaimed snapshot · .+ UTC$/);
  expect(settled.operationHref).toBe("/operations/op_w379_cap_3");
  const running = must(sites.find((site) => site.id === "w379b"));
  expect(running.operationDetail).toMatch(/^Running · .+ UTC$/);
  const probed = must(sites.find((site) => site.id === "w379a"));
  expect(probed.operation).toBe("Restore probe");
  expect(probed.operationDetail).toMatch(/^Succeeded · .+ UTC$/);
});

test("a site with only an unclaimed snapshot says so in its snapshot table", async () => {
  // W382: the empty snapshot table of a settled capture's site names the
  // unclaimed snapshot instead of "No snapshots recorded".
  const directory = await mkdtemp(join(tmpdir(), "ri-unclaimed-"));
  const file = join(directory, "observation.json");
  await writeFile(file, JSON.stringify(states));
  const route = observationRoute(file);
  const original = globalThis.fetch;
  globalThis.fetch = (async () =>
    route(new Request("http://console.test/api/observation"))) as unknown as typeof fetch;
  try {
    const router = createRouter({
      routeTree,
      history: createMemoryHistory({ initialEntries: ["/sites/w379d/recovery"] }),
    });
    render(<RouterProvider router={router} />);
    await screen.findByText("Newest first · retention follows repository policy");
    const table = must(document.querySelector('[role="region"][aria-label="Snapshots"]'));
    expect(table.textContent).toContain(
      "No snapshot of record · 1 unclaimed, not a backup of record",
    );
    expect(table.textContent).not.toContain("No snapshots recorded for this site.");
  } finally {
    globalThis.fetch = original;
    await rm(directory, { recursive: true });
  }
});

test("W702: the Services fact lines keep their order and skip unreported facts", () => {
  const machine = {
    ...fixtureMachine(),
    tls: { listeners_443: 2 },
    firewall: { readable: true, state: "running", default_zone: "public", services: ["ssh"] },
    failed_units: { readable: true, units: [] },
  };
  expect(serviceFactLines(machine, observation.sites)).toEqual([
    "2 TLS listeners on port 443. Certificate expiry was not read.",
    "Firewall running · zone public · services ssh",
    "No failed units",
  ]);
  expect(serviceFactLines({ ...machine, firewall: undefined }, observation.sites)).toEqual([
    "2 TLS listeners on port 443. Certificate expiry was not read.",
    "No failed units",
  ]);
  expect(serviceFactLines(null, observation.sites)).toEqual([]);
});

test("W737 (QA-06): a live site's HTTP card names its observation, not a fixed time", async () => {
  const directory = await mkdtemp(join(tmpdir(), "ri-http-time-"));
  const file = join(directory, "observation.json");
  await writeFile(file, JSON.stringify(observation));
  const route = observationRoute(file);
  const original = globalThis.fetch;
  globalThis.fetch = (async () =>
    route(new Request("http://console.test/api/observation"))) as unknown as typeof fetch;
  try {
    const router = createRouter({
      routeTree,
      history: createMemoryHistory({ initialEntries: ["/sites/blog13"] }),
    });
    render(<RouterProvider router={router} />);
    const card = await screen.findByLabelText("Site HTTP observation");
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 50));
    });
    expect(card.textContent).toMatch(/HTTP 200 · observed \d\d:\d\d UTC · \d+ (s|min|h) ago/);
    expect(document.body.textContent).not.toContain("16:41 UTC");
    expect(document.body.textContent).toContain("HTTP comes from the host status");
  } finally {
    globalThis.fetch = original;
    await rm(directory, { recursive: true });
  }
});

test("W750 (QA-19): the site header chips name their facts", async () => {
  const directory = await mkdtemp(join(tmpdir(), "ri-site-chips-"));
  const file = join(directory, "observation.json");
  await writeFile(file, JSON.stringify(observation));
  const route = observationRoute(file);
  const original = globalThis.fetch;
  globalThis.fetch = (async () =>
    route(new Request("http://console.test/api/observation"))) as unknown as typeof fetch;
  try {
    const router = createRouter({
      routeTree,
      history: createMemoryHistory({ initialEntries: ["/sites/blog13"] }),
    });
    render(<RouterProvider router={router} />);
    expect(await screen.findByText(/^Serving: /)).toBeDefined();
    expect(screen.getByText(/^Runtime: /)).toBeDefined();
  } finally {
    globalThis.fetch = original;
    await rm(directory, { recursive: true });
  }
});

test("W751 (QA-20): a compensated failure is not shown with a check mark", () => {
  const row = must(liveOperations(observation).find((item) => item.id === "op_ej1"));
  expect(row.outcome).toBe("Failed, compensated");
  expect(row.icon).toBe(RotateCcw);
  expect(row.icon).not.toBe(CircleCheck);
});

test("W752 (QA-21): an unknown domain gets a not-found state, a served one renders", async () => {
  const directory = await mkdtemp(join(tmpdir(), "ri-domain-404-"));
  const file = join(directory, "observation.json");
  await writeFile(file, JSON.stringify(observation));
  const route = observationRoute(file);
  const original = globalThis.fetch;
  globalThis.fetch = (async () =>
    route(new Request("http://console.test/api/observation"))) as unknown as typeof fetch;
  try {
    const router = createRouter({
      routeTree,
      history: createMemoryHistory({ initialEntries: ["/domains/nope.example.org"] }),
    });
    render(<RouterProvider router={router} />);
    expect(await screen.findByText("Domain not found on this host")).toBeDefined();
    expect(screen.queryByRole("button", { name: /Manage DNS records/ })).toBeNull();
    await act(() =>
      router.navigate({ to: "/domains/$hostname", params: { hostname: "blog13.example.test" } }),
    );
    expect(
      await screen.findByRole("heading", { level: 1, name: "blog13.example.test" }),
    ).toBeDefined();
    expect(screen.queryByText("Domain not found on this host")).toBeNull();
  } finally {
    globalThis.fetch = original;
    await rm(directory, { recursive: true });
  }
});

test("W754 (QA-23): pages ask the coordinator for evidence and site records only on demand", async () => {
  const directory = await mkdtemp(join(tmpdir(), "ri-on-demand-"));
  const file = join(directory, "observation.json");
  await writeFile(file, JSON.stringify(observation));
  const route = observationRoute(file);
  const asked: string[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url.includes("/api/backend/status")) {
      return Response.json({
        schema: "rustiron-console-backend/1",
        mode: "read_only",
        d090_hardened: true,
        write_workflows_enabled: false,
        observation_configured: true,
        coordinator_configured: true,
        coordinator_reachable: true,
        doctor: null,
      });
    }
    if (url.includes("/api/coordinator/")) {
      asked.push(new URL(url, "http://console.test").pathname);
      return Response.json({ schema_version: 1, status: "ok", data: null });
    }
    return route(new Request("http://console.test/api/observation"));
  }) as unknown as typeof fetch;
  try {
    const router = createRouter({
      routeTree,
      history: createMemoryHistory({ initialEntries: ["/operations/op_ej1"] }),
    });
    render(<RouterProvider router={router} />);
    await screen.findByRole("button", { name: /Query coordinator/ });
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 50));
    });
    expect(asked.some((path) => path.startsWith("/api/coordinator/evidence/"))).toBe(false);
    expect(asked).toContain("/api/coordinator/operations/op_ej1");
    await act(() => router.navigate({ to: "/sites/$siteId", params: { siteId: "blog13" } }));
    await screen.findByText(/Live coordinator record/);
    expect(asked.some((path) => path.startsWith("/api/coordinator/sites/"))).toBe(false);
  } finally {
    globalThis.fetch = original;
    await rm(directory, { recursive: true });
  }
});
