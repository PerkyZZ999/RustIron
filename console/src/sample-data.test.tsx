// W732 (QA-01): a Console on a real host never shows the sample host. With no
// live source, pages say nothing is observed instead of falling back to the
// sample data that the fixture mode shows.
import { afterEach, expect, test } from "bun:test";
import { cleanup, render, screen } from "@testing-library/react";
import { createMemoryHistory, createRouter, RouterProvider } from "@tanstack/react-router";

import { resolveBackupSite } from "./backup-migration-wizards";
import { unavailableReason } from "./data";
import { routeTree } from "./router";

afterEach(cleanup);

const SAMPLE_TEXT = [
  "lab-01",
  "op_7Q2KX9",
  "shop.lab.test",
  "portfolio.lab.test",
  "Operation needs attention",
  "Decryption test failed",
  "25-minute collection gap",
  "Observed 24 Oct 2026",
];

/** The wizard-deployed Console of QA-02: no observation file, coordinator refused. */
function unavailableBackend(input: string | URL | Request): Response {
  const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
  if (url.includes("/api/backend/status")) {
    return Response.json({
      schema: "rustiron-console-backend/1",
      mode: "read_only",
      d090_hardened: true,
      write_workflows_enabled: false,
      observation_configured: false,
      coordinator_configured: true,
      coordinator_reachable: false,
      doctor: null,
    });
  }
  if (url.includes("/api/observation")) {
    return Response.json({ error: "LIVE_SOURCE_NOT_CONFIGURED" }, { status: 503 });
  }
  if (url.includes("/api/coordinator/")) {
    return Response.json({ error: "UNAUTHORIZED_PEER" }, { status: 403 });
  }
  return Response.json({ error: "NOT_FOUND" }, { status: 404 });
}

for (const [path, heading] of [
  ["/", "Host overview"],
  ["/recovery", "Backups"],
  ["/recovery/schedules", "Scheduled capture"],
  ["/host/metrics", "Host metrics"],
  ["/host/services", "Services"],
  ["/host/diagnoses", "Host diagnoses"],
  ["/host/cron", "Cron jobs & timers"],
  ["/sites", "Websites"],
  ["/domains", "Domains"],
  ["/databases", "Databases"],
  ["/apps", "Apps"],
  ["/migration", "Migration"],
  ["/operations", "Operations"],
  ["/help", "Docs & Knowledge Base"],
] as const) {
  test(`${path} shows no sample host when the live source is unavailable (QA-01)`, async () => {
    const original = globalThis.fetch;
    globalThis.fetch = (async (input: string | URL | Request) =>
      unavailableBackend(input)) as unknown as typeof fetch;
    try {
      const router = createRouter({
        routeTree,
        history: createMemoryHistory({ initialEntries: [path] }),
      });
      render(<RouterProvider router={router} />);
      await screen.findByRole("heading", { level: 1, name: heading });
      await screen.findAllByText(/Unavailable/);
      const text = document.body.textContent ?? "";
      for (const sample of SAMPLE_TEXT) expect(text).not.toContain(sample);
      expect(text).not.toContain("Connected");
    } finally {
      globalThis.fetch = original;
    }
  });
}

// W736 (QA-05): before the first reply the Console knows nothing about the host,
// so a full page load never flashes the sample sites.
for (const [path, heading] of [
  ["/", "Host overview"],
  ["/sites", "Websites"],
  ["/recovery", "Backups"],
  ["/help", "Docs & Knowledge Base"],
] as const) {
  test(`${path} shows no sample data while the first observation loads (QA-05)`, async () => {
    const original = globalThis.fetch;
    globalThis.fetch = (() => new Promise<Response>(() => {})) as unknown as typeof fetch;
    try {
      const router = createRouter({
        routeTree,
        history: createMemoryHistory({ initialEntries: [path] }),
      });
      render(<RouterProvider router={router} />);
      await screen.findByRole("heading", { level: 1, name: heading });
      const text = document.body.textContent ?? "";
      for (const sample of SAMPLE_TEXT) expect(text).not.toContain(sample);
      expect(text).not.toContain("site_8KD2QW");
    } finally {
      globalThis.fetch = original;
    }
  });
}

test("the backup panel targets only a site in the current list (QA-07)", () => {
  const live = [{ id: "p01r" }, { id: "cp02" }];
  expect(resolveBackupSite("", live)).toBe("p01r");
  expect(resolveBackupSite("cp02", live)).toBe("cp02");
  // A choice from the sample list never survives the live list.
  expect(resolveBackupSite("site_8KD2QW", live)).toBe("p01r");
  expect(resolveBackupSite("typed", [])).toBe("typed");
});

test("the unavailable banner names the cause and what to check (QA-14)", async () => {
  expect(unavailableReason(403, "UNAUTHORIZED_PEER")).toContain(
    "run the Console as rustiron-coordinator",
  );
  expect(unavailableReason(503, "LIVE_SOURCE_NOT_CONFIGURED")).toContain("RUSTIRON_OBSERVATION");
  expect(unavailableReason(500, "SOMETHING")).toBe("The server answered 500 (SOMETHING)");
  expect(unavailableReason(null, null)).toBe("The Console server did not answer");
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request) =>
    unavailableBackend(input)) as unknown as typeof fetch;
  try {
    const router = createRouter({
      routeTree,
      history: createMemoryHistory({ initialEntries: ["/"] }),
    });
    render(<RouterProvider router={router} />);
    expect(await screen.findByText(/The coordinator refused the Console's user/)).toBeTruthy();
  } finally {
    globalThis.fetch = original;
  }
});
