import { afterEach, expect, test } from "bun:test";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { createMemoryHistory, createRouter, RouterProvider } from "@tanstack/react-router";

import { allowedLoopbackHosts } from "./backend-server";
import type { Machine, Observation } from "./live";
import { allowedLogUnits, createHostLogsHandler, redactLogLine } from "./logs-backend";
import { liveDomains, liveFindings, liveSupportComponents } from "./platform-data";
import { routeTree } from "./router";

afterEach(cleanup);

test("apps page shows P27/P30 workloads and opens the slide-over inspector only when selected", async () => {
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ["/apps"] }),
  });
  render(<RouterProvider router={router} />);
  expect(await screen.findByRole("heading", { level: 1, name: "Apps" })).toBeTruthy();
  expect(screen.getByRole("button", { name: "emdash.lab.test" })).toBeTruthy();
  expect(screen.queryByText(/EMDASH_ENCRYPTION_KEY/)).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "emdash.lab.test" }));
  expect(screen.getByText(/EMDASH_ENCRYPTION_KEY/)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "dashboard.lab.test" }));
  expect(screen.getByText(/Automatic rollback preserved serving/)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Close app details" }));
  expect(screen.queryByText(/Automatic rollback preserved serving/)).toBeNull();

  await act(() => router.navigate({ to: "/apps/$appId", params: { appId: "app_emdash" } }));
  expect(await screen.findByRole("heading", { level: 1, name: "emdash.lab.test" })).toBeTruthy();
  fireEvent.click(screen.getByRole("link", { name: "Configuration & secrets" }));
  expect(screen.getAllByText(/0400 value hidden/).length).toBeGreaterThan(0);
});

test("host diagnoses keeps open findings visible and collapses passed checks by default", async () => {
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ["/host/diagnoses"] }),
  });
  render(<RouterProvider router={router} />);
  expect(await screen.findByRole("heading", { level: 1, name: "Host diagnoses" })).toBeTruthy();
  const toggle = screen.getByRole("button", { name: /Passed checks/ });
  expect(toggle.getAttribute("aria-expanded")).toBe("false");
  fireEvent.click(screen.getByRole("button", { name: "SSH" }));
  expect(screen.getAllByText(/sshd -T/).length).toBeGreaterThan(0);
  fireEvent.click(toggle);
  expect(toggle.getAttribute("aria-expanded")).toBe("true");
  expect(screen.getByRole("button", { name: "SELinux" })).toBeTruthy();
});

test("host updates, domains, and migration views render read-only platform evidence", async () => {
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ["/host/updates"] }),
  });
  render(<RouterProvider router={router} />);
  expect(await screen.findByRole("heading", { level: 1, name: "Host updates" })).toBeTruthy();
  expect(screen.getByRole("button", { name: "PowerDNS" })).toBeTruthy();

  await act(() => router.navigate({ to: "/domains" }));
  expect(await screen.findByRole("heading", { level: 1, name: "Domains" })).toBeTruthy();
  expect(screen.getByRole("button", { name: "emdash.lab.test" })).toBeTruthy();

  await act(() => router.navigate({ to: "/migration" }));
  expect(await screen.findByRole("heading", { level: 1, name: "Migration" })).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "imp_3a09" }));
  expect(screen.getByText(/SECOND_DATABASE/)).toBeTruthy();
});

test("live derivations report honest diagnoses, support versions, and domain summaries", () => {
  const machine: Machine = {
    schema: "rustiron-host-status/1",
    observed_at: 1_760_000_000,
    os: { name: "AlmaLinux", version: "10.3", kernel: "6.12.0" },
    uptime_seconds: 1200,
    cpu: { count: 4, load: [0.1, 0.2, 0.3] },
    memory: { total_bytes: 8_000_000_000, available_bytes: 4_000_000_000 },
    disk: { path: "/srv/sites", total_bytes: 50_000_000_000, available_bytes: 30_000_000_000 },
    selinux: "Enforcing",
    clock: { synchronized: true },
    ssh: {
      readable: false,
      permit_root_login: null,
      password_authentication: null,
      pubkey_authentication: null,
      kbd_interactive_authentication: null,
    },
    firewall: { readable: false, state: null, default_zone: null, services: null },
    database: { socket: "/run/mariadb/mariadb.sock", ping: "responding" },
    stack: { openlitespeed: "1.8.4", mariadb: "10.11.15", php: ["8.4.18"] },
    services: [],
  };
  const observation = {
    schema: "rustiron-lab-observation/1",
    host: {
      host_id: "h1",
      host_epoch: "e1",
      issuer: "lab_agent",
      signer_policy_epoch: "policy_3",
      ols_listener: "0.0.0.0:80",
      backup_destination: "s3://lab/bucket",
    },
    sites: [
      {
        site_id: "s_1",
        hostname: "app.example.test",
        state: "active",
        ejected: false,
      },
      {
        site_id: "s_2",
        hostname: "q.example.test",
        state: "quarantined",
        failed_step: "ols_reload",
      },
    ],
    captures: [{ unclaimed_snapshot_id: "snap_unclaimed" }],
  } as unknown as Observation;

  const findings = liveFindings(observation, machine);
  expect(findings.some((f) => f.id === "live-selinux" && f.state === "ok")).toBe(true);
  expect(findings.some((f) => f.id === "live-ssh" && f.state === "unknown")).toBe(true);
  expect(findings.some((f) => f.id === "live-firewalld" && f.state === "unknown")).toBe(true);
  expect(findings.some((f) => f.id === "live-storage" && f.state === "ok")).toBe(true);
  expect(findings.some((f) => f.id === "live-site-s_2" && f.state === "fail")).toBe(true);
  expect(findings.some((f) => f.id === "live-unclaimed" && f.state === "warn")).toBe(true);

  const observedMachine: Machine = {
    ...machine,
    selinux: "enforcing",
    ssh: {
      readable: true,
      permit_root_login: "without-password",
      password_authentication: "no",
      pubkey_authentication: "yes",
      kbd_interactive_authentication: "no",
    },
    firewall: {
      readable: true,
      state: "running",
      default_zone: "rustiron",
      services: ["http", "https", "ssh"],
    },
  };
  const observedFindings = liveFindings(observation, observedMachine);
  expect(observedFindings.some((f) => f.id === "live-selinux" && f.state === "ok")).toBe(true);
  expect(observedFindings.some((f) => f.id === "live-ssh" && f.state === "ok")).toBe(true);
  expect(observedFindings.some((f) => f.id === "live-firewalld" && f.state === "ok")).toBe(true);

  const components = liveSupportComponents(machine);
  expect(components.find((c) => c.id === "comp-ols")?.observed).toBe("1.8.4");
  expect(components.find((c) => c.id === "comp-php")?.observed).toBe("8.4.18");

  const domains = liveDomains(
    [
      {
        id: "s_1",
        domain: "app.example.test",
        serving: "Serving",
        servingKind: "ok",
        runtime: "Node 22",
        ownership: "Created",
        operation: "Deployed",
        operationDetail: "op_1",
        operationHref: null,
        marks: ["pass", "pass", "pass", "pass", "pass", "pass", "pass"],
        http: "200",
        httpKind: "ok",
      },
    ],
    observation,
  );
  expect(domains[0]?.hostname).toBe("app.example.test");
  expect(domains[0]?.certificateLabel).toBe("Not observed in journal");
  expect(domains[0]?.renewedBy).toBe("—");
});

test("sites inspector drawer, recovery subviews, and domain DNS views render read-only", async () => {
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ["/sites"] }),
  });
  render(<RouterProvider router={router} />);
  expect(await screen.findByRole("heading", { level: 1, name: "Sites" })).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Inspect shop.lab.test" }));
  expect(screen.getByRole("complementary", { name: "Details for shop.lab.test" })).toBeTruthy();
  fireEvent.change(screen.getByLabelText("Filter sites by hostname"), {
    target: { value: "blog" },
  });
  expect(screen.getByRole("link", { name: "blog.lab.test" })).toBeTruthy();

  await act(() => router.navigate({ to: "/recovery/schedules" }));
  expect(await screen.findByRole("heading", { level: 1, name: "Scheduled capture" })).toBeTruthy();
  expect(screen.getByText("sg_03")).toBeTruthy();

  await act(() => router.navigate({ to: "/recovery/store" }));
  expect(await screen.findByRole("heading", { level: 1, name: "Backup store" })).toBeTruthy();
  expect(screen.getByText(/COMPLIANCE mode/)).toBeTruthy();

  await act(() =>
    router.navigate({ to: "/domains/$hostname", params: { hostname: "blog.lab.test" } }),
  );
  expect(await screen.findByRole("heading", { level: 1, name: "blog.lab.test" })).toBeTruthy();
  expect(screen.getByText(/ECDSA P-256/)).toBeTruthy();

  await act(() =>
    router.navigate({ to: "/domains/$hostname/dns", params: { hostname: "blog.lab.test" } }),
  );
  expect(await screen.findByText(/Records for blog\.lab\.test/)).toBeTruthy();
  expect(screen.getAllByText(/Protected mail/).length).toBeGreaterThan(0);

  await act(() =>
    router.navigate({
      to: "/migration/emdash/$migrationId",
      params: { migrationId: "wxr_emdash_01" },
    }),
  );
  expect(
    await screen.findByRole("heading", { level: 1, name: "WordPress → EmDash CMS rehearsal" }),
  ).toBeTruthy();
  expect(screen.getByText(/301 verified/)).toBeTruthy();
});

test("W624 views: host alerts, firewall, mail relay, site maintenance, apps filter, and persisted settings", async () => {
  localStorage.removeItem("ri-prefs");
  delete document.documentElement.dataset.transparency;

  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ["/host/alerts"] }),
  });
  render(<RouterProvider router={router} />);
  expect(await screen.findByRole("heading", { level: 1, name: "Alerts" })).toBeTruthy();
  expect(screen.getAllByText(/Uptime Kuma/).length).toBeGreaterThan(0);

  await act(() => router.navigate({ to: "/host/firewall" }));
  expect(await screen.findByRole("heading", { level: 1, name: "Firewall" })).toBeTruthy();
  expect(screen.getByText(/zz-rustiron-loopback\.cnf/)).toBeTruthy();

  await act(() => router.navigate({ to: "/mail" }));
  expect(await screen.findByRole("heading", { level: 1, name: "Email" })).toBeTruthy();
  expect(screen.getByText(/rustiron_mail_relay/)).toBeTruthy();

  await act(() =>
    router.navigate({ to: "/sites/$siteId/maintenance", params: { siteId: "site_8KD2QW" } }),
  );
  expect(await screen.findByText(/Database password rotation/)).toBeTruthy();
  expect(screen.getAllByText(/site_credential_rotate/).length).toBeGreaterThan(0);

  await act(() => router.navigate({ to: "/apps" }));
  fireEvent.click(screen.getByRole("button", { name: "Bun app" }));
  expect(screen.getByRole("button", { name: "api.lab.test" })).toBeTruthy();
  expect(screen.queryByRole("button", { name: "emdash.lab.test" })).toBeNull();

  await act(() => router.navigate({ to: "/settings" }));
  fireEvent.change(screen.getByLabelText("Transparency"), { target: { value: "reduce" } });
  fireEvent.click(screen.getByRole("button", { name: "Save preferences" }));
  expect(document.documentElement.getAttribute("data-transparency")).toBe("reduce");
  expect(localStorage.getItem("ri-prefs")).toContain('"transparency":"reduce"');
  expect(screen.getByText(/Automation & remote access/)).toBeTruthy();
});

test("W626 live mode never leaks fixture rows in Apps, Migration, DNS, EmDash, Updates, or Metrics", async () => {
  const liveObs: Observation = {
    schema: "rustiron-lab-observation/1",
    host: {
      host_id: "prod-live-01",
      host_epoch: "epoch_live",
      issuer: "operator",
      signer_policy_epoch: "policy_live",
      ols_listener: "live",
      backup_destination: null,
    },
    journal_last_time: 1_795_500_000,
    sites: [
      {
        site_id: "wp_live",
        hostname: "live.example.test",
        operation_id: "op_live_wp",
        state: "succeeded",
        steps_done: 8,
        steps_recorded: 8,
        ejected: false,
      },
    ],
    operations: [],
    captures: [],
    probes: [],
  };
  const origFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url.includes("/api/observation")) {
      return Response.json({ observed_at: Date.now(), observation: liveObs });
    }
    return Response.json({
      mode: "read_only",
      d090_hardened: true,
      coordinator_configured: false,
      coordinator_reachable: false,
      write_workflows_enabled: false,
      observation_configured: true,
      server_time_ms: Date.now(),
    });
  }) as unknown as typeof fetch;

  try {
    const router = createRouter({
      routeTree,
      history: createMemoryHistory({ initialEntries: ["/apps"] }),
    });
    render(<RouterProvider router={router} />);
    expect(await screen.findByText(/No modern apps deployed on this host yet/)).toBeTruthy();
    expect(screen.queryByText(/emdash\.lab\.test/)).toBeNull();
    expect(screen.queryByText(/api\.lab\.test/)).toBeNull();

    await act(() => router.navigate({ to: "/migration" }));
    expect(
      await screen.findByText(/No migration or import operations recorded on this host yet/),
    ).toBeTruthy();
    expect(screen.queryByText(/shop\.lab\.test/)).toBeNull();

    await act(() =>
      router.navigate({ to: "/domains/$hostname/dns", params: { hostname: "live.example.test" } }),
    );
    expect(
      await screen.findByText(/No live RRset export in observation for live\.example\.test/),
    ).toBeTruthy();
    expect(screen.queryByText(/192\.0\.2\.10/)).toBeNull();

    await act(() =>
      router.navigate({
        to: "/migration/emdash/$migrationId",
        params: { migrationId: "wxr_emdash_01" },
      }),
    );
    expect(
      await screen.findByText(/Offline WXR parity report stays on the operator workstation/),
    ).toBeTruthy();
    expect(screen.queryByText(/42 posts/)).toBeNull();

    await act(() => router.navigate({ to: "/host/updates" }));
    expect(await screen.findByRole("heading", { level: 1, name: "Host updates" })).toBeTruthy();
    expect(screen.queryByText(/10\.11\.11/)).toBeNull();
    expect(screen.getAllByText("Not observed").length).toBeGreaterThan(0);

    await act(() => router.navigate({ to: "/host/metrics" }));
    expect((await screen.findAllByText(/Waiting for host metric samples/)).length).toBe(3);
  } finally {
    globalThis.fetch = origFetch;
  }
});

test("W651 liveSupportComponents observes Node.js, Bun, MariaDB 10.11, and optional PowerDNS", () => {
  const fullStackMachine: Machine = {
    schema: "rustiron-host-status/1",
    observed_at: 1_795_000_000,
    os: { name: "AlmaLinux", version: "10.3", kernel: "6.12.0" },
    cpu: { count: 4, load: [0.2, 0.15, 0.1] },
    memory: { total_bytes: 8e9, available_bytes: 5e9 },
    disk: { path: "/srv/sites", total_bytes: 40e9, available_bytes: 30e9 },
    selinux: "Enforcing",
    uptime_seconds: 1200,
    services: [],
    stack: {
      openlitespeed: "1.9.4",
      mariadb: "10.11.18",
      php: ["8.4.28"],
      nodejs: "22.23.4",
      bun: "1.4.5",
      powerdns: null,
    },
  };
  const liveComps = liveSupportComponents(fullStackMachine, true);
  expect(liveComps.find((c) => c.id === "comp-node")?.observed).toBe("22.23.4");
  expect(liveComps.find((c) => c.id === "comp-bun")?.observed).toBe("1.4.5");
  expect(liveComps.find((c) => c.id === "comp-pdns")?.observed).toBe("Not installed");
  expect(liveComps.find((c) => c.id === "comp-pdns")?.state).toBe("optional");
  expect(liveComps.find((c) => c.id === "comp-mariadb")?.series).toBe("10.11 LTS");
});

test("W628 hosting wizards: Create Website, Add Domain/Zone, and interactive DNS Record Editor", async () => {
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ["/sites/new"] }),
  });
  render(<RouterProvider router={router} />);
  expect(await screen.findByRole("heading", { level: 1, name: "Add website" })).toBeTruthy();
  const domainInput = screen.getByLabelText("Domain name");
  fireEvent.change(domainInput, { target: { value: "invalid host!" } });
  expect(screen.getByText(/Domain must be a valid hostname/)).toBeTruthy();
  fireEvent.change(domainInput, { target: { value: "store.example.com" } });
  expect(screen.getByText(/site-provision .*--site-id 'storeexamplecom'/)).toBeTruthy();
  fireEvent.click(screen.getByRole("radio", { name: /EmDash CMS/ }));
  expect(screen.getByText(/app-provision .*--site-id 'storeexamplecom'/)).toBeTruthy();

  await act(() => router.navigate({ to: "/domains/new" }));
  expect(await screen.findByRole("heading", { level: 1, name: "Add domain" })).toBeTruthy();
  expect(screen.getByText(/example\.com\. 3600 IN SOA/)).toBeTruthy();
  expect(screen.getByText(/dns-zone-import .*--zone 'example\.com'/)).toBeTruthy();

  await act(() =>
    router.navigate({ to: "/domains/$hostname/dns", params: { hostname: "blog.lab.test" } }),
  );
  expect(await screen.findByRole("heading", { level: 2, name: "Manage DNS records" })).toBeTruthy();
  fireEvent.change(screen.getByLabelText("Record type"), { target: { value: "MX" } });
  fireEvent.change(screen.getByLabelText("Value / Target"), {
    target: { value: "mx.mailprovider.example." },
  });
  fireEvent.click(screen.getByRole("button", { name: /Add record to change set/ }));
  expect(screen.getByText(/Mail-sensitive DNS change staged/)).toBeTruthy();
  expect(screen.getByText(/dns-change .*--zone 'blog\.lab\.test'/)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Remove MX @" }));
  expect(screen.queryByText(/Mail-sensitive DNS change staged/)).toBeNull();
});

test("W630 Databases Manager and interactive Site Lifecycle Controls", async () => {
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ["/databases"] }),
  });
  render(<RouterProvider router={router} />);
  expect(await screen.findByRole("heading", { level: 1, name: "Databases" })).toBeTruthy();
  expect(screen.getAllByText(/rs_site_8KD2QW_wp/).length).toBeGreaterThan(0);
  expect(screen.queryByText(/site-credential-rotate/)).toBeNull();
  const manageBtns = screen.getAllByRole("button", { name: "Manage" });
  expect(manageBtns[0]).toBeTruthy();
  fireEvent.click(manageBtns[0]!);
  expect(screen.getAllByText(/site-credential-rotate/).length).toBeGreaterThan(0);
  fireEvent.click(screen.getByRole("button", { name: "Close database details" }));
  expect(screen.queryByText(/site-credential-rotate/)).toBeNull();

  await act(() =>
    router.navigate({ to: "/sites/$siteId/maintenance", params: { siteId: "site_8KD2QW" } }),
  );
  expect(await screen.findByRole("heading", { level: 2, name: "Website controls" })).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Disk Quota" }));
  expect(screen.getByText(/Canonical verb: site_quota/)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Staging Clone" }));
  expect(screen.getByText(/Canonical verb: site_clone/)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Delete Website" }));
  expect(screen.getByText(/Destructive action/)).toBeTruthy();
});

test("W632 interactive Backup/Restore, Schedule Creator, and CyberPanel/EmDash Migration Wizards", async () => {
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ["/recovery"] }),
  });
  render(<RouterProvider router={router} />);
  expect(
    await screen.findByRole("heading", { level: 2, name: "Backup & restore actions" }),
  ).toBeTruthy();
  expect(screen.getByText(/product-backup-capture/)).toBeTruthy();
  fireEvent.click(screen.getByRole("tab", { name: "Guided site restore" }));
  expect(screen.getByText(/Guided live restore/)).toBeTruthy();

  await act(() => router.navigate({ to: "/recovery/schedules" }));
  expect(
    await screen.findByRole("heading", { level: 2, name: "Create backup schedule" }),
  ).toBeTruthy();
  expect(screen.getByText(/product-standing-capture/)).toBeTruthy();

  await act(() => router.navigate({ to: "/migration" }));
  expect(await screen.findByRole("heading", { level: 2, name: "Start a migration" })).toBeTruthy();
  expect(screen.getByText(/rustiron-plan migrate/)).toBeTruthy();
  fireEvent.click(screen.getByRole("tab", { name: /WordPress → EmDash CMS/ }));
  expect(screen.getByText(/wordpress-to-emdash\.py plan/)).toBeTruthy();
});

test("W632 Server Operations: Firewall rule builder, Cron jobs, Logs viewer & redaction", async () => {
  expect(redactLogLine("auth token=secret123 Bearer abc.def\u001b[31m")).toBe(
    "auth token=[REDACTED] Bearer [REDACTED]",
  );
  expect(allowedLogUnits().length).toBeGreaterThanOrEqual(10);
  expect(
    allowedLogUnits().some(
      (u) => u.key === "coordinator" && u.unit === "rustiron-coordinator.service",
    ),
  ).toBe(true);
  expect(
    allowedLogUnits().some((u) => u.key === "console" && u.unit === "rustiron-console.service"),
  ).toBe(true);

  const hosts = allowedLoopbackHosts(4319);
  const handler = createHostLogsHandler({ getAllowedHosts: () => hosts, disableSpawn: true });
  const badRes = await handler({
    method: "GET",
    url: "http://127.0.0.1:4319/api/host/logs?unit=../../etc/passwd",
    headers: new Headers({ host: "127.0.0.1:4319" }),
  } as unknown as Request);
  expect(badRes.status).toBe(400);

  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ["/host/firewall"] }),
  });
  render(<RouterProvider router={router} />);
  expect(
    await screen.findByRole("heading", { level: 2, name: "Manage firewall rules" }),
  ).toBeTruthy();
  fireEvent.change(screen.getByLabelText("Port (1–65535)"), { target: { value: "3306" } });
  fireEvent.click(screen.getByRole("button", { name: /Add rule to change set/ }));
  expect(screen.getByText(/Warning: sensitive local port selected/)).toBeTruthy();
  expect(screen.getByText(/--add-port=3306\/tcp/)).toBeTruthy();

  await act(() => router.navigate({ to: "/host/cron" }));
  expect(await screen.findByRole("heading", { level: 1, name: "Cron jobs & timers" })).toBeTruthy();
  expect(screen.getByText("rustiron-site-cron.timer")).toBeTruthy();
  expect(screen.getByText("rustiron-scheduled-capture.timer")).toBeTruthy();

  await act(() => router.navigate({ to: "/host/logs" }));
  expect(await screen.findByRole("heading", { level: 1, name: "Server logs" })).toBeTruthy();
  expect(screen.getByLabelText("Service unit")).toBeTruthy();
});
