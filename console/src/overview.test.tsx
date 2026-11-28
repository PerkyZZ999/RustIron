import { afterEach, expect, test } from "bun:test";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { createMemoryHistory, createRouter, RouterProvider } from "@tanstack/react-router";

import { routeTree } from "./router";

afterEach(cleanup);

test("host overview keeps the uncertain operation visible", async () => {
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ["/"] }),
  });
  render(<RouterProvider router={router} />);
  expect(await screen.findByRole("heading", { level: 1, name: "Host overview" })).toBeTruthy();
  expect(screen.getByText(/Operation needs attention/)).toBeTruthy();
  expect(screen.getByRole("img", { name: /Decryption tested: fail/ })).toBeTruthy();
  expect(
    screen.getAllByRole("img", { name: /Independent copy confirmed: pass/ }).length,
  ).toBeGreaterThan(0);
});

test("services keep an unchecked firewall and a stale cron visible", async () => {
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ["/host/services"] }),
  });
  render(<RouterProvider router={router} />);
  expect(await screen.findByRole("heading", { level: 1, name: "Services" })).toBeTruthy();
  expect(screen.getByText(/services need a look: .*firewalld/)).toBeTruthy();
  const firewall = screen.getByRole("button", { name: "firewalld" });
  expect(firewall.closest("tr")?.textContent).toContain("Not checked");
  expect(screen.getByRole("button", { name: "crond" }).closest("tr")?.textContent).toContain(
    "Stale",
  );
  fireEvent.change(screen.getByLabelText("Filter services"), { target: { value: "cron" } });
  expect(screen.getByRole("button", { name: "crond" })).toBeTruthy();
  expect(screen.queryByRole("button", { name: "firewalld" })).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "crond" }));
  expect(screen.getByRole("heading", { level: 2, name: "crond" })).toBeTruthy();
});

test("operations keep a rejected request distinct from a completed one", async () => {
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ["/operations"] }),
  });
  render(<RouterProvider router={router} />);
  expect(await screen.findByRole("heading", { level: 1, name: "Operations" })).toBeTruthy();
  expect(screen.getByRole("link", { name: "Config activation" })).toBeTruthy();
  expect(screen.getByText("op_7Q2KX9")).toBeTruthy();
  expect(screen.getByText(/agent: maint-bot/)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: /^Rejected/ }));
  expect(screen.queryByText("op_7Q2KX9")).toBeNull();
  expect(screen.getByText(/agent: maint-bot/)).toBeTruthy();
});

test("a plan shows its steps and approval without any way to sign or export", async () => {
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ["/plans/plan_3HV8RA"] }),
  });
  render(<RouterProvider router={router} />);
  expect(
    await screen.findByRole("heading", { level: 1, name: /config activation for shop.lab.test/ }),
  ).toBeTruthy();
  expect(screen.getAllByRole("row").length).toBe(7);
  expect(screen.getByText("Signature verified")).toBeTruthy();
  expect(
    (screen.getByRole("button", { name: /Export signed plan/ }) as HTMLButtonElement).disabled,
  ).toBe(true);
  expect(screen.getByText(/the console never holds signing keys/)).toBeTruthy();
});

test("the new plan workflow validates bounded inputs, carries draft to review, and discards cleanly", async () => {
  sessionStorage.removeItem("ri-plan-draft-v1");
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ["/plans/new"] }),
  });
  render(<RouterProvider router={router} />);
  expect(await screen.findByRole("heading", { level: 1, name: "New plan" })).toBeTruthy();
  expect(
    (screen.getByRole("radio", { name: /Config activation/ }) as HTMLInputElement).checked,
  ).toBe(true);
  const workers = screen.getByLabelText(/PHP worker limit/);
  expect(workers.getAttribute("aria-invalid")).toBe("false");
  fireEvent.change(workers, { target: { value: "24" } });
  expect(workers.getAttribute("aria-invalid")).toBe("true");
  expect(screen.getByText(/Must be an integer between 1 and 16/)).toBeTruthy();
  fireEvent.change(workers, { target: { value: "8" } });
  expect(workers.getAttribute("aria-invalid")).toBe("false");
  expect(screen.queryByText(/Must be an integer between 1 and 16/)).toBeNull();
  fireEvent.click(screen.getByRole("radio", { name: /Site provision/ }));
  expect(screen.queryByLabelText(/PHP worker limit/)).toBeNull();
  expect(screen.getByLabelText("New site ID")).toBeTruthy();

  await act(() => router.navigate({ to: "/plans/new/review" }));
  expect(
    await screen.findByRole("heading", { level: 1, name: "Review plan before approval" }),
  ).toBeTruthy();
  expect(screen.getAllByText(/site_provision/).length).toBeGreaterThan(0);
  expect(screen.getByText(/ssh-keygen -Y sign -n rustiron-plan-v1/)).toBeTruthy();
  const discard = screen.getByRole("button", { name: "Discard draft" }) as HTMLButtonElement;
  expect(discard.disabled).toBe(false);
  fireEvent.click(discard);
  expect(await screen.findByRole("heading", { level: 1, name: "New plan" })).toBeTruthy();
  expect(
    (screen.getByRole("radio", { name: /Config activation/ }) as HTMLInputElement).checked,
  ).toBe(true);
});

test("recovery keeps each evidence field separate and filters passing sites", async () => {
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ["/recovery"] }),
  });
  render(<RouterProvider router={router} />);
  expect(await screen.findByRole("heading", { level: 1, name: "Backups" })).toBeTruthy();
  expect(screen.getByRole("link", { name: "blog.lab.test" })).toBeTruthy();
  expect(screen.getByRole("link", { name: "rcpt_2YB7" })).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: /^Needs a look/ }));
  expect(screen.queryByRole("link", { name: "blog.lab.test" })).toBeNull();
  expect(screen.getByRole("link", { name: "portfolio.lab.test" })).toBeTruthy();
  expect(screen.getByRole("link", { name: "docs.lab.test" })).toBeTruthy();

  await act(() =>
    router.navigate({
      to: "/recovery/evidence/$receiptId",
      params: { receiptId: "rcpt_2YB7" },
    }),
  );
  expect(await screen.findByRole("heading", { level: 1, name: /rcpt_2YB7/ })).toBeTruthy();
  const summary = screen.getByRole("list", { name: "Evidence summary" });
  expect(summary.querySelectorAll("li").length).toBe(7);
  expect(summary.textContent).toContain("Fail");
  expect(screen.getByText(/does not match the repository key id/)).toBeTruthy();
});

test("site configuration keeps the uncertain generation apart from the verified one", async () => {
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ["/sites/site_8KD2QW/configuration"] }),
  });
  render(<RouterProvider router={router} />);
  expect(await screen.findByRole("heading", { level: 2, name: "Managed settings" })).toBeTruthy();
  const workers = () => screen.getByText("PHP worker limit").closest("tr")?.textContent ?? "";
  expect(workers()).toContain("Matches");
  fireEvent.click(screen.getByRole("button", { name: "42 · uncertain" }));
  expect(workers()).toContain("Activation uncertain");
  expect(screen.getByText("Cache recipe").closest("tr")?.textContent).toContain("Drift");

  await act(() =>
    router.navigate({ to: "/sites/$siteId/operations", params: { siteId: "site_8KD2QW" } }),
  );
  expect(await screen.findByText("op_9JW3LE")).toBeTruthy();
  fireEvent.change(screen.getByLabelText("State"), { target: { value: "Rejected" } });
  expect(screen.queryByText("op_9JW3LE")).toBeNull();
  expect(screen.getByText(/Grant expired before admission/)).toBeTruthy();
});

test("settings theme choice matches the top bar toggle", async () => {
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ["/settings"] }),
  });
  render(<RouterProvider router={router} />);
  expect(await screen.findByRole("heading", { level: 1, name: "Settings" })).toBeTruthy();
  fireEvent.click(screen.getByRole("radio", { name: "Dark" }));
  expect(document.documentElement.dataset.theme).toBe("dark");
  expect(screen.getByRole("button", { name: "Dark theme" }).getAttribute("aria-pressed")).toBe(
    "true",
  );
  fireEvent.click(screen.getByRole("button", { name: "Light theme" }));
  expect((screen.getByRole("radio", { name: "Light" }) as HTMLInputElement).checked).toBe(true);
  fireEvent.click(screen.getByRole("radio", { name: /Match system/ }));
  expect(localStorage.getItem("ri-theme")).toBeNull();
});

test("an unknown address shows a not-found page inside the shell (W718)", async () => {
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ["/no-such-page"] }),
  });
  render(<RouterProvider router={router} />);
  expect(await screen.findByRole("heading", { level: 1, name: "Page not found" })).toBeTruthy();
  expect(screen.getByRole("navigation", { name: "Primary" })).toBeTruthy();
  expect(screen.getByRole("link", { name: "Go to Host overview" }).getAttribute("href")).toBe("/");
});

test("websites and a website answer whether they are fine (W789)", async () => {
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ["/sites"] }),
  });
  render(<RouterProvider router={router} />);
  expect(await screen.findByRole("heading", { level: 1, name: "Websites" })).toBeTruthy();
  expect(screen.getByText(/8 websites\. 4 need a look; blocked: shop\.lab\.test\./)).toBeTruthy();
  await act(() => router.navigate({ to: "/sites/$siteId", params: { siteId: "site_8KD2QW" } }));
  expect(await screen.findByText(/This website is .*Open its activity to see why\./)).toBeTruthy();
});

test("domains, recovery, and operations answer first (W790)", async () => {
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ["/domains"] }),
  });
  render(<RouterProvider router={router} />);
  expect(await screen.findByRole("heading", { level: 1, name: "Domains" })).toBeTruthy();
  expect(screen.getByText(/domains\. 1 needs a look\./)).toBeTruthy();
  await act(() => router.navigate({ to: "/recovery" }));
  expect(await screen.findByText(/pass every recovery check; .* failed check\./)).toBeTruthy();
  await act(() => router.navigate({ to: "/operations" }));
  expect(await screen.findByText(/recorded changes: 1 needs attention/)).toBeTruthy();
});
