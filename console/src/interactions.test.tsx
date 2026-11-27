// W682 (v0.2 pass 15): clipboard and write-submission failures are reported, not swallowed.
import { afterEach, expect, spyOn, test } from "bun:test";

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { createMemoryHistory, createRouter, RouterProvider } from "@tanstack/react-router";

import { toastManager } from "@/components/ui/toast";
import { routeTree } from "./router";
import { copyText } from "./ui";
import { postProtectedJson } from "./write-panel";

const realFetch = globalThis.fetch;
const realClipboard = Object.getOwnPropertyDescriptor(navigator, "clipboard");

afterEach(() => {
  cleanup();
  globalThis.fetch = realFetch;
  if (realClipboard) Object.defineProperty(navigator, "clipboard", realClipboard);
});

function setClipboard(writeText: ((text: string) => Promise<void>) | undefined) {
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: writeText ? { writeText } : undefined,
  });
}

test("copyText reports a missing or refusing clipboard as an error toast", async () => {
  const add = spyOn(toastManager, "add");
  setClipboard(undefined);
  expect(await copyText("a", "Copied")).toBe(false);
  setClipboard(() => Promise.reject(new Error("denied")));
  expect(await copyText("a", "Copied")).toBe(false);
  expect(add.mock.calls.map(([toast]) => toast.type)).toEqual(["error", "error"]);
  let written = "";
  setClipboard(async (text) => {
    written = text;
  });
  expect(await copyText("abc", "Copied")).toBe(true);
  expect(written).toBe("abc");
  add.mockRestore();
});

function serve(apply: () => Promise<Response>) {
  globalThis.fetch = (async (input: RequestInfo | URL) =>
    String(input).endsWith("/api/write/session")
      ? Response.json({ write_workflows_enabled: true, csrf_token: "t" })
      : apply()) as unknown as typeof fetch;
}

test("an interrupted or outcome-unknown submission is not reported as refused", async () => {
  serve(async () =>
    Response.json(
      { error: "DEPENDENCY_UNAVAILABLE", outcome: { kind: "outcome_unknown" } },
      { status: 503 },
    ),
  );
  expect(await postProtectedJson("/api/write/plan/apply", {})).toEqual({
    ok: false,
    code: "DEPENDENCY_UNAVAILABLE",
    outcomeUnknown: true,
  });
  serve(() => Promise.reject(new TypeError("network")));
  expect(await postProtectedJson("/api/write/plan/apply", {})).toEqual({
    ok: false,
    code: "CONSOLE_UNREACHABLE",
    outcomeUnknown: true,
  });
  serve(async () => Response.json({ error: "INVALID_ID" }, { status: 400 }));
  expect(await postProtectedJson("/api/write/plan/apply", {})).toEqual({
    ok: false,
    code: "INVALID_ID",
    outcomeUnknown: false,
  });
});

test("W749 (QA-18): the Add website command appears only for valid input", async () => {
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ["/sites/new"] }),
  });
  render(<RouterProvider router={router} />);
  await screen.findByRole("heading", { level: 1, name: "Add website" });
  expect(document.body.textContent).toContain("plan create site-provision");
  expect(screen.queryByRole("button", { name: "Copy create website commands" })).toBeTruthy();
  fireEvent.change(screen.getByLabelText("Domain name"), { target: { value: "" } });
  expect(await screen.findByText("Fix the highlighted fields to see the command.")).toBeTruthy();
  expect(document.body.textContent).not.toContain("plan create site-provision");
  expect(screen.queryByRole("button", { name: "Copy create website commands" })).toBeNull();
});
