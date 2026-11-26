// W629 (P29 Slice 9): Better Auth + bun:sqlite real-HTTP integration & UI tests.
import { Database } from "bun:sqlite";
import { afterEach, describe, expect, it } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cleanup, render, screen } from "@testing-library/react";
import { createMemoryHistory, createRouter, RouterProvider } from "@tanstack/react-router";

import { createConsoleAuthBackend } from "./auth-backend";
import { allowedLoopbackHosts } from "./backend-server";
import { routeTree } from "./router";

afterEach(cleanup);

describe("Console Better Auth accounts & UI (W629)", () => {
  it("initializes an in-memory Better Auth backend and exposes fresh setup status", async () => {
    const hosts = allowedLoopbackHosts(4319);
    const auth = createConsoleAuthBackend({
      dbPath: ":memory:",
      baseURL: "http://127.0.0.1:4319",
      getAllowedHosts: () => hosts,
    });
    try {
      const req = {
        method: "GET",
        url: "http://127.0.0.1:4319/api/accounts/status",
        headers: new Headers({ host: "127.0.0.1:4319" }),
      } as unknown as Request;
      const res = await auth.status(req);
      expect(res.status).toBe(200);
      const body = (await res.json()) as { auth_provider: string; setup_required: boolean };
      expect(body.auth_provider).toBe("better-auth");
      expect(body.setup_required).toBe(true);
    } finally {
      auth.close();
    }
  });

  it("verifies real Bun HTTP Better Auth setup, HttpOnly Strict cookies, roles, and last-admin guards", () => {
    const proc = Bun.spawnSync(["bun", "scripts/verify-auth.ts"], {
      cwd: import.meta.dir.replace(/\/src$/, ""),
      stdout: "pipe",
      stderr: "pipe",
    });
    const out = proc.stdout.toString().trim();
    const err = proc.stderr.toString().trim();
    if (proc.exitCode !== 0) {
      throw new Error(`verify-auth.ts failed (${proc.exitCode}): ${err || out}`);
    }
    expect(out).toBe("better-auth-ok");
  });

  it("renders Users & access and Login setup pages cleanly", async () => {
    const router = createRouter({
      routeTree,
      history: createMemoryHistory({ initialEntries: ["/users"] }),
    });
    render(<RouterProvider router={router} />);
    expect(await screen.findByRole("heading", { level: 1, name: "Users & access" })).toBeTruthy();
    expect(screen.getByRole("button", { name: /Create admin account/ })).toBeTruthy();
  });

  it("hides sidebar, topbar, and protected pages behind a standalone auth gate when auth_required and signed out (W648)", async () => {
    const origFetch = globalThis.fetch;
    globalThis.fetch = (async (input: string | URL | Request) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url.includes("/api/accounts/status")) {
        return Response.json({
          auth_provider: "better-auth",
          auth_required: true,
          setup_required: false,
          setup_token_required: false,
          user_count: 1,
          session: null,
        });
      }
      return Response.json({ error: "AUTH_REQUIRED" }, { status: 401 });
    }) as unknown as typeof fetch;

    try {
      const router = createRouter({
        routeTree,
        history: createMemoryHistory({ initialEntries: ["/apps"] }),
      });
      render(<RouterProvider router={router} />);
      expect(
        await screen.findByRole("heading", { level: 1, name: "Sign in to RustIron Console" }),
      ).toBeTruthy();
      expect(screen.queryByRole("navigation", { name: "Primary" })).toBeNull();
      expect(screen.queryByRole("banner")).toBeNull();
      expect(screen.queryByRole("heading", { level: 1, name: "Apps" })).toBeNull();
    } finally {
      globalThis.fetch = origFetch;
    }
  });

  it("enforces WAL, synchronous=FULL, and fail-closed user_version checks (W644 M-04)", () => {
    const dir = mkdtempSync(join(tmpdir(), "ri-auth-m04-"));
    const dbPath = join(dir, "auth.sqlite");
    const hosts = allowedLoopbackHosts(4319);
    try {
      const auth = createConsoleAuthBackend({
        dbPath,
        baseURL: "http://127.0.0.1:4319",
        getAllowedHosts: () => hosts,
      });
      auth.close();

      const inspect = new Database(dbPath);
      const uv = (inspect.query("PRAGMA user_version").get() as { user_version: number })
        .user_version;
      const jm = (inspect.query("PRAGMA journal_mode").get() as { journal_mode: string })
        .journal_mode;
      expect(uv).toBe(1);
      expect(jm.toLowerCase()).toBe("wal");
      inspect.exec("PRAGMA user_version = 99;");
      inspect.close();

      expect(() =>
        createConsoleAuthBackend({
          dbPath,
          baseURL: "http://127.0.0.1:4319",
          getAllowedHosts: () => hosts,
        }),
      ).toThrow(/Unsupported auth database schema version 99/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("rate-limits failed setup token attempts, blocks mixed-case /Sign-Up, and caps /api/auth body size (W651)", async () => {
    const hosts = allowedLoopbackHosts(4319);
    const auth = createConsoleAuthBackend({
      dbPath: ":memory:",
      baseURL: "https://127.0.0.1:4319",
      setupToken: "expected-bootstrap-secret-token",
      getAllowedHosts: () => hosts,
    });
    const makePost = (path: string, body: unknown, extraHeaders: Record<string, string> = {}) => {
      const raw = JSON.stringify(body);
      return {
        method: "POST",
        url: `https://127.0.0.1:4319${path}`,
        headers: new Headers({
          host: "127.0.0.1:4319",
          origin: "https://127.0.0.1:4319",
          "sec-fetch-site": "same-origin",
          "content-type": "application/json",
          ...extraHeaders,
        }),
        text: async () => raw,
      } as unknown as Request;
    };
    try {
      const mixedSignUp = await auth.handleAuth(
        makePost("/api/auth/Sign-Up/email", {
          name: "X",
          email: "x@example.test",
          password: "Password123!",
        }),
      );
      expect(mixedSignUp.status).toBe(403);

      const hugeAuth = await auth.handleAuth(
        makePost("/api/auth/sign-in/email", {}, { "content-length": "99999" }),
      );
      expect(hugeAuth.status).toBe(413);

      for (let i = 0; i < 5; i += 1) {
        const res = await auth.setupAdmin(
          makePost("/api/accounts/setup", {
            name: "Admin User",
            email: "admin@example.test",
            password: "LongEnoughPassword123!",
            setupToken: "wrong-token",
          }),
        );
        expect(res.status).toBe(403);
      }
      const blocked = await auth.setupAdmin(
        makePost("/api/accounts/setup", {
          name: "Admin User",
          email: "admin@example.test",
          password: "LongEnoughPassword123!",
          setupToken: "expected-bootstrap-secret-token",
        }),
      );
      expect(blocked.status).toBe(429);
    } finally {
      auth.close();
    }
  });
});
