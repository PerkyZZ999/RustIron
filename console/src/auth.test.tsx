// W629 (P29 Slice 9): Better Auth + bun:sqlite real-HTTP integration & UI tests.
import { Database } from "bun:sqlite";
import { afterEach, describe, expect, it } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { createMemoryHistory, createRouter, RouterProvider } from "@tanstack/react-router";

import { usersAnswer } from "./accounts-pages";
import {
  createConsoleAuthBackend,
  generateRecoveryCodes,
  SESSION_LIFETIME_SECONDS,
} from "./auth-backend";
import { allowedLoopbackHosts } from "./backend-server";
import { routeTree } from "./router";
import { setupKey } from "./second-factor-setup";

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

  it("shows the rate-limit wait at sign-in, and a generic message for other refusals (W717)", async () => {
    const origFetch = globalThis.fetch;
    let signInStatus = 429;
    globalThis.fetch = (async (input: string | URL | Request) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url.includes("/api/accounts/status")) {
        return Response.json({
          auth_provider: "better-auth",
          setup_required: false,
          auth_required: true,
          user_count: null,
          session: null,
        });
      }
      if (url.includes("/api/auth/sign-in/email")) {
        return Response.json(
          {
            error: signInStatus === 429 ? "RATE_LIMITED" : "INVALID_EMAIL_OR_PASSWORD",
            message:
              signInStatus === 429
                ? "Too many failed sign-in attempts from this address. Wait 42 seconds and try again."
                : "Invalid email or password",
          },
          { status: signInStatus },
        );
      }
      return Response.json({ error: "AUTH_REQUIRED" }, { status: 401 });
    }) as unknown as typeof fetch;
    try {
      const router = createRouter({
        routeTree,
        history: createMemoryHistory({ initialEntries: ["/"] }),
      });
      render(<RouterProvider router={router} />);
      const email = await screen.findByLabelText("Email address");
      fireEvent.change(email, { target: { value: "admin@example.test" } });
      fireEvent.change(screen.getByLabelText("Password"), {
        target: { value: "WrongPassword123!" },
      });
      const form = email.closest("form");
      if (!form) throw new Error("no sign-in form");
      fireEvent.submit(form);
      expect(await screen.findByText(/Wait 42 seconds and try again/)).toBeTruthy();
      signInStatus = 401;
      fireEvent.submit(form);
      expect(await screen.findByText("Invalid email or password.")).toBeTruthy();
    } finally {
      globalThis.fetch = origFetch;
    }
  });

  it("asks for the second factor after the password, and keeps refusals generic (W728)", async () => {
    const origFetch = globalThis.fetch;
    const calls: Array<{ url: string; body: unknown }> = [];
    let signedIn = false;
    globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      const body: unknown = typeof init?.body === "string" ? JSON.parse(init.body) : null;
      calls.push({ url, body });
      if (url.includes("/api/accounts/status")) {
        return Response.json({
          auth_provider: "better-auth",
          setup_required: false,
          auth_required: true,
          user_count: null,
          session: null,
        });
      }
      if (url.includes("/api/auth/sign-in/email")) {
        return Response.json({ twoFactorRedirect: true, twoFactorMethods: ["totp"] });
      }
      if (url.includes("/api/auth/two-factor/verify-totp")) {
        return Response.json({ code: "INVALID_CODE", message: "Invalid code" }, { status: 401 });
      }
      if (url.includes("/api/auth/two-factor/verify-backup-code")) {
        signedIn = true;
        return Response.json({ token: "t" });
      }
      return Response.json({ error: "AUTH_REQUIRED" }, { status: 401 });
    }) as unknown as typeof fetch;
    try {
      const router = createRouter({
        routeTree,
        history: createMemoryHistory({ initialEntries: ["/"] }),
      });
      render(<RouterProvider router={router} />);
      const email = await screen.findByLabelText("Email address");
      fireEvent.change(email, { target: { value: "admin@example.test" } });
      fireEvent.change(screen.getByLabelText("Password"), {
        target: { value: "CorrectPassword123!" },
      });
      const passwordForm = email.closest("form");
      if (!passwordForm) throw new Error("no sign-in form");
      fireEvent.submit(passwordForm);

      expect(await screen.findByRole("heading", { name: "Enter your code" })).toBeTruthy();
      expect(screen.getByText(/Step 2 of 2 · admin@example.test/)).toBeTruthy();
      // The visible label names the first box; the others carry "Digit N".
      const firstDigit = screen.getByLabelText("6-digit code from your authenticator app", {
        selector: "input",
      });
      const codeForm = firstDigit.closest("form");
      if (!codeForm) throw new Error("no code form");
      fireEvent.submit(codeForm);
      expect(
        await screen.findByText("Enter all 6 digits from your authenticator app."),
      ).toBeTruthy();

      fireEvent.change(firstDigit, { target: { value: "1" } });
      for (const n of [2, 3, 4, 5, 6]) {
        fireEvent.change(screen.getByLabelText(`Digit ${n}`), { target: { value: String(n) } });
      }
      fireEvent.submit(codeForm);
      expect(
        await screen.findByText("Sign-in failed. Check your details and try again."),
      ).toBeTruthy();
      const totpCall = calls.find((c) => c.url.includes("/two-factor/verify-totp"));
      expect(totpCall?.body).toEqual({ code: "123456" });

      fireEvent.click(screen.getByRole("button", { name: "Use a recovery code instead" }));
      fireEvent.change(screen.getByLabelText("Recovery code"), { target: { value: "7kq4-m2xd" } });
      fireEvent.submit(codeForm);
      await waitFor(() => expect(signedIn).toBe(true));
      const recoveryCall = calls.find((c) => c.url.includes("/two-factor/verify-backup-code"));
      // The server never sees a request to trust this browser.
      expect(recoveryCall?.body).toEqual({ code: "7KQ4-M2XD" });
    } finally {
      globalThis.fetch = origFetch;
    }
  });

  it("shows an Admin without a second factor only the setup, then the Console (W729)", async () => {
    const origFetch = globalThis.fetch;
    let factorOn = false;
    const codes = ["7KQ4-M2XD", "P9RT-3HWF", "C6ZN-8VLA", "Y2BE-5QJU", "H8MS-4TKC"];
    globalThis.fetch = (async (input: string | URL | Request) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url.includes("/api/accounts/status")) {
        return Response.json({
          auth_provider: "better-auth",
          setup_required: false,
          auth_required: true,
          user_count: 1,
          session: {
            sessionId: "s1",
            user: {
              id: "u1",
              name: "Owner",
              email: "owner@example.test",
              role: "admin",
              twoFactorEnabled: factorOn,
            },
          },
        });
      }
      if (url.includes("/api/auth/two-factor/enable")) {
        return Response.json({
          totpURI:
            "otpauth://totp/Rustiron%20Console:owner%40example.test?secret=JBSWY3DPEHPK3PXP&issuer=Rustiron%20Console",
          backupCodes: codes,
        });
      }
      if (url.includes("/api/auth/two-factor/verify-totp")) {
        factorOn = true;
        return Response.json({ token: "t" });
      }
      return Response.json({ error: "SECOND_FACTOR_REQUIRED" }, { status: 403 });
    }) as unknown as typeof fetch;
    try {
      const router = createRouter({
        routeTree,
        history: createMemoryHistory({ initialEntries: ["/"] }),
      });
      render(<RouterProvider router={router} />);
      expect(await screen.findByText("Set up a second factor to continue.")).toBeTruthy();
      expect(screen.queryByRole("navigation", { name: "Primary" })).toBeNull();

      fireEvent.change(screen.getByLabelText("Current password"), {
        target: { value: "CorrectPassword123!" },
      });
      fireEvent.click(screen.getByRole("button", { name: "Show the setup key" }));
      expect(
        await screen.findByRole("img", { name: "QR code to scan with the authenticator app" }),
      ).toBeTruthy();
      expect(screen.getByText("JBSW Y3DP EHPK 3PXP")).toBeTruthy();
      expect(screen.queryByText("7KQ4-M2XD")).toBeNull();

      fireEvent.change(screen.getByLabelText("6-digit code", { selector: "input" }), {
        target: { value: "1" },
      });
      for (const n of [2, 3, 4, 5, 6]) {
        fireEvent.change(screen.getByLabelText(`Digit ${n}`), { target: { value: String(n) } });
      }
      fireEvent.click(screen.getByRole("button", { name: "Turn on the second factor" }));
      expect(await screen.findByText("7KQ4-M2XD")).toBeTruthy();

      const finish = screen.getByRole("button", { name: "Finish and open the Console" });
      expect((finish as HTMLButtonElement).disabled).toBe(true);
      fireEvent.click(screen.getByLabelText("I saved these codes somewhere outside this server"));
      fireEvent.click(finish);
      await waitFor(() =>
        expect(screen.queryByText("Set up a second factor to continue.")).toBeNull(),
      );
      expect(await screen.findByRole("navigation", { name: "Primary" })).toBeTruthy();
    } finally {
      globalThis.fetch = origFetch;
    }
  });

  it("reads the setup key out of the otpauth link in groups of four (W729)", () => {
    expect(setupKey("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&issuer=y")).toBe(
      "JBSW Y3DP EHPK 3PXP",
    );
    expect(setupKey("otpauth://totp/x?issuer=y")).toBe("");
  });

  it("stops the start on a database error instead of reading it as no users (W722)", () => {
    const dir = mkdtempSync(join(tmpdir(), "ri-auth-w722-"));
    const dbPath = join(dir, "auth.sqlite");
    const broken = new Database(dbPath);
    broken.exec(
      "CREATE TABLE gone(x); CREATE VIEW user AS SELECT x FROM gone; DROP TABLE gone; PRAGMA user_version = 1;",
    );
    broken.close();
    const hosts = allowedLoopbackHosts(4319);
    try {
      expect(() =>
        createConsoleAuthBackend({
          dbPath,
          baseURL: "https://127.0.0.1:4319",
          requireSetupToken: true,
          getAllowedHosts: () => hosts,
        }),
      ).toThrow("no such table: main.gone");
      expect(existsSync(`${dbPath}.setup-token`)).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("makes ten distinct recovery codes from the look-alike-free alphabet (W727)", () => {
    const codes = generateRecoveryCodes();
    expect(codes).toHaveLength(10);
    expect(new Set(codes).size).toBe(10);
    for (const code of codes) expect(code).toMatch(/^[A-HJKMNP-Z2-9]{4}-[A-HJKMNP-Z2-9]{4}$/);
    // Every letter of the alphabet turns up over many codes, so none is unreachable.
    const seen = new Set(generateRecoveryCodes(400).join("").replaceAll("-", ""));
    expect(seen.size).toBe(31);
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

  it("requires a generated one-time setup token in production when none is configured (W663-C1)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "ri-auth-c1-"));
    const dbPath = join(dir, "auth.sqlite");
    const hosts = allowedLoopbackHosts(4319);
    const auth = createConsoleAuthBackend({
      dbPath,
      baseURL: "https://127.0.0.1:4319",
      requireSetupToken: true,
      getAllowedHosts: () => hosts,
    });
    const post = (setupToken: string) => {
      const raw = JSON.stringify({
        name: "Admin User",
        email: "admin@example.test",
        password: "LongEnoughPassword123!",
        setupToken,
      });
      return {
        method: "POST",
        url: "https://127.0.0.1:4319/api/accounts/setup",
        headers: new Headers({
          host: "127.0.0.1:4319",
          origin: "https://127.0.0.1:4319",
          "sec-fetch-site": "same-origin",
          "content-type": "application/json",
        }),
        text: async () => raw,
      } as unknown as Request;
    };
    try {
      const tokenPath = `${dbPath}.setup-token`;
      expect(statSync(tokenPath).mode & 0o777).toBe(0o600);
      const token = readFileSync(tokenPath, "utf8").trim();
      expect(token.length).toBeGreaterThanOrEqual(32);
      expect((await auth.setupAdmin(post(""))).status).toBe(403);
      expect((await auth.setupAdmin(post(token))).status).toBe(201);
      expect(existsSync(tokenPath)).toBe(false);
    } finally {
      auth.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("issues sessions that expire after 12 hours, not the 7-day default (W678)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "ri-auth-w678-"));
    const dbPath = join(dir, "auth.sqlite");
    const hosts = allowedLoopbackHosts(4319);
    const auth = createConsoleAuthBackend({
      dbPath,
      baseURL: "https://127.0.0.1:4319",
      getAllowedHosts: () => hosts,
    });
    const raw = JSON.stringify({
      name: "Admin User",
      email: "admin@example.test",
      password: "LongEnoughPassword123!",
    });
    try {
      const res = await auth.setupAdmin({
        method: "POST",
        url: "https://127.0.0.1:4319/api/accounts/setup",
        headers: new Headers({
          host: "127.0.0.1:4319",
          origin: "https://127.0.0.1:4319",
          "sec-fetch-site": "same-origin",
          "content-type": "application/json",
        }),
        text: async () => raw,
      } as unknown as Request);
      expect(res.status).toBe(201);
      const inspect = new Database(dbPath);
      const row = inspect.query("SELECT expiresAt FROM session").get() as {
        expiresAt: number | string;
      };
      inspect.close();
      const expires = new Date(row.expiresAt).getTime();
      const lifetime = (expires - Date.now()) / 1000;
      expect(lifetime).toBeGreaterThan(SESSION_LIFETIME_SECONDS - 120);
      expect(lifetime).toBeLessThanOrEqual(SESSION_LIFETIME_SECONDS + 5);
    } finally {
      auth.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

/** W741/W747: the backend of an Admin with a second factor on the Users page. */
function usersPageFetch(write: (url: string, method: string) => Response | null): typeof fetch {
  const users = [
    {
      id: "u1",
      name: "Owner",
      email: "owner@example.test",
      role: "admin",
      createdAt: "2026-11-27T00:00:00Z",
      activeSessions: 1,
    },
    {
      id: "u2",
      name: "Ops",
      email: "ops@example.test",
      role: "operator",
      createdAt: "2026-11-27T00:00:00Z",
      activeSessions: 0,
    },
  ];
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const method = init?.method ?? "GET";
    const written = method === "GET" ? null : write(url, method);
    if (written) return written;
    if (url.includes("/api/accounts/status")) {
      return Response.json({
        auth_provider: "better-auth",
        setup_required: false,
        auth_required: true,
        user_count: 2,
        session: { sessionId: "s1", user: { ...users[0], twoFactorEnabled: true } },
      });
    }
    if (url.includes("/api/accounts/users")) return Response.json({ setup_required: false, users });
    return Response.json({ error: "NOT_FOUND" }, { status: 404 });
  }) as unknown as typeof fetch;
}

describe("W741 (QA-10): deleting an account asks once", () => {
  it("sends nothing on the first click and deletes on Confirm", async () => {
    const origFetch = globalThis.fetch;
    const deletes: string[] = [];
    globalThis.fetch = usersPageFetch((url, method) => {
      if (method !== "DELETE") return null;
      deletes.push(url);
      return Response.json({ ok: true });
    });
    try {
      const router = createRouter({
        routeTree,
        history: createMemoryHistory({ initialEntries: ["/users"] }),
      });
      render(<RouterProvider router={router} />);
      const button = await screen.findByRole("button", { name: "Delete ops@example.test" });
      fireEvent.click(button);
      expect(deletes).toEqual([]);
      const confirm = screen.getByRole("button", { name: "Confirm: Delete ops@example.test" });
      fireEvent.click(confirm);
      await waitFor(() => expect(deletes.length).toBe(1));
      expect(deletes[0]).toContain("/api/accounts/users/u2");
    } finally {
      globalThis.fetch = origFetch;
    }
  });
});

describe("W747 (QA-16): one current message on the Users page", () => {
  it("replaces the create message with the role change message", async () => {
    const origFetch = globalThis.fetch;
    globalThis.fetch = usersPageFetch((_url, method) =>
      method === "POST"
        ? Response.json({ ok: true }, { status: 201 })
        : Response.json({ ok: true }),
    );
    try {
      const router = createRouter({
        routeTree,
        history: createMemoryHistory({ initialEntries: ["/users"] }),
      });
      render(<RouterProvider router={router} />);
      fireEvent.change(await screen.findByLabelText("Full name"), {
        target: { value: "New Person" },
      });
      fireEvent.change(screen.getByLabelText("Email"), { target: { value: "new@example.test" } });
      fireEvent.change(screen.getByLabelText(/Initial password/), {
        target: { value: "LongEnough123!" },
      });
      const form = screen.getByLabelText("Full name").closest("form");
      if (!form) throw new Error("no create form");
      fireEvent.submit(form);
      expect(
        await screen.findByText("Created operator account for new@example.test."),
      ).toBeTruthy();
      fireEvent.change(screen.getByLabelText("Role for ops@example.test"), {
        target: { value: "viewer" },
      });
      expect(await screen.findByText("Account role updated.")).toBeTruthy();
      expect(screen.queryByText("Created operator account for new@example.test.")).toBeNull();
    } finally {
      globalThis.fetch = origFetch;
    }
  });
});

describe("W748 (QA-17): sign-in keeps the page that was asked for", () => {
  it("opens /sites after signing in from a /sites deep link", async () => {
    const origFetch = globalThis.fetch;
    let signedIn = false;
    globalThis.fetch = (async (input: string | URL | Request) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url.includes("/api/auth/sign-in/email")) {
        signedIn = true;
        return Response.json({ token: "t" });
      }
      if (url.includes("/api/accounts/status")) {
        return Response.json({
          auth_provider: "better-auth",
          setup_required: false,
          auth_required: true,
          user_count: null,
          session: signedIn
            ? {
                sessionId: "s1",
                user: {
                  id: "u2",
                  name: "Ops",
                  email: "ops@example.test",
                  role: "operator",
                  twoFactorEnabled: false,
                },
              }
            : null,
        });
      }
      return Response.json({ error: "NOT_FOUND" }, { status: 404 });
    }) as unknown as typeof fetch;
    try {
      const router = createRouter({
        routeTree,
        history: createMemoryHistory({ initialEntries: ["/sites"] }),
      });
      render(<RouterProvider router={router} />);
      const email = await screen.findByLabelText("Email address");
      fireEvent.change(email, { target: { value: "ops@example.test" } });
      fireEvent.change(screen.getByLabelText("Password"), { target: { value: "LongEnough123!" } });
      const form = email.closest("form");
      if (!form) throw new Error("no sign-in form");
      fireEvent.submit(form);
      expect(await screen.findByRole("heading", { level: 1, name: "Websites" })).toBeTruthy();
      expect(router.state.location.pathname).toBe("/sites");
    } finally {
      globalThis.fetch = origFetch;
    }
  });
});

describe("W791 Users & access answer", () => {
  const base = { auth_provider: "better-auth", auth_required: true, user_count: 2 } as const;
  const admin = {
    ...base,
    setup_required: false,
    session: {
      sessionId: "s1",
      user: { id: "u1", name: "A", email: "a@lab.test", role: "admin", twoFactorEnabled: true },
    },
  } as const;
  const user = (activeSessions: number) => ({
    id: "u",
    name: "U",
    email: "u@lab.test",
    role: "readonly",
    createdAt: "",
    activeSessions,
  });
  it("never claims anything before the status, and keeps non-Admins in the dark", () => {
    expect(usersAnswer(null, false, []).text).toBe("Checking who can sign in…");
    expect(usersAnswer(null, true, []).text).toBe("The sign-in service could not be reached.");
    expect(usersAnswer({ ...base, setup_required: true, session: null }, true, []).tone).toBe(
      "warn",
    );
    expect(usersAnswer({ ...admin, session: null }, true, []).text).toContain("Only an Admin");
  });
  it("counts accounts and sessions for an Admin", () => {
    expect(usersAnswer(admin, true, [user(1), user(2)] as never).text).toBe(
      "2 accounts can sign in, with 3 active sessions.",
    );
  });
});
