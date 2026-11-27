// W629, W703: Better Auth and bun:sqlite over real Bun HTTP, so real Set-Cookie,
// HttpOnly, and SameSite=Strict cookies are checked. The steps share one
// backend and run in order.
import { Database } from "bun:sqlite";
import { afterAll, describe, expect, it } from "bun:test";
import { createHmac } from "node:crypto";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createConsoleAuthBackend } from "./auth-backend";
import { allowedLoopbackHosts, jsonReply } from "./backend-server";

let hosts = allowedLoopbackHosts(0);
let auth: ReturnType<typeof createConsoleAuthBackend> | null = null;
// The server needs its port before the backend can be created; routes reach
// the backend through this accessor, which fails loudly if it is not ready.
function backend(): ReturnType<typeof createConsoleAuthBackend> {
  if (!auth) throw new Error("auth backend not ready");
  return auth;
}

const srv = Bun.serve({
  hostname: "127.0.0.1",
  port: 0,
  routes: {
    "/api/auth/*": (r, s) => backend().handleAuth(r, s),
    "/api/accounts/status": (r) => backend().status(r),
    "/api/accounts/setup": (r) => backend().setupAdmin(r),
    "/api/accounts/users": (r) => backend().usersCollection(r),
    "/api/accounts/users/:userId": (r) => backend().mutateUser(r),
    "/api/accounts/sessions/revoke-others": (r) => backend().revokeOtherSessions(r),
    "/api/protected-read": async (r) => {
      const check = await backend().requireSession(r);
      return "error" in check
        ? check.error
        : jsonReply(200, { ok: true, role: check.session?.user.role });
    },
    "/api/protected-write": async (r) => {
      const check = await backend().requireSession(r, ["admin", "operator"], {
        requireInitialized: true,
      });
      return "error" in check
        ? check.error
        : jsonReply(200, { ok: true, role: check.session?.user.role });
    },
  },
  development: false,
});

const port = srv.port;
if (port === undefined) throw new Error("server has no port");
const base = `http://127.0.0.1:${port}`;
hosts = allowedLoopbackHosts(port);
// W727: a file, not memory, so a step can read what the database stores.
const dataDir = mkdtempSync(join(tmpdir(), "ri-auth-http-"));
const dbPath = join(dataDir, "auth.sqlite");
auth = createConsoleAuthBackend({
  dbPath,
  baseURL: base,
  trustedOrigins: [base],
  getAllowedHosts: () => hosts,
});

afterAll(() => {
  srv.stop(true);
  backend().close();
  rmSync(dataDir, { recursive: true, force: true });
});

/** The cookies a client holds after `res`: its earlier `cookie` updated by `res`. */
function mergeCookies(cookie: string, res: Response): string {
  const jar = new Map(
    cookie
      .split("; ")
      .filter(Boolean)
      .map((pair) => [pair.split("=")[0] ?? "", pair] as const),
  );
  for (const pair of cookieFrom(res).split("; ").filter(Boolean)) {
    jar.set(pair.split("=")[0] ?? "", pair);
  }
  return [...jar.values()].join("; ");
}

/** RFC 4648 base32, as in an `otpauth://` secret. */
function base32Bytes(text: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const char of text.replace(/=+$/, "").toUpperCase()) {
    const value = alphabet.indexOf(char);
    if (value < 0) throw new Error("not base32");
    bits += value.toString(2).padStart(5, "0");
  }
  const bytes = bits.match(/.{8}/g) ?? [];
  return Buffer.from(bytes.map((byte) => Number.parseInt(byte, 2)));
}

/** RFC 6238 TOTP: 6 digits, 30 s steps, HMAC-SHA1, the authenticator-app default. */
function totp(secret: string, at = Date.now()): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 30_000)));
  const mac = createHmac("sha1", base32Bytes(secret)).update(counter).digest();
  const offset = (mac[mac.length - 1] ?? 0) & 0xf;
  return ((mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).toString().padStart(6, "0");
}

function cookieFrom(res: Response): string {
  return res.headers
    .getSetCookie()
    .map((c) => c.split(";")[0])
    .join("; ");
}

// The preload stubs the global fetch; Bun.fetch is the real one.
function req(
  path: string,
  method = "GET",
  opts: { body?: unknown; cookie?: string; forwardedFor?: string } = {},
): Promise<Response> {
  const headers: Record<string, string> = { "sec-fetch-site": "same-origin", origin: base };
  if (opts.cookie) headers.cookie = opts.cookie;
  if (opts.forwardedFor) headers["x-forwarded-for"] = opts.forwardedFor;
  const body = opts.body !== undefined ? JSON.stringify(opts.body) : undefined;
  if (body) headers["content-type"] = "application/json";
  return Bun.fetch(`${base}${path}`, { method, headers, body });
}

function signIn(email: string, password: string, forwardedFor?: string): Promise<Response> {
  return req("/api/auth/sign-in/email", "POST", { body: { email, password }, forwardedFor });
}

const ADMIN = { email: "admin@example.test", password: "SuperStrongPassword1!" };
const VIEWER_PASSWORD = "ViewerPassword123!";
let adminCookie = "";
let adminId = "";
let viewerId = "";
let viewerCookie = "";
const TWO_FACTOR = { email: "tf@example.test", password: VIEWER_PASSWORD };
let twoFactorCookie = "";
let twoFactorSecret = "";
let recoveryCodes: string[] = [];

describe("Console accounts over real Bun HTTP", () => {
  it("starts in setup state, refuses public sign-up, and fails writes closed", async () => {
    const r0 = await req("/api/accounts/status");
    expect(r0.status).toBe(200);
    expect(await r0.json()).toMatchObject({
      auth_provider: "better-auth",
      setup_required: true,
      auth_required: false,
      user_count: null,
    });
    // W635 (H-02, R2): before setup, public sign-up is 403 and writes are 401.
    const prePub = await req("/api/auth/sign-up/email", "POST", {
      body: { name: "Sneaky", email: "sneaky@example.test", password: ADMIN.password },
    });
    expect(prePub.status).toBe(403);
    expect((await req("/api/protected-write", "POST", { body: {} })).status).toBe(401);
  });

  it("lets exactly one of two concurrent setups win, with HttpOnly Strict cookies", async () => {
    const [setupRes, raceRes] = await Promise.all([
      req("/api/accounts/setup", "POST", { body: { name: "Charles Admin", ...ADMIN } }),
      req("/api/accounts/setup", "POST", {
        body: { name: "Race Admin", email: "race@example.test", password: ADMIN.password },
      }),
    ]);
    expect([setupRes.status, raceRes.status].sort()).toEqual([201, 409]);
    const winner = setupRes.status === 201 ? setupRes : raceRes;
    const rawSetCookie = winner.headers.getSetCookie().join("; ");
    expect(rawSetCookie).toContain("HttpOnly");
    expect(rawSetCookie).toContain("SameSite=Strict");
    adminCookie = cookieFrom(winner);
    expect(adminCookie).toContain("better-auth.session_token=");
  });

  it("refuses a second setup and public sign-up after setup", async () => {
    const dup = await req("/api/accounts/setup", "POST", {
      body: { name: "Evil", email: "evil@example.test", password: ADMIN.password },
    });
    expect(dup.status).toBe(409);
    const pub = await req("/api/auth/sign-up/email", "POST", {
      body: { name: "Pub", email: "pub@example.test", password: ADMIN.password },
    });
    expect(pub.status).toBe(403);
  });

  it("shows the account count only to a signed-in caller (W721)", async () => {
    const signedOut = (await (await req("/api/accounts/status")).json()) as {
      user_count: number | null;
    };
    expect(signedOut.user_count).toBeNull();
    const signedIn = (await (
      await req("/api/accounts/status", "GET", { cookie: adminCookie })
    ).json()) as { user_count: number | null };
    expect(signedIn.user_count).toBe(1);
  });

  it("refuses an Admin's other requests until its second factor is on (W729)", async () => {
    const status = (await (
      await req("/api/accounts/status", "GET", { cookie: adminCookie })
    ).json()) as { session: { user: { twoFactorEnabled: boolean } } };
    expect(status.session.user.twoFactorEnabled).toBe(false);
    for (const [path, method] of [
      ["/api/protected-read", "GET"],
      ["/api/accounts/users", "GET"],
      ["/api/accounts/users", "POST"],
    ] as const) {
      const refused = await req(path, method, {
        cookie: adminCookie,
        body: method === "POST" ? { name: "Nobody", email: "n@example.test" } : undefined,
      });
      expect(refused.status).toBe(403);
      expect(((await refused.json()) as { error?: string }).error).toBe("SECOND_FACTOR_REQUIRED");
    }

    // The setup itself goes through /api/auth/*, which stays open.
    const enable = await req("/api/auth/two-factor/enable", "POST", {
      cookie: adminCookie,
      body: { password: ADMIN.password },
      forwardedFor: "198.51.100.60",
    });
    expect(enable.status).toBe(200);
    const secret =
      new URL(((await enable.json()) as { totpURI: string }).totpURI).searchParams.get("secret") ??
      "";
    const verify = await req("/api/auth/two-factor/verify-totp", "POST", {
      cookie: adminCookie,
      body: { code: totp(secret) },
      forwardedFor: "198.51.100.61",
    });
    expect(verify.status).toBe(200);
    adminCookie = mergeCookies(adminCookie, verify);
    expect((await req("/api/protected-read", "GET", { cookie: adminCookie })).status).toBe(200);
  });

  it("never shows a raw session token to page script (W755, QA-24)", async () => {
    for (const path of ["/api/auth/get-session", "/api/auth/list-sessions"]) {
      const res = await req(path, "GET", { cookie: adminCookie });
      expect(res.status).toBe(404);
      expect(await res.text()).not.toContain("token");
    }
    const revoke = await req("/api/auth/revoke-session", "POST", {
      cookie: adminCookie,
      body: { token: "x" },
    });
    expect(revoke.status).toBe(404);
    // The Console's own status still reads the session, without its token.
    const status = await req("/api/accounts/status", "GET", { cookie: adminCookie });
    expect(status.status).toBe(200);
    expect(await status.text()).not.toContain('"token"');
  });

  it("needs a session to read, and an Admin session reads as admin", async () => {
    expect((await req("/api/protected-read")).status).toBe(401);
    const adminRead = await req("/api/protected-read", "GET", { cookie: adminCookie });
    expect(adminRead.status).toBe(200);
    expect(((await adminRead.json()) as { role: string }).role).toBe("admin");
  });

  it("protects the last Admin from demotion and self-deletion", async () => {
    const listRes = await req("/api/accounts/users", "GET", { cookie: adminCookie });
    expect(listRes.status).toBe(200);
    const { users } = (await listRes.json()) as { users: { id: string; role: string }[] };
    expect(users).toHaveLength(1);
    adminId = users[0]?.id ?? "";
    expect(adminId).not.toBe("");
    const demote = await req(`/api/accounts/users/${adminId}`, "PATCH", {
      cookie: adminCookie,
      body: { role: "viewer" },
    });
    expect(demote.status).toBe(409);
    const remove = await req(`/api/accounts/users/${adminId}`, "DELETE", { cookie: adminCookie });
    expect(remove.status).toBe(409);
  });

  it("creates a Viewer and refuses malformed account requests (W681)", async () => {
    const created = await req("/api/accounts/users", "POST", {
      cookie: adminCookie,
      body: {
        name: "Read Viewer",
        email: "viewer@example.test",
        password: VIEWER_PASSWORD,
        role: "viewer",
      },
    });
    expect(created.status).toBe(201);
    viewerId = ((await created.json()) as { user: { id: string } }).user.id;

    const extraField = await req("/api/accounts/users", "POST", {
      cookie: adminCookie,
      body: {
        name: "Extra",
        email: "extra@example.test",
        password: VIEWER_PASSWORD,
        emailVerified: true,
      },
    });
    expect(extraField.status).toBe(400);
    const badRole = await req("/api/accounts/users", "POST", {
      cookie: adminCookie,
      body: { name: "Bad", email: "bad@example.test", password: VIEWER_PASSWORD, role: "root" },
    });
    expect(badRole.status).toBe(400);
    for (const body of [{}, { role: "superuser" }]) {
      const res = await req(`/api/accounts/users/${viewerId}`, "PATCH", {
        cookie: adminCookie,
        body,
      });
      expect(res.status).toBe(400);
      expect(((await res.json()) as { error?: string }).error).toBe("INVALID_ROLE");
    }
  });

  it("names the field and its rule when account input is refused (W744, QA-13)", async () => {
    const refused = async (body: Record<string, unknown>) => {
      const res = await req("/api/accounts/users", "POST", { cookie: adminCookie, body });
      return [res.status, await res.json()];
    };
    const valid = { name: "Valid Name", email: "field@example.test", password: "LongEnough123!" };
    expect(await refused({ ...valid, name: "A" })).toEqual([
      400,
      {
        error: "INVALID_ACCOUNT_INPUT",
        field: "name",
        message: "Enter a name of 2 to 100 characters.",
      },
    ]);
    expect(await refused({ ...valid, name: "N".repeat(101) })).toMatchObject([
      400,
      { field: "name" },
    ]);
    expect(await refused({ ...valid, email: "nope" })).toMatchObject([400, { field: "email" }]);
    expect(await refused({ ...valid, password: "short" })).toMatchObject([
      400,
      { field: "password", message: "Enter a password of 10 to 128 characters." },
    ]);
    // An unknown field keeps the general refusal.
    expect(await refused({ ...valid, extra: true })).toMatchObject([
      400,
      { error: "INVALID_ACCOUNT_INPUT" },
    ]);
  });

  it("keeps a Viewer from raising its role or removing accounts (W685)", async () => {
    const login = await signIn("viewer@example.test", VIEWER_PASSWORD);
    expect(login.status).toBe(200);
    viewerCookie = cookieFrom(login);

    const selfPromote = await req("/api/auth/update-user", "POST", {
      cookie: viewerCookie,
      body: { role: "admin" },
    });
    expect(selfPromote.ok).toBe(false);
    const after = (await (
      await req("/api/accounts/status", "GET", { cookie: viewerCookie })
    ).json()) as { session: { user: { role: string } } | null };
    expect(after.session?.user.role).toBe("viewer");
    for (const path of ["/api/auth/delete-user", "/api/auth/change-email"]) {
      const res = await req(path, "POST", {
        cookie: viewerCookie,
        body: { newEmail: "moved@example.test", password: VIEWER_PASSWORD },
      });
      expect(res.ok).toBe(false);
    }
    expect((await req("/api/protected-read", "GET", { cookie: viewerCookie })).status).toBe(200);
    const write = await req("/api/protected-write", "POST", { cookie: viewerCookie, body: {} });
    expect(write.status).toBe(403);
  });

  it("lets an Operator write but not manage accounts, and deletes it (W685)", async () => {
    const promote = await req(`/api/accounts/users/${viewerId}`, "PATCH", {
      cookie: adminCookie,
      body: { role: "operator" },
    });
    expect(promote.status).toBe(200);
    const write = await req("/api/protected-write", "POST", { cookie: viewerCookie, body: {} });
    expect(write.status).toBe(200);
    for (const [path, method, body] of [
      ["/api/accounts/users", "GET", undefined],
      [
        "/api/accounts/users",
        "POST",
        { name: "Op Made", email: "opmade@example.test", password: VIEWER_PASSWORD },
      ],
      [`/api/accounts/users/${viewerId}`, "PATCH", { role: "admin" }],
    ] as const) {
      expect((await req(path, method, { cookie: viewerCookie, body })).status).toBe(403);
    }
    const remove = await req(`/api/accounts/users/${viewerId}`, "DELETE", { cookie: adminCookie });
    expect(remove.status).toBe(200);
  });

  it("turns on a second factor only after one correct code, with encrypted recovery codes (W727)", async () => {
    const created = await req("/api/accounts/users", "POST", {
      cookie: adminCookie,
      body: { name: "Two Factor", email: TWO_FACTOR.email, password: TWO_FACTOR.password },
    });
    expect(created.status).toBe(201);
    const login = await signIn(TWO_FACTOR.email, TWO_FACTOR.password, "198.51.100.70");
    expect(login.status).toBe(200);
    twoFactorCookie = cookieFrom(login);

    const enable = await req("/api/auth/two-factor/enable", "POST", {
      cookie: twoFactorCookie,
      body: { password: TWO_FACTOR.password },
      forwardedFor: "198.51.100.71",
    });
    expect(enable.status).toBe(200);
    const setup = (await enable.json()) as { totpURI: string; backupCodes: string[] };
    expect(setup.backupCodes).toHaveLength(10);
    for (const code of setup.backupCodes)
      expect(code).toMatch(/^[A-HJKMNP-Z2-9]{4}-[A-HJKMNP-Z2-9]{4}$/);
    const uri = new URL(setup.totpURI);
    expect(uri.protocol).toBe("otpauth:");
    expect(uri.searchParams.get("issuer")).toBe("Rustiron Console");
    twoFactorSecret = uri.searchParams.get("secret") ?? "";
    recoveryCodes = setup.backupCodes;

    // Not on until one correct code arrives.
    const before = (await (
      await req("/api/accounts/status", "GET", { cookie: twoFactorCookie })
    ).json()) as { session: { user: { twoFactorEnabled: boolean } } };
    expect(before.session.user.twoFactorEnabled).toBe(false);

    // The database holds neither the codes nor the secret in plain text.
    const stored = new Database(dbPath, { readonly: true });
    const row = stored.query("SELECT secret, backupCodes FROM twoFactor").get() as {
      secret: string;
      backupCodes: string;
    };
    stored.close();
    for (const code of recoveryCodes) expect(row.backupCodes).not.toContain(code);
    expect(row.secret).not.toContain(twoFactorSecret);

    const verify = await req("/api/auth/two-factor/verify-totp", "POST", {
      cookie: twoFactorCookie,
      body: { code: totp(twoFactorSecret) },
      forwardedFor: "198.51.100.72",
    });
    expect(verify.status).toBe(200);
    twoFactorCookie = mergeCookies(twoFactorCookie, verify);
    const after = (await (
      await req("/api/accounts/status", "GET", { cookie: twoFactorCookie })
    ).json()) as { session: { user: { twoFactorEnabled: boolean } } };
    expect(after.session.user.twoFactorEnabled).toBe(true);
  });

  it("asks for the code at the next sign-in and never trusts a device (W727)", async () => {
    const login = await signIn(TWO_FACTOR.email, TWO_FACTOR.password, "198.51.100.73");
    expect(login.status).toBe(200);
    expect(await login.json()).toMatchObject({ twoFactorRedirect: true });
    const challenge = cookieFrom(login);
    expect((await req("/api/protected-read", "GET", { cookie: challenge })).status).toBe(401);

    const trusted = await req("/api/auth/two-factor/verify-totp", "POST", {
      cookie: challenge,
      body: { code: totp(twoFactorSecret), trustDevice: true },
      forwardedFor: "198.51.100.74",
    });
    expect(trusted.status).toBe(400);
    expect(((await trusted.json()) as { error?: string }).error).toBe("TRUSTED_DEVICES_DISABLED");

    const wrong = (Number(totp(twoFactorSecret)) + 500_000) % 1_000_000;
    const refused = await req("/api/auth/two-factor/verify-totp", "POST", {
      cookie: challenge,
      body: { code: wrong.toString().padStart(6, "0") },
      forwardedFor: "198.51.100.75",
    });
    expect(refused.status).toBe(401);

    const accepted = await req("/api/auth/two-factor/verify-totp", "POST", {
      cookie: challenge,
      body: { code: totp(twoFactorSecret) },
      forwardedFor: "198.51.100.76",
    });
    expect(accepted.status).toBe(200);
    const session = mergeCookies(challenge, accepted);
    expect((await req("/api/protected-read", "GET", { cookie: session })).status).toBe(200);
  });

  it("accepts each recovery code once (W727)", async () => {
    const code = recoveryCodes[0] ?? "";
    const first = await signIn(TWO_FACTOR.email, TWO_FACTOR.password, "198.51.100.77");
    const used = await req("/api/auth/two-factor/verify-backup-code", "POST", {
      cookie: cookieFrom(first),
      body: { code },
      forwardedFor: "198.51.100.78",
    });
    expect(used.status).toBe(200);
    const second = await signIn(TWO_FACTOR.email, TWO_FACTOR.password, "198.51.100.79");
    const again = await req("/api/auth/two-factor/verify-backup-code", "POST", {
      cookie: cookieFrom(second),
      body: { code },
      forwardedFor: "198.51.100.80",
    });
    expect(again.status).toBe(401);
  });

  it("resets one account's second factor from the host shell (W730)", async () => {
    const script = join(import.meta.dir, "..", "scripts", "reset-second-factor.ts");
    const run = (env: Record<string, string>, ...args: string[]) =>
      Bun.spawnSync(["bun", script, ...args], { env: { ...process.env, ...env } });

    expect(run({}, TWO_FACTOR.email).exitCode).toBe(2);
    const missing = run({ RUSTIRON_CONSOLE_AUTH_DB: `${dbPath}.missing` }, TWO_FACTOR.email);
    expect(missing.exitCode).toBe(1);
    expect(existsSync(`${dbPath}.missing`)).toBe(false);
    const unknown = run({ RUSTIRON_CONSOLE_AUTH_DB: dbPath }, "nobody@example.test");
    expect(unknown.exitCode).toBe(1);
    expect(unknown.stderr.toString()).toContain("No Console account has the email");

    const reset = run({ RUSTIRON_CONSOLE_AUTH_DB: dbPath }, TWO_FACTOR.email.toUpperCase());
    expect(reset.exitCode).toBe(0);
    expect(reset.stdout.toString()).toContain(`Removed the second factor of ${TWO_FACTOR.email}`);
    // The old session ends, and the password alone signs in again.
    expect((await req("/api/protected-read", "GET", { cookie: twoFactorCookie })).status).toBe(401);
    const login = await signIn(TWO_FACTOR.email, TWO_FACTOR.password, "198.51.100.81");
    expect(login.status).toBe(200);
    expect(await login.json()).not.toMatchObject({ twoFactorRedirect: true });
    expect((await req("/api/protected-read", "GET", { cookie: cookieFrom(login) })).status).toBe(
      200,
    );

    const again = run({ RUSTIRON_CONSOLE_AUTH_DB: dbPath }, TWO_FACTOR.email);
    expect(again.stdout.toString()).toContain("had no second factor");
  });

  it("limits one proxied address alone; the owner still signs in over the tunnel (W694)", async () => {
    // Better Auth allows 3 per 10 s per address, the Console 5 per minute.
    let proxied429: Response | null = null;
    for (let i = 0; i < 6 && !proxied429; i += 1) {
      const bad = await signIn(ADMIN.email, "WrongPassword123!", "198.51.100.50");
      if (bad.status === 429) proxied429 = bad;
      else expect([400, 401]).toContain(bad.status);
    }
    expect(proxied429).not.toBeNull();
    const retry =
      proxied429?.headers.get("retry-after") ?? proxied429?.headers.get("x-retry-after");
    expect(Number(retry)).toBeGreaterThan(0);
    expect((await signIn(ADMIN.email, ADMIN.password)).status).toBe(200);
  });

  it("limits repeated wrong passwords with 429 in every NODE_ENV (W635)", async () => {
    let saw429 = false;
    for (let i = 0; i < 6 && !saw429; i += 1) {
      const bad = await signIn(ADMIN.email, "WrongPassword123!");
      if (bad.status === 429) saw429 = true;
      else expect([400, 401]).toContain(bad.status);
    }
    expect(saw429).toBe(true);
  });
});
