// W629 (P29 Slice 9): Better Auth Console user accounts, sessions, and role-based access
// backed by Bun's built-in SQLite (bun:sqlite). Preserves D-090 loopback hardening and
// separate host signing custody (Console auth gates panel access & roles, never host keys).
import { Database } from "bun:sqlite";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { betterAuth } from "better-auth";
import { twoFactor } from "better-auth/plugins/two-factor";
import { getMigrations } from "better-auth/db/migration";
import { z } from "zod";

import {
  checkD090Request,
  checkSameOriginMutation,
  jsonReply,
  withD090Headers,
} from "./backend-server";
import { parseBody, readJsonBody } from "./request-body";
import { clientAddress, createSignInLimiter } from "./sign-in-limiter";

/** W694: the part of Bun's server `handleAuth` reads: the connection's peer address. */
type PeerSource = { requestIP(req: Request): { address: string } | null };

/** W694: the header the Console sets, replacing any client copy, for Better Auth's limiter. */
const CLIENT_HEADER = "x-rustiron-client";
const MAX_ACCOUNT_KEY = 254;

export type ConsoleRole = "admin" | "operator" | "viewer";

export type ConsoleAccountUser = {
  id: string;
  name: string;
  email: string;
  role: ConsoleRole;
  createdAt: string;
  activeSessions: number;
};

export type ConsoleAuthStatus = {
  auth_provider: "better-auth";
  auth_required: boolean;
  setup_required: boolean;
  /** Null unless the caller is signed in. */
  user_count: number | null;
  session: {
    sessionId: string;
    user: {
      id: string;
      name: string;
      email: string;
      role: ConsoleRole;
      /** W727: the account signs in with an authenticator app code too. */
      twoFactorEnabled: boolean;
    };
  } | null;
};

export type AuthBackendOptions = {
  dbPath?: string;
  secret?: string;
  setupToken?: string;
  /** W663-C1: production refuses first-run setup without a token; one is generated if unset. */
  requireSetupToken?: boolean;
  baseURL: string;
  trustedOrigins?: string[];
  forceRequired?: boolean;
  disableEnforcement?: boolean;
  getAllowedHosts: () => Set<string>;
};

const VALID_ROLES = new Set<ConsoleRole>(["admin", "operator", "viewer"]);
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_AUTH_BODY_BYTES = 32_768;
const MAX_PASSWORD_LENGTH = 128;
const LOGIN_WINDOW_MS = 60_000;
const LOGIN_MAX_FAILURES = 5;
/** W678: seconds a Console session stays valid without use. */
export const SESSION_LIFETIME_SECONDS = 12 * 60 * 60;

/** W727: the letters of a recovery code: no 0/O, 1/I/L, or other look-alikes. */
const RECOVERY_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";

/**
 * W727: ten recovery codes in the approved `XXXX-XXXX` form (owner, 2026-11-27):
 * 8 letters each from a 31-letter alphabet, from the system's secure random
 * source, with rejection sampling so every letter is equally likely.
 */
export function generateRecoveryCodes(count = 10): string[] {
  const pick = (): string => {
    const limit = 256 - (256 % RECOVERY_ALPHABET.length);
    for (;;) {
      const [byte] = randomBytes(1);
      if (byte !== undefined && byte < limit) {
        return RECOVERY_ALPHABET[byte % RECOVERY_ALPHABET.length] ?? "";
      }
    }
  };
  return Array.from({ length: count }, () => {
    const letters = Array.from({ length: 8 }, pick).join("");
    return `${letters.slice(0, 4)}-${letters.slice(4)}`;
  });
}

/**
 * W727: the TOTP second factor (owner, 2026-11-27). The factor turns on only
 * after one verified code. Recovery codes are stored encrypted: the plugin's
 * default would store them as plain JSON.
 */
function secondFactor() {
  return twoFactor({
    issuer: "Rustiron Console",
    backupCodeOptions: {
      storeBackupCodes: "encrypted",
      customBackupCodesGenerate: () => generateRecoveryCodes(),
    },
  });
}

/** W727: the two second-factor code checks of a sign-in. */
function isCodeCheck(method: string, pathname: string): boolean {
  return (
    method === "POST" &&
    (pathname.endsWith("/two-factor/verify-totp") ||
      pathname.endsWith("/two-factor/verify-backup-code"))
  );
}

/** W727: a password sign-in or a code check, which the W694 limits count alike. */
function isSignInAttempt(method: string, pathname: string): boolean {
  return method === "POST" && (pathname.includes("/sign-in") || isCodeCheck(method, pathname));
}

/**
 * W727: a code check that asks Better Auth to remember this browser is
 * refused, so every sign-in asks for a code (owner, 2026-11-27).
 */
async function trustedDeviceRefusal(req: Request, pathname: string): Promise<Response | null> {
  if (!isCodeCheck(req.method, pathname)) return null;
  const body: unknown = await req
    .clone()
    .json()
    .catch(() => null);
  if ((body as { trustDevice?: unknown } | null)?.trustDevice !== true) return null;
  return jsonReply(400, { error: "TRUSTED_DEVICES_DISABLED" });
}

function parseRole(raw: unknown): ConsoleRole {
  return typeof raw === "string" && VALID_ROLES.has(raw as ConsoleRole)
    ? (raw as ConsoleRole)
    : "viewer";
}

function defaultAuthDbPath(): string {
  return join(homedir(), ".config", "rustiron-console", "auth.sqlite");
}

function loadOrCreateSecret(dbPath: string, explicit?: string, suffix = ".secret"): string {
  if (explicit && explicit.length >= 32) return explicit;
  if (dbPath === ":memory:") return randomBytes(32).toString("hex");
  const secretPath = `${dbPath}${suffix}`;
  mkdirSync(dirname(secretPath), { recursive: true, mode: 0o700 });
  if (existsSync(secretPath)) {
    const stored = readFileSync(secretPath, "utf8").trim();
    if (stored.length >= 32) return stored;
  }
  const generated = randomBytes(32).toString("hex");
  writeFileSync(secretPath, `${generated}\n`, { mode: 0o600 });
  chmodSync(secretPath, 0o600);
  return generated;
}

/**
 * Users before migrations ran: a missing `user` table means none. W722: any
 * other database error stops the start, so it never reads as "no users".
 */
function countUsersIn(db: Database): number {
  try {
    const row = db.query("SELECT COUNT(*) as c FROM user").get() as { c: number } | null;
    return row?.c ?? 0;
  } catch (error) {
    if (error instanceof Error && error.message === "no such table: user") return 0;
    throw error;
  }
}

const AUTH_SCHEMA_VERSION = 1;

function openAuthDatabase(dbPath: string): Database {
  if (dbPath !== ":memory:") {
    mkdirSync(dirname(dbPath), { recursive: true, mode: 0o700 });
  }
  const db = new Database(dbPath);
  if (dbPath !== ":memory:") {
    try {
      chmodSync(dbPath, 0o600);
    } catch {
      // File may be created lazily on first write.
    }
  }
  // W644 (M-04): enforce durable WAL + FULL sync and fail-closed schema version check.
  db.exec(
    "PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;",
  );
  const row = db.query("PRAGMA user_version").get() as { user_version?: number } | null;
  const currentVersion = row?.user_version ?? 0;
  if (currentVersion > AUTH_SCHEMA_VERSION) {
    db.close();
    throw new Error(
      `Unsupported auth database schema version ${currentVersion}; expected <= ${AUTH_SCHEMA_VERSION}.`,
    );
  }
  if (currentVersion < AUTH_SCHEMA_VERSION) {
    db.exec(`PRAGMA user_version = ${AUTH_SCHEMA_VERSION};`);
  }
  return db;
}

function checkSameOriginWrite(req: Request, allowedHosts: Set<string>): Response | null {
  return checkSameOriginMutation(req, allowedHosts);
}

function tokenEquals(expected: string, provided: string): boolean {
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(provided, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

const ACCOUNT_REFUSAL = {
  error: "INVALID_ACCOUNT_INPUT",
  message: "Provide a name, valid email, and password between 10 and 128 characters.",
};

const roleSchema = z.enum(["admin", "operator", "viewer"]);

/** W681: setup and account creation; `role` is ignored by setup, which always makes an Admin. */
const accountBody = z.strictObject({
  name: z.string().trim().min(2).max(100),
  email: z.string().trim().toLowerCase().regex(EMAIL_RE),
  password: z.string().min(10).max(MAX_PASSWORD_LENGTH),
  role: roleSchema.default("viewer"),
  setupToken: z.string().trim().default(""),
});

/** W681: a role change must name a valid role; it no longer falls back to Viewer. */
const roleBody = z.strictObject({ role: roleSchema });

type ParsedAccount = z.infer<typeof accountBody>;

/** W744 (QA-13): name the field and its rule instead of one sentence for all. */
const ACCOUNT_FIELD_MESSAGES: Record<string, string> = {
  name: "Enter a name of 2 to 100 characters.",
  email: "Enter a valid email address.",
  password: "Enter a password of 10 to 128 characters.",
};

function accountRefusal(field: string | undefined) {
  const message = field === undefined ? undefined : ACCOUNT_FIELD_MESSAGES[field];
  return message ? { error: ACCOUNT_REFUSAL.error, field, message } : ACCOUNT_REFUSAL;
}

async function parseAccountBody(req: Request): Promise<ParsedAccount | Response> {
  const payload = await readJsonBody(req, MAX_AUTH_BODY_BYTES);
  if (payload instanceof Response) return payload;
  return parseBody(accountBody, payload, accountRefusal);
}

function parseUserId(url: string): string | null {
  const path = new URL(url).pathname;
  const match = /^\/api\/accounts\/users\/([A-Za-z0-9_-]{4,64})$/.exec(path);
  return match?.[1] ?? null;
}

/**
 * W729 (TOTP task 37): an Admin without a second factor may only finish its setup.
 * `/api/auth/*` stays open for the setup and for sign-out.
 */
function secondFactorRefusal(session: NonNullable<ConsoleAuthStatus["session"]>): Response | null {
  if (session.user.role !== "admin" || session.user.twoFactorEnabled) return null;
  return jsonReply(403, {
    error: "SECOND_FACTOR_REQUIRED",
    message: "Set up a second factor to continue.",
  });
}

/** The refusal for a signed-in caller: no second factor yet, or a role outside `allowedRoles`. */
function accessRefusal(
  session: NonNullable<ConsoleAuthStatus["session"]>,
  allowedRoles?: ConsoleRole[],
): Response | null {
  const refusal = secondFactorRefusal(session);
  if (refusal) return refusal;
  if (allowedRoles && !allowedRoles.includes(session.user.role)) {
    return jsonReply(403, { error: "INSUFFICIENT_ROLE" });
  }
  return null;
}

export function createConsoleAuthBackend(options: AuthBackendOptions) {
  const dbPath = options.dbPath ?? defaultAuthDbPath();
  const db = openAuthDatabase(dbPath);
  const secret = loadOrCreateSecret(dbPath, options.secret);
  const setupTokenPath = `${dbPath}.setup-token`;
  const setupToken =
    options.setupToken ||
    (options.requireSetupToken && countUsersIn(db) === 0
      ? loadOrCreateSecret(dbPath, undefined, ".setup-token")
      : undefined);
  if (setupToken && !options.setupToken && dbPath !== ":memory:") {
    console.log(`Rustiron console first-run setup token: read it from ${setupTokenPath} (0600)`);
  }
  const trustedOrigins = options.trustedOrigins ?? [options.baseURL];

  const isHttpsOrigin = options.baseURL.trim().toLowerCase().startsWith("https://");
  const auth = betterAuth({
    database: db,
    baseURL: options.baseURL,
    basePath: "/api/auth",
    // W755 (QA-24): these return or take a raw session token, which the HttpOnly
    // cookie keeps away from page script. The Console reads its session through
    // /api/accounts/status and revokes through /api/accounts/sessions/revoke-others.
    disabledPaths: ["/get-session", "/list-sessions", "/revoke-session"],
    secret,
    trustedOrigins,
    emailAndPassword: {
      enabled: true,
      minPasswordLength: 10,
      maxPasswordLength: MAX_PASSWORD_LENGTH,
      autoSignIn: true,
    },
    // W678 (security-and-hardening): an admin console session lasts 12 hours,
    // refreshed hourly while in use, instead of Better Auth's 7-day default.
    session: {
      expiresIn: SESSION_LIFETIME_SECONDS,
      updateAge: 60 * 60,
    },
    rateLimit: {
      enabled: true,
      window: 60,
      max: 20,
      storage: "memory",
      // W703: only the first-Admin setup reaches sign-up (public sign-up is 403
      // before Better Auth). Setup has its own limiter and a one-time 409, and
      // the process-wide count would otherwise couple separate backends.
      customRules: { "/sign-up/email": false },
    },
    plugins: [secondFactor()],
    user: {
      additionalFields: {
        role: {
          type: "string",
          defaultValue: "viewer",
          input: false,
        },
      },
    },
    advanced: {
      // W694: Better Auth keys its own limits on the address the Console derived.
      ipAddress: { ipAddressHeaders: [CLIENT_HEADER] },
      useSecureCookies: isHttpsOrigin,
      defaultCookieAttributes: {
        httpOnly: true,
        sameSite: "strict",
        secure: isHttpsOrigin,
      },
    },
  });

  let migrated: Promise<void> | null = null;
  function ensureReady(): Promise<void> {
    if (!migrated) {
      migrated = getMigrations(auth.options).then((m) => m.runMigrations());
    }
    return migrated;
  }

  function countUsers(): number {
    const row = db.query("SELECT COUNT(*) as c FROM user").get() as { c: number } | null;
    return row?.c ?? 0;
  }

  function countAdmins(): number {
    const row = db.query("SELECT COUNT(*) as c FROM user WHERE role = 'admin'").get() as {
      c: number;
    } | null;
    return row?.c ?? 0;
  }

  function isEnforcementActive(): boolean {
    if (options.disableEnforcement) return false;
    if (options.forceRequired) return true;
    return countUsers() > 0;
  }

  async function readSession(req: Request): Promise<ConsoleAuthStatus["session"]> {
    await ensureReady();
    const res = await auth.api.getSession({ headers: req.headers });
    if (!res?.user || !res.session) return null;
    const row = db
      .query("SELECT role, twoFactorEnabled FROM user WHERE id = ?")
      .get(res.user.id) as { role?: string; twoFactorEnabled?: number | boolean | null } | null;
    return {
      sessionId: res.session.id,
      user: {
        id: res.user.id,
        name: res.user.name,
        email: res.user.email,
        role: parseRole(row?.role ?? (res.user as { role?: unknown }).role),
        twoFactorEnabled: Boolean(row?.twoFactorEnabled),
      },
    };
  }

  async function requireSession(
    req: Request,
    allowedRoles?: ConsoleRole[],
    opts?: { requireInitialized?: boolean },
  ): Promise<{ session: ConsoleAuthStatus["session"] } | { error: Response }> {
    await ensureReady();
    if (options.disableEnforcement) return { session: null };
    if (countUsers() === 0) {
      if (opts?.requireInitialized || options.forceRequired) {
        return { error: jsonReply(401, { error: "SETUP_REQUIRED" }) };
      }
      return { session: null };
    }
    const session = await readSession(req);
    if (!session) {
      return { error: jsonReply(401, { error: "AUTH_REQUIRED" }) };
    }
    const refusal = accessRefusal(session, allowedRoles);
    return refusal ? { error: refusal } : { session };
  }

  async function status(req: Request): Promise<Response> {
    const guard = checkD090Request(req, options.getAllowedHosts());
    if (guard) return guard;
    await ensureReady();
    const userCount = countUsers();
    const session = await readSession(req);
    const body: ConsoleAuthStatus = {
      auth_provider: "better-auth",
      auth_required: isEnforcementActive(),
      setup_required: userCount === 0,
      // W721: the account count is for signed-in callers only.
      user_count: session ? userCount : null,
      session,
    };
    return jsonReply(200, body);
  }

  async function requireAdminSession(
    req: Request,
  ): Promise<{ session: NonNullable<ConsoleAuthStatus["session"]> } | { error: Response }> {
    const guard = checkSameOriginWrite(req, options.getAllowedHosts());
    if (guard) return { error: guard };
    await ensureReady();
    const session = await readSession(req);
    if (!session) return { error: jsonReply(401, { error: "AUTH_REQUIRED" }) };
    if (session.user.role !== "admin")
      return { error: jsonReply(403, { error: "ADMIN_REQUIRED" }) };
    const refusal = secondFactorRefusal(session);
    if (refusal) return { error: refusal };
    return { session };
  }

  async function callSignUp(account: { name: string; email: string; password: string }) {
    const signUpReq = new Request(new URL("/api/auth/sign-up/email", options.baseURL), {
      method: "POST",
      // W694: a server-side call; the setup route has its own limiter.
      headers: {
        "content-type": "application/json",
        origin: options.baseURL,
        [CLIENT_HEADER]: "127.0.0.1",
      },
      body: JSON.stringify(account),
    });
    return auth.handler(signUpReq);
  }

  let setupInFlight = false;
  const signInLimiter = createSignInLimiter();
  const failedSetupAttempts: number[] = [];

  function pruneAndCheckRate(bucket: number[], now: number): boolean {
    for (
      let first = bucket[0];
      first !== undefined && now - first > LOGIN_WINDOW_MS;
      first = bucket[0]
    ) {
      bucket.shift();
    }
    return bucket.length >= LOGIN_MAX_FAILURES;
  }

  async function createFirstAdmin(parsed: ParsedAccount): Promise<Response> {
    if (setupToken && !tokenEquals(setupToken, parsed.setupToken)) {
      failedSetupAttempts.push(Date.now());
      return jsonReply(403, {
        error: "SETUP_TOKEN_REQUIRED",
        message: "Provide the one-time setup token from the Console startup log.",
      });
    }
    if (countUsers() > 0) return jsonReply(409, { error: "ALREADY_INITIALIZED" });
    const signUpRes = await callSignUp(parsed);
    if (!signUpRes.ok) return withD090Headers(signUpRes);
    const created = (await signUpRes.clone().json()) as { user?: { id?: string } };
    if (created.user?.id) {
      db.query("UPDATE user SET role = 'admin' WHERE id = ?").run(created.user.id);
    }
    failedSetupAttempts.length = 0;
    if (!options.setupToken) rmSync(setupTokenPath, { force: true });
    const headers = new Headers(signUpRes.headers);
    headers.set("cache-control", "no-store");
    return withD090Headers(
      new Response(
        JSON.stringify({
          ok: true,
          user: { id: created.user?.id, name: parsed.name, email: parsed.email, role: "admin" },
        }),
        { status: 201, headers },
      ),
    );
  }

  async function setupAdmin(req: Request): Promise<Response> {
    if (req.method !== "POST") return jsonReply(405, { error: "METHOD_NOT_ALLOWED" });
    const guard = checkSameOriginWrite(req, options.getAllowedHosts());
    if (guard) return guard;
    if (pruneAndCheckRate(failedSetupAttempts, Date.now())) {
      return jsonReply(429, {
        error: "RATE_LIMITED",
        message: "Too many failed setup attempts. Wait 60 seconds and try again.",
      });
    }
    await ensureReady();
    // W635 (H-02): serialize first-run Admin creation so concurrent setup requests
    // can never create two admins.
    if (setupInFlight || countUsers() > 0) return jsonReply(409, { error: "ALREADY_INITIALIZED" });
    setupInFlight = true;
    try {
      const parsed = await parseAccountBody(req);
      if (parsed instanceof Response) return parsed;
      return await createFirstAdmin(parsed);
    } finally {
      setupInFlight = false;
    }
  }

  /** The account a sign-in names, for its slowdown; null when the body has none. */
  async function signInAccount(req: Request): Promise<string | null> {
    const body: unknown = await req
      .clone()
      .json()
      .catch(() => null);
    const email = (body as { email?: unknown } | null)?.email;
    return typeof email === "string" ? email.trim().toLowerCase().slice(0, MAX_ACCOUNT_KEY) : null;
  }

  /** The request Better Auth sees: the derived client address in `CLIENT_HEADER`. */
  function withClientHeader(req: Request, address: string): Request {
    const headers = new Headers(req.headers);
    headers.set(CLIENT_HEADER, address);
    return new Request(req, { headers });
  }

  function refuseSignIn(reason: "address" | "global", retryAfterSeconds: number): Response {
    const message =
      reason === "global"
        ? `Sign-in is paused after many failed attempts. Try again in ${retryAfterSeconds} seconds, or sign in over the SSH tunnel.`
        : `Too many failed sign-in attempts from this address. Wait ${retryAfterSeconds} seconds and try again.`;
    return jsonReply(
      429,
      { error: "RATE_LIMITED", message },
      {
        "retry-after": String(retryAfterSeconds),
      },
    );
  }

  function exceedsAuthBodyLimit(req: Request): boolean {
    const contentLength = Number(req.headers.get("content-length") ?? "0");
    return Number.isFinite(contentLength) && contentLength > MAX_AUTH_BODY_BYTES;
  }

  /** W694: a sign-in, after the address, account, and global limits allow it. */
  async function signIn(
    req: Request,
    client: { address: string; tunnel: boolean },
  ): Promise<Response> {
    // Read the account from a clone first: the forwarded request takes over the body.
    const account = await signInAccount(req);
    const forwarded = withClientHeader(req, client.address);
    const verdict = signInLimiter.check(client.address, account, client.tunnel, Date.now());
    if (verdict.kind === "refuse") return refuseSignIn(verdict.reason, verdict.retryAfterSeconds);
    if (verdict.delayMs > 0) await Bun.sleep(verdict.delayMs);
    const res = await auth.handler(forwarded);
    const failed = res.status === 401 || res.status === 400;
    if (failed || res.ok) signInLimiter.record(client.address, account, failed, Date.now());
    return res;
  }

  async function handleAuth(req: Request, server?: PeerSource): Promise<Response> {
    const guard = checkSameOriginWrite(req, options.getAllowedHosts());
    if (guard) return guard;
    if (exceedsAuthBodyLimit(req)) return jsonReply(413, { error: "PAYLOAD_TOO_LARGE" });
    await ensureReady();
    const pathname = new URL(req.url).pathname.toLowerCase();
    // W635 (H-02) / W651: always refuse public self-signup (case-insensitive), even before setup.
    if (pathname.includes("/sign-up")) return jsonReply(403, { error: "SIGNUP_DISABLED" });
    // W727: a second-factor code check counts like a sign-in attempt, so the
    // W694 limits also slow code guessing. A trusted device would skip the
    // code at later sign-ins, which the owner does not want.
    const refusal = await trustedDeviceRefusal(req, pathname);
    if (refusal) return refusal;
    const isSignIn = isSignInAttempt(req.method, pathname);
    const client = clientAddress(req.headers, server?.requestIP(req)?.address ?? null);
    if (isSignIn) return withD090Headers(await signIn(req, client));
    return withD090Headers(await auth.handler(withClientHeader(req, client.address)));
  }

  async function listUsers(req: Request): Promise<Response> {
    const guard = checkD090Request(req, options.getAllowedHosts());
    if (guard) return guard;
    await ensureReady();
    if (countUsers() === 0) {
      return jsonReply(200, { setup_required: true, users: [] });
    }
    const session = await readSession(req);
    if (!session) return jsonReply(401, { error: "AUTH_REQUIRED" });
    if (session.user.role !== "admin") return jsonReply(403, { error: "ADMIN_REQUIRED" });
    const refusal = secondFactorRefusal(session);
    if (refusal) return refusal;

    const rows = db
      .query(
        `SELECT u.id, u.name, u.email, u.role, u.createdAt,
          (SELECT COUNT(*) FROM session s WHERE s.userId = u.id) as activeSessions
         FROM user u ORDER BY u.createdAt ASC`,
      )
      .all() as {
      id: string;
      name: string;
      email: string;
      role: string;
      createdAt: string | number;
      activeSessions: number;
    }[];

    const users: ConsoleAccountUser[] = rows.map((r) => ({
      id: r.id,
      name: r.name,
      email: r.email,
      role: parseRole(r.role),
      createdAt: new Date(r.createdAt).toISOString(),
      activeSessions: Number(r.activeSessions) || 0,
    }));
    return jsonReply(200, { setup_required: false, users });
  }

  async function createUser(req: Request): Promise<Response> {
    const authCheck = await requireAdminSession(req);
    if ("error" in authCheck) return authCheck.error;
    const parsed = await parseAccountBody(req);
    if (parsed instanceof Response) return parsed;
    if (db.query("SELECT id FROM user WHERE email = ?").get(parsed.email)) {
      return jsonReply(409, {
        error: "EMAIL_EXISTS",
        message: "That email is already registered.",
      });
    }
    const res = await callSignUp(parsed);
    if (!res.ok) return withD090Headers(res);
    const created = (await res.json()) as { user?: { id?: string } };
    if (created.user?.id) {
      db.query("UPDATE user SET role = ? WHERE id = ?").run(parsed.role, created.user.id);
      db.query("DELETE FROM session WHERE userId = ?").run(created.user.id);
    }
    return jsonReply(201, {
      ok: true,
      user: { id: created.user?.id, name: parsed.name, email: parsed.email, role: parsed.role },
    });
  }

  const roleRank: Record<ConsoleRole, number> = { viewer: 0, operator: 1, admin: 2 };

  async function patchUserRole(
    req: Request,
    target: { id: string; role: string },
  ): Promise<Response> {
    const payload = await readJsonBody(req, MAX_AUTH_BODY_BYTES);
    if (payload instanceof Response) return payload;
    const body = parseBody(roleBody, payload, {
      error: "INVALID_ROLE",
      message: "Choose Admin, Operator, or Viewer.",
    });
    if (body instanceof Response) return body;
    const nextRole = body.role;
    const applyRole = db.transaction((): Response | null => {
      if (target.role === "admin" && nextRole !== "admin" && countAdmins() <= 1) {
        return jsonReply(409, {
          error: "LAST_ADMIN",
          message: "Cannot demote the last remaining Admin account.",
        });
      }
      db.query("UPDATE user SET role = ? WHERE id = ?").run(nextRole, target.id);
      if (roleRank[nextRole] < roleRank[parseRole(target.role)]) {
        db.query("DELETE FROM session WHERE userId = ?").run(target.id);
      }
      return null;
    });
    const refusal = applyRole();
    if (refusal) return refusal;
    return jsonReply(200, { ok: true, id: target.id, role: nextRole });
  }

  function deleteUserAccount(target: { id: string; role: string }, actorUserId: string): Response {
    if (target.id === actorUserId) {
      return jsonReply(409, {
        error: "CANNOT_DELETE_SELF",
        message: "Sign in as another Admin to remove this account.",
      });
    }
    const removeUser = db.transaction((): Response | null => {
      if (target.role === "admin" && countAdmins() <= 1) {
        return jsonReply(409, {
          error: "LAST_ADMIN",
          message: "Cannot delete the last remaining Admin account.",
        });
      }
      db.query("DELETE FROM session WHERE userId = ?").run(target.id);
      db.query("DELETE FROM account WHERE userId = ?").run(target.id);
      db.query("DELETE FROM user WHERE id = ?").run(target.id);
      return null;
    });
    const refusal = removeUser();
    if (refusal) return refusal;
    return jsonReply(200, { ok: true, deleted: target.id });
  }

  async function mutateUser(req: Request): Promise<Response> {
    const authCheck = await requireAdminSession(req);
    if ("error" in authCheck) return authCheck.error;
    const userId = parseUserId(req.url);
    if (!userId) return jsonReply(400, { error: "INVALID_USER_ID" });
    const target = db.query("SELECT id, role FROM user WHERE id = ?").get(userId) as {
      id: string;
      role: string;
    } | null;
    if (!target) return jsonReply(404, { error: "USER_NOT_FOUND" });
    if (req.method === "PATCH") return patchUserRole(req, target);
    if (req.method === "DELETE") return deleteUserAccount(target, authCheck.session.user.id);
    return jsonReply(405, { error: "METHOD_NOT_ALLOWED" });
  }

  async function revokeOtherSessions(req: Request): Promise<Response> {
    if (req.method !== "POST") return jsonReply(405, { error: "METHOD_NOT_ALLOWED" });
    const guard = checkSameOriginWrite(req, options.getAllowedHosts());
    if (guard) return guard;
    await ensureReady();
    const session = await readSession(req);
    if (!session) return jsonReply(401, { error: "AUTH_REQUIRED" });
    db.query("DELETE FROM session WHERE userId = ? AND id != ?").run(
      session.user.id,
      session.sessionId,
    );
    return jsonReply(200, { ok: true });
  }

  async function usersCollection(req: Request): Promise<Response> {
    if (req.method === "GET" || req.method === "HEAD") return listUsers(req);
    if (req.method === "POST") return createUser(req);
    return jsonReply(405, { error: "METHOD_NOT_ALLOWED" });
  }

  return {
    status,
    setupAdmin,
    handleAuth,
    usersCollection,
    mutateUser,
    revokeOtherSessions,
    requireSession,
    close: () => db.close(),
  };
}
