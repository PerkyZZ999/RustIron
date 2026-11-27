// W629 (P29 Slice 9): Better Auth Console user accounts, sessions, and role-based access
// backed by Bun's built-in SQLite (bun:sqlite). Preserves D-090 loopback hardening and
// separate host signing custody (Console auth gates panel access & roles, never host keys).
import { Database } from "bun:sqlite";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";

import {
  checkD090Request,
  checkSameOriginMutation,
  jsonReply,
  withD090Headers,
} from "./backend-server";

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
  user_count: number;
  session: {
    sessionId: string;
    user: { id: string; name: string; email: string; role: ConsoleRole };
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

/** Users before migrations ran: a missing `user` table means none. */
function countUsersIn(db: Database): number {
  try {
    const row = db.query("SELECT COUNT(*) as c FROM user").get() as { c: number } | null;
    return row?.c ?? 0;
  } catch {
    return 0;
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

async function readBoundedJson(req: Request): Promise<Record<string, unknown> | Response> {
  const ct = req.headers.get("content-type")?.toLowerCase() ?? "";
  if (!ct.includes("application/json")) {
    return jsonReply(415, { error: "UNSUPPORTED_MEDIA_TYPE" });
  }
  const raw = typeof req.text === "function" ? await req.text() : JSON.stringify(await req.json());
  if (Buffer.byteLength(raw, "utf8") > MAX_AUTH_BODY_BYTES) {
    return jsonReply(413, { error: "PAYLOAD_TOO_LARGE" });
  }
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return jsonReply(400, { error: "INVALID_JSON" });
    }
    return parsed as Record<string, unknown>;
  } catch {
    return jsonReply(400, { error: "INVALID_JSON" });
  }
}

type ParsedAccount = {
  name: string;
  email: string;
  password: string;
  role: ConsoleRole;
  setupToken: string;
};

function strField(obj: Record<string, unknown> | null, key: string): string {
  const val = obj?.[key];
  return typeof val === "string" ? val : "";
}

async function parseAccountBody(req: Request): Promise<ParsedAccount | Response> {
  const payload = await readBoundedJson(req);
  if (payload instanceof Response) return payload;
  const name = strField(payload, "name").trim();
  const email = strField(payload, "email").trim().toLowerCase();
  const password = strField(payload, "password");
  if (
    name.length < 2 ||
    name.length > 100 ||
    !EMAIL_RE.test(email) ||
    password.length < 10 ||
    password.length > MAX_PASSWORD_LENGTH
  ) {
    return jsonReply(400, {
      error: "INVALID_ACCOUNT_INPUT",
      message: "Provide a name, valid email, and password between 10 and 128 characters.",
    });
  }
  return {
    name,
    email,
    password,
    role: parseRole(payload.role),
    setupToken: strField(payload, "setupToken").trim(),
  };
}

function parseUserId(url: string): string | null {
  const path = new URL(url).pathname;
  const match = /^\/api\/accounts\/users\/([A-Za-z0-9_-]{4,64})$/.exec(path);
  return match?.[1] ?? null;
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
    secret,
    trustedOrigins,
    emailAndPassword: {
      enabled: true,
      minPasswordLength: 10,
      maxPasswordLength: MAX_PASSWORD_LENGTH,
      autoSignIn: true,
    },
    rateLimit: {
      enabled: true,
      window: 60,
      max: 20,
      storage: "memory",
    },
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
    const row = db.query("SELECT role FROM user WHERE id = ?").get(res.user.id) as {
      role?: string;
    } | null;
    return {
      sessionId: res.session.id,
      user: {
        id: res.user.id,
        name: res.user.name,
        email: res.user.email,
        role: parseRole(row?.role ?? (res.user as { role?: unknown }).role),
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
    if (allowedRoles && !allowedRoles.includes(session.user.role)) {
      return { error: jsonReply(403, { error: "INSUFFICIENT_ROLE" }) };
    }
    return { session };
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
      user_count: userCount,
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
    return { session };
  }

  async function callSignUp(account: { name: string; email: string; password: string }) {
    const signUpReq = new Request(new URL("/api/auth/sign-up/email", options.baseURL), {
      method: "POST",
      headers: { "content-type": "application/json", origin: options.baseURL },
      body: JSON.stringify(account),
    });
    return auth.handler(signUpReq);
  }

  let setupInFlight = false;
  const failedSignIns: number[] = [];
  const failedSetupAttempts: number[] = [];

  function pruneAndCheckRate(bucket: number[], now: number): boolean {
    while (bucket.length > 0 && now - bucket[0]! > LOGIN_WINDOW_MS) {
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

  function recordSignInOutcome(httpStatus: number, ok: boolean) {
    if (httpStatus === 401 || httpStatus === 400) {
      failedSignIns.push(Date.now());
    } else if (ok) {
      failedSignIns.length = 0;
    }
  }

  function exceedsAuthBodyLimit(req: Request): boolean {
    const contentLength = Number(req.headers.get("content-length") ?? "0");
    return Number.isFinite(contentLength) && contentLength > MAX_AUTH_BODY_BYTES;
  }

  async function handleAuth(req: Request): Promise<Response> {
    const guard = checkSameOriginWrite(req, options.getAllowedHosts());
    if (guard) return guard;
    if (exceedsAuthBodyLimit(req)) return jsonReply(413, { error: "PAYLOAD_TOO_LARGE" });
    await ensureReady();
    const pathname = new URL(req.url).pathname.toLowerCase();
    // W635 (H-02) / W651: always refuse public self-signup (case-insensitive), even before setup.
    if (pathname.includes("/sign-up")) return jsonReply(403, { error: "SIGNUP_DISABLED" });
    const isSignIn = req.method === "POST" && pathname.includes("/sign-in");
    if (isSignIn && pruneAndCheckRate(failedSignIns, Date.now())) {
      return jsonReply(429, {
        error: "RATE_LIMITED",
        message: "Too many failed sign-in attempts. Wait 60 seconds and try again.",
      });
    }
    const res = await auth.handler(req);
    if (isSignIn) recordSignInOutcome(res.status, res.ok);
    return withD090Headers(res);
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
    const body = await readBoundedJson(req);
    if (body instanceof Response) return body;
    const nextRole = parseRole(body.role);
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
