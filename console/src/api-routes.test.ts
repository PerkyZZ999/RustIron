// W712: the route policy of the one Console API table, through stand-in backends.
import { describe, expect, it } from "bun:test";

import { type ApiBackends, consoleApiRoutes } from "./api-routes";
import type { ConsoleRole } from "./auth-backend";

/** Every handler answers 200 with its own name, so a test sees which one ran. */
function stub<T>(): T {
  return new Proxy(
    {},
    { get: (_, name) => () => new Response(String(name), { status: 200 }) },
  ) as T;
}

/** A session backend whose caller's role comes from the `x-role` header. */
function sessions(): ApiBackends["auth"] {
  const requireSession = async (req: Request, roles?: ConsoleRole[]) => {
    const role = req.headers.get("x-role") as ConsoleRole | null;
    if (!role) return { error: new Response("AUTH_REQUIRED", { status: 401 }) };
    if (roles && !roles.includes(role)) {
      return { error: new Response("INSUFFICIENT_ROLE", { status: 403 }) };
    }
    return { session: null };
  };
  return new Proxy(
    {},
    {
      get: (_, name) =>
        name === "requireSession" ? requireSession : () => new Response(String(name)),
    },
  ) as ApiBackends["auth"];
}

const routes = consoleApiRoutes(
  {
    auth: sessions(),
    readOnly: stub(),
    write: stub(),
    mail: stub(),
    hostLogs: () => new Response("hostLogs"),
  },
  { production: true },
);

async function call(path: keyof typeof routes, role?: ConsoleRole): Promise<number> {
  const headers = role ? { "x-role": role } : undefined;
  const handler = routes[path] as (req: Request) => Response | Promise<Response>;
  return (await handler(new Request(`http://127.0.0.1${path}`, { headers }))).status;
}

const SELF_CHECKED = [
  "/api/auth/*",
  "/api/accounts/status",
  "/api/accounts/setup",
  "/api/accounts/users",
  "/api/accounts/users/:userId",
  "/api/accounts/sessions/revoke-others",
  "/api/backend/status",
] as const;
const WRITES = [
  "/api/mail/mailboxes",
  "/api/mail/mailboxes/:id",
  "/api/mail/aliases",
  "/api/mail/aliases/:id",
  "/api/write/session",
  "/api/write/plan/review",
  "/api/write/plan/apply",
] as const;
const paths = Object.keys(routes) as (keyof typeof routes)[];
const reads = paths.filter(
  (path) =>
    !(SELF_CHECKED as readonly string[]).includes(path) &&
    !(WRITES as readonly string[]).includes(path),
);

describe("Console API route policy (W712)", () => {
  it("lists every API route once, each in exactly one access class", () => {
    expect(paths.length).toBe(24);
    expect(reads.length).toBe(paths.length - SELF_CHECKED.length - WRITES.length);
    for (const path of [...SELF_CHECKED, ...WRITES]) expect(paths).toContain(path);
  });

  it("refuses every protected route without a session", async () => {
    for (const path of [...reads, ...WRITES]) expect(await call(path)).toBe(401);
  });

  it("lets a Viewer read but not write", async () => {
    for (const path of reads) expect(await call(path, "viewer")).toBe(200);
    for (const path of WRITES) expect(await call(path, "viewer")).toBe(403);
  });

  it("lets an Operator and an Admin write", async () => {
    for (const role of ["operator", "admin"] as const) {
      for (const path of WRITES) expect(await call(path, role)).toBe(200);
    }
  });

  it("leaves the account routes and the public status to their own checks", async () => {
    for (const path of SELF_CHECKED) expect(await call(path)).toBe(200);
  });
});
