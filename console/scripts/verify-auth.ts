// W629 (P29 Slice 9): Real Bun HTTP integration verifier for Better Auth + bun:sqlite
// (runs outside happy-dom so real Set-Cookie / HttpOnly / SameSite=Strict cookies are verified).
import { createConsoleAuthBackend } from "../src/auth-backend";
import { allowedLoopbackHosts, jsonReply } from "../src/backend-server";

function assert(cond: unknown, msg: string): asserts cond {
  if (!cond) throw new Error(`auth verification failed: ${msg}`);
}

let hosts = allowedLoopbackHosts(0);
let auth: ReturnType<typeof createConsoleAuthBackend> | null = null;

const srv = Bun.serve({
  hostname: "127.0.0.1",
  port: 0,
  routes: {
    "/api/auth/*": (r) => auth!.handleAuth(r),
    "/api/accounts/status": (r) => auth!.status(r),
    "/api/accounts/setup": (r) => auth!.setupAdmin(r),
    "/api/accounts/users": (r) => auth!.usersCollection(r),
    "/api/accounts/users/:userId": (r) => auth!.mutateUser(r),
    "/api/accounts/sessions/revoke-others": (r) => auth!.revokeOtherSessions(r),
    "/api/protected-read": async (r) => {
      const check = await auth!.requireSession(r);
      return "error" in check
        ? check.error
        : jsonReply(200, { ok: true, role: check.session?.user.role });
    },
    "/api/protected-write": async (r) => {
      const check = await auth!.requireSession(r, ["admin", "operator"], {
        requireInitialized: true,
      });
      return "error" in check
        ? check.error
        : jsonReply(200, { ok: true, role: check.session?.user.role });
    },
  },
  development: false,
});

const port = srv.port!;
const base = `http://127.0.0.1:${port}`;
hosts = allowedLoopbackHosts(port);
auth = createConsoleAuthBackend({
  dbPath: ":memory:",
  baseURL: base,
  trustedOrigins: [base],
  getAllowedHosts: () => hosts,
});

function cookieFrom(res: Response): string {
  return res.headers
    .getSetCookie()
    .map((c) => c.split(";")[0])
    .join("; ");
}

async function req(
  path: string,
  method = "GET",
  opts: { body?: unknown; cookie?: string } = {},
): Promise<Response> {
  const headers: Record<string, string> = { "sec-fetch-site": "same-origin", origin: base };
  if (opts.cookie) headers.cookie = opts.cookie;
  const body = opts.body !== undefined ? JSON.stringify(opts.body) : undefined;
  if (body) headers["content-type"] = "application/json";
  return fetch(`${base}${path}`, { method, headers, body });
}

try {
  // 1. Fresh DB: setup_required=true, auth_required=false
  const r0 = await req("/api/accounts/status");
  assert(r0.status === 200, `status expected 200 got ${r0.status}`);
  const st0 = (await r0.json()) as {
    auth_provider: string;
    setup_required: boolean;
    auth_required: boolean;
    user_count: number;
  };
  assert(st0.auth_provider === "better-auth", "provider must be better-auth");
  assert(st0.setup_required && !st0.auth_required && st0.user_count === 0, "fresh setup state");

  // 1b. W635 (H-02 & R2): before setup completes, public signup is ALWAYS 403 and
  // protected writes fail closed (401 SETUP_REQUIRED).
  const prePub = await req("/api/auth/sign-up/email", "POST", {
    body: { name: "Sneaky", email: "sneaky@example.test", password: "SuperStrongPassword1!" },
  });
  assert(prePub.status === 403, `pre-setup public signup expected 403 got ${prePub.status}`);
  assert(
    (await req("/api/protected-write", "POST", { body: {} })).status === 401,
    "pre-setup protected write must fail closed with 401",
  );

  // 2. W635 (H-02): concurrent first-run Admin setup returns exactly one 201 and one 409
  const [setupRes, raceRes] = await Promise.all([
    req("/api/accounts/setup", "POST", {
      body: {
        name: "Charles Admin",
        email: "admin@example.test",
        password: "SuperStrongPassword1!",
      },
    }),
    req("/api/accounts/setup", "POST", {
      body: { name: "Race Admin", email: "race@example.test", password: "SuperStrongPassword1!" },
    }),
  ]);
  const statuses = [setupRes.status, raceRes.status].sort();
  assert(
    statuses[0] === 201 && statuses[1] === 409,
    `concurrent setup expected [201, 409] got ${JSON.stringify(statuses)}`,
  );
  const winnerRes = setupRes.status === 201 ? setupRes : raceRes;
  const rawSetCookie = winnerRes.headers.getSetCookie().join("; ");
  assert(rawSetCookie.includes("HttpOnly"), "session cookie must be HttpOnly");
  assert(rawSetCookie.includes("SameSite=Strict"), "session cookie must be SameSite=Strict");
  const adminCookie = cookieFrom(winnerRes);
  assert(adminCookie.includes("better-auth.session_token="), "session token cookie missing");

  // 3. Second setup refused (409), public signup refused (403)
  const dup = await req("/api/accounts/setup", "POST", {
    body: { name: "Evil", email: "evil@example.test", password: "SuperStrongPassword1!" },
  });
  assert(dup.status === 409, `dup setup expected 409 got ${dup.status}`);

  const pub = await req("/api/auth/sign-up/email", "POST", {
    body: { name: "Pub", email: "pub@example.test", password: "SuperStrongPassword1!" },
  });
  assert(pub.status === 403, `public signup expected 403 got ${pub.status}`);

  // 4. Unauthenticated read blocked (401), Admin cookie succeeds (200)
  assert((await req("/api/protected-read")).status === 401, "unauth read must be 401");
  const adminRead = await req("/api/protected-read", "GET", { cookie: adminCookie });
  assert(adminRead.status === 200, "admin read must be 200");
  assert(((await adminRead.json()) as { role: string }).role === "admin", "role must be admin");

  // 5. List users & protect last Admin from demotion/self-delete (409)
  const listRes = await req("/api/accounts/users", "GET", { cookie: adminCookie });
  assert(listRes.status === 200, "list users 200");
  const listBody = (await listRes.json()) as { users: { id: string; role: string }[] };
  assert(listBody.users.length === 1, "expected 1 admin user");
  const adminId = listBody.users[0]!.id;

  assert(
    (
      await req(`/api/accounts/users/${adminId}`, "PATCH", {
        cookie: adminCookie,
        body: { role: "viewer" },
      })
    ).status === 409,
    "last admin demote must be 409",
  );
  assert(
    (await req(`/api/accounts/users/${adminId}`, "DELETE", { cookie: adminCookie })).status === 409,
    "self delete must be 409",
  );

  // 6. Admin creates Viewer -> Viewer logs in -> can read (200), denied write (403)
  const createViewer = await req("/api/accounts/users", "POST", {
    cookie: adminCookie,
    body: {
      name: "Read Viewer",
      email: "viewer@example.test",
      password: "ViewerPassword123!",
      role: "viewer",
    },
  });
  assert(createViewer.status === 201, "create viewer 201");
  const viewerId = ((await createViewer.json()) as { user: { id: string } }).user.id;

  const viewerLogin = await req("/api/auth/sign-in/email", "POST", {
    body: { email: "viewer@example.test", password: "ViewerPassword123!" },
  });
  assert(viewerLogin.status === 200, "viewer login 200");
  const viewerCookie = cookieFrom(viewerLogin);

  assert(
    (await req("/api/protected-read", "GET", { cookie: viewerCookie })).status === 200,
    "viewer read 200",
  );
  assert(
    (await req("/api/protected-write", "POST", { cookie: viewerCookie, body: {} })).status === 403,
    "viewer write 403",
  );

  // 7. Admin promotes Viewer -> Operator (now allowed write!) -> deletes user
  assert(
    (
      await req(`/api/accounts/users/${viewerId}`, "PATCH", {
        cookie: adminCookie,
        body: { role: "operator" },
      })
    ).status === 200,
    "promote to operator 200",
  );
  assert(
    (await req("/api/protected-write", "POST", { cookie: viewerCookie, body: {} })).status === 200,
    "operator write 200",
  );
  assert(
    (await req(`/api/accounts/users/${viewerId}`, "DELETE", { cookie: adminCookie })).status ===
      200,
    "delete operator 200",
  );

  // 8. W635 (H-02): repeated wrong passwords must trigger 429 rate limiting regardless of NODE_ENV
  let saw429 = false;
  for (let i = 0; i < 6; i += 1) {
    const bad = await req("/api/auth/sign-in/email", "POST", {
      body: { email: "admin@example.test", password: "WrongPassword123!" },
    });
    if (bad.status === 429) {
      saw429 = true;
      break;
    }
    assert(
      bad.status === 401 || bad.status === 400,
      `attempt ${i + 1} expected 401/400/429 got ${bad.status}`,
    );
  }
  assert(saw429, "repeated wrong password attempts must trigger 429 rate limit");

  console.log("better-auth-ok");
} finally {
  srv.stop(true);
  auth.close();
}
