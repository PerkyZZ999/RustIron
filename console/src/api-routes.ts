// W712 (pass 33, fix 5): every Console API route with its access rule, in one
// table. The server and the browser gate both serve this table, so the gate
// runs the same route policy as production.
import type { ConsoleRole, createConsoleAuthBackend } from "./auth-backend";
import type { createReadOnlyBackendHandlers } from "./backend-server";
import type { createMailBackend } from "./mail-backend";
import type { createWriteBackendHandlers } from "./write-backend";

type Handler = (req: Request) => Response | Promise<Response>;

/** The backends the route table serves. */
export type ApiBackends = {
  auth: Pick<
    ReturnType<typeof createConsoleAuthBackend>,
    | "handleAuth"
    | "status"
    | "setupAdmin"
    | "usersCollection"
    | "mutateUser"
    | "revokeOtherSessions"
    | "requireSession"
  >;
  readOnly: ReturnType<typeof createReadOnlyBackendHandlers>;
  write: ReturnType<typeof createWriteBackendHandlers>;
  mail: ReturnType<typeof createMailBackend>;
  hostLogs: Handler;
};

const WRITERS: ConsoleRole[] = ["admin", "operator"];

/**
 * The API routes. Account and auth routes check their own sessions. Every other
 * route needs a session once an Admin exists; writes need an Admin or Operator.
 * In production the observation and mail state also need the first Admin.
 */
export function consoleApiRoutes(backends: ApiBackends, options: { production: boolean }) {
  const { auth, readOnly, write, mail, hostLogs } = backends;

  function protect(handler: Handler, roles?: ConsoleRole[], requireInitialized = true): Handler {
    return async (req) => {
      const check = await auth.requireSession(req, roles, { requireInitialized });
      if ("error" in check) return check.error;
      return handler(req);
    };
  }

  // W635 (M-17): unauthenticated /api/backend/status returns capability flags only,
  // withholding Coordinator Doctor OS/kernel/profile metadata until authenticated.
  async function backendStatus(req: Request): Promise<Response> {
    const check = await auth.requireSession(req, undefined, { requireInitialized: true });
    if ("error" in check) return readOnly.publicStatus(req);
    return readOnly.status(req);
  }

  return {
    "/api/auth/*": auth.handleAuth,
    "/api/accounts/status": auth.status,
    "/api/accounts/setup": auth.setupAdmin,
    "/api/accounts/users": auth.usersCollection,
    "/api/accounts/users/:userId": auth.mutateUser,
    "/api/accounts/sessions/revoke-others": auth.revokeOtherSessions,
    "/api/mail/state": protect(mail.getState, undefined, options.production),
    "/api/mail/export": protect(mail.exportBundle),
    "/api/mail/mailboxes": protect(mail.mailboxesCollection, WRITERS),
    "/api/mail/mailboxes/:id": protect(mail.mutateMailbox, WRITERS),
    "/api/mail/aliases": protect(mail.aliasesCollection, WRITERS),
    "/api/mail/aliases/:id": protect(mail.deleteAlias, WRITERS),
    "/api/host/logs": protect(hostLogs),
    // W663-C3: in production no host data is readable before the first Admin exists.
    "/api/observation": protect(readOnly.observation, undefined, options.production),
    "/api/backend/status": backendStatus,
    "/api/coordinator/live": protect(readOnly.coordinatorLive),
    "/api/coordinator/doctor": protect(readOnly.coordinatorDoctor),
    "/api/coordinator/sites": protect(readOnly.coordinatorSites),
    "/api/coordinator/sites/:siteId": protect(readOnly.coordinatorSiteInspect),
    "/api/coordinator/operations/:operationId": protect(readOnly.coordinatorOperationStatus),
    "/api/coordinator/evidence/:operationId": protect(readOnly.coordinatorEvidenceExport),
    "/api/write/session": protect(write.session, WRITERS),
    "/api/write/plan/review": protect(write.review, WRITERS),
    "/api/write/plan/apply": protect(write.apply, WRITERS),
  } as const;
}
