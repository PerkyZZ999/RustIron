// W612 (P29 Slice 4 / CP04): Unit & Unix-socket integration tests for the D-090
// read-only Console backend adapter, coordinator IPC framing, and live app mapping.
import { afterEach, describe, expect, it, test } from "bun:test";
import { chmod, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:net";
import { join } from "node:path";

import {
  allowedConsoleHosts,
  allowedLoopbackHosts,
  type BackendStatus,
  checkD090Request,
  consolePort,
  createProdDistHandler,
  createReadOnlyBackendHandlers,
  D090_CSP,
  D090_SECURITY_HEADERS,
  jsonReply,
  replyErrorStatus,
  withD090Headers,
} from "./backend-server";
import {
  COORDINATOR_DEADLINE_MS,
  coordinatorDoctor,
  coordinatorEvidenceExport,
  coordinatorOperationStatus,
  coordinatorSiteInspect,
  coordinatorSiteList,
  isValidCursor,
  isValidOpaqueId,
  MAX_REQUEST_BYTES,
  MAX_RESPONSE_BYTES,
  sendCoordinatorRead,
} from "./coordinator-client";
import { isObservation, type Observation } from "./live";
import { observationRoute } from "./observation-route";
import { liveApps } from "./platform-data";

const cleanupDirs: string[] = [];
const cleanupServers: Server[] = [];

afterEach(async () => {
  while (cleanupServers.length > 0) {
    const srv = cleanupServers.pop();
    if (srv) {
      await new Promise<void>((resolve) => srv.close(() => resolve()));
    }
  }
  while (cleanupDirs.length > 0) {
    const dir = cleanupDirs.pop();
    if (dir) {
      await rm(dir, { recursive: true, force: true });
    }
  }
});

async function startMockCoordinator(
  onRequest: (req: Record<string, unknown>) => Buffer | Record<string, unknown>,
  options?: { dirMode?: number; sockMode?: number; trailingBytes?: Buffer },
): Promise<string> {
  // Always use /tmp so AF_UNIX sun_path stays well under 108 bytes.
  const dir = await mkdtemp("/tmp/ri-cons-");
  cleanupDirs.push(dir);
  await chmod(dir, options?.dirMode ?? 0o700);
  const sockPath = join(dir, "control.sock");

  const server = createServer((socket) => {
    const chunks: Buffer[] = [];
    socket.on("data", (chunk: Buffer) => chunks.push(chunk));
    socket.on("end", () => {
      const buf = Buffer.concat(chunks);
      const len = buf.readUInt32BE(0);
      const req = JSON.parse(buf.subarray(4, 4 + len).toString("utf8")) as Record<string, unknown>;
      const reply = onRequest(req);
      if (Buffer.isBuffer(reply)) {
        socket.write(reply);
      } else {
        const body = Buffer.from(JSON.stringify(reply), "utf8");
        const frame = Buffer.allocUnsafe(4 + body.length);
        frame.writeUInt32BE(body.length, 0);
        body.copy(frame, 4);
        socket.write(frame);
      }
      if (options?.trailingBytes) {
        socket.write(options.trailingBytes);
      }
      socket.end();
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(sockPath, () => resolve());
  });
  await chmod(sockPath, options?.sockMode ?? 0o600);
  cleanupServers.push(server);
  return sockPath;
}

function makeReq(path: string, method = "GET", headers: Record<string, string> = {}): Request {
  return {
    method,
    url: `http://127.0.0.1:4319${path}`,
    headers: new Headers({ host: "127.0.0.1:4319", ...headers }),
  } as unknown as Request;
}

describe("coordinator-client (READ-PROTOCOL.md v1 IPC)", () => {
  it("validates opaque IDs, cursors, and protocol bounds", () => {
    expect(MAX_REQUEST_BYTES).toBe(262_144);
    expect(MAX_RESPONSE_BYTES).toBe(1_048_576);
    expect(COORDINATOR_DEADLINE_MS).toBe(5_000);
    expect(isValidOpaqueId("site_01-ok")).toBe(true);
    expect(isValidOpaqueId("../etc/passwd")).toBe(false);
    expect(isValidOpaqueId("bad;id")).toBe(false);
    expect(isValidOpaqueId("")).toBe(false);
    expect(isValidOpaqueId("a".repeat(65))).toBe(false);
    expect(isValidCursor("cursor_abc123")).toBe(true);
    expect(isValidCursor("has space")).toBe(false);
  });

  it("round-trips doctor, site_list, site_inspect, operation_status, and evidence_export", async () => {
    const methodsSeen: string[] = [];
    const sock = await startMockCoordinator((req) => {
      const method = String(req.method);
      methodsSeen.push(method);
      return {
        schema_version: 1,
        request_id: req.request_id,
        status: "ok",
        data: { kind: method, value: { method, params: req.params } },
        error: null,
      };
    });

    const doc = await coordinatorDoctor(sock);
    expect(doc.ok).toBe(true);
    const list = await coordinatorSiteList(sock, 10, null);
    expect(list.ok).toBe(true);
    const inspect = await coordinatorSiteInspect(sock, "cp02");
    expect(inspect.ok).toBe(true);
    const status = await coordinatorOperationStatus(sock, "op_w612_1");
    expect(status.ok).toBe(true);
    const evidence = await coordinatorEvidenceExport(sock, "op_w612_1");
    expect(evidence.ok).toBe(true);

    expect(methodsSeen).toEqual([
      "doctor",
      "site_list",
      "site_inspect",
      "operation_status",
      "evidence_export",
    ]);
  });

  it("refuses insecure directory/socket modes, trailing frames, and oversized replies", async () => {
    const looseDirSock = await startMockCoordinator(
      (req) => ({
        schema_version: 1,
        request_id: req.request_id,
        status: "ok",
        data: null,
        error: null,
      }),
      { dirMode: 0o755 },
    );
    expect(await coordinatorDoctor(looseDirSock)).toEqual({ ok: false, code: "UNAUTHORIZED_PEER" });

    const looseSock = await startMockCoordinator(
      (req) => ({
        schema_version: 1,
        request_id: req.request_id,
        status: "ok",
        data: null,
        error: null,
      }),
      { sockMode: 0o666 },
    );
    expect(await coordinatorDoctor(looseSock)).toEqual({ ok: false, code: "UNAUTHORIZED_PEER" });

    const trailingSock = await startMockCoordinator(
      (req) => ({
        schema_version: 1,
        request_id: req.request_id,
        status: "ok",
        data: null,
        error: null,
      }),
      { trailingBytes: Buffer.from("X") },
    );
    expect(await coordinatorDoctor(trailingSock)).toEqual({ ok: false, code: "INVALID_RESPONSE" });

    const hugeHeaderSock = await startMockCoordinator(() => {
      const hdr = Buffer.alloc(4);
      hdr.writeUInt32BE(MAX_RESPONSE_BYTES + 1, 0);
      return hdr;
    });
    expect(await sendCoordinatorRead(hugeHeaderSock, "doctor", {})).toEqual({
      ok: false,
      code: "RESPONSE_TOO_LARGE",
    });

    expect(await coordinatorSiteInspect(undefined, "../escape")).toEqual({
      ok: false,
      code: "INVALID_ID",
    });
    expect(await coordinatorDoctor(undefined)).toEqual({
      ok: false,
      code: "COORDINATOR_NOT_CONFIGURED",
    });
  });
});

describe("backend-server (D-090 loopback hardening)", () => {
  it("enforces Host allowlist, zero CORS, GET/HEAD-only methods, and CSP headers", () => {
    const hosts = allowedLoopbackHosts(4319);

    const badHost = checkD090Request(
      makeReq("/api/backend/status", "GET", { host: "attacker.example:4319" }),
      hosts,
    );
    expect(badHost?.status).toBe(421);

    const badOrigin = checkD090Request(
      makeReq("/api/backend/status", "GET", { origin: "https://attacker.example" }),
      hosts,
    );
    expect(badOrigin?.status).toBe(403);
    expect(badOrigin?.headers.get("access-control-allow-origin")).toBeNull();

    const badMethod = checkD090Request(makeReq("/api/backend/status", "POST"), hosts);
    expect(badMethod?.status).toBe(405);
    expect(badMethod?.headers.get("allow")).toBe("GET, HEAD");

    const ok = checkD090Request(
      makeReq("/api/backend/status", "GET", { origin: "http://127.0.0.1:4319" }),
      hosts,
    );
    expect(ok).toBeNull();

    const stripped = withD090Headers(
      new Response("ok", { headers: { "access-control-allow-origin": "*" } }),
      { hsts: true },
    );
    expect(stripped.headers.get("access-control-allow-origin")).toBeNull();
    expect(stripped.headers.get("content-security-policy")).toBe(D090_CSP);
    expect(stripped.headers.get("permissions-policy")).toContain("camera=()");
    expect(stripped.headers.get("cross-origin-opener-policy")).toBe("same-origin");
    expect(stripped.headers.get("strict-transport-security")).toContain("max-age=31536000");
    expect(D090_SECURITY_HEADERS["x-frame-options"]).toBe("DENY");
    expect(jsonReply(200, { ok: true }).headers.get("cache-control")).toBe("no-store");
  });

  it("allows an explicitly configured HTTPS console origin while rejecting unlisted hosts", () => {
    const hosts = allowedConsoleHosts(4319, "https://console.example.test");
    expect(hosts.has("console.example.test")).toBe(true);
    expect(hosts.has("127.0.0.1:4319")).toBe(true);

    const proxied = checkD090Request(
      makeReq("/api/backend/status", "GET", {
        host: "console.example.test",
        origin: "https://console.example.test",
      }),
      hosts,
    );
    expect(proxied).toBeNull();

    const wrongOrigin = checkD090Request(
      makeReq("/api/backend/status", "GET", {
        host: "console.example.test",
        origin: "https://evil.example",
      }),
      hosts,
    );
    expect(wrongOrigin?.status).toBe(403);

    const malformed = allowedConsoleHosts(4319, "not-a-url");
    expect(malformed).toEqual(allowedLoopbackHosts(4319));
  });

  it("reads the Console port, with an empty value as unset (W723)", () => {
    expect(consolePort(undefined)).toBe(4319);
    expect(consolePort("")).toBe(4319);
    expect(consolePort("  ")).toBe(4319);
    expect(consolePort("8443")).toBe(8443);
    expect(consolePort(" 8443 ")).toBe(8443);
    expect(consolePort("0")).toBe(0);
    for (const bad of ["65536", "-1", "80.5", "eighty"]) expect(consolePort(bad)).toBe(4319);
  });

  it("serves production SPA HTML & chunks with CSP, HSTS, Host guard, and symlink/traversal refusal (W651)", async () => {
    const dir = await mkdtemp("/tmp/ri-dist-");
    cleanupDirs.push(dir);
    await writeFile(join(dir, "index.html"), "<!doctype html><title>RustIron</title>");
    await writeFile(join(dir, "chunk-abc123.js"), "console.log('ok');");
    await symlink("/etc/hosts", join(dir, "leak.txt"));

    const hosts = allowedConsoleHosts(4319, "https://console.example.test");
    const handler = createProdDistHandler({
      distDir: dir,
      getAllowedHosts: () => hosts,
      hsts: true,
    });

    const badHost = handler(makeReq("/", "GET", { host: "evil.example" }));
    expect(badHost.status).toBe(421);

    const htmlRes = handler(makeReq("/host/logs", "GET", { host: "console.example.test" }));
    expect(htmlRes.status).toBe(200);
    expect(htmlRes.headers.get("content-security-policy")).toBe(D090_CSP);
    expect(htmlRes.headers.get("x-frame-options")).toBe("DENY");
    expect(htmlRes.headers.get("strict-transport-security")).toContain("max-age=31536000");
    expect(htmlRes.headers.get("permissions-policy")).toContain("camera=()");
    expect(await htmlRes.text()).toContain("RustIron");

    const chunkRes = handler(makeReq("/chunk-abc123.js", "GET", { host: "console.example.test" }));
    expect(chunkRes.status).toBe(200);
    expect(chunkRes.headers.get("cache-control")).toContain("immutable");
    expect(chunkRes.headers.get("content-encoding")).toBeNull();

    // W683: a gzip sidecar is served only to clients that accept gzip.
    await writeFile(join(dir, "chunk-abc123.js.gz"), Bun.gzipSync("console.log('ok');"));
    const gzReq = (encoding: string) =>
      handler(
        makeReq("/chunk-abc123.js", "GET", {
          host: "console.example.test",
          "accept-encoding": encoding,
        }),
      );
    const gzRes = gzReq("br, gzip");
    expect(gzRes.headers.get("content-encoding")).toBe("gzip");
    expect(gzRes.headers.get("content-type")).toContain("text/javascript");
    expect(gzRes.headers.get("vary")).toBe("accept-encoding");
    expect(
      new TextDecoder().decode(Bun.gunzipSync(new Uint8Array(await gzRes.arrayBuffer()))),
    ).toBe("console.log('ok');");
    expect(gzReq("gzip;q=0, br").headers.get("content-encoding")).toBeNull();
    expect(gzReq("identity").headers.get("content-encoding")).toBeNull();

    // Symlink and path traversal never leak files outside dist/. W719: a
    // top-level asset that is not a regular dist file is 404, not the app.
    const symlinkRes = handler(makeReq("/leak.txt", "GET", { host: "console.example.test" }));
    expect(symlinkRes.status).toBe(404);
    expect(await symlinkRes.text()).not.toContain("localhost");

    // W719: an old chunk after an update is 404 with the D-090 headers; page
    // addresses, also nested ones with a dot, still get the app.
    const staleChunk = handler(
      makeReq("/chunk-old999.js", "GET", { host: "console.example.test" }),
    );
    expect(staleChunk.status).toBe(404);
    expect(staleChunk.headers.get("content-security-policy")).toBe(D090_CSP);
    for (const page of ["/domains/lab.test", "/help/how-rustiron-works", "/no-such-page"]) {
      const res = handler(makeReq(page, "GET", { host: "console.example.test" }));
      expect(res.status).toBe(200);
      expect(await res.text()).toContain("RustIron");
    }
    const travRes = handler(makeReq("/../etc/passwd", "GET", { host: "console.example.test" }));
    expect(await travRes.text()).toContain("RustIron");
  });

  it("serves live coordinator routes over hardened loopback handlers", async () => {
    const sock = await startMockCoordinator((req) => ({
      schema_version: 1,
      request_id: req.request_id,
      status: "ok",
      data: { kind: String(req.method), value: { ok: true, params: req.params } },
      error: null,
    }));

    const hosts = allowedLoopbackHosts(4319);
    const api = createReadOnlyBackendHandlers({
      coordinatorSocket: sock,
      getAllowedHosts: () => hosts,
    });

    const statusRes = await api.status(makeReq("/api/backend/status"));
    expect(statusRes.status).toBe(200);
    expect(statusRes.headers.get("content-security-policy")).toBe(D090_CSP);
    expect(statusRes.headers.get("x-frame-options")).toBe("DENY");
    expect(statusRes.headers.get("access-control-allow-origin")).toBeNull();
    const status = (await statusRes.json()) as BackendStatus;
    expect(status.mode).toBe("read_only");
    expect(status.d090_hardened).toBe(true);
    expect(status.coordinator_configured).toBe(true);
    expect(status.coordinator_reachable).toBe(true);

    const rebindRes = await api.status(
      makeReq("/api/backend/status", "GET", { host: "evil.example:4319" }),
    );
    expect(rebindRes.status).toBe(421);

    const corsRes = await api.status(
      makeReq("/api/backend/status", "GET", { origin: "https://evil.example" }),
    );
    expect(corsRes.status).toBe(403);
    expect(corsRes.headers.get("access-control-allow-origin")).toBeNull();

    const postRes = await api.status(makeReq("/api/backend/status", "POST"));
    expect(postRes.status).toBe(405);
    expect(postRes.headers.get("allow")).toBe("GET, HEAD");

    const docRes = await api.coordinatorDoctor(makeReq("/api/coordinator/doctor"));
    expect(docRes.status).toBe(200);

    const sitesRes = await api.coordinatorSites(makeReq("/api/coordinator/sites?limit=10"));
    expect(sitesRes.status).toBe(200);

    const siteRes = await api.coordinatorSiteInspect(makeReq("/api/coordinator/sites/cp02"));
    expect(siteRes.status).toBe(200);

    const opRes = await api.coordinatorOperationStatus(
      makeReq("/api/coordinator/operations/op_w612_1"),
    );
    expect(opRes.status).toBe(200);

    const evRes = await api.coordinatorEvidenceExport(
      makeReq("/api/coordinator/evidence/op_w612_1"),
    );
    expect(evRes.status).toBe(200);

    const badSiteRes = await api.coordinatorSiteInspect(makeReq("/api/coordinator/sites/bad%3Bid"));
    expect(badSiteRes.status).toBe(400);

    const badLimit = await api.coordinatorSites(makeReq("/api/coordinator/sites?limit=999"));
    expect(badLimit.status).toBe(400);
  });

  it("hydrates a live Observation from coordinator doctor + site_list via /api/coordinator/live", async () => {
    const sock = await startMockCoordinator((req) => {
      if (req.method === "doctor") {
        return {
          schema_version: 1,
          request_id: req.request_id,
          status: "ok",
          data: {
            kind: "doctor",
            value: {
              host_id: "prod_host_01",
              host_epoch: "epoch_1",
              issuer: "prod_operator",
              signer_policy_epoch: "policy_5",
            },
          },
          error: null,
        };
      }
      return {
        schema_version: 1,
        request_id: req.request_id,
        status: "ok",
        data: {
          kind: "site_list",
          value: {
            sites: [
              {
                site_id: "s01",
                hostname: "app.prod.test",
                operation_id: "op_live_1",
                state: "succeeded",
                steps_done: 8,
                steps_recorded: 8,
              },
            ],
          },
        },
        error: null,
      };
    });

    const hosts = allowedLoopbackHosts(4319);
    const api = createReadOnlyBackendHandlers({
      coordinatorSocket: sock,
      getAllowedHosts: () => hosts,
      allowFixture: false,
    });

    const liveRes = await api.coordinatorLive(makeReq("/api/coordinator/live"));
    expect(liveRes.status).toBe(200);
    const body = (await liveRes.json()) as {
      source: string;
      observed_at: number;
      observation: unknown;
    };
    expect(body.source).toBe("coordinator");
    expect(isObservation(body.observation)).toBe(true);
    if (isObservation(body.observation)) {
      expect(body.observation.host.host_id).toBe("prod_host_01");
      expect(body.observation.sites).toHaveLength(1);
      expect(body.observation.sites[0]?.hostname).toBe("app.prod.test");
    }

    const strictObs = observationRoute(undefined, { allowFixture: false });
    const noFixRes = await strictObs(makeReq("/api/observation"));
    expect(noFixRes.status).toBe(503);
    const noFixBody = (await noFixRes.json()) as { error: string };
    expect(noFixBody.error).toBe("LIVE_SOURCE_NOT_CONFIGURED");
  });

  it("W635 (H-03, M-01, M-17): rejects mismatched request_id, fails closed on site_list error, and withholds doctor on publicStatus", async () => {
    // M-01: wrong request_id must be rejected as INVALID_RESPONSE.
    const badIdSock = await startMockCoordinator(() => ({
      schema_version: 1,
      request_id: "wrong-request-id",
      status: "ok",
      data: { kind: "doctor", value: {} },
      error: null,
    }));
    const badIdRes = await coordinatorDoctor(badIdSock);
    expect(badIdRes.ok).toBe(false);
    if (!badIdRes.ok) expect(badIdRes.code).toBe("INVALID_RESPONSE");

    // W680/W681: an error reply without a string code, or with an extra field, is not the wire shape.
    const noCodeSock = await startMockCoordinator((req) => ({
      schema_version: 1,
      request_id: req.request_id,
      status: "error",
      data: null,
      error: { message: "no code" },
    }));
    expect(await coordinatorDoctor(noCodeSock)).toEqual({ ok: false, code: "INVALID_RESPONSE" });
    const extraFieldSock = await startMockCoordinator((req) => ({
      schema_version: 1,
      request_id: req.request_id,
      status: "ok",
      data: { kind: "doctor", value: {} },
      error: null,
      debug: "unexpected",
    }));
    expect(await coordinatorDoctor(extraFieldSock)).toEqual({
      ok: false,
      code: "INVALID_RESPONSE",
    });

    // H-03: failed site_list must fail closed (not 200 empty), and canonical items without state stay unknown.
    const failingSitesSock = await startMockCoordinator((req) => {
      if (req.method === "doctor") {
        return {
          schema_version: 1,
          request_id: req.request_id,
          status: "ok",
          data: { kind: "doctor", value: {} },
          error: null,
        };
      }
      return {
        schema_version: 1,
        request_id: req.request_id,
        status: "error",
        data: null,
        error: {
          code: "DEPENDENCY_UNAVAILABLE",
          message: "db offline",
          retryable: true,
          operation_id: null,
          details: [],
        },
      };
    });
    const hosts = allowedLoopbackHosts(4319);
    const failApi = createReadOnlyBackendHandlers({
      coordinatorSocket: failingSitesSock,
      getAllowedHosts: () => hosts,
      allowFixture: false,
    });
    const failLive = await failApi.coordinatorLive(makeReq("/api/coordinator/live"));
    // W739 (QA-08): a dependency outage inside the reply is a 503, not a client 400.
    expect(failLive.status).toBe(503);

    // M-17: publicStatus never calls doctor or exposes host OS/kernel metadata.
    const pubRes = await failApi.publicStatus(makeReq("/api/backend/status"));
    expect(pubRes.status).toBe(200);
    const pubBody = (await pubRes.json()) as BackendStatus;
    expect(pubBody.doctor).toBeNull();
    expect(pubBody.coordinator_reachable).toBe(false);
  });
});

describe("liveApps (v43/v44 journal app derivation)", () => {
  it("maps observed P27/P30 apps without leaking fixture data", () => {
    const obs: Observation = {
      schema: "rustiron-lab-observation/1",
      host: {
        host_id: "h1",
        host_epoch: "e1",
        issuer: "lab_agent",
        signer_policy_epoch: "policy_3",
        ols_listener: "W447",
        backup_destination: null,
      },
      journal_last_time: 1_795_500_000,
      sites: [
        {
          site_id: "cp02",
          hostname: "cp02.example.test",
          operation_id: "op_wp",
          state: "succeeded",
          steps_done: 8,
          steps_recorded: 8,
          ejected: false,
        },
        {
          site_id: "emdash01",
          hostname: "cms.example.test",
          operation_id: "op_em",
          state: "succeeded",
          steps_done: 8,
          steps_recorded: 8,
          ejected: false,
          app_runtime: "node_22_v1",
          app_active_release: "rel_160",
          proxy_ports: [3401],
          http_status: 200,
        },
        {
          site_id: "bunapi",
          hostname: "api.example.test",
          operation_id: "op_bun",
          state: "succeeded",
          steps_done: 8,
          steps_recorded: 8,
          ejected: false,
          app_runtime: "bun_1_v1",
          app_active_release: "rel_bun_2",
          proxy_ports: [43187],
        },
      ],
      operations: [],
      captures: [],
      probes: [],
    };
    const apps = liveApps(obs);
    expect(apps).toHaveLength(2);
    expect(apps[0]?.kind).toBe("EmDash CMS");
    expect(apps[0]?.port).toBe(3401);
    expect(apps[0]?.currentRelease).toBe("rel_160");
    expect(apps[1]?.kind).toBe("Bun app");
    expect(apps[1]?.port).toBe(43187);
  });
});

test("W739 (QA-08): every coordinator reply error code has a deliberate HTTP status", () => {
  expect(replyErrorStatus("NOT_FOUND")).toBe(404);
  expect(replyErrorStatus("CURSOR_EXPIRED")).toBe(404);
  expect(replyErrorStatus("INVALID_REQUEST")).toBe(400);
  expect(replyErrorStatus("REQUEST_TOO_LARGE")).toBe(400);
  expect(replyErrorStatus("UNAUTHORIZED_PEER")).toBe(403);
  expect(replyErrorStatus("DEPENDENCY_UNAVAILABLE")).toBe(503);
  expect(replyErrorStatus("UNSUPPORTED_VERSION")).toBe(502);
  expect(replyErrorStatus("RESPONSE_TOO_LARGE")).toBe(502);
  expect(replyErrorStatus("SOMETHING_NEW")).toBe(502);
});
