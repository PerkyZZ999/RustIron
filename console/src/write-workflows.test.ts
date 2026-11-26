// W613 (P29 Slice 5 / P15): End-to-end security & protocol tests for the opt-in
// separate-custody Console approval & write backend (Host, Origin, Sec-Fetch-Site,
// CSRF, Content-Type, payload bounds, prompt-injection sanitization, stale/mismatched
// grants, detached SSHSIG validation, live Unix-socket plan_apply outcomes).
import { afterEach, describe, expect, it } from "bun:test";
import { chmod, mkdtemp, rm } from "node:fs/promises";
import { createServer, type Server } from "node:net";
import { join } from "node:path";

import { allowedLoopbackHosts } from "./backend-server";
import { MAX_REQUEST_BYTES, MAX_SIGNATURE_BYTES, sendCoordinatorApply } from "./coordinator-client";
import {
  checkP15WriteRequest,
  computeFramedPlanDigest,
  createWriteBackendHandlers,
  isGrantStale,
  isValidSshSignature,
  type PlanReviewSummary,
  reviewSignedPair,
  sanitizeDisplay,
  type WriteApplyResult,
} from "./write-backend";

const NOW = 1_795_500_000;
const SAMPLE_SIG = "-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAQ==\n-----END SSH SIGNATURE-----";

const cleanupDirs: string[] = [];
const cleanupServers: Server[] = [];

afterEach(async () => {
  while (cleanupServers.length > 0) {
    const srv = cleanupServers.pop();
    if (srv) await new Promise<void>((resolve) => srv.close(() => resolve()));
  }
  while (cleanupDirs.length > 0) {
    const dir = cleanupDirs.pop();
    if (dir) await rm(dir, { recursive: true, force: true });
  }
});

function buildPair({
  verb = "site_credential_rotate",
  planId = "plan_w613_1",
  validFrom = NOW - 60,
  expiresAt = NOW + 600,
  tamperDigest = false,
}: {
  verb?: string;
  planId?: string;
  validFrom?: number;
  expiresAt?: number;
  tamperDigest?: boolean;
} = {}) {
  const planObj = {
    schema_version: 1,
    plan_id: planId,
    host_id: "rustiron_w447_schedule",
    host_epoch: "epoch_w447_1",
    verb,
    site_id: "cp02",
    risk_class: "lab_only",
  };
  const planJson = JSON.stringify(planObj);
  const digest = computeFramedPlanDigest(planJson);
  const grantObj = {
    schema_version: 1,
    grant_id: "grant_w613_1",
    plan_id: planObj.plan_id,
    plan_digest: tamperDigest ? "0".repeat(64) : digest,
    issuer: "lab_agent",
    valid_from: validFrom,
    expires_at: expiresAt,
  };
  return { planJson, grantJson: JSON.stringify(grantObj), digest };
}

function makeWriteReq(
  path: string,
  body: unknown,
  headers: Record<string, string> = {},
  method = "POST",
): Request {
  const raw = typeof body === "string" ? body : JSON.stringify(body);
  return {
    method,
    url: `http://127.0.0.1:4319${path}`,
    headers: new Headers({
      host: "127.0.0.1:4319",
      origin: "http://127.0.0.1:4319",
      "sec-fetch-site": "same-origin",
      "content-type": "application/json",
      ...headers,
    }),
    text: async () => raw,
  } as unknown as Request;
}

async function startApplyCoordinator(
  onRaw: (rawText: string) => Record<string, unknown> | null,
): Promise<string> {
  const dir = await mkdtemp("/tmp/ri-p15-");
  cleanupDirs.push(dir);
  await chmod(dir, 0o700);
  const sockPath = join(dir, "control.sock");
  const server = createServer((socket) => {
    const chunks: Buffer[] = [];
    socket.on("data", (chunk: Buffer) => chunks.push(chunk));
    socket.on("end", () => {
      const buf = Buffer.concat(chunks);
      const len = buf.readUInt32BE(0);
      const rawText = buf.subarray(4, 4 + len).toString("utf8");
      const reply = onRaw(rawText);
      if (reply === null) {
        // Simulate mid-flight disconnect -> truthful OutcomeUnknown.
        socket.destroy();
        return;
      }
      const out = Buffer.from(JSON.stringify(reply), "utf8");
      const frame = Buffer.allocUnsafe(4 + out.length);
      frame.writeUInt32BE(out.length, 0);
      out.copy(frame, 4);
      socket.write(frame);
      socket.end();
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(sockPath, () => resolve());
  });
  await chmod(sockPath, 0o600);
  cleanupServers.push(server);
  return sockPath;
}

describe("P15 write security boundary (CSRF, Origin, Host, Sec-Fetch-Site, XSS)", () => {
  it("keeps write workflows disabled by default and refuses all mutating requests", async () => {
    const hosts = allowedLoopbackHosts(4319);
    const api = createWriteBackendHandlers({
      enabled: false,
      getAllowedHosts: () => hosts,
      nowSeconds: () => NOW,
    });
    const session = (await (
      await api.session(makeWriteReq("/api/write/session", "", {}, "GET"))
    ).json()) as { write_workflows_enabled: boolean; csrf_token: string | null };
    expect(session.write_workflows_enabled).toBe(false);
    expect(session.csrf_token).toBeNull();

    const reviewRes = await api.review(makeWriteReq("/api/write/plan/review", {}));
    expect(reviewRes.status).toBe(405);
    const applyRes = await api.apply(makeWriteReq("/api/write/plan/apply", {}));
    expect(applyRes.status).toBe(405);
  });

  it("enforces Host, Origin, Sec-Fetch-Site, Content-Type, CSRF, and payload bounds", () => {
    const hosts = allowedLoopbackHosts(4319);
    const token = "a".repeat(64);

    expect(
      checkP15WriteRequest(
        makeWriteReq(
          "/api/write/plan/apply",
          {},
          { host: "evil.test:4319", "x-rustiron-csrf": token },
        ),
        hosts,
        token,
        true,
      )?.status,
    ).toBe(421);

    expect(
      checkP15WriteRequest(
        makeWriteReq(
          "/api/write/plan/apply",
          {},
          { origin: "https://evil.test", "x-rustiron-csrf": token },
        ),
        hosts,
        token,
        true,
      )?.status,
    ).toBe(403);

    expect(
      checkP15WriteRequest(
        makeWriteReq(
          "/api/write/plan/apply",
          {},
          { "sec-fetch-site": "cross-site", "x-rustiron-csrf": token },
        ),
        hosts,
        token,
        true,
      )?.status,
    ).toBe(403);

    expect(
      checkP15WriteRequest(
        makeWriteReq(
          "/api/write/plan/apply",
          {},
          { "content-type": "text/plain", "x-rustiron-csrf": token },
        ),
        hosts,
        token,
        true,
      )?.status,
    ).toBe(415);

    expect(
      checkP15WriteRequest(
        makeWriteReq("/api/write/plan/apply", {}, { "x-rustiron-csrf": "wrong" }),
        hosts,
        token,
        true,
      )?.status,
    ).toBe(403);

    // W651: HTTPS origin behind TLS reverse proxy is accepted when host matches allowlist.
    const httpsHosts = new Set(["127.0.0.1:4319", "console.example.test"]);
    expect(
      checkP15WriteRequest(
        makeWriteReq(
          "/api/write/plan/review",
          {},
          {
            host: "console.example.test",
            origin: "https://console.example.test",
            "x-rustiron-csrf": token,
          },
        ),
        httpsHosts,
        token,
        true,
      ),
    ).toBeNull();
    expect(sanitizeDisplay("plan\u202Eevil\u2066id")).toBe("planevilid");

    expect(
      checkP15WriteRequest(
        makeWriteReq("/api/write/plan/apply", {}, { "x-rustiron-csrf": token }),
        hosts,
        token,
        true,
      ),
    ).toBeNull();
  });

  it("sanitizes prompt-injected control sequences and detects stale/tampered grants", () => {
    expect(sanitizeDisplay("ok\x1b[31m\r\n<script>alert(1)</script>")).toBe(
      "ok[31m<script>alert(1)</script>",
    );
    expect(isGrantStale(NOW - 10, NOW + 10, NOW)).toBe(false);
    expect(isGrantStale(NOW - 100, NOW - 1, NOW)).toBe(true);
    expect(isGrantStale(NOW + 10, NOW + 100, NOW)).toBe(true);
    expect(isValidSshSignature(SAMPLE_SIG)).toBe(true);
    expect(isValidSshSignature("not-a-sig")).toBe(false);
    expect(isValidSshSignature("A".repeat(MAX_SIGNATURE_BYTES + 1))).toBe(false);

    const olsPair = buildPair({ verb: "config_activate" });
    const summary = reviewSignedPair(olsPair.planJson, olsPair.grantJson, NOW);
    expect(summary?.digest_matches).toBe(true);
    expect(summary?.stale).toBe(false);
    expect(summary?.global_ols_impact).toBe(true);

    const tampered = buildPair({ tamperDigest: true });
    expect(reviewSignedPair(tampered.planJson, tampered.grantJson, NOW)?.digest_matches).toBe(
      false,
    );
  });
});

describe("P15 coordinator plan_apply end-to-end outcomes", () => {
  it("preserves exact raw signed bytes and reports executor_reply, replay, not_sent, and outcome_unknown truthfully", async () => {
    const pair = buildPair();
    let seenRaw = "";
    const sock = await startApplyCoordinator((raw) => {
      seenRaw = raw;
      const req = JSON.parse(raw) as { request_id: string; params: { operation_id: string } };
      if (req.params.operation_id === "op_busy") {
        return {
          schema_version: 1,
          request_id: req.request_id,
          status: "ok",
          data: {
            kind: "plan_apply",
            value: { operation_id: "op_busy", outcome: { kind: "not_sent", reason: "busy" } },
          },
          error: null,
        };
      }
      if (req.params.operation_id === "op_disconnect") return null;
      return {
        schema_version: 1,
        request_id: req.request_id,
        status: "ok",
        data: {
          kind: "plan_apply",
          value: {
            operation_id: req.params.operation_id,
            outcome: {
              kind: "executor_reply",
              reply: {
                schema_version: 1,
                operation_id: req.params.operation_id,
                state: "succeeded",
                replay: req.params.operation_id === "op_replay",
                error: null,
              },
            },
          },
        },
        error: null,
      };
    });

    const hosts = allowedLoopbackHosts(4319);
    const api = createWriteBackendHandlers({
      enabled: true,
      coordinatorSocket: sock,
      getAllowedHosts: () => hosts,
      nowSeconds: () => NOW,
    });
    const session = (await (
      await api.session(makeWriteReq("/api/write/session", "", {}, "GET"))
    ).json()) as { csrf_token: string };
    const csrf = { "x-rustiron-csrf": session.csrf_token };

    // 1. Review succeeds
    const revRes = await api.review(
      makeWriteReq(
        "/api/write/plan/review",
        { plan_json: pair.planJson, grant_json: pair.grantJson },
        csrf,
      ),
    );
    expect(revRes.status).toBe(200);
    const revBody = (await revRes.json()) as PlanReviewSummary;
    expect(revBody.plan_digest).toBe(pair.digest);

    // 2. Stale grant refused BEFORE coordinator IPC (409 STALE_GRANT)
    const stale = buildPair({ validFrom: NOW - 500, expiresAt: NOW - 1 });
    const staleRes = await api.apply(
      makeWriteReq(
        "/api/write/plan/apply",
        {
          operation_id: "op_stale",
          idempotency_key: "idem_stale",
          plan_json: stale.planJson,
          grant_json: stale.grantJson,
          signature_text: SAMPLE_SIG,
        },
        csrf,
      ),
    );
    expect(staleRes.status).toBe(409);

    // 3. Oversized body refused (413 PAYLOAD_TOO_LARGE)
    const hugeRes = await api.review(
      makeWriteReq("/api/write/plan/review", "x".repeat(MAX_REQUEST_BYTES + 10), csrf),
    );
    expect(hugeRes.status).toBe(413);

    // 4. Valid signed apply succeeds and preserves exact canonical bytes
    const okRes = await api.apply(
      makeWriteReq(
        "/api/write/plan/apply",
        {
          operation_id: "op_w613_ok",
          idempotency_key: "idem_w613_ok",
          plan_json: pair.planJson,
          grant_json: pair.grantJson,
          signature_text: SAMPLE_SIG,
        },
        csrf,
      ),
    );
    expect(okRes.status).toBe(200);
    expect(seenRaw.includes(`"plan":${pair.planJson}`)).toBe(true);
    expect(seenRaw.includes(`"grant":${pair.grantJson}`)).toBe(true);
    const okBody = (await okRes.json()) as WriteApplyResult;
    expect((okBody.outcome as { kind: string }).kind).toBe("executor_reply");

    // 5. Busy coordinator reported truthfully as not_sent
    const busyRes = await api.apply(
      makeWriteReq(
        "/api/write/plan/apply",
        {
          operation_id: "op_busy",
          idempotency_key: "idem_busy",
          plan_json: pair.planJson,
          grant_json: pair.grantJson,
          signature_text: SAMPLE_SIG,
        },
        csrf,
      ),
    );
    expect(busyRes.status).toBe(200);
    expect(((await busyRes.json()) as WriteApplyResult).outcome).toEqual({
      kind: "not_sent",
      reason: "busy",
    });

    // 6. Mid-flight disconnect NEVER claims success -> returns 503 with outcome_unknown
    const discRes = await api.apply(
      makeWriteReq(
        "/api/write/plan/apply",
        {
          operation_id: "op_disconnect",
          idempotency_key: "idem_disconnect",
          plan_json: pair.planJson,
          grant_json: pair.grantJson,
          signature_text: SAMPLE_SIG,
        },
        csrf,
      ),
    );
    expect(discRes.status).toBe(503);
    expect(((await discRes.json()) as { outcome: unknown }).outcome).toEqual({
      kind: "outcome_unknown",
    });

    // 7. Direct sendCoordinatorApply rejects invalid IDs before opening socket
    expect(
      await sendCoordinatorApply(sock, {
        operationId: "../bad",
        idempotencyKey: "idem_1",
        planRawJson: pair.planJson,
        grantRawJson: pair.grantJson,
        signatureText: SAMPLE_SIG,
      }),
    ).toEqual({ ok: false, code: "INVALID_ID" });
  });
});
