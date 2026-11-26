// W612 (P29 Slice 4 / CP04): Strictly read-only local IPC client for the
// Rustiron coordinator Unix socket, implementing READ-PROTOCOL.md v1 framing
// (crates/contracts/src/local.rs). Zero write methods, zero signing keys.
import { lstat, realpath } from "node:fs/promises";
import { createConnection } from "node:net";
import { dirname, isAbsolute } from "node:path";

export const MAX_REQUEST_BYTES = 262_144;
export const MAX_RESPONSE_BYTES = 1_048_576;
export const MAX_SIGNATURE_BYTES = 16_384;
export const COORDINATOR_DEADLINE_MS = 5_000;

const OPAQUE_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const CURSOR_RE = /^[\x21-\x7e]{1,256}$/;

export type ReadMethod =
  | "doctor"
  | "site_list"
  | "site_inspect"
  | "operation_status"
  | "evidence_export";

export type CoordinatorErrorCode =
  | "COORDINATOR_NOT_CONFIGURED"
  | "INVALID_ID"
  | "INVALID_REQUEST"
  | "UNAUTHORIZED_PEER"
  | "DEPENDENCY_UNAVAILABLE"
  | "RESPONSE_TOO_LARGE"
  | "INVALID_RESPONSE";

export type CoordinatorWireResponse = {
  schema_version: 1;
  request_id: string | null;
  status: "ok" | "error";
  data: { kind: string; value: unknown } | null;
  error: {
    code: string;
    message: string;
    retryable: boolean;
    operation_id: string | null;
    details: string[];
  } | null;
};

export type CoordinatorResult =
  | { ok: true; response: CoordinatorWireResponse }
  | { ok: false; code: CoordinatorErrorCode };

export function isValidOpaqueId(value: string): boolean {
  return OPAQUE_ID_RE.test(value);
}

export function isValidCursor(value: string): boolean {
  return CURSOR_RE.test(value);
}

let requestCounter = 0;

function nextRequestId(): string {
  requestCounter = (requestCounter + 1) % 1_000_000_000;
  return `console-${process.pid}-${requestCounter}`;
}

function currentUid(): number | null {
  return typeof process.getuid === "function" ? process.getuid() : null;
}

async function checkParentDir(parent: string, uid: number): Promise<boolean> {
  const info = await lstat(parent);
  if (!info.isDirectory() || info.uid !== uid || (info.mode & 0o7777) !== 0o700) {
    return false;
  }
  return (await realpath(parent)) === parent;
}

async function checkSocketFile(socketPath: string, uid: number): Promise<boolean> {
  const info = await lstat(socketPath);
  return info.isSocket() && info.uid === uid && (info.mode & 0o7777) === 0o600;
}

function mapFsError(err: unknown): CoordinatorErrorCode {
  const code = (err as NodeJS.ErrnoException | null)?.code;
  return code === "EACCES" || code === "EPERM" ? "UNAUTHORIZED_PEER" : "DEPENDENCY_UNAVAILABLE";
}

function validSocketParent(socketPath: string): string | null {
  if (!socketPath || socketPath.includes("\0") || !isAbsolute(socketPath)) return null;
  const parent = dirname(socketPath);
  return parent && parent !== socketPath ? parent : null;
}

/** Validates socket ancestry & owner-only permissions matching crates/contracts/src/local.rs. */
async function checkSocketPath(socketPath: string): Promise<CoordinatorErrorCode | null> {
  const parent = validSocketParent(socketPath);
  if (!parent) return "INVALID_REQUEST";
  const uid = currentUid();
  if (!uid) return "UNAUTHORIZED_PEER";
  try {
    const ok = (await checkParentDir(parent, uid)) && (await checkSocketFile(socketPath, uid));
    return ok ? null : "UNAUTHORIZED_PEER";
  } catch (err) {
    return mapFsError(err);
  }
}

function isPresent(value: unknown): boolean {
  return value !== undefined && value !== null;
}

function hasValidWireEnvelope(
  parsed: Partial<CoordinatorWireResponse>,
  expectedRequestId?: string,
): boolean {
  if (parsed.schema_version !== 1) return false;
  if (expectedRequestId && parsed.request_id !== expectedRequestId) return false;
  const hasData = isPresent(parsed.data);
  const hasError = isPresent(parsed.error);
  return (
    (parsed.status === "ok" && hasData && !hasError) ||
    (parsed.status === "error" && hasError && !hasData)
  );
}

function parseWireResponse(payload: Buffer, expectedRequestId?: string): CoordinatorResult {
  try {
    const parsed = JSON.parse(payload.toString("utf8")) as Partial<CoordinatorWireResponse> | null;
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      !hasValidWireEnvelope(parsed, expectedRequestId)
    ) {
      return { ok: false, code: "INVALID_RESPONSE" };
    }
    return { ok: true, response: parsed as CoordinatorWireResponse };
  } catch {
    return { ok: false, code: "INVALID_RESPONSE" };
  }
}

function sendFramedPayload(
  socketPath: string,
  body: Buffer,
  deadlineMs: number,
  expectedRequestId?: string,
): Promise<CoordinatorResult> {
  if (body.length === 0 || body.length > MAX_REQUEST_BYTES) {
    return Promise.resolve({ ok: false, code: "INVALID_REQUEST" });
  }
  const frame = Buffer.allocUnsafe(4 + body.length);
  frame.writeUInt32BE(body.length, 0);
  body.copy(frame, 4);

  return new Promise<CoordinatorResult>((resolve) => {
    let settled = false;
    const chunks: Buffer[] = [];
    let totalBytes = 0;
    let expectedLength: number | null = null;

    const finish = (result: CoordinatorResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(result);
    };

    const socket = createConnection({ path: socketPath });
    const timer = setTimeout(() => {
      finish({ ok: false, code: "DEPENDENCY_UNAVAILABLE" });
    }, deadlineMs);

    socket.on("connect", () => {
      socket.write(frame);
      socket.end();
    });

    socket.on("data", (chunk: Buffer) => {
      totalBytes += chunk.length;
      if (totalBytes > 4 + MAX_RESPONSE_BYTES + 1) {
        finish({ ok: false, code: "RESPONSE_TOO_LARGE" });
        return;
      }
      chunks.push(chunk);
      if (expectedLength === null && totalBytes >= 4) {
        const header = Buffer.concat(chunks, Math.min(totalBytes, 4));
        expectedLength = header.readUInt32BE(0);
        if (expectedLength === 0) {
          finish({ ok: false, code: "INVALID_RESPONSE" });
          return;
        }
        if (expectedLength > MAX_RESPONSE_BYTES) {
          finish({ ok: false, code: "RESPONSE_TOO_LARGE" });
          return;
        }
      }
      if (expectedLength !== null && totalBytes > 4 + expectedLength) {
        finish({ ok: false, code: "INVALID_RESPONSE" });
      }
    });

    socket.on("end", () => {
      if (expectedLength === null || totalBytes !== 4 + expectedLength) {
        finish({ ok: false, code: "INVALID_RESPONSE" });
        return;
      }
      const all = Buffer.concat(chunks, totalBytes);
      finish(parseWireResponse(all.subarray(4), expectedRequestId));
    });

    socket.on("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "EACCES" || err.code === "EPERM") {
        finish({ ok: false, code: "UNAUTHORIZED_PEER" });
      } else {
        finish({ ok: false, code: "DEPENDENCY_UNAVAILABLE" });
      }
    });
  });
}

/** Sends one length-prefixed read request frame and reads one bounded response frame + EOF. */
export async function sendCoordinatorRead(
  socketPath: string | undefined,
  method: ReadMethod,
  params: Record<string, unknown>,
  deadlineMs = COORDINATOR_DEADLINE_MS,
): Promise<CoordinatorResult> {
  if (!socketPath) {
    return { ok: false, code: "COORDINATOR_NOT_CONFIGURED" };
  }
  const pathError = await checkSocketPath(socketPath);
  if (pathError) {
    return { ok: false, code: pathError };
  }
  const reqId = nextRequestId();
  const body = Buffer.from(
    JSON.stringify({
      schema_version: 1,
      request_id: reqId,
      method,
      params,
    }),
    "utf8",
  );
  return sendFramedPayload(socketPath, body, deadlineMs, reqId);
}

export type ApplySubmissionInput = {
  operationId: string;
  idempotencyKey: string;
  planRawJson: string;
  grantRawJson: string;
  signatureText: string;
};

/**
 * W613 (P15): forwards already-signed canonical plan + grant bytes and detached
 * SSHSIG signature to the coordinator's `plan_apply` method without altering bytes.
 * Never signs, never mints authority.
 */
export async function sendCoordinatorApply(
  socketPath: string | undefined,
  input: ApplySubmissionInput,
  deadlineMs = COORDINATOR_DEADLINE_MS,
): Promise<CoordinatorResult> {
  if (!socketPath) return { ok: false, code: "COORDINATOR_NOT_CONFIGURED" };
  if (!isValidOpaqueId(input.operationId) || !isValidOpaqueId(input.idempotencyKey)) {
    return { ok: false, code: "INVALID_ID" };
  }
  // W635 (M-22): never silently alter or trim signed canonical bytes; reject
  // outer whitespace visibly so exact signed bytes reach the coordinator.
  const plan = input.planRawJson;
  const grant = input.grantRawJson;
  if (
    plan !== plan.trim() ||
    grant !== grant.trim() ||
    !plan.startsWith("{") ||
    !grant.startsWith("{")
  ) {
    return { ok: false, code: "INVALID_REQUEST" };
  }
  const pathError = await checkSocketPath(socketPath);
  if (pathError) return { ok: false, code: pathError };
  const rawReqId = nextRequestId();
  const reqId = JSON.stringify(rawReqId);
  const opId = JSON.stringify(input.operationId);
  const idem = JSON.stringify(input.idempotencyKey);
  const sig = JSON.stringify(input.signatureText);
  // Preserve exact signed plan & grant JSON bytes verbatim (crates/contracts/src/apply.rs).
  const rawEnvelope =
    `{"schema_version":1,"request_id":${reqId},"method":"plan_apply",` +
    `"params":{"operation_id":${opId},"idempotency_key":${idem},"plan":${plan},"grant":${grant},"signature":${sig}}}`;
  return sendFramedPayload(socketPath, Buffer.from(rawEnvelope, "utf8"), deadlineMs, rawReqId);
}

export function coordinatorDoctor(socketPath: string | undefined): Promise<CoordinatorResult> {
  return sendCoordinatorRead(socketPath, "doctor", {});
}

export function coordinatorSiteList(
  socketPath: string | undefined,
  limit = 25,
  cursor: string | null = null,
): Promise<CoordinatorResult> {
  const boundedLimit = Number.isInteger(limit) ? Math.min(Math.max(limit, 1), 100) : 25;
  if (cursor !== null && !isValidCursor(cursor)) {
    return Promise.resolve({ ok: false, code: "INVALID_REQUEST" });
  }
  return sendCoordinatorRead(socketPath, "site_list", {
    limit: boundedLimit,
    cursor,
  });
}

export function coordinatorSiteInspect(
  socketPath: string | undefined,
  siteId: string,
): Promise<CoordinatorResult> {
  if (!isValidOpaqueId(siteId)) {
    return Promise.resolve({ ok: false, code: "INVALID_ID" });
  }
  return sendCoordinatorRead(socketPath, "site_inspect", { site_id: siteId });
}

export function coordinatorOperationStatus(
  socketPath: string | undefined,
  operationId: string,
): Promise<CoordinatorResult> {
  if (!isValidOpaqueId(operationId)) {
    return Promise.resolve({ ok: false, code: "INVALID_ID" });
  }
  return sendCoordinatorRead(socketPath, "operation_status", { operation_id: operationId });
}

export function coordinatorEvidenceExport(
  socketPath: string | undefined,
  operationId: string,
): Promise<CoordinatorResult> {
  if (!isValidOpaqueId(operationId)) {
    return Promise.resolve({ ok: false, code: "INVALID_ID" });
  }
  return sendCoordinatorRead(socketPath, "evidence_export", { operation_id: operationId });
}
