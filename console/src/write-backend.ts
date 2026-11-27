// W613 (P29 Slice 5 / P15): Explicit opt-in separate-custody approval & write
// backend adapter for the Rustiron Console. NEVER holds signing keys and NEVER
// mints grants; enforces loopback Host, mandatory same-origin Origin &
// Sec-Fetch-Site, JSON Content-Type, constant-time CSRF token, payload bounds,
// stale-grant refusal, digest matching, and truthful ApplyOutcome reporting.
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

import { z } from "zod";

import { checkD090Request, jsonReply } from "./backend-server";
import {
  type CoordinatorWireResponse,
  isValidOpaqueId,
  MAX_REQUEST_BYTES,
  MAX_SIGNATURE_BYTES,
  sendCoordinatorApply,
} from "./coordinator-client";
import { parseBody } from "./request-body";
import { PLAN_DOMAIN } from "./signed";

export type PlanReviewSummary = {
  schema: "rustiron-console-plan-review/1";
  verb: string;
  plan_id: string;
  host_id: string;
  host_epoch: string;
  site_ids: string[];
  issuer: string;
  risk_class: string;
  plan_bytes: number;
  plan_digest: string;
  grant_bytes: number;
  grant_sha256: string;
  grant_plan_digest: string;
  digest_matches: boolean;
  valid_from: number | null;
  expires_at: number | null;
  stale: boolean;
  global_ols_impact: boolean;
  offline_sign_command: string;
};

export type WriteApplyResult = {
  schema: "rustiron-console-apply/1";
  operation_id: string;
  outcome: unknown;
};

export type WriteBackendConfig = {
  enabled: boolean;
  coordinatorSocket?: string;
  getAllowedHosts: () => ReadonlySet<string>;
  nowSeconds?: () => number;
};

function isUnsafeDisplayCode(code: number): boolean {
  return (
    code < 0x20 ||
    code === 0x7f ||
    code === 0x061c ||
    code === 0x200e ||
    code === 0x200f ||
    (code >= 0x202a && code <= 0x202e) ||
    (code >= 0x2066 && code <= 0x2069)
  );
}

/** Strips ASCII control and Unicode Bidi override characters so plan text stays safe. */
export function sanitizeDisplay(value: unknown, maxLen = 128): string {
  if (typeof value !== "string") return "";
  let out = "";
  for (let i = 0; i < value.length && out.length < maxLen; i += 1) {
    if (!isUnsafeDisplayCode(value.charCodeAt(i))) out += value[i];
  }
  return out;
}

function parseJsonObject(raw: string): Record<string, unknown> | null {
  // W635 (M-22): reject leading/trailing outer whitespace instead of silently trimming signed bytes.
  if (raw !== raw.trim() || !raw.startsWith("{") || raw.length > MAX_REQUEST_BYTES) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

export function computeFramedPlanDigest(rawPlanJson: string): string {
  const bytes = Buffer.from(rawPlanJson, "utf8");
  return createHash("sha256")
    .update(Buffer.from(`${PLAN_DOMAIN}\0`, "ascii"))
    .update(bytes)
    .digest("hex");
}

function computePlainSha256(rawJson: string): string {
  return createHash("sha256").update(Buffer.from(rawJson, "utf8")).digest("hex");
}

function extractSiteIds(plan: Record<string, unknown>): string[] {
  if (Array.isArray(plan.site_ids)) {
    return plan.site_ids.slice(0, 64).map((item) => sanitizeDisplay(item, 64));
  }
  if (typeof plan.site_id === "string") {
    return [sanitizeDisplay(plan.site_id, 64)];
  }
  return [];
}

function readTimestamp(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

export function isGrantStale(
  validFrom: number | null,
  expiresAt: number | null,
  nowSec: number,
): boolean {
  if (validFrom === null || expiresAt === null) return true;
  return nowSec < validFrom || nowSec >= expiresAt;
}

export function isValidSshSignature(signatureText: string): boolean {
  const trimmed = signatureText.trim();
  if (trimmed.length === 0 || Buffer.byteLength(trimmed, "utf8") > MAX_SIGNATURE_BYTES) {
    return false;
  }
  return (
    trimmed.startsWith("-----BEGIN SSH SIGNATURE-----") &&
    trimmed.endsWith("-----END SSH SIGNATURE-----")
  );
}

/** Builds a sanitized, prompt-injection-safe P15 review summary from raw canonical bytes. */
export function reviewSignedPair(
  planRaw: string,
  grantRaw: string,
  nowSec: number,
): PlanReviewSummary | null {
  const plan = parseJsonObject(planRaw);
  const grant = parseJsonObject(grantRaw);
  if (!plan || !grant) return null;
  const planDigest = computeFramedPlanDigest(planRaw);
  const grantSha = computePlainSha256(grantRaw);
  const grantPlanDigest = sanitizeDisplay(grant.plan_digest, 64);
  const validFrom = readTimestamp(grant.valid_from);
  const expiresAt = readTimestamp(grant.expires_at);
  const verb = sanitizeDisplay(plan.verb, 64);
  return {
    schema: "rustiron-console-plan-review/1",
    verb,
    plan_id: sanitizeDisplay(plan.plan_id, 64),
    host_id: sanitizeDisplay(plan.host_id, 64),
    host_epoch: sanitizeDisplay(plan.host_epoch, 64),
    site_ids: extractSiteIds(plan),
    issuer: sanitizeDisplay(grant.issuer, 64),
    risk_class: sanitizeDisplay(plan.risk_class, 32),
    plan_bytes: Buffer.byteLength(planRaw.trim(), "utf8"),
    plan_digest: planDigest,
    grant_bytes: Buffer.byteLength(grantRaw.trim(), "utf8"),
    grant_sha256: grantSha,
    grant_plan_digest: grantPlanDigest,
    digest_matches: grantPlanDigest === planDigest,
    valid_from: validFrom,
    expires_at: expiresAt,
    stale: isGrantStale(validFrom, expiresAt, nowSec),
    global_ols_impact: verb === "config_activate",
    offline_sign_command:
      "ssh-keygen -Y sign -n rustiron-plan-v1 -f ~/.ssh/rustiron_operator grant.json",
  };
}

function tokensEqual(expected: string, actual: string): boolean {
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(actual, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

function checkSameOriginPost(request: Request, host: string): Response | null {
  const origin = request.headers.get("origin")?.trim().toLowerCase() ?? "";
  if (!origin || (origin !== `http://${host}` && origin !== `https://${host}`)) {
    return jsonReply(403, { error: "CROSS_ORIGIN_FORBIDDEN" });
  }
  const fetchSite = request.headers.get("sec-fetch-site")?.trim().toLowerCase();
  if (fetchSite && fetchSite !== "same-origin") {
    return jsonReply(403, { error: "CROSS_ORIGIN_FORBIDDEN" });
  }
  const contentType = request.headers.get("content-type")?.trim().toLowerCase() ?? "";
  if (!contentType.startsWith("application/json")) {
    return jsonReply(415, { error: "UNSUPPORTED_MEDIA_TYPE" });
  }
  return null;
}

/** Enforces P15 write security boundary: opt-in, Host, Origin, Sec-Fetch-Site, JSON, CSRF. */
export function checkP15WriteRequest(
  request: Request,
  allowedHosts: ReadonlySet<string>,
  csrfToken: string,
  enabled: boolean,
): Response | null {
  if (!enabled) {
    return jsonReply(405, { error: "WRITE_WORKFLOWS_DISABLED" }, { allow: "GET, HEAD" });
  }
  const host = request.headers.get("host")?.trim().toLowerCase() ?? "";
  if (!host || !allowedHosts.has(host)) {
    return jsonReply(421, { error: "HOST_NOT_ALLOWED" });
  }
  if (request.method !== "POST") {
    return jsonReply(405, { error: "METHOD_NOT_ALLOWED" }, { allow: "POST" });
  }
  const originError = checkSameOriginPost(request, host);
  if (originError) return originError;
  const provided = request.headers.get("x-rustiron-csrf")?.trim() ?? "";
  if (!provided || !tokensEqual(csrfToken, provided)) {
    return jsonReply(403, { error: "CSRF_TOKEN_INVALID" });
  }
  return null;
}

async function readBoundedJson(
  request: Request,
): Promise<{ ok: true; data: Record<string, unknown> } | { ok: false; response: Response }> {
  const text = await request.text();
  if (Buffer.byteLength(text, "utf8") > MAX_REQUEST_BYTES) {
    return { ok: false, response: jsonReply(413, { error: "PAYLOAD_TOO_LARGE" }) };
  }
  const parsed = parseJsonObject(text);
  if (!parsed) {
    return { ok: false, response: jsonReply(400, { error: "INVALID_REQUEST" }) };
  }
  return { ok: true, data: parsed };
}

const REQUEST_REFUSAL = { error: "INVALID_REQUEST" };

/** W681: plan and grant stay raw strings; the Rust decoder is their only authority. */
const reviewBody = z.strictObject({ plan_json: z.string(), grant_json: z.string() });

const applyBody = reviewBody.extend({
  operation_id: z.string(),
  idempotency_key: z.string(),
  signature_text: z.string(),
});

async function readWriteBody<T>(request: Request, schema: z.ZodType<T>): Promise<T | Response> {
  const body = await readBoundedJson(request);
  if (!body.ok) return body.response;
  return parseBody(schema, body.data, REQUEST_REFUSAL);
}

function checkReviewValidity(summary: PlanReviewSummary | null): Response | null {
  if (!summary) return jsonReply(400, { error: "INVALID_PLAN_OR_GRANT" });
  if (!summary.digest_matches) return jsonReply(400, { error: "DIGEST_MISMATCH" });
  if (summary.stale) return jsonReply(409, { error: "STALE_GRANT" });
  return null;
}

function validateApplyPayload(
  data: z.infer<typeof applyBody>,
  nowSec: number,
):
  | {
      ok: true;
      operationId: string;
      idempotencyKey: string;
      planRaw: string;
      grantRaw: string;
      signatureText: string;
    }
  | { ok: false; response: Response } {
  const {
    operation_id: operationId,
    idempotency_key: idempotencyKey,
    plan_json: planRaw,
    grant_json: grantRaw,
    signature_text: signatureText,
  } = data;

  if (!isValidOpaqueId(operationId) || !isValidOpaqueId(idempotencyKey)) {
    return { ok: false, response: jsonReply(400, { error: "INVALID_ID" }) };
  }
  const reviewErr = checkReviewValidity(reviewSignedPair(planRaw, grantRaw, nowSec));
  if (reviewErr) return { ok: false, response: reviewErr };
  if (!isValidSshSignature(signatureText)) {
    return { ok: false, response: jsonReply(400, { error: "INVALID_SIGNATURE" }) };
  }
  return { ok: true, operationId, idempotencyKey, planRaw, grantRaw, signatureText };
}

const OUTCOME_UNKNOWN = { kind: "outcome_unknown" } as const;

/** W687: mirrors `ApplyOutcome` (crates/contracts/src/apply.rs). */
const applyOutcome = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("not_sent"), reason: z.string() }),
  z.strictObject({ kind: z.literal("outcome_unknown") }),
  z.strictObject({
    kind: z.literal("executor_reply"),
    reply: z.looseObject({ operation_id: z.string() }),
  }),
]);

const applyReplyValue = z.strictObject({ operation_id: z.string(), outcome: applyOutcome });

/**
 * W687: as `decode_apply_response` does, a reply counts only when it is this
 * operation's `plan_apply` value; anything else is `outcome_unknown`, never success.
 */
function correlatedOutcome(response: CoordinatorWireResponse, operationId: string): unknown {
  if (response.status !== "ok" || response.data.kind !== "plan_apply") return OUTCOME_UNKNOWN;
  const value = applyReplyValue.safeParse(response.data.value);
  if (!value.success || value.data.operation_id !== operationId) return OUTCOME_UNKNOWN;
  const { outcome } = value.data;
  if (outcome.kind === "executor_reply" && outcome.reply.operation_id !== operationId) {
    return OUTCOME_UNKNOWN;
  }
  return outcome;
}

export function createWriteBackendHandlers(config: WriteBackendConfig) {
  const csrfToken = randomBytes(32).toString("hex");
  const nowSec = config.nowSeconds ?? (() => Math.floor(Date.now() / 1000));

  return {
    session: async (request: Request): Promise<Response> => {
      const refused = checkD090Request(request, config.getAllowedHosts());
      if (refused) return refused;
      return jsonReply(200, {
        schema: "rustiron-console-write-session/1",
        write_workflows_enabled: config.enabled,
        csrf_token: config.enabled ? csrfToken : null,
        custody: "external_sshsig_only",
      });
    },
    review: async (request: Request): Promise<Response> => {
      const refused = checkP15WriteRequest(
        request,
        config.getAllowedHosts(),
        csrfToken,
        config.enabled,
      );
      if (refused) return refused;
      const fields = await readWriteBody(request, reviewBody);
      if (fields instanceof Response) return fields;
      const summary = reviewSignedPair(fields.plan_json, fields.grant_json, nowSec());
      if (!summary) return jsonReply(400, { error: "INVALID_PLAN_OR_GRANT" });
      return jsonReply(200, summary);
    },
    apply: async (request: Request): Promise<Response> => {
      const refused = checkP15WriteRequest(
        request,
        config.getAllowedHosts(),
        csrfToken,
        config.enabled,
      );
      if (refused) return refused;
      const fields = await readWriteBody(request, applyBody);
      if (fields instanceof Response) return fields;
      const valid = validateApplyPayload(fields, nowSec());
      if (!valid.ok) return valid.response;

      const ipc = await sendCoordinatorApply(config.coordinatorSocket, {
        operationId: valid.operationId,
        idempotencyKey: valid.idempotencyKey,
        planRawJson: valid.planRaw,
        grantRawJson: valid.grantRaw,
        signatureText: valid.signatureText,
      });
      if (!ipc.ok) {
        const status = ipc.code === "UNAUTHORIZED_PEER" ? 403 : 503;
        return jsonReply(status, { error: ipc.code, outcome: { kind: "outcome_unknown" } });
      }
      const result: WriteApplyResult = {
        schema: "rustiron-console-apply/1",
        operation_id: valid.operationId,
        outcome: correlatedOutcome(ipc.response, valid.operationId),
      };
      return jsonReply(200, result);
    },
  };
}
