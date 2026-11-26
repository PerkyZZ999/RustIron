// W396 (D-045): the exact signed bytes of one admission, as the executor
// journal stored them, and the receipt attestation of this host (W392,
// D-042). The console never trusts the stored digests by themselves: it
// hashes the bytes it shows and compares them with what the journal recorded.
import type { Observation } from "./live";

/** The plan digest framing of CANONICAL-BYTES: ASCII("rustiron/plan/v1") || 00 || bytes. */
export const PLAN_DOMAIN = "rustiron/plan/v1";
/** The SSHSIG namespace of plan and grant signatures. */
const PLAN_NAMESPACE = "rustiron-plan-v1";

const hex64 = /^[0-9a-f]{64}$/;
const id = /^[A-Za-z0-9_-]{1,64}$/;
const MAX_REQUEST_BYTES = 262_144;

export type SignedObject = {
  part: "plan" | "grant";
  /** The canonical JSON text; null when the journal did not keep it (over its bound). */
  text: string | null;
  /** Length the journal recorded, in bytes. */
  bytes: number;
  /** Plain SHA-256 of the bytes, as the journal recorded it. */
  sha256: string;
  /** The intent digest: domain-framed for a plan, plain for a grant. */
  digest: string;
};

export type SignedBytes =
  | { state: "absent" }
  | { state: "not_recorded"; planDigest: string; grantDigest: string }
  | { state: "malformed" }
  | {
      state: "recorded";
      issuer: string;
      signerPolicyEpoch: string;
      namespace: string;
      plan: SignedObject;
      grant: SignedObject;
    };

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

const isHex64 = (value: unknown): value is string => typeof value === "string" && hex64.test(value);
const isId = (value: unknown): value is string => typeof value === "string" && id.test(value);
const isLength = (value: unknown): value is number =>
  typeof value === "number" &&
  Number.isSafeInteger(value) &&
  value >= 2 &&
  value <= MAX_REQUEST_BYTES;

const MALFORMED: SignedBytes = { state: "malformed" };

function part(
  value: unknown,
  name: SignedObject["part"],
  digest: string,
  objects: Record<string, unknown>,
): SignedObject | null {
  const { sha256, bytes, stored } = record(value) ?? {};
  if (!isHex64(sha256) || !isLength(bytes) || typeof stored !== "boolean") return null;
  const text = stored ? objects[sha256] : null;
  if (stored && typeof text !== "string") return null;
  return { part: name, text: text as string | null, bytes, sha256, digest };
}

/** The issuer and epoch of a verified admission; null for any other shape. */
function signerOf(facts: Record<string, unknown>) {
  const { issuer, signer_policy_epoch: epoch, verification, namespace } = facts;
  const verified = verification === "sshsig_verified" && namespace === PLAN_NAMESPACE;
  return verified && isId(issuer) && isId(epoch) ? { issuer, signerPolicyEpoch: epoch } : null;
}

function admissionOf(observation: Observation, operationId: string) {
  if (!Array.isArray(observation.admissions)) return null;
  return (
    observation.admissions.map(record).find((item) => item?.operation_id === operationId) ?? null
  );
}

function recordedBytes(
  signed: unknown,
  objects: Record<string, unknown>,
  planDigest: string,
  grantDigest: string,
): SignedBytes {
  const facts = record(signed);
  if (!facts) return MALFORMED;
  const signer = signerOf(facts);
  const plan = part(facts.plan, "plan", planDigest, objects);
  const grant = part(facts.grant, "grant", grantDigest, objects);
  if (!signer || !plan || !grant) return MALFORMED;
  return { state: "recorded", ...signer, namespace: PLAN_NAMESPACE, plan, grant };
}

/** The signed bytes of one operation, or why they are not shown. */
export function signedBytes(observation: Observation, operationId: string): SignedBytes {
  const admission = admissionOf(observation, operationId);
  if (!admission) return { state: "absent" };
  const objects = record(observation.signed_objects);
  const { plan_digest: planDigest, grant_digest: grantDigest, signed } = admission;
  if (!objects || !isHex64(planDigest) || !isHex64(grantDigest)) return MALFORMED;
  if (signed === null) return { state: "not_recorded", planDigest, grantDigest };
  return recordedBytes(signed, objects, planDigest, grantDigest);
}

/**
 * W429: the requester that the operation's recorded signed plan names, or
 * null when the journal kept no plan bytes or the plan names no valid id.
 * The text is the recorded signed plan; the signed panel checks its digests.
 */
export function signedRequester(observation: Observation, operationId: string): string | null {
  const signed = signedBytes(observation, operationId);
  if (signed.state !== "recorded" || signed.plan.text === null) return null;
  try {
    const { requester } = (record(JSON.parse(signed.plan.text)) ?? {}) as { requester?: unknown };
    return isId(requester) ? requester : null;
  } catch {
    return null;
  }
}

export type ObjectCheck =
  | { state: "not_kept" }
  | {
      state: "match" | "mismatch";
      /** SHA-256 the console computed over the shown bytes. */
      sha256: string;
      /** Byte length the console counted. */
      bytes: number;
      /** Which recorded values differ from the console's own result. */
      differs: ("length" | "sha256" | "digest")[];
    };

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function digestHex(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  return toHex(await crypto.subtle.digest("SHA-256", bytes));
}

/**
 * Hashes the shown bytes in the browser and compares them with the journal:
 * the length, the plain SHA-256, and the intent digest (with the plan domain
 * framing for a plan). Any difference is a mismatch.
 */
export async function checkObject(object: SignedObject): Promise<ObjectCheck> {
  if (object.text === null) return { state: "not_kept" };
  const bytes = new TextEncoder().encode(object.text);
  const plain = await digestHex(bytes);
  let digest = plain;
  if (object.part === "plan") {
    const prefix = new TextEncoder().encode(PLAN_DOMAIN);
    const framed = new Uint8Array(prefix.length + 1 + bytes.length);
    framed.set(prefix, 0);
    framed.set(bytes, prefix.length + 1);
    digest = await digestHex(framed);
  }
  const differs: ("length" | "sha256" | "digest")[] = [];
  if (bytes.length !== object.bytes) differs.push("length");
  if (plain !== object.sha256) differs.push("sha256");
  if (digest !== object.digest) differs.push("digest");
  return {
    state: differs.length === 0 ? "match" : "mismatch",
    sha256: plain,
    bytes: bytes.length,
    differs,
  };
}

export type ReceiptAttestation =
  | { state: "signed"; label: string; fingerprint: string; namespace: string }
  | { state: "unsigned" | "refused" | "absent" | "malformed"; label: string };

/**
 * W392 (D-042): how receipts exported from this host state their
 * attestation. A receipt is signed when it is exported, with the host key
 * that the observation names; the signature does not make it independent.
 */
export function receiptAttestation(host: Observation["host"]): ReceiptAttestation {
  const key = host.receipt_key;
  if (key === undefined) return { state: "absent", label: "Not in this observation" };
  const facts = record(key);
  if (!facts) return { state: "malformed", label: "Receipt key facts are malformed; not shown" };
  if (facts.state === "absent") return { state: "unsigned", label: "Self-attested, unsigned" };
  if (facts.state === "refused")
    return { state: "refused", label: "Receipt key refused: exports are refused" };
  const { fingerprint, namespace, algorithm } = facts;
  if (
    facts.state !== "present" ||
    algorithm !== "ssh-ed25519" ||
    namespace !== "rustiron-receipt-v1" ||
    typeof fingerprint !== "string" ||
    !/^SHA256:[A-Za-z0-9+/]{43}$/.test(fingerprint)
  )
    return { state: "malformed", label: "Receipt key facts are malformed; not shown" };
  return { state: "signed", label: "Self-attested, signed", fingerprint, namespace };
}

/** Whether an operation id names a record that has a receipt (a capture or a probe). */
export function hasReceipt(observation: Observation, operationId: string): boolean {
  return (
    observation.captures.some((item) => item.operation_id === operationId) ||
    observation.probes.some((item) => item.operation_id === operationId)
  );
}

const byteCount = new Intl.NumberFormat("en");

export function bytesText(bytes: number): string {
  return `${byteCount.format(bytes)} ${bytes === 1 ? "byte" : "bytes"}`;
}
