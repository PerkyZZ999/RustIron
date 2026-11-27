// W681 (v0.2 queue item 4): one strict Zod schema per Console JSON route.
// Host, Origin, CSRF, and size guards run before these helpers; plans and grants
// stay raw strings for the Rust decoder, which remains their only authority.
import type { z } from "zod";

import { jsonReply } from "./backend-server";

export type BodyRefusal = { error: string; field?: string; message?: string };

/** Reads a JSON request body after the content-type and byte-limit checks. */
export async function readJsonBody(req: Request, maxBytes: number): Promise<unknown> {
  const ct = req.headers.get("content-type")?.toLowerCase() ?? "";
  if (!ct.includes("application/json")) {
    return jsonReply(415, { error: "UNSUPPORTED_MEDIA_TYPE" });
  }
  const raw = await req.text();
  if (Buffer.byteLength(raw, "utf8") > maxBytes) {
    return jsonReply(413, { error: "PAYLOAD_TOO_LARGE" });
  }
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    return jsonReply(400, { error: "INVALID_JSON" });
  }
}

/**
 * Parses `body` with `schema`, or answers 400 with the refusal for the first failing
 * top-level field (`undefined` for a non-object body or an unknown field).
 */
export function parseBody<T>(
  schema: z.ZodType<T>,
  body: unknown,
  refusal: BodyRefusal | ((field: string | undefined) => BodyRefusal),
): T | Response {
  const result = schema.safeParse(body);
  if (result.success) return result.data;
  const first = result.error.issues[0];
  const field = first?.code === "unrecognized_keys" ? undefined : first?.path[0];
  const chosen =
    typeof refusal === "function"
      ? refusal(typeof field === "string" ? field : undefined)
      : refusal;
  return jsonReply(400, chosen);
}
