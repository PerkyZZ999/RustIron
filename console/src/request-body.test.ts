// W690 (v0.2 pass 24): the shared JSON body reader refuses before any schema runs,
// and parseBody names the refusal for the first failing field.
import { expect, test } from "bun:test";
import { z } from "zod";

import { parseBody, readJsonBody } from "./request-body";

function post(body: string, contentType = "application/json"): Request {
  return new Request("http://127.0.0.1:4319/api/x", {
    method: "POST",
    headers: { "content-type": contentType },
    body,
  });
}

async function refusal(result: unknown): Promise<[number, string]> {
  if (!(result instanceof Response)) throw new Error("expected a refusal");
  return [result.status, ((await result.json()) as { error: string }).error];
}

test("a non-JSON content type is refused with 415", async () => {
  expect(await refusal(await readJsonBody(post("{}", "text/plain"), 64))).toEqual([
    415,
    "UNSUPPORTED_MEDIA_TYPE",
  ]);
});

test("a body over the byte limit is refused with 413", async () => {
  expect(await refusal(await readJsonBody(post(`"${"é".repeat(40)}"`), 64))).toEqual([
    413,
    "PAYLOAD_TOO_LARGE",
  ]);
});

test("malformed JSON is refused with 400", async () => {
  expect(await refusal(await readJsonBody(post("{"), 64))).toEqual([400, "INVALID_JSON"]);
});

test("a body within the limit is returned parsed", async () => {
  expect(await readJsonBody(post('{"a":1}'), 64)).toEqual({ a: 1 });
});

const schema = z.strictObject({ name: z.string().min(2), age: z.int() });
const byField = (field: string | undefined) => ({ error: field ? `BAD_${field}` : "BAD_BODY" });

test("parseBody names the first failing field and treats unknown fields as the body", async () => {
  expect(await refusal(parseBody(schema, { name: "x", age: 1 }, byField))).toEqual([
    400,
    "BAD_name",
  ]);
  expect(await refusal(parseBody(schema, { name: "xy", age: 1, extra: 1 }, byField))).toEqual([
    400,
    "BAD_BODY",
  ]);
  expect(await refusal(parseBody(schema, ["xy"], byField))).toEqual([400, "BAD_BODY"]);
  expect(parseBody(schema, { name: "xy", age: 1 }, byField)).toEqual({ name: "xy", age: 1 });
});
