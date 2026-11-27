// W713: the browser's one request path to the Console API.
import { afterEach, describe, expect, it } from "bun:test";

import { consoleRequest, failureText } from "./console-request";

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

function answer(response: Response | Error) {
  const seen: { url: string; init?: RequestInit }[] = [];
  globalThis.fetch = (async (url: string, init?: RequestInit) => {
    seen.push({ url, init });
    if (response instanceof Error) throw response;
    return response;
  }) as unknown as typeof fetch;
  return seen;
}

describe("consoleRequest (W713)", () => {
  it("sends the cookie, no cache, and a JSON body, and returns the data", async () => {
    const seen = answer(Response.json({ ok: true, n: 1 }));
    const reply = await consoleRequest<{ n: number }>("/api/x", {
      method: "POST",
      json: { a: 1 },
    });
    expect(reply).toEqual({ ok: true, status: 200, data: { ok: true, n: 1 } as never });
    const init = seen[0]?.init ?? {};
    expect(init.credentials).toBe("same-origin");
    expect(init.cache).toBe("no-store");
    expect(init.body).toBe('{"a":1}');
    expect(init.headers).toEqual({ "content-type": "application/json" });
  });

  it("sends no body or content type without JSON", async () => {
    const seen = answer(Response.json({}));
    await consoleRequest("/api/x", { method: "DELETE" });
    expect(seen[0]?.init?.body).toBeUndefined();
    expect(seen[0]?.init?.headers).toEqual({});
  });

  it("returns the server's code and message on a refusal", async () => {
    answer(Response.json({ error: "INVALID_ROLE", message: "Choose a role." }, { status: 400 }));
    const reply = await consoleRequest("/api/x");
    expect(reply).toMatchObject({
      ok: false,
      status: 400,
      code: "INVALID_ROLE",
      message: "Choose a role.",
    });
    if (!reply.ok) expect(failureText(reply, "fallback")).toBe("Choose a role.");
  });

  it("falls back to the code, then the caller's text, for a bare refusal", async () => {
    answer(Response.json({ error: "RATE_LIMITED" }, { status: 429 }));
    const coded = await consoleRequest("/api/x");
    if (!coded.ok) expect(failureText(coded, "fallback")).toBe("RATE_LIMITED");
    answer(new Response("<html>", { status: 502 }));
    const bare = await consoleRequest("/api/x");
    expect(bare).toMatchObject({ ok: false, status: 502, code: null, message: null, data: null });
    if (!bare.ok) expect(failureText(bare, "fallback")).toBe("fallback");
  });

  it("never rejects when the server does not answer", async () => {
    answer(new TypeError("network down"));
    const reply = await consoleRequest("/api/x");
    expect(reply).toMatchObject({ ok: false, status: null });
    if (!reply.ok) {
      expect(failureText(reply, "fallback", "unreachable")).toBe("unreachable");
      expect(failureText(reply, "fallback")).toContain("did not answer");
    }
  });
});
