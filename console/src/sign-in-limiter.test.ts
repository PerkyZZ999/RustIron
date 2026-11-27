// W694: sign-in protection limits, with an injected clock.
import { expect, test } from "bun:test";

import { SIGN_IN_LIMITS, clientAddress, createSignInLimiter } from "./sign-in-limiter";

const T0 = 1_000_000;

function failMany(
  limiter: ReturnType<typeof createSignInLimiter>,
  count: number,
  address: (i: number) => string,
  account: string | null,
) {
  for (let i = 0; i < count; i += 1) limiter.record(address(i), account, true, T0 + i);
}

test("an address is refused after 5 failures in a minute, then allowed again", () => {
  const limiter = createSignInLimiter();
  failMany(limiter, 5, () => "203.0.113.5", null);
  expect(limiter.check("203.0.113.5", null, false, T0 + 10)).toEqual({
    kind: "refuse",
    reason: "address",
    retryAfterSeconds: 60,
  });
  expect(limiter.check("198.51.100.7", null, false, T0 + 10).kind).toBe("allow");
  expect(limiter.check("203.0.113.5", null, false, T0 + SIGN_IN_LIMITS.windowMs + 5).kind).toBe(
    "allow",
  );
});

test("an account slows down with failures but is never locked out", () => {
  const limiter = createSignInLimiter();
  const delays = [1, 2, 3, 4, 10].map((failures) => {
    const fresh = createSignInLimiter();
    failMany(fresh, failures, (i) => `192.0.2.${i}`, "owner@example.test");
    return fresh.check("198.51.100.9", "owner@example.test", false, T0 + 100);
  });
  expect(delays).toEqual([
    { kind: "allow", delayMs: 250 },
    { kind: "allow", delayMs: 500 },
    { kind: "allow", delayMs: 1000 },
    { kind: "allow", delayMs: 2000 },
    { kind: "allow", delayMs: 8000 },
  ]);
  expect(limiter.check("198.51.100.9", "owner@example.test", false, T0)).toEqual({
    kind: "allow",
    delayMs: 0,
  });
});

test("a success clears its own address and account, not everyone's", () => {
  const limiter = createSignInLimiter();
  failMany(limiter, 4, () => "203.0.113.5", "owner@example.test");
  failMany(limiter, 5, () => "198.51.100.7", null);
  limiter.record("203.0.113.5", "owner@example.test", false, T0 + 50);
  expect(limiter.check("203.0.113.5", "owner@example.test", false, T0 + 60)).toEqual({
    kind: "allow",
    delayMs: 0,
  });
  expect(limiter.check("198.51.100.7", null, false, T0 + 60).kind).toBe("refuse");
});

test("the global breaker stops a flood but never the SSH tunnel", () => {
  const limiter = createSignInLimiter();
  failMany(limiter, 100, (i) => `10.0.${Math.floor(i / 4)}.${i % 4}`, null);
  expect(limiter.check("198.51.100.20", null, false, T0 + 200)).toEqual({
    kind: "refuse",
    reason: "global",
    retryAfterSeconds: 60,
  });
  expect(limiter.check("127.0.0.1", null, true, T0 + 200).kind).toBe("allow");
});

test("memory stays bounded by the key cap", () => {
  const limiter = createSignInLimiter({ ...SIGN_IN_LIMITS, maxKeys: 3 });
  failMany(limiter, 5, () => "203.0.113.5", null);
  for (const other of ["a", "b", "c"]) limiter.record(other, null, true, T0 + 10);
  // The oldest key was dropped, so its failures no longer count.
  expect(limiter.check("203.0.113.5", null, false, T0 + 20).kind).toBe("allow");
});

test("the forwarded address is trusted only from a loopback peer", () => {
  const via = (xff: string | null) => new Headers(xff === null ? {} : { "x-forwarded-for": xff });
  expect(clientAddress(via("198.51.100.4"), "127.0.0.1")).toEqual({
    address: "198.51.100.4",
    tunnel: false,
  });
  expect(clientAddress(via("6.6.6.6, 198.51.100.4"), "::1").address).toBe("198.51.100.4");
  expect(clientAddress(via(null), "127.0.0.1")).toEqual({ address: "127.0.0.1", tunnel: true });
  expect(clientAddress(via("not-an-ip"), "127.0.0.1")).toEqual({
    address: "127.0.0.1",
    tunnel: false,
  });
  expect(clientAddress(via("198.51.100.4"), "203.0.113.9")).toEqual({
    address: "203.0.113.9",
    tunnel: false,
  });
});
