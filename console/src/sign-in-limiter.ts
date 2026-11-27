// W694 (v0.2 queue item 3): sign-in protection that cannot lock the owner out.
// Per-address limits stop guessing from one source, a per-account slowdown
// (never a lockout) slows guessing spread across sources, and a high global
// breaker stops a flood while sign-in over the SSH tunnel stays open.
import { isIP } from "node:net";

export const SIGN_IN_LIMITS = {
  windowMs: 60_000,
  perAddress: 5,
  global: 100,
  accountWindowMs: 15 * 60_000,
  accountBaseDelayMs: 250,
  accountMaxDelayMs: 8_000,
  // Bounds memory against many addresses or invented account names.
  maxKeys: 10_000,
} as const;

export type SignInVerdict =
  | { kind: "allow"; delayMs: number }
  | { kind: "refuse"; reason: "address" | "global"; retryAfterSeconds: number };

type Limits = Record<keyof typeof SIGN_IN_LIMITS, number>;

function prune(list: number[], now: number, windowMs: number): number[] {
  while (list[0] !== undefined && now - list[0] >= windowMs) list.shift();
  return list;
}

function retryAfter(oldest: number | undefined, now: number, windowMs: number): number {
  return Math.max(1, Math.ceil(((oldest ?? now) + windowMs - now) / 1000));
}

/** Failure timestamps per key; the oldest key goes first when the map is full. */
function failureLog(maxKeys: number) {
  const entries = new Map<string, number[]>();
  return {
    get: (key: string) => entries.get(key) ?? [],
    push(key: string, at: number) {
      const list = entries.get(key) ?? [];
      list.push(at);
      entries.delete(key);
      entries.set(key, list);
      if (entries.size > maxKeys) {
        const oldest = entries.keys().next().value;
        if (oldest !== undefined) entries.delete(oldest);
      }
    },
    clear: (key: string) => entries.delete(key),
  };
}

export function createSignInLimiter(limits: Limits = SIGN_IN_LIMITS) {
  const addresses = failureLog(limits.maxKeys);
  const accounts = failureLog(limits.maxKeys);
  const global: number[] = [];

  return {
    /** `tunnel`: a loopback peer with no proxy header, which the global breaker never stops. */
    check(address: string, account: string | null, tunnel: boolean, now: number): SignInVerdict {
      const all = prune(global, now, limits.windowMs);
      if (!tunnel && all.length >= limits.global) {
        return {
          kind: "refuse",
          reason: "global",
          retryAfterSeconds: retryAfter(all[0], now, limits.windowMs),
        };
      }
      const fromAddress = prune(addresses.get(address), now, limits.windowMs);
      if (fromAddress.length >= limits.perAddress) {
        return {
          kind: "refuse",
          reason: "address",
          retryAfterSeconds: retryAfter(fromAddress[0], now, limits.windowMs),
        };
      }
      const forAccount = account ? prune(accounts.get(account), now, limits.accountWindowMs) : [];
      const delayMs =
        forAccount.length === 0
          ? 0
          : Math.min(
              limits.accountBaseDelayMs * 2 ** (forAccount.length - 1),
              limits.accountMaxDelayMs,
            );
      return { kind: "allow", delayMs };
    },

    record(address: string, account: string | null, failed: boolean, now: number) {
      if (!failed) {
        addresses.clear(address);
        if (account) accounts.clear(account);
        return;
      }
      global.push(now);
      addresses.push(address, now);
      if (account) accounts.push(account, now);
    },
  };
}

function isLoopback(address: string | null): boolean {
  if (!address) return false;
  const v4 = address.startsWith("::ffff:") ? address.slice(7) : address;
  return v4 === "::1" || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(v4);
}

/**
 * The address a request comes from. Caddy, on loopback, replaces any client
 * `X-Forwarded-For` with the real one, so its last entry is trusted only from a
 * loopback peer; any other peer is its own address.
 */
export function clientAddress(
  headers: Headers,
  peer: string | null,
): { address: string; tunnel: boolean } {
  const forwarded = headers.get("x-forwarded-for");
  if (!isLoopback(peer)) return { address: peer ?? "unknown", tunnel: false };
  if (forwarded === null) return { address: peer ?? "127.0.0.1", tunnel: true };
  const last = forwarded.split(",").pop()?.trim() ?? "";
  return { address: isIP(last) ? last : (peer ?? "127.0.0.1"), tunnel: false };
}
