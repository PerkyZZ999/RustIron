// W713 (pass 33, fix 6): the one way the browser calls the Console API. It sends
// the session cookie, encodes a JSON body, never caches, and never rejects.

/** A reply from the Console API. `status: null` means the server did not answer. */
export type ConsoleReply<T> =
  | { ok: true; status: number; data: T }
  | {
      ok: false;
      status: number | null;
      /** The server's machine code (`error`), if it sent one. */
      code: string | null;
      /** The server's human message, if it sent one. */
      message: string | null;
      /** The parsed body, or null when there was none or it was not JSON. */
      data: unknown;
    };

export type ConsoleRequestOptions = {
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  /** A body to send as JSON. */
  json?: unknown;
  headers?: Record<string, string>;
};

export async function consoleRequest<T = unknown>(
  path: string,
  options: ConsoleRequestOptions = {},
): Promise<ConsoleReply<T>> {
  const headers: Record<string, string> = { ...options.headers };
  if (options.json !== undefined) headers["content-type"] = "application/json";
  let res: Response;
  try {
    res = await fetch(path, {
      method: options.method ?? "GET",
      cache: "no-store",
      credentials: "same-origin",
      headers,
      body: options.json === undefined ? undefined : JSON.stringify(options.json),
    });
  } catch {
    return { ok: false, status: null, code: null, message: null, data: null };
  }
  const data: unknown = await res.json().catch(() => null);
  if (res.ok) return { ok: true, status: res.status, data: data as T };
  const body = (data ?? {}) as { error?: unknown; message?: unknown };
  return {
    ok: false,
    status: res.status,
    code: typeof body.error === "string" ? body.error : null,
    message: typeof body.message === "string" ? body.message : null,
    data,
  };
}

/**
 * The text to show for a failed reply: the server's message, then its code,
 * then `fallback`. A server that did not answer gives `unreachable`.
 */
export function failureText(
  reply: Extract<ConsoleReply<unknown>, { ok: false }>,
  fallback: string,
  unreachable = "The Console server did not answer. Reload to see the current state.",
): string {
  if (reply.status === null) return unreachable;
  return reply.message ?? reply.code ?? fallback;
}
