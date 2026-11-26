// Read-only route: serves the newest executor observation file, never writes.
// Without RUSTIRON_OBSERVATION the console runs on fixture data.
// W635 (V-02): opens with O_NOFOLLOW and validates fstat on the open descriptor
// so a local writer cannot swap in a symlink between stat and read.
import { constants } from "node:fs";
import { open } from "node:fs/promises";

const MAX_BYTES = 4 * 1024 * 1024;

function reply(status: number, body: unknown) {
  return Response.json(body, {
    status,
    headers: {
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "cross-origin-resource-policy": "same-origin",
    },
  });
}

export async function observationResponse(
  path: string | undefined,
  options?: { allowFixture?: boolean },
): Promise<Response> {
  if (!path) {
    if (options?.allowFixture === false) {
      return reply(503, { error: "LIVE_SOURCE_NOT_CONFIGURED" });
    }
    return reply(200, { source: "fixture" });
  }
  let handle: Awaited<ReturnType<typeof open>> | null = null;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const info = await handle.stat();
    if (!info.isFile() || info.size > MAX_BYTES) {
      return reply(503, { error: "OBSERVATION_UNUSABLE" });
    }
    const raw = await handle.readFile("utf8");
    const observation: unknown = JSON.parse(raw);
    return reply(200, { observed_at: info.mtimeMs, observation });
  } catch {
    return reply(503, { error: "OBSERVATION_UNAVAILABLE" });
  } finally {
    await handle?.close().catch(() => {});
  }
}

/** The only handler servers mount: reads only, so a sample screen cannot become a write. */
export function observationRoute(
  path: string | undefined,
  options?: { allowFixture?: boolean },
): (request: Request) => Promise<Response> {
  return async (request) => {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return Response.json(
        { error: "METHOD_NOT_ALLOWED" },
        { status: 405, headers: { allow: "GET, HEAD", "cache-control": "no-store" } },
      );
    }
    return observationResponse(path, options);
  };
}
