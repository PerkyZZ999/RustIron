// W753 (QA-22): the breadcrumb title-cases route words only, never values.
import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";

import { formatSegment, ROUTE_WORDS } from "./shell";

test("ROUTE_WORDS holds exactly the fixed words of the route paths", () => {
  const source = readFileSync(new URL("./router.tsx", import.meta.url), "utf8");
  const words = new Set(
    [...source.matchAll(/path: "([^"]*)"/g)]
      .flatMap((match) => (match[1] ?? "").split("/"))
      .filter((part) => part !== "" && !part.startsWith("$")),
  );
  expect([...ROUTE_WORDS].sort()).toEqual([...words].sort());
});

test("values keep their case, route words get their labels", () => {
  expect(formatSegment("p01r")).toBe("p01r");
  expect(formatSegment("example.com")).toBe("example.com");
  expect(formatSegment("nope")).toBe("nope");
  expect(formatSegment("site_8KD2QW")).toBe("site_8KD2QW");
  expect(formatSegment("sites")).toBe("Sites");
  expect(formatSegment("dns")).toBe("DNS");
  expect(formatSegment("cron")).toBe("Cron jobs");
  expect(formatSegment("updates-and-releases")).toBe("Update RustIron");
});
