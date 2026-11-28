// Item 64: the list and bulk parts' pure logic.
import { expect, test } from "bun:test";

import { bulkCommands } from "@/components/console/bulk";
import { matches, pageWindow } from "@/components/console/list";

test("pageWindow keeps first, last, and neighbours, with gaps between", () => {
  expect(pageWindow(0, 1)).toEqual([0]);
  expect(pageWindow(0, 3)).toEqual([0, 1, 2]);
  expect(pageWindow(0, 6)).toEqual([0, 1, "gap", 5]);
  expect(pageWindow(3, 8)).toEqual([0, "gap", 2, 3, 4, "gap", 7]);
  expect(pageWindow(7, 8)).toEqual([0, "gap", 6, 7]);
});

test("matches ignores case and an empty query", () => {
  expect(matches("", "anything")).toBe(true);
  expect(matches(" Shop ", "blog.lab.test", "shop.lab.test")).toBe(true);
  expect(matches("wiki", "blog.lab.test")).toBe(false);
});

test("bulkCommands writes one numbered plan file per chosen entry", () => {
  const out = bulkCommands(
    ["a", "b"],
    (id) => `rustiron plan create x --site-id '${id}' > ./plan.json`,
  );
  expect(out).toBe(
    "rustiron plan create x --site-id 'a' > ./plan-1.json\nrustiron plan create x --site-id 'b' > ./plan-2.json",
  );
});
