// W695 (v0.2 pass 18): which route changes animate, and how.
import { afterEach, expect, test } from "bun:test";

import { routeTransitionTypes } from "./router";

const move = (from: string | undefined, to: string, pathChanged = true) =>
  routeTransitionTypes({
    fromLocation: from === undefined ? undefined : { pathname: from },
    toLocation: { pathname: to },
    pathChanged,
  });

afterEach(() => {
  delete document.documentElement.dataset.motion;
});

test("deeper slides forward, shallower slides back, same depth only fades", () => {
  expect(move("/apps", "/apps/app_emdash")).toEqual(["nav-forward"]);
  expect(move("/apps/app_emdash", "/apps")).toEqual(["nav-back"]);
  expect(move("/apps", "/domains")).toEqual(["nav-lateral"]);
  expect(move(undefined, "/apps")).toEqual(["nav-forward"]);
});

test("a search-only change and reduced motion get no transition", () => {
  expect(move("/apps/app_emdash", "/apps/app_emdash", false)).toBe(false);
  document.documentElement.dataset.motion = "reduce";
  expect(move("/apps", "/apps/app_emdash")).toBe(false);
});
