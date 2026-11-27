// W746 (QA-15): a skipped view transition never becomes an unhandled rejection.
import { expect, mock, test } from "bun:test";

import { settleSkippedTransitions } from "./view-transitions";

test("the wrapper handles a transition's ready and finished promises", () => {
  const ready = { catch: mock(() => undefined) };
  const finished = { catch: mock(() => undefined) };
  const transition = { ready, finished, updateCallbackDone: Promise.resolve() };
  const start = mock(() => transition);
  const doc = { startViewTransition: start } as unknown as {
    startViewTransition?: () => typeof transition;
  };
  settleSkippedTransitions(doc as never);
  const returned = doc.startViewTransition?.();
  expect(returned).toBe(transition);
  expect(start).toHaveBeenCalledTimes(1);
  expect(ready.catch).toHaveBeenCalledTimes(1);
  expect(finished.catch).toHaveBeenCalledTimes(1);
});

test("a document without view transitions is left alone", () => {
  const doc: { startViewTransition?: () => never } = {};
  settleSkippedTransitions(doc);
  expect(doc.startViewTransition).toBeUndefined();
});
