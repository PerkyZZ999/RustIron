// W746 (QA-15): TanStack Router starts a view transition for each navigation
// and keeps only its `updateCallbackDone` promise. When a newer navigation
// skips a transition, the browser rejects its `ready` and `finished` promises
// with an AbortError that nothing handled, so it reached the console as an
// unhandled rejection. A skipped transition is expected, not an error.

type TransitionLike = { ready: Promise<unknown>; finished: Promise<unknown> };
type ViewTransitionDocument = {
  startViewTransition?: (...args: never[]) => TransitionLike;
};

/** Wraps `startViewTransition` once so a skipped transition's promises are handled. */
export function settleSkippedTransitions(doc: ViewTransitionDocument): void {
  const start = doc.startViewTransition;
  if (typeof start !== "function") return;
  doc.startViewTransition = ((...args: never[]) => {
    const transition = start.apply(doc, args);
    transition.ready.catch(() => {});
    transition.finished.catch(() => {});
    return transition;
  }) as typeof start;
}
