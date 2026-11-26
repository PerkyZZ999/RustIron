// Structured client-side logging for the Rustiron Console via evlog/client.
// Emits structured wide events to the browser console only — no network drain,
// and never logs secrets, signatures, tokens, or signed canonical bytes.
import { initLog, log } from "evlog/client";

let initialised = false;

export function initConsoleLog() {
  if (initialised || typeof window === "undefined") return;
  initialised = true;
  initLog({
    service: "rustiron-console",
    minLevel: "warn",
    pretty: true,
  });
}

/** Log a page/route view. Safe, non-sensitive context only. */
export function logPageView(path: string, label: string) {
  log.info({ action: "page_view", path, label });
}

/** Log a meaningful operator interaction (never form values or secrets). */
export function logInteraction(action: string, detail?: Record<string, unknown>) {
  log.info({ action, ...detail });
}
