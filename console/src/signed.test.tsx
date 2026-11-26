// W396 (B14): the signed plan and grant bytes, checked in the browser, and
// the receipt attestation. The state observation is synthetic
// (docs/validation/S10-W396/make_states.py), with digests computed in Python.
import { afterEach, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { createMemoryHistory, createRouter, RouterProvider } from "@tanstack/react-router";

import type { Observation } from "./live";
import { observationRoute } from "./observation-route";
import { routeTree } from "./router";
import { liveOperations } from "./live";
import {
  checkObject,
  receiptAttestation,
  signedBytes,
  signedRequester,
  type SignedObject,
} from "./signed";

const states = JSON.parse(
  readFileSync(new URL("../e2e/states/w396-observation.json", import.meta.url), "utf8"),
) as Observation;

afterEach(cleanup);

function recorded(id: string) {
  const signed = signedBytes(states, id);
  if (signed.state !== "recorded") throw new Error(`${id} is ${signed.state}`);
  return signed;
}

test("recorded signed bytes carry the signer facts and both objects", () => {
  const signed = recorded("op_w391_cap_1");
  expect(signed.issuer).toBe("lab_agent");
  expect(signed.signerPolicyEpoch).toBe("policy_3");
  expect(signed.namespace).toBe("rustiron-plan-v1");
  expect(signed.plan.text).toContain('"verb":"backup_capture"');
  expect(signed.grant.text).toContain(`"plan_digest":"${signed.plan.digest}"`);
});

test("the console recomputes the length, SHA-256 and framed plan digest of UTF-8 bytes", async () => {
  const signed = recorded("op_w391_cap_1");
  // The plan holds non-ASCII text: the byte count is not the string length.
  expect(signed.plan.bytes).toBeGreaterThan(signed.plan.text?.length ?? 0);
  expect(await checkObject(signed.plan)).toEqual({
    state: "match",
    sha256: signed.plan.sha256,
    bytes: signed.plan.bytes,
    differs: [],
  });
  const grant = await checkObject(signed.grant);
  expect(grant.state).toBe("match");
});

test("bytes that do not hash to the recorded digests are a mismatch", async () => {
  const signed = recorded("op_w379_cap_1");
  const plan = await checkObject(signed.plan);
  expect(plan.state).toBe("mismatch");
  if (plan.state !== "mismatch") return;
  expect(plan.differs).toEqual(["sha256", "digest"]);
  const longer: SignedObject = { ...recorded("op_w391_cap_1").grant };
  longer.bytes += 1;
  const check = await checkObject(longer);
  expect(check.state === "mismatch" && check.differs).toEqual(["length"]);
  // A plan whose plain hash matches but whose framed digest does not.
  const unframed: SignedObject = { ...recorded("op_w391_cap_1").plan };
  unframed.digest = unframed.sha256;
  const framed = await checkObject(unframed);
  expect(framed.state === "mismatch" && framed.differs).toEqual(["digest"]);
});

test("an object over the journal bound keeps its digests only", async () => {
  const signed = recorded("op_w379_readopt");
  expect(signed.plan.text).toBeNull();
  expect(signed.plan.bytes).toBeGreaterThan(8192);
  expect(await checkObject(signed.plan)).toEqual({ state: "not_kept" });
  expect((await checkObject(signed.grant)).state).toBe("match");
});

test("older admissions and observations say why no bytes are shown", () => {
  expect(signedBytes(states, "op_w379_cap_2").state).toBe("not_recorded");
  expect(signedBytes(states, "op_w379_pc_in").state).toBe("absent");
  const older = { ...states, admissions: undefined, signed_objects: undefined };
  expect(signedBytes(older, "op_w391_cap_1").state).toBe("absent");
});

// W429: the requester comes from the recorded signed plan, never a fixed label.
test("the requester is the one the signed plan names, or not in this observation", () => {
  // The W396 fixture plans name no requester; old admissions keep no bytes.
  expect(signedRequester(states, "op_w391_cap_1")).toBeNull();
  expect(signedRequester(states, "op_w379_cap_2")).toBeNull();
  expect(signedRequester(states, "op_w379_pc_in")).toBeNull();
  const rows = liveOperations(states);
  expect(rows.find((row) => row.id === "op_w391_cap_1")?.requester).toBe("Not in this observation");
  expect(rows.some((row) => row.requester.includes("rustiron_build"))).toBe(false);
  // A product plan names its requester.
  const sha = recorded("op_w391_cap_1").plan.sha256;
  const objects = { ...(states.signed_objects as Record<string, string>) };
  const plan = JSON.parse(objects[sha] ?? "{}") as Record<string, unknown>;
  objects[sha] = JSON.stringify({ ...plan, requester: "rustiron_coordinator" });
  const product = { ...states, signed_objects: objects };
  expect(signedRequester(product, "op_w391_cap_1")).toBe("rustiron_coordinator");
  expect(liveOperations(product).find((row) => row.id === "op_w391_cap_1")?.requester).toBe(
    "rustiron_coordinator (signed plan)",
  );
  objects[sha] = JSON.stringify({ ...plan, requester: "bad name\u202e" });
  expect(signedRequester({ ...states, signed_objects: objects }, "op_w391_cap_1")).toBeNull();
});

test("malformed signed facts are refused, not shown", () => {
  const admissions = states.admissions as Record<string, unknown>[];
  const edit = (change: (entry: Record<string, unknown>) => void) => {
    const copy = structuredClone(admissions);
    const entry = copy.find((item) => item.operation_id === "op_w391_cap_1");
    if (entry) change(entry);
    return signedBytes({ ...states, admissions: copy }, "op_w391_cap_1").state;
  };
  const signed = (entry: Record<string, unknown>) => entry.signed as Record<string, unknown>;
  expect(edit((entry) => (signed(entry).verification = "unchecked"))).toBe("malformed");
  expect(edit((entry) => (signed(entry).namespace = "rustiron-receipt-v1"))).toBe("malformed");
  expect(edit((entry) => (signed(entry).issuer = "bad issuer"))).toBe("malformed");
  expect(edit((entry) => (entry.plan_digest = "ABC"))).toBe("malformed");
  expect(
    edit((entry) => ((signed(entry).plan as Record<string, unknown>).sha256 = "0".repeat(64))),
  ).toBe("malformed");
  expect(signedBytes({ ...states, signed_objects: [] }, "op_w391_cap_1").state).toBe("malformed");
});

test("the receipt attestation follows the host receipt key facts", () => {
  const signed = receiptAttestation(states.host);
  expect(signed).toEqual({
    state: "signed",
    label: "Self-attested, signed",
    fingerprint: "SHA256:W396syntheticReceiptKeyFingerprintNotReal00",
    namespace: "rustiron-receipt-v1",
  });
  const host = (receipt_key: unknown) => ({ ...states.host, receipt_key });
  expect(receiptAttestation(host({ state: "absent" })).label).toBe("Self-attested, unsigned");
  expect(receiptAttestation(host({ state: "refused" })).state).toBe("refused");
  expect(receiptAttestation(host(undefined)).label).toBe("Not in this observation");
  expect(
    receiptAttestation(
      host({ ...(states.host.receipt_key as object), namespace: "rustiron-plan-v1" }),
    ).state,
  ).toBe("malformed");
});

async function renderOperation(id: string) {
  const directory = await mkdtemp(join(tmpdir(), "ri-w396-"));
  const file = join(directory, "observation.json");
  await writeFile(file, JSON.stringify(states));
  const route = observationRoute(file);
  const original = globalThis.fetch;
  globalThis.fetch = (async () =>
    route(new Request("http://console.test/api/observation"))) as unknown as typeof fetch;
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: [`/operations/${id}`] }),
  });
  render(<RouterProvider router={router} />);
  return async () => {
    globalThis.fetch = original;
    await rm(directory, { recursive: true });
  };
}

test("the operation page shows the bytes, the signer and the receipt attestation", async () => {
  const done = await renderOperation("op_w391_cap_1");
  try {
    expect(await screen.findByRole("heading", { level: 2, name: "Signed plan and grant" }));
    // Both digests are computed asynchronously; wait for the second.
    await waitFor(() => expect(screen.getAllByText("Digests match").length).toBe(2));
    const plan = document.querySelector('pre[data-part="plan"]')?.textContent;
    expect(plan ?? null).toBe(recorded("op_w391_cap_1").plan.text);
    expect(screen.getByText("SSHSIG verified at admission")).toBeTruthy();
    expect(screen.getByText("SHA256:W396syntheticPlanSignerFingerprintNotReal00")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Copy plan bytes" })).toBeTruthy();
    expect(screen.getByText("Self-attested, signed")).toBeTruthy();
    expect(screen.getByText("SHA256:W396syntheticReceiptKeyFingerprintNotReal00")).toBeTruthy();
  } finally {
    await done();
  }
});

test("a mismatch is an alert and an old admission says it was not recorded", async () => {
  let done = await renderOperation("op_w379_cap_1");
  try {
    expect(await screen.findByText("Digest mismatch")).toBeTruthy();
    expect(screen.getByRole("alert").textContent).toContain(
      "do not match the recorded SHA-256 and intent digest",
    );
  } finally {
    await done();
  }
  cleanup();
  done = await renderOperation("op_w379_cap_2");
  try {
    expect(await screen.findByText("Not recorded: admitted before journal v20")).toBeTruthy();
  } finally {
    await done();
  }
});
