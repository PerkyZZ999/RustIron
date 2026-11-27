// W613 / W626 (P29 Slice 5 / P15): Separate-custody signed plan review &
// coordinator submission panel for /plans/new/review. Never stores or creates
// signing keys; supports loading plan.json, grant.json, and grant.json.sig
// from disk or paste, verifies canonical digests, and submits byte-exact
// plan_apply frames when RUSTIRON_CONSOLE_WRITE_WORKFLOWS=1.
import { consoleRequest } from "./console-request";
import { Button } from "@/components/ui/button";
import { Link } from "@tanstack/react-router";
import {
  CircleAlert,
  CircleCheck,
  KeyRound,
  ShieldCheck,
  TriangleAlert,
  Upload,
} from "lucide-react";
import { type ChangeEvent, useState } from "react";

import { useData } from "./data";
import { Glyph } from "./ui";
import type { PlanReviewSummary, WriteApplyResult } from "./write-backend";

type WriteSession = {
  write_workflows_enabled: boolean;
  csrf_token: string | null;
};

type SubmitOutcome =
  | { state: "idle" }
  | { state: "error"; code: string; outcomeUnknown: boolean; operationId: string }
  | { state: "applied"; result: WriteApplyResult };

async function fetchCsrfToken(): Promise<WriteSession | null> {
  const reply = await consoleRequest<WriteSession | null>("/api/write/session");
  return reply.ok ? reply.data : null;
}

function ReviewResultBox({ summary }: { summary: PlanReviewSummary }) {
  return (
    <div className="stack" style={{ gap: 10 }}>
      {summary.global_ols_impact ? (
        <div className="attention" role="alert">
          <Glyph icon={TriangleAlert} />
          <div className="att-body">
            <strong>Global OLS reload impact:</strong> activating this plan reloads every served
            site on the enrolled listener.
          </div>
        </div>
      ) : null}
      <dl className="kv">
        <dt>Verb &amp; plan</dt>
        <dd className="mono">
          {summary.verb || "—"} · {summary.plan_id || "—"}
        </dd>
        <dt>Framed plan digest</dt>
        <dd className="mono">{summary.plan_digest}</dd>
        <dt>Digest binding</dt>
        <dd>
          {summary.digest_matches ? (
            <span className="pill ok">
              <Glyph icon={CircleCheck} />
              Grant matches plan digest
            </span>
          ) : (
            <span className="pill err">
              <Glyph icon={CircleAlert} />
              Digest mismatch (refused)
            </span>
          )}
        </dd>
        <dt>Grant window</dt>
        <dd>
          {summary.stale ? (
            <span className="pill err">Expired / stale grant (refused)</span>
          ) : (
            <span className="pill ok">Within validity window</span>
          )}
        </dd>
        <dt>Offline sign command</dt>
        <dd className="mono">{summary.offline_sign_command}</dd>
      </dl>
    </div>
  );
}

function ApplyOutcomeBox({ outcome }: { outcome: SubmitOutcome }) {
  if (outcome.state === "idle") return null;
  if (outcome.state === "error" && outcome.outcomeUnknown) {
    // W682: an interrupted submission is not a refusal; only the operation record can say.
    return (
      <div className="attention" role="alert">
        <Glyph icon={TriangleAlert} />
        <div className="att-body">
          <strong>Outcome unknown:</strong> <span className="mono">{outcome.code}</span>. The
          submission may have reached the coordinator. Check{" "}
          <Link to="/operations/$operationId" params={{ operationId: outcome.operationId }}>
            {outcome.operationId}
          </Link>{" "}
          before retrying.
        </div>
      </div>
    );
  }
  if (outcome.state === "error") {
    return (
      <div className="attention err" role="alert">
        <Glyph icon={CircleAlert} />
        <div className="att-body">
          <strong>Submission refused:</strong> <span className="mono">{outcome.code}</span>
        </div>
      </div>
    );
  }
  const kind = (outcome.result.outcome as { kind?: string } | null)?.kind ?? "outcome_unknown";
  return (
    <div className={kind === "executor_reply" ? "attention info" : "attention"} role="status">
      <Glyph icon={ShieldCheck} />
      <div className="att-body">
        <strong>Coordinator outcome:</strong> <span className="mono">{kind}</span> for{" "}
        <Link to="/operations/$operationId" params={{ operationId: outcome.result.operation_id }}>
          {outcome.result.operation_id}
        </Link>
        .
      </div>
    </div>
  );
}

type ApplyFormState = {
  operationId: string;
  idempotencyKey: string;
  planJson: string;
  grantJson: string;
  signatureText: string;
};

const emptyForm: ApplyFormState = {
  operationId: "",
  idempotencyKey: "",
  planJson: "",
  grantJson: "",
  signatureText: "",
};

type ProtectedReply<T> =
  | { ok: true; data: T }
  | { ok: false; code: string; outcomeUnknown: boolean };

/** Never rejects. `outcomeUnknown` is true when the request may have taken effect. */
export async function postProtectedJson<T>(
  path: string,
  payload: unknown,
): Promise<ProtectedReply<T>> {
  const session = await fetchCsrfToken();
  if (!session?.write_workflows_enabled || !session.csrf_token) {
    return { ok: false, code: "WRITE_WORKFLOWS_DISABLED", outcomeUnknown: false };
  }
  const reply = await consoleRequest<T | null>(path, {
    method: "POST",
    json: payload,
    headers: { "x-rustiron-csrf": session.csrf_token },
  });
  if (reply.status === null) {
    return { ok: false, code: "CONSOLE_UNREACHABLE", outcomeUnknown: true };
  }
  if (reply.ok && reply.data) return { ok: true, data: reply.data };
  const body = reply.data as { outcome?: { kind?: string } } | null;
  return {
    ok: false,
    code: (!reply.ok && reply.code) || `HTTP_${reply.status}`,
    outcomeUnknown: !body || body.outcome?.kind === "outcome_unknown",
  };
}

function isFormReady(
  enabled: boolean,
  form: ApplyFormState,
  review: PlanReviewSummary | null,
): boolean {
  if (!enabled) return false;
  if (!form.operationId.trim() || !form.idempotencyKey.trim() || !form.signatureText.trim()) {
    return false;
  }
  return review === null || (review.digest_matches && !review.stale);
}

function FileLoadButton({
  id,
  label,
  accept,
  onLoad,
}: {
  id: string;
  label: string;
  accept: string;
  onLoad: (text: string) => void;
}) {
  function handleChange(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    void file.text().then(onLoad);
    event.target.value = "";
  }
  return (
    <label htmlFor={id} className="btn quiet sm" style={{ cursor: "pointer" }}>
      <Glyph icon={Upload} />
      {label}
      <input id={id} type="file" accept={accept} className="sr-only" onChange={handleChange} />
    </label>
  );
}

function deriveIdsFromPlan(raw: string, current: ApplyFormState): Partial<ApplyFormState> {
  const patch: Partial<ApplyFormState> = { planJson: raw };
  try {
    const parsed = JSON.parse(raw) as { plan_id?: string };
    const stem =
      typeof parsed.plan_id === "string"
        ? parsed.plan_id.replace(/[^A-Za-z0-9_-]/g, "").slice(0, 32)
        : "";
    if (stem && !current.operationId) patch.operationId = `op_${stem}`;
    if (stem && !current.idempotencyKey) patch.idempotencyKey = `idem_${stem}`;
  } catch {
    // Non-JSON paste handled during verification.
  }
  return patch;
}

function ApplyFormInputs({
  form,
  onChange,
}: {
  form: ApplyFormState;
  onChange: (patch: Partial<ApplyFormState>) => void;
}) {
  return (
    <div className="form-grid">
      <div className="form-row">
        <label htmlFor="p15-op-id">Operation ID</label>
        <input
          id="p15-op-id"
          className="input mono"
          value={form.operationId}
          onChange={(e) => onChange({ operationId: e.target.value })}
          placeholder="op_20261124_01"
          autoComplete="off"
        />
      </div>
      <div className="form-row">
        <label htmlFor="p15-idem-key">Idempotency key</label>
        <input
          id="p15-idem-key"
          className="input mono"
          value={form.idempotencyKey}
          onChange={(e) => onChange({ idempotencyKey: e.target.value })}
          placeholder="idem_20261124_01"
          autoComplete="off"
        />
      </div>
      <div className="form-row" style={{ gridColumn: "1 / -1" }}>
        <div className="row" style={{ justifyContent: "space-between" }}>
          <label htmlFor="p15-plan-json">1. Canonical plan.json</label>
          <FileLoadButton
            id="p15-plan-file"
            label="Load plan.json"
            accept=".json,application/json"
            onLoad={(text) => onChange(deriveIdsFromPlan(text, form))}
          />
        </div>
        <textarea
          id="p15-plan-json"
          className="input mono"
          rows={3}
          value={form.planJson}
          onChange={(e) => onChange({ planJson: e.target.value })}
          placeholder='{"schema_version":1,"verb":"site_credential_rotate",...}'
        />
      </div>
      <div className="form-row" style={{ gridColumn: "1 / -1" }}>
        <div className="row" style={{ justifyContent: "space-between" }}>
          <label htmlFor="p15-grant-json">2. Canonical grant.json</label>
          <FileLoadButton
            id="p15-grant-file"
            label="Load grant.json"
            accept=".json,application/json"
            onLoad={(text) => onChange({ grantJson: text })}
          />
        </div>
        <textarea
          id="p15-grant-json"
          className="input mono"
          rows={3}
          value={form.grantJson}
          onChange={(e) => onChange({ grantJson: e.target.value })}
          placeholder='{"schema_version":1,"plan_digest":"...",...}'
        />
      </div>
      <div className="form-row" style={{ gridColumn: "1 / -1" }}>
        <div className="row" style={{ justifyContent: "space-between" }}>
          <label htmlFor="p15-sig">3. Detached SSHSIG (grant.json.sig)</label>
          <FileLoadButton
            id="p15-sig-file"
            label="Load grant.json.sig"
            accept=".sig,text/plain"
            onLoad={(text) => onChange({ signatureText: text })}
          />
        </div>
        <textarea
          id="p15-sig"
          className="input mono"
          rows={3}
          value={form.signatureText}
          onChange={(e) => onChange({ signatureText: e.target.value })}
          placeholder="-----BEGIN SSH SIGNATURE-----"
        />
      </div>
    </div>
  );
}

export function SeparateCustodyApplyPanel() {
  const data = useData();
  const enabled = data.backend?.write_workflows_enabled === true;
  const [form, setForm] = useState<ApplyFormState>(emptyForm);
  const [review, setReview] = useState<PlanReviewSummary | null>(null);
  const [reviewError, setReviewError] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<SubmitOutcome>({ state: "idle" });
  const [busy, setBusy] = useState(false);

  const patchForm = (patch: Partial<ApplyFormState>) => setForm((prev) => ({ ...prev, ...patch }));

  async function handleReview() {
    setReviewError(null);
    setBusy(true);
    let res: ProtectedReply<PlanReviewSummary>;
    try {
      res = await postProtectedJson<PlanReviewSummary>("/api/write/plan/review", {
        plan_json: form.planJson,
        grant_json: form.grantJson,
      });
    } finally {
      setBusy(false);
    }
    if (!res.ok) {
      setReview(null);
      setReviewError(res.code);
      return;
    }
    setReview(res.data);
  }

  async function handleApply() {
    setOutcome({ state: "idle" });
    setBusy(true);
    const operationId = form.operationId.trim();
    let res: ProtectedReply<WriteApplyResult>;
    try {
      res = await postProtectedJson<WriteApplyResult>("/api/write/plan/apply", {
        operation_id: operationId,
        idempotency_key: form.idempotencyKey.trim(),
        plan_json: form.planJson,
        grant_json: form.grantJson,
        signature_text: form.signatureText,
      });
    } finally {
      setBusy(false);
    }
    if (!res.ok) {
      setOutcome({
        state: "error",
        code: res.code,
        outcomeUnknown: res.outcomeUnknown,
        operationId,
      });
      return;
    }
    setOutcome({ state: "applied", result: res.data });
    void data.refresh();
  }

  return (
    <section className="panel" aria-labelledby="p15-apply-t">
      <div className="panel-head">
        <div className="row" style={{ gap: 8 }}>
          <Glyph icon={KeyRound} />
          <h2 id="p15-apply-t">Separate-custody signed submission</h2>
        </div>
        <span className={enabled ? "pill ok" : "pill"}>
          {enabled ? "Signed apply enabled" : "Read-only mode"}
        </span>
      </div>
      <p className="muted" style={{ marginBottom: 12 }}>
        Load or paste your offline-signed <span className="mono">plan.json</span>,{" "}
        <span className="mono">grant.json</span>, and <span className="mono">grant.json.sig</span>.
        The Console verifies digests before forwarding byte-exact frames to the local coordinator.
      </p>
      <ApplyFormInputs form={form} onChange={patchForm} />
      <div className="row end" style={{ marginTop: 12 }}>
        <Button variant="outline" disabled={!enabled || busy} onClick={() => void handleReview()}>
          {busy ? "Verifying…" : "Verify canonical bytes"}
        </Button>
        <Button
          variant="default"
          disabled={busy || !isFormReady(enabled, form, review)}
          onClick={() => void handleApply()}
        >
          {busy ? "Submitting…" : "Submit signed grant"}
        </Button>
      </div>
      {reviewError ? (
        <div className="attention err" role="alert" style={{ marginTop: 12 }}>
          <Glyph icon={CircleAlert} />
          <div className="att-body">
            <strong>Review refused:</strong> <span className="mono">{reviewError}</span>
          </div>
        </div>
      ) : null}
      {review ? (
        <div style={{ marginTop: 12 }}>
          <ReviewResultBox summary={review} />
        </div>
      ) : null}
      <div style={{ marginTop: 12 }}>
        <ApplyOutcomeBox outcome={outcome} />
      </div>
    </section>
  );
}
