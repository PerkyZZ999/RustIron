// W396 (B14): the exact signed bytes of an operation and the receipt
// attestation, on the live operation page. Read-only: the copy button writes
// to the clipboard only.
import { Button } from "@/components/ui/button";
import {
  ChevronDown,
  CircleAlert,
  CircleCheck,
  CircleDashed,
  CircleMinus,
  Copy,
  FileCode,
  LoaderCircle,
} from "lucide-react";
import { useEffect, useState } from "react";

import { type Observation, signerFacts } from "./live";
import {
  bytesText,
  checkObject,
  hasReceipt,
  type ObjectCheck,
  PLAN_DOMAIN,
  receiptAttestation,
  type SignedObject,
  signedBytes,
} from "./signed";
import { copyText, Glyph } from "./ui";

const partTitle = { plan: "Plan", grant: "Grant" } as const;

/** The browser's own check of one object; null while it runs. */
function useCheck(object: SignedObject): ObjectCheck | null {
  const [check, setCheck] = useState<{ object: SignedObject; result: ObjectCheck } | null>(null);
  useEffect(() => {
    let current = true;
    const failed: ObjectCheck = { state: "mismatch", sha256: "", bytes: 0, differs: ["sha256"] };
    checkObject(object).then(
      (result) => {
        if (current) setCheck({ object, result });
      },
      () => {
        if (current) setCheck({ object, result: failed });
      },
    );
    return () => {
      current = false;
    };
  }, [object]);
  return check?.object === object ? check.result : null;
}

function CheckPill({ check }: { check: ObjectCheck | null }) {
  if (check === null)
    return (
      <span className="state unknown">
        <Glyph icon={LoaderCircle} />
        Checking…
      </span>
    );
  if (check.state === "not_kept")
    return (
      <span className="state notrun">
        <Glyph icon={CircleMinus} />
        Bytes not kept
      </span>
    );
  if (check.state === "match")
    return (
      <span className="state ok">
        <Glyph icon={CircleCheck} />
        Digests match
      </span>
    );
  return (
    <span className="state err">
      <Glyph icon={CircleAlert} />
      Digest mismatch
    </span>
  );
}

const differsText = {
  length: "byte count",
  sha256: "SHA-256",
  digest: "intent digest",
} as const;

function CopyBytes({ object }: { object: SignedObject }) {
  const [copied, setCopied] = useState(false);
  if (object.text === null) return null;
  const text = object.text;
  return (
    <div className="row signed-copy">
      <Button
        variant="outline"
        size="sm"
        onClick={async () => {
          if (await copyText(text, `${partTitle[object.part]} bytes copied`)) setCopied(true);
        }}
      >
        <Glyph icon={Copy} />
        {`Copy ${object.part} bytes`}
      </Button>
      <span className="cap" aria-live="polite">
        {copied ? `${partTitle[object.part]} bytes copied` : ""}
      </span>
    </div>
  );
}

function SignedObjectView({ object }: { object: SignedObject }) {
  const check = useCheck(object);
  const title = partTitle[object.part];
  return (
    <details className="disclose signed-object" open>
      <summary>
        <Glyph icon={FileCode} />
        <span>
          {title} · canonical JSON · {bytesText(object.bytes)}
        </span>
        <CheckPill check={check} />
        <Glyph icon={ChevronDown} className="chev" />
      </summary>
      <div className="d-body">
        {check?.state === "mismatch" ? (
          <div className="attention err" role="alert">
            <Glyph icon={CircleAlert} />
            <span className="att-body">
              The shown {object.part} bytes do not match the recorded{" "}
              {check.differs.map((item) => differsText[item]).join(" and ")}. Do not rely on them.
              Preserve the journal and the observation for diagnosis.
            </span>
          </div>
        ) : null}
        <dl className="kv signed-facts">
          <dt>Recorded length</dt>
          <dd className="tnum">{bytesText(object.bytes)}</dd>
          <dt>Recorded SHA-256</dt>
          <dd className="hash" translate="no">
            {object.sha256}
          </dd>
          <dt>Console SHA-256</dt>
          <dd className="hash" translate="no">
            {check && check.state !== "not_kept" ? check.sha256 || "Not computed" : "—"}
          </dd>
          <dt>
            {object.part === "plan" ? `Plan digest (${PLAN_DOMAIN} framing)` : "Grant digest"}
          </dt>
          <dd className="hash" translate="no">
            {object.digest}
          </dd>
        </dl>
        {object.text === null ? (
          <p className="cap">
            The journal keeps objects up to 8,192 bytes. This one is larger, so only its length and
            digests are recorded.
          </p>
        ) : (
          <>
            <pre className="code signed-bytes" translate="no" data-part={object.part}>
              {object.text}
            </pre>
            <CopyBytes object={object} />
          </>
        )}
      </div>
    </details>
  );
}

function SignerFacts({
  observation,
  issuer,
  epoch,
}: {
  observation: Observation;
  issuer: string;
  epoch: string;
}) {
  const current = signerFacts(observation.host);
  const sameEpoch = observation.host.signer_policy_epoch === epoch;
  return (
    <dl className="kv">
      <dt>Signer</dt>
      <dd translate="no">{issuer}</dd>
      <dt>Signer-policy epoch</dt>
      <dd translate="no">{epoch}</dd>
      <dt>Verification</dt>
      <dd>
        <span className="state ok">
          <Glyph icon={CircleCheck} />
          SSHSIG verified at admission
        </span>{" "}
        · namespace <code>rustiron-plan-v1</code>
      </dd>
      <dt>Signing key</dt>
      <dd>
        {current && sameEpoch ? (
          <>
            <code className="hash">{current.fingerprint}</code>
            <p className="cap">The key enrolled now, under the same signer-policy epoch.</p>
          </>
        ) : (
          <span className="cap">
            Not recorded per operation. The enrolled signer-policy epoch is now{" "}
            {observation.host.signer_policy_epoch}.
          </span>
        )}
      </dd>
    </dl>
  );
}

export function SignedBytesPanel({
  observation,
  operationId,
}: {
  observation: Observation;
  operationId: string;
}) {
  const signed = signedBytes(observation, operationId);
  return (
    <section className="panel" aria-labelledby="signed-bytes-heading">
      <div className="panel-head">
        <h2 id="signed-bytes-heading">Signed plan and grant</h2>
        <span className="meta">Executor journal, hashed again in this browser</span>
      </div>
      {signed.state === "recorded" ? (
        <>
          <SignerFacts
            observation={observation}
            issuer={signed.issuer}
            epoch={signed.signerPolicyEpoch}
          />
          <p className="cap signed-note">
            The signature covers the grant bytes. The grant names the plan digest. The console
            recomputes each SHA-256 here and compares it with what the journal recorded.
          </p>
          <SignedObjectView object={signed.plan} />
          <SignedObjectView object={signed.grant} />
        </>
      ) : (
        <p className="row">
          <span className={signed.state === "malformed" ? "state err" : "state unknown"}>
            <Glyph icon={signed.state === "malformed" ? CircleAlert : CircleDashed} />
            {signed.state === "malformed"
              ? "Signed bytes are malformed; not shown"
              : signed.state === "not_recorded"
                ? "Not recorded: admitted before journal v20"
                : "Not in this observation"}
          </span>
        </p>
      )}
    </section>
  );
}

export function ReceiptAttestationPanel({
  observation,
  operationId,
}: {
  observation: Observation;
  operationId: string;
}) {
  if (!hasReceipt(observation, operationId)) return null;
  const attestation = receiptAttestation(observation.host);
  const tone =
    attestation.state === "signed"
      ? "state ok"
      : attestation.state === "unsigned"
        ? "state notrun"
        : attestation.state === "absent"
          ? "state unknown"
          : "state err";
  const icon =
    attestation.state === "signed"
      ? CircleCheck
      : attestation.state === "unsigned"
        ? CircleMinus
        : attestation.state === "absent"
          ? CircleDashed
          : CircleAlert;
  return (
    <section className="panel" aria-labelledby="receipt-attestation-heading">
      <div className="panel-head">
        <h2 id="receipt-attestation-heading">Receipt attestation</h2>
        <span className="meta">Host receipt key</span>
      </div>
      <dl className="kv">
        <dt>Exported receipts state</dt>
        <dd>
          <span className={tone}>
            <Glyph icon={icon} />
            {attestation.label}
          </span>
        </dd>
        {attestation.state === "signed" ? (
          <>
            <dt>Key fingerprint</dt>
            <dd>
              <code className="hash">{attestation.fingerprint}</code>
            </dd>
            <dt>Namespace</dt>
            <dd>
              <code>{attestation.namespace}</code>
            </dd>
          </>
        ) : null}
      </dl>
      <p className="cap signed-note">
        The executor signs a receipt when it is exported. Root on this host can sign any receipt
        with this key, so a signed receipt is still self-attested, not independent evidence.
      </p>
    </section>
  );
}
