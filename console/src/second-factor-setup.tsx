// W729 (TOTP task 37): the required second-factor setup for Admin accounts, ported
// from the refined `/settings/security`. Until the factor is on, the server refuses
// the Admin's other requests and the Console shows only this page.
import { consoleRequest, failureText } from "./console-request";
import {
  Check,
  Copy,
  Download,
  KeyRound,
  LogOut,
  ShieldAlert,
  ShieldCheck,
  Smartphone,
} from "lucide-react";
import { useMemo, useState } from "react";
import { encode } from "uqr";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { OTPField, OTPFieldInput, OTPFieldSeparator } from "@/components/ui/otp-field";
import { useAuth } from "./auth-context";
import { copyText, Glyph } from "./ui";

/** What `/two-factor/enable` returns: the factor stays off until one correct code. */
type PendingFactor = { totpURI: string; backupCodes: string[] };

const CODE_MISMATCH =
  "That code did not match. Check that the time on your phone is correct, then enter the new code.";

/** The secret from an `otpauth://` link, in groups of four for reading. */
export function setupKey(totpURI: string): string {
  const secret = new URL(totpURI).searchParams.get("secret") ?? "";
  return secret.replace(/(.{4})(?=.)/g, "$1 ");
}

/** The QR code of the `otpauth://` link, drawn as one SVG path. */
function SetupQrCode({ uri }: { uri: string }) {
  const { size, path } = useMemo(() => {
    const { data } = encode(uri, { border: 2 });
    let d = "";
    data.forEach((row, y) =>
      row.forEach((on, x) => {
        if (on) d += `M${x} ${y}h1v1h-1z`;
      }),
    );
    return { size: data.length, path: d };
  }, [uri]);
  return (
    <div className="shrink-0 self-start rounded-control border border-border bg-white p-1">
      <svg
        viewBox={`0 0 ${size} ${size}`}
        className="size-40"
        role="img"
        aria-label="QR code to scan with the authenticator app"
        shapeRendering="crispEdges"
      >
        <path d={path} fill="#0b0d10" />
      </svg>
    </div>
  );
}

function downloadCodes(codes: string[], email: string) {
  const text = `Rustiron Console recovery codes · ${email}\nEach code signs in once.\n\n${codes.join("\n")}\n`;
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = "rustiron-recovery-codes.txt";
  link.click();
  URL.revokeObjectURL(url);
}

function StepOne({
  email,
  pending,
  onPending,
}: {
  email: string;
  pending: PendingFactor | null;
  onPending: (next: PendingFactor) => void;
}) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function handleShow(e: React.FormEvent) {
    e.preventDefault();
    if (!password) {
      setErr("Enter your current password to make the setup key.");
      return;
    }
    setBusy(true);
    setErr(null);
    const reply = await consoleRequest<PendingFactor>("/api/auth/two-factor/enable", {
      method: "POST",
      json: { password },
    });
    setBusy(false);
    if (!reply.ok || !reply.data?.totpURI) {
      setErr(
        !reply.ok && (reply.status === null || reply.status === 429)
          ? failureText(reply, "Too many attempts. Wait a minute and try again.")
          : "That password did not match. Enter your current password.",
      );
      return;
    }
    setPassword("");
    onPending(reply.data);
  }

  return (
    <section className="panel" aria-labelledby="tf-step1">
      <div className="panel-head">
        <h2 id="tf-step1" className="inline-flex items-center gap-2">
          <Glyph icon={Smartphone} />
          Step 1 of 3 · Add the Console to your authenticator app
        </h2>
        {pending ? <span className="pill ok">Done</span> : null}
      </div>
      {pending ? (
        <div className="flex flex-col gap-6 sm:flex-row">
          <SetupQrCode uri={pending.totpURI} />
          <div className="min-w-0 flex-1 space-y-4">
            <p className="text-sm text-muted-foreground">
              Scan the code with an authenticator app, for example a password manager or a phone
              app.
            </p>
            <div className="form-row">
              <span id="tf-key-label">Can't scan? Enter this key</span>
              <div className="flex items-center gap-2">
                <code aria-labelledby="tf-key-label" className="mono break-all" translate="no">
                  {setupKey(pending.totpURI)}
                </code>
                <CopyKey text={setupKey(pending.totpURI).replaceAll(" ", "")} />
              </div>
            </div>
            <dl className="kv">
              <dt>Account</dt>
              <dd translate="no">{email}</dd>
              <dt>Type</dt>
              <dd>Time-based, 6 digits, 30 s</dd>
            </dl>
          </div>
        </div>
      ) : (
        <form className="space-y-4" onSubmit={(e) => void handleShow(e)} noValidate>
          <p className="text-sm text-muted-foreground">
            Confirm your current password. The Console then makes a new setup key for this account.
          </p>
          {err ? <FormError text={err} /> : null}
          <div className="form-row max-w-sm">
            <label htmlFor="tf-password">Current password</label>
            <Input
              id="tf-password"
              type="password"
              autoComplete="current-password"
              value={password}
              aria-invalid={err ? true : undefined}
              onChange={(e) => {
                setPassword(e.target.value);
                if (err) setErr(null);
              }}
            />
          </div>
          <Button type="submit" disabled={busy}>
            {busy ? "Making the key…" : "Show the setup key"}
          </Button>
        </form>
      )}
    </section>
  );
}

function CopyKey({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="btn quiet sm"
      onClick={async () => {
        if (await copyText(text, "Setup key copied")) setCopied(true);
      }}
    >
      <Glyph icon={copied ? Check : Copy} />
      {copied ? "Copied" : "Copy key"}
    </button>
  );
}

function FormError({ text }: { text: string }) {
  return (
    <div className="attention err" role="alert">
      <div className="att-body">{text}</div>
    </div>
  );
}

function StepTwo({
  ready,
  enabled,
  onEnabled,
}: {
  ready: boolean;
  enabled: boolean;
  onEnabled: () => void;
}) {
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function handleEnable(e: React.FormEvent) {
    e.preventDefault();
    if (!/^\d{6}$/.test(code)) {
      setErr("Enter the 6-digit code from the app.");
      return;
    }
    setBusy(true);
    setErr(null);
    const reply = await consoleRequest("/api/auth/two-factor/verify-totp", {
      method: "POST",
      json: { code },
    });
    setBusy(false);
    if (!reply.ok) {
      setErr(
        reply.status === null || reply.status === 429
          ? failureText(reply, "Too many attempts. Wait a minute and try again.")
          : CODE_MISMATCH,
      );
      return;
    }
    onEnabled();
  }

  const locked = !ready || enabled;
  return (
    <section className={ready ? "panel" : "panel opacity-60"} aria-labelledby="tf-step2">
      <div className="panel-head">
        <h2 id="tf-step2" className="inline-flex items-center gap-2">
          <Glyph icon={KeyRound} />
          Step 2 of 3 · Enter the code from the app
        </h2>
        {enabled ? <span className="pill ok">On</span> : null}
      </div>
      <form className="space-y-4" onSubmit={(e) => void handleEnable(e)} noValidate>
        {err ? <FormError text={err} /> : null}
        <div className="form-row">
          <label id="tf-code-label" htmlFor="tf-code">
            6-digit code
          </label>
          <OTPField
            length={6}
            value={code}
            disabled={locked}
            autoComplete="one-time-code"
            aria-labelledby="tf-code-label"
            aria-invalid={err ? true : undefined}
            onValueChange={(value) => {
              setCode(value);
              if (err) setErr(null);
            }}
          >
            <OTPFieldInput id="tf-code" aria-label="Digit 1" />
            <OTPFieldInput aria-label="Digit 2" />
            <OTPFieldInput aria-label="Digit 3" />
            <OTPFieldSeparator />
            <OTPFieldInput aria-label="Digit 4" />
            <OTPFieldInput aria-label="Digit 5" />
            <OTPFieldInput aria-label="Digit 6" />
          </OTPField>
        </div>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="max-w-[46ch] text-xs leading-4 text-muted-foreground">
            The second factor turns on only after one correct code, so a wrong scan cannot lock you
            out.
          </p>
          <Button type="submit" disabled={locked || busy}>
            {enabled ? "Second factor on" : busy ? "Checking…" : "Turn on the second factor"}
          </Button>
        </div>
      </form>
    </section>
  );
}

function StepThree({
  codes,
  email,
  onFinish,
}: {
  codes: string[] | null;
  email: string;
  onFinish: () => void;
}) {
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);
  return (
    <section className={codes ? "panel" : "panel opacity-60"} aria-labelledby="tf-step3">
      <div className="panel-head">
        <h2 id="tf-step3" className="inline-flex items-center gap-2">
          <Glyph icon={ShieldCheck} />
          Step 3 of 3 · Save your recovery codes
        </h2>
      </div>
      <div className="space-y-4">
        <p className="text-sm text-muted-foreground">
          Each code signs you in once if you lose the app. The Console shows them only now and
          stores them encrypted.
        </p>
        {codes ? (
          <ol className="grid grid-cols-2 gap-2 sm:grid-cols-5" aria-label="Recovery codes">
            {codes.map((code) => (
              <li
                key={code}
                className="rounded-control border border-border bg-canvas px-3 py-2 text-center font-mono text-sm tracking-wider text-foreground"
                translate="no"
              >
                {code}
              </li>
            ))}
          </ol>
        ) : (
          <p className="text-sm text-muted-foreground">
            The codes appear after the second factor turns on.
          </p>
        )}
        <div className="flex flex-wrap gap-2">
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={!codes}
            onClick={async () => {
              if (codes && (await copyText(codes.join("\n"), "Recovery codes copied")))
                setCopied(true);
            }}
          >
            <Glyph icon={copied ? Check : Copy} />
            {copied ? "Copied" : "Copy all"}
          </Button>
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={!codes}
            onClick={() => codes && downloadCodes(codes, email)}
          >
            <Glyph icon={Download} />
            Download .txt
          </Button>
        </div>
        <label className="row cursor-pointer text-sm" style={{ gap: 8 }}>
          <input
            type="checkbox"
            checked={saved}
            disabled={!codes}
            onChange={(e) => setSaved(e.target.checked)}
          />
          <span>I saved these codes somewhere outside this server</span>
        </label>
        <div className="flex justify-end">
          <Button type="button" disabled={!codes || !saved} onClick={onFinish}>
            Finish and open the Console
          </Button>
        </div>
      </div>
    </section>
  );
}

function SideNotes({ enabled, codeCount }: { enabled: boolean; codeCount: number }) {
  return (
    <div className="space-y-6">
      <section className="panel" aria-labelledby="tf-methods">
        <div className="panel-head">
          <h2 id="tf-methods">Sign-in methods</h2>
        </div>
        <dl className="kv">
          <dt>Password</dt>
          <dd>
            <span className="pill ok">Set</span>
          </dd>
          <dt>Authenticator app</dt>
          <dd>
            {enabled ? (
              <span className="pill ok">On</span>
            ) : (
              <span className="pill warn">Required</span>
            )}
          </dd>
          <dt>Recovery codes</dt>
          <dd>{enabled ? `${codeCount} unused` : <span className="pill muted">Not made</span>}</dd>
          <dt>Passkeys</dt>
          <dd>
            <span className="pill muted">Later</span>
          </dd>
        </dl>
      </section>
      <section className="panel" aria-labelledby="tf-lost">
        <div className="panel-head">
          <h2 id="tf-lost">If you lose access</h2>
        </div>
        <div className="space-y-3 text-sm text-muted-foreground">
          <p>Lost the app? Sign in with one recovery code, then set up the app again.</p>
          <p>
            Lost both the app and the codes? Reset the second factor from the host shell, as Runbook
            38 describes.
          </p>
          <p>
            Passkeys come later as an option. A passkey works only on the address it was made on,
            and the SSH tunnel and Caddy addresses differ.
          </p>
        </div>
      </section>
    </div>
  );
}

/** The full-screen setup an Admin without a second factor sees instead of the Console. */
export function SecondFactorSetupGate({ themeControl }: { themeControl?: React.ReactNode }) {
  const { status, refresh, signOut } = useAuth();
  const email = status?.session?.user.email ?? "";
  const [pending, setPending] = useState<PendingFactor | null>(null);
  const [enabled, setEnabled] = useState(false);

  return (
    <div className="min-h-screen bg-background px-4 py-10 text-foreground">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <main id="main" className="mx-auto w-full max-w-6xl space-y-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Security</h1>
            <p className="mt-1.5 max-w-[70ch] text-sm text-muted-foreground">
              Console sign-in and second factor. A Console session never carries executor authority;
              changes still need a signed grant.
            </p>
          </div>
          <div className="flex items-center gap-2">
            {themeControl}
            <Button type="button" variant="outline" size="sm" onClick={() => void signOut()}>
              <Glyph icon={LogOut} />
              Sign out
            </Button>
          </div>
        </div>
        {!enabled ? (
          <div className="attention" role="status">
            <Glyph icon={ShieldAlert} />
            <div className="att-body">
              <strong>Set up a second factor to continue.</strong> Admin accounts need an
              authenticator app code at each sign-in. Until you finish these steps, the Console
              shows only this page.
            </div>
          </div>
        ) : null}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          <div className="space-y-6 lg:col-span-2">
            <StepOne email={email} pending={pending} onPending={setPending} />
            <StepTwo
              ready={pending !== null}
              enabled={enabled}
              onEnabled={() => setEnabled(true)}
            />
            <StepThree
              codes={enabled ? (pending?.backupCodes ?? null) : null}
              email={email}
              onFinish={() => void refresh()}
            />
          </div>
          <SideNotes enabled={enabled} codeCount={pending?.backupCodes.length ?? 0} />
        </div>
      </main>
    </div>
  );
}
