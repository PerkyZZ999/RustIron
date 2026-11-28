// W629 (P29 Slice 9): Console Sign-In, First-Run Admin Setup (/login), and
// Console User Accounts & Roles management (/users) powered by Better Auth.
import { AnswerLine, SimpleHeader } from "@/components/console/simple";
import { consoleRequest, failureText, type ConsoleReply } from "./console-request";
import { Link, useNavigate, useRouterState } from "@tanstack/react-router";
import {
  AlertCircle,
  ArrowLeft,
  Check,
  Eye,
  EyeOff,
  KeyRound,
  Lock,
  LogIn,
  LogOut,
  ShieldCheck,
  UserPlus,
  Users,
} from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { BrandLockup, BrandMark } from "@/components/console/brand-logo";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { OTPField, OTPFieldInput, OTPFieldSeparator } from "@/components/ui/otp-field";
import type { ConsoleAccountUser, ConsoleAuthStatus, ConsoleRole } from "./auth-backend";
import { useAuth } from "./auth-context";
import { ConfirmDeleteButton, Crumbs, Glyph, Page, TableScroll } from "./ui";

const roleDescriptions: Record<ConsoleRole, string> = {
  admin: "Full panel access, user management, and signed plan submission",
  operator: "View all server resources, draft plans, and submit signed plans",
  viewer: "Read-only access to dashboards, metrics, sites, and logs",
};

function AuthAlert({ tone, text }: { tone: "err" | "ok"; text: string }) {
  return (
    <div className={tone === "err" ? "attention err" : "attention info"} role="alert">
      <Glyph icon={tone === "err" ? AlertCircle : Check} />
      <div className="att-body">{text}</div>
    </div>
  );
}

function AdminSetupForm({ onDone }: { onDone: () => Promise<void> }) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [setupToken, setSetupToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (password.length < 10) {
      setErr("Password must be at least 10 characters.");
      return;
    }
    if (password !== confirm) {
      setErr("Passwords do not match.");
      return;
    }
    setBusy(true);
    setErr(null);
    const reply = await consoleRequest("/api/accounts/setup", {
      method: "POST",
      json: {
        name,
        email,
        password,
        ...(setupToken.trim() ? { setupToken: setupToken.trim() } : {}),
      },
    });
    if (!reply.ok) {
      setBusy(false);
      setErr(
        failureText(
          reply,
          `Setup failed (HTTP ${reply.status}).`,
          "Could not reach the Console authentication service.",
        ),
      );
      return;
    }
    try {
      await onDone();
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="panel stack" onSubmit={(e) => void handleSubmit(e)}>
      <div className="panel-head">
        <div className="row" style={{ gap: 10 }}>
          <BrandMark className="size-7 shrink-0" />
          <h2>Create administrator account</h2>
        </div>
        <span className="pill ok">Better Auth</span>
      </div>
      <p className="muted">
        Set up the first Admin account to protect access to the Rustiron Console with secure
        HttpOnly sessions.
      </p>
      {err ? <AuthAlert tone="err" text={err} /> : null}
      <div className="form-grid">
        <div className="form-row">
          <label htmlFor="setup-name">Full name</label>
          <input
            id="setup-name"
            className="input"
            required
            minLength={2}
            maxLength={100}
            autoComplete="name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Alex Rivera"
          />
        </div>
        <div className="form-row">
          <label htmlFor="setup-email">Email address</label>
          <input
            id="setup-email"
            className="input"
            type="email"
            required
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="admin@example.com"
          />
        </div>
        <div className="form-row">
          <label htmlFor="setup-pass">Password (min 10 characters)</label>
          <input
            id="setup-pass"
            className="input"
            type="password"
            required
            minLength={10}
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        <div className="form-row">
          <label htmlFor="setup-confirm">Confirm password</label>
          <input
            id="setup-confirm"
            className="input"
            type="password"
            required
            minLength={10}
            autoComplete="new-password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
          />
        </div>
        <div className="form-row">
          <label htmlFor="setup-token">Setup token (if configured on host)</label>
          <input
            id="setup-token"
            className="input mono"
            type="password"
            autoComplete="one-time-code"
            value={setupToken}
            onChange={(e) => setSetupToken(e.target.value)}
            placeholder="Optional RUSTIRON_CONSOLE_SETUP_TOKEN"
          />
        </div>
      </div>
      <div className="row">
        <button type="submit" className="btn primary" disabled={busy}>
          <Glyph icon={UserPlus} />
          {busy ? "Creating admin…" : "Create admin account"}
        </button>
      </div>
    </form>
  );
}

/** W728: every refused second-factor code reads the same, so a refusal names no factor. */
const CODE_REFUSED = "Sign-in failed. Check your details and try again.";
const RECOVERY_CODE = /^[A-Z0-9]{4}-[A-Z0-9]{4}$/;

type SecondFactorMethod = "totp" | "recovery";

/** The text for a refused code check: the server's wait on 429, else the generic refusal. */
function codeFailureText(reply: Extract<ConsoleReply<unknown>, { ok: false }>): string {
  if (reply.status === null) return "Could not reach the Console authentication service.";
  if (reply.status === 429)
    return failureText(reply, "Too many attempts. Wait a minute and try again.");
  return CODE_REFUSED;
}

/**
 * W728 (TOTP task 36): step 2 of sign-in for an account with a second factor, ported
 * from the refined `/login`. The challenge cookie from step 1 names the account.
 */
function SecondFactorForm({
  email,
  onBack,
  onSignedIn,
}: {
  email: string;
  onBack: () => void;
  onSignedIn: () => Promise<void>;
}) {
  const [method, setMethod] = useState<SecondFactorMethod>("totp");
  const [code, setCode] = useState("");
  const [recoveryCode, setRecoveryCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  // The step replaced the password form, so focus moves to each input as it appears.
  const focusOnMount = useCallback((input: HTMLInputElement | null) => input?.focus(), []);

  async function handleVerify(e: React.FormEvent) {
    e.preventDefault();
    const value = method === "totp" ? code : recoveryCode.trim();
    const complete = method === "totp" ? /^\d{6}$/.test(value) : RECOVERY_CODE.test(value);
    if (!complete) {
      setErr(
        method === "totp"
          ? "Enter all 6 digits from your authenticator app."
          : "Enter one recovery code, for example 7KQ4-M2XD.",
      );
      return;
    }
    setBusy(true);
    setErr(null);
    const path =
      method === "totp"
        ? "/api/auth/two-factor/verify-totp"
        : "/api/auth/two-factor/verify-backup-code";
    const reply = await consoleRequest(path, { method: "POST", json: { code: value } });
    if (!reply.ok) {
      setBusy(false);
      setErr(codeFailureText(reply));
      return;
    }
    try {
      await onSignedIn();
    } finally {
      setBusy(false);
    }
  }

  function switchMethod() {
    setMethod((m) => (m === "totp" ? "recovery" : "totp"));
    setErr(null);
  }

  return (
    <form
      className="motion-hero rounded-panel border border-border bg-surface p-6 shadow-[var(--shadow-float)] matte-surface sm:p-8"
      onSubmit={(e) => void handleVerify(e)}
      noValidate
    >
      <div className="mb-6 flex flex-col gap-2">
        <BrandLockup className="h-8 w-auto self-start" />
        <div className="min-w-0">
          <h2 className="text-base font-semibold leading-6 tracking-tight text-foreground">
            Enter your code
          </h2>
          <p className="truncate font-mono text-xs text-muted-foreground">Step 2 of 2 · {email}</p>
        </div>
      </div>
      <div className="space-y-4">
        {err ? <AuthAlert tone="err" text={err} /> : null}
        {method === "totp" ? (
          <div className="form-row">
            <label id="login-code-label" htmlFor="login-code">
              6-digit code from your authenticator app
            </label>
            <OTPField
              length={6}
              size="lg"
              value={code}
              autoComplete="one-time-code"
              aria-labelledby="login-code-label"
              aria-invalid={err ? true : undefined}
              onValueChange={(value) => {
                setCode(value);
                if (err) setErr(null);
              }}
              className="justify-between"
            >
              <OTPFieldInput ref={focusOnMount} id="login-code" aria-label="Digit 1" />
              <OTPFieldInput aria-label="Digit 2" />
              <OTPFieldInput aria-label="Digit 3" />
              <OTPFieldSeparator />
              <OTPFieldInput aria-label="Digit 4" />
              <OTPFieldInput aria-label="Digit 5" />
              <OTPFieldInput aria-label="Digit 6" />
            </OTPField>
            <span className="hint">The code changes every 30 seconds.</span>
          </div>
        ) : (
          <div className="form-row">
            <label htmlFor="login-recovery">Recovery code</label>
            <Input
              id="login-recovery"
              placeholder="XXXX-XXXX"
              ref={focusOnMount}
              autoComplete="off"
              spellCheck={false}
              value={recoveryCode}
              aria-invalid={err ? true : undefined}
              onChange={(e) => {
                setRecoveryCode(e.target.value.toUpperCase());
                if (err) setErr(null);
              }}
              className="font-mono tracking-wider"
            />
            <span className="hint">Each recovery code works once.</span>
          </div>
        )}
        <Button type="submit" variant="default" className="w-full" disabled={busy}>
          <Glyph icon={ShieldCheck} />
          {busy ? "Verifying…" : "Verify and sign in"}
        </Button>
        <div className="flex items-center justify-between gap-3 text-xs">
          <button
            type="button"
            onClick={onBack}
            className="inline-flex min-h-8 cursor-pointer items-center gap-1 font-medium text-muted-foreground hover:text-foreground"
          >
            <ArrowLeft aria-hidden="true" className="size-3.5" />
            Back
          </button>
          <button
            type="button"
            onClick={switchMethod}
            className="inline-flex min-h-8 cursor-pointer items-center gap-1 font-medium text-focus hover:underline"
          >
            <KeyRound aria-hidden="true" className="size-3.5" />
            {method === "totp" ? "Use a recovery code instead" : "Use the authenticator app"}
          </button>
        </div>
      </div>
      <div className="mt-6 flex items-center justify-center gap-1.5 border-t border-border pt-4 text-xs text-muted-foreground">
        <Lock aria-hidden="true" className="size-3.5" strokeWidth={1.75} />
        <span>Better Auth · second factor</span>
      </div>
    </form>
  );
}

function SignInForm({ onSignedIn }: { onSignedIn: () => Promise<void> }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [needsCode, setNeedsCode] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function handleSignIn(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    const reply = await consoleRequest("/api/auth/sign-in/email", {
      method: "POST",
      json: { email, password },
    });
    if (!reply.ok) {
      setBusy(false);
      // W717: a rate-limit refusal (W694) names its wait; any other refusal stays
      // generic so it never reveals which factor failed.
      setErr(
        reply.status === null
          ? "Could not reach the Console authentication service."
          : reply.status === 429
            ? failureText(reply, "Too many sign-in attempts. Wait a minute and try again.")
            : "Invalid email or password.",
      );
      return;
    }
    // W728: an account with a second factor gets a challenge cookie, not a session.
    if ((reply.data as { twoFactorRedirect?: unknown } | null)?.twoFactorRedirect === true) {
      setBusy(false);
      setPassword("");
      setNeedsCode(true);
      return;
    }
    try {
      await onSignedIn();
    } finally {
      setBusy(false);
    }
  }

  if (needsCode) {
    return (
      <SecondFactorForm email={email} onBack={() => setNeedsCode(false)} onSignedIn={onSignedIn} />
    );
  }

  return (
    <form
      className="motion-hero rounded-panel border border-border bg-surface p-6 shadow-[var(--shadow-float)] matte-surface sm:p-8"
      onSubmit={(e) => void handleSignIn(e)}
    >
      <div className="mb-6 flex flex-col gap-2">
        <BrandLockup className="h-8 w-auto self-start" />
        <div className="min-w-0">
          <h2 className="text-base font-semibold leading-6 tracking-tight text-foreground">
            Sign in
          </h2>
          <p className="text-xs text-muted-foreground">Operations Console · Better Auth</p>
        </div>
      </div>
      <div className="space-y-4">
        {err ? <AuthAlert tone="err" text={err} /> : null}
        <div className="form-row">
          <label htmlFor="login-email">Email address</label>
          <Input
            id="login-email"
            type="email"
            required
            autoComplete="email"
            placeholder="operator@lab.test"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </div>
        <div className="form-row">
          <label htmlFor="login-pass">Password</label>
          <div className="relative w-full">
            <Input
              id="login-pass"
              type={showPassword ? "text" : "password"}
              required
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="pr-9"
            />
            <button
              type="button"
              aria-label={showPassword ? "Hide password" : "Show password"}
              onClick={() => setShowPassword((v) => !v)}
              className="absolute right-2 top-1/2 z-10 grid size-7 -translate-y-1/2 cursor-pointer place-items-center rounded text-muted-foreground transition-colors hover:bg-hover hover:text-foreground"
            >
              {showPassword ? (
                <EyeOff aria-hidden="true" className="size-4" strokeWidth={1.75} />
              ) : (
                <Eye aria-hidden="true" className="size-4" strokeWidth={1.75} />
              )}
            </button>
          </div>
          <span className="hint">Authentication errors never reveal which factor failed.</span>
        </div>
        <Button type="submit" variant="default" className="w-full" disabled={busy}>
          <Glyph icon={LogIn} />
          {busy ? "Signing in…" : "Sign in"}
        </Button>
      </div>
      <div className="mt-6 flex items-center justify-center gap-1.5 border-t border-border pt-4 text-xs text-muted-foreground">
        <Lock aria-hidden="true" className="size-3.5" strokeWidth={1.75} />
        <span>Better Auth · HttpOnly Strict cookie</span>
      </div>
    </form>
  );
}

export function StandaloneAuthGate({ themeControl }: { themeControl?: React.ReactNode }) {
  const { status, refresh } = useAuth();
  const navigate = useNavigate();
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  const setupRequired = status?.setup_required ?? false;

  // W748 (QA-17): the gate stands in for the page that was asked for, so after
  // sign-in that page opens; only the sign-in page itself moves on to the Overview.
  async function handleSuccess() {
    await refresh();
    if (pathname === "/login") void navigate({ to: "/" });
  }

  return (
    <div className="relative flex min-h-screen flex-col items-center justify-center bg-background px-4 py-10 text-foreground">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      {themeControl ? <div className="absolute right-4 top-4">{themeControl}</div> : null}
      <main id="main" className="w-full max-w-[440px]">
        <div className="mb-6 text-center">
          <h1 className="text-2xl font-semibold tracking-tight text-foreground">
            {setupRequired ? "Console account setup" : "Sign in to RustIron Console"}
          </h1>
          <p className="mt-1.5 text-sm text-muted-foreground">
            {setupRequired
              ? "Create your administrator account to unlock the operations panel."
              : "Sign in with your administrator or operator credentials to continue."}
          </p>
        </div>
        {setupRequired ? (
          <AdminSetupForm onDone={handleSuccess} />
        ) : (
          <SignInForm onSignedIn={handleSuccess} />
        )}
      </main>
    </div>
  );
}

export function LoginPage() {
  const { status, refresh, signOut } = useAuth();
  const navigate = useNavigate();
  const setupRequired = status?.setup_required ?? true;

  async function handleSuccess() {
    await refresh();
    void navigate({ to: "/" });
  }

  return (
    <Page live>
      <div className="page-head">
        <div>
          <h1>{setupRequired ? "Console account setup" : "Sign in to Rustiron Console"}</h1>
          <p className="sub">
            {setupRequired
              ? "Create your first administrator account to enable Better Auth login and role-based access."
              : "Enter your Console credentials to access server administration."}
          </p>
        </div>
      </div>
      <div style={{ maxWidth: 560 }}>
        {status?.session ? (
          <section className="panel stack">
            <div className="panel-head">
              <h2>Signed in as {status.session.user.name}</h2>
              <span className="pill ok">{status.session.user.role}</span>
            </div>
            <p className="muted mono">{status.session.user.email}</p>
            <div className="row" style={{ gap: 8 }}>
              <Link className="btn primary sm" to="/users">
                Manage accounts
              </Link>
              <button type="button" className="btn quiet sm" onClick={() => void signOut()}>
                <Glyph icon={LogOut} />
                Sign out
              </button>
            </div>
          </section>
        ) : setupRequired ? (
          <AdminSetupForm onDone={handleSuccess} />
        ) : (
          <SignInForm onSignedIn={handleSuccess} />
        )}
      </div>
    </Page>
  );
}

/** W747 (QA-16): success goes to the page notice; the form keeps only its own error. */
function CreateUserForm({ onCreated }: { onCreated: (message: string) => Promise<void> }) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<ConsoleRole>("operator");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    const reply = await consoleRequest("/api/accounts/users", {
      method: "POST",
      json: { name, email, password, role },
    });
    if (!reply.ok) {
      setBusy(false);
      setErr(failureText(reply, "Failed to create user.", "Could not reach the accounts API."));
      return;
    }
    setName("");
    setEmail("");
    setPassword("");
    try {
      await onCreated(`Created ${role} account for ${email}.`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form
      className="panel stack"
      onSubmit={(e) => void handleCreate(e)}
      onInvalidCapture={() => setErr(null)}
    >
      <div className="panel-head">
        <div className="row" style={{ gap: 8 }}>
          <Glyph icon={UserPlus} />
          <h2>Add Console user</h2>
        </div>
      </div>
      {err ? <AuthAlert tone="err" text={err} /> : null}
      <div className="form-grid">
        <div className="form-row">
          <label htmlFor="u-name">Full name</label>
          <input
            id="u-name"
            className="input"
            required
            minLength={2}
            maxLength={100}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Jordan Lee"
          />
        </div>
        <div className="form-row">
          <label htmlFor="u-email">Email</label>
          <input
            id="u-email"
            className="input"
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="operator@example.com"
          />
        </div>
        <div className="form-row">
          <label htmlFor="u-pass">Initial password (min 10 chars)</label>
          <input
            id="u-pass"
            className="input"
            type="password"
            required
            minLength={10}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        <div className="form-row">
          <label htmlFor="u-role">Role</label>
          <select
            id="u-role"
            className="input"
            value={role}
            onChange={(e) => setRole(e.target.value as ConsoleRole)}
          >
            <option value="admin">Admin</option>
            <option value="operator">Operator</option>
            <option value="viewer">Viewer (read-only)</option>
          </select>
        </div>
      </div>
      <p className="cap">{roleDescriptions[role]}</p>
      <div>
        <button type="submit" className="btn primary sm" disabled={busy}>
          <Glyph icon={UserPlus} />
          {busy ? "Creating…" : "Create account"}
        </button>
      </div>
    </form>
  );
}

function AccountsTable({
  users,
  currentUserId,
  onRoleChange,
  onDelete,
}: {
  users: ConsoleAccountUser[];
  currentUserId: string;
  onRoleChange: (id: string, role: ConsoleRole) => Promise<void>;
  onDelete: (id: string) => Promise<void>;
}) {
  return (
    <section className="panel flush" aria-label="Console user accounts">
      <div className="panel-head" style={{ padding: "14px 16px 10px" }}>
        <div className="row" style={{ gap: 8 }}>
          <Glyph icon={Users} />
          <h2>Console accounts ({users.length})</h2>
        </div>
        <span className="meta">Managed by Better Auth · SQLite</span>
      </div>
      <TableScroll label="Console user accounts">
        <table className="data">
          <thead>
            <tr>
              <th>Name</th>
              <th>Email</th>
              <th>Role</th>
              <th>Sessions</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td>
                  <strong>{u.name}</strong>
                  {u.id === currentUserId ? (
                    <span className="pill ok" style={{ marginLeft: 8 }}>
                      You
                    </span>
                  ) : null}
                </td>
                <td className="mono">{u.email}</td>
                <td>
                  <select
                    aria-label={`Role for ${u.email}`}
                    className="input"
                    value={u.role}
                    onChange={(e) => void onRoleChange(u.id, e.target.value as ConsoleRole)}
                  >
                    <option value="admin">Admin</option>
                    <option value="operator">Operator</option>
                    <option value="viewer">Viewer</option>
                  </select>
                </td>
                <td className="tnum">{u.activeSessions}</td>
                <td>
                  <ConfirmDeleteButton
                    label={`Delete ${u.email}`}
                    disabled={u.id === currentUserId}
                    onConfirm={() => void onDelete(u.id)}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableScroll>
    </section>
  );
}

async function fetchConsoleUsers(): Promise<ConsoleAccountUser[] | null> {
  const reply = await consoleRequest<{ users?: ConsoleAccountUser[] }>("/api/accounts/users");
  return reply.ok ? (reply.data?.users ?? []) : null;
}

/** W791 (v0.3 item 61): "Who can sign in?" without guessing for a non-Admin. */
export function usersAnswer(
  status: ConsoleAuthStatus | null,
  resolved: boolean,
  users: ConsoleAccountUser[],
): { tone: "ok" | "warn" | "unknown"; text: string } {
  if (!resolved) return { tone: "unknown", text: "Checking who can sign in…" };
  if (status === null)
    return { tone: "unknown", text: "The sign-in service could not be reached." };
  if (status.setup_required) {
    return { tone: "warn", text: "No account exists yet. Create the first Admin." };
  }
  if (status.session?.user.role !== "admin") {
    return { tone: "unknown", text: "Only an Admin can see who else can sign in." };
  }
  const sessions = users.reduce((sum, user) => sum + user.activeSessions, 0);
  const accounts = `${users.length} ${users.length === 1 ? "account" : "accounts"}`;
  return {
    tone: "ok",
    text: `${accounts} can sign in, with ${sessions} active ${sessions === 1 ? "session" : "sessions"}.`,
  };
}

export function UsersPage() {
  const { status, resolved, refresh, signOut } = useAuth();
  const [users, setUsers] = useState<ConsoleAccountUser[]>([]);
  const [notice, setNotice] = useState<{ tone: "err" | "ok"; text: string } | null>(null);

  const loadUsers = useCallback(async () => {
    const list = await fetchConsoleUsers();
    if (list) setUsers(list);
  }, []);

  const isAdmin = status?.session?.user.role === "admin";
  useEffect(() => {
    if (!isAdmin) return undefined;
    let active = true;
    void fetchConsoleUsers().then((list) => {
      if (active && list) setUsers(list);
    });
    return () => {
      active = false;
    };
  }, [isAdmin]);

  async function handleRoleChange(id: string, role: ConsoleRole) {
    setNotice(null);
    const res = await consoleRequest(`/api/accounts/users/${id}`, {
      method: "PATCH",
      json: { role },
    });
    if (!res.ok) {
      setNotice({ tone: "err", text: failureText(res, "Role update failed.") });
      return;
    }
    setNotice({ tone: "ok", text: "Account role updated." });
    await loadUsers();
  }

  async function handleDelete(id: string) {
    setNotice(null);
    const res = await consoleRequest(`/api/accounts/users/${id}`, { method: "DELETE" });
    if (!res.ok) {
      setNotice({ tone: "err", text: failureText(res, "Could not delete account.") });
      return;
    }
    setNotice({ tone: "ok", text: "Account removed and sessions revoked." });
    await loadUsers();
  }

  async function handleRevokeOthers() {
    const res = await consoleRequest("/api/accounts/sessions/revoke-others", { method: "POST" });
    if (!res.ok) {
      setNotice({ tone: "err", text: failureText(res, "Could not sign out other sessions.") });
      return;
    }
    setNotice({ tone: "ok", text: "All other sessions for your account have been signed out." });
    await loadUsers();
  }

  const session = status?.session ?? null;
  const setupRequired = status ? status.setup_required : true;

  return (
    <Page live>
      <Crumbs items={[{ href: "/", label: "Overview" }, { label: "Users & access" }]} />
      <div className="page-head">
        <SimpleHeader
          title="Users & access"
          answer={
            <AnswerLine tone={usersAnswer(status, resolved, users).tone}>
              {usersAnswer(status, resolved, users).text}
            </AnswerLine>
          }
        />
        {session ? (
          <div className="row" style={{ gap: 8 }}>
            <button
              type="button"
              className="btn quiet sm"
              onClick={() => void handleRevokeOthers()}
            >
              <Glyph icon={KeyRound} />
              Sign out other sessions
            </button>
            <button type="button" className="btn sm" onClick={() => void signOut()}>
              <Glyph icon={LogOut} />
              Sign out
            </button>
          </div>
        ) : (
          <Link className="btn primary sm" to="/login">
            <Glyph icon={LogIn} />
            Sign in
          </Link>
        )}
      </div>

      {notice ? <AuthAlert tone={notice.tone} text={notice.text} /> : null}

      {/* W747 (QA-16): any form action replaces the page notice. */}
      <div
        style={{ display: "contents" }}
        onSubmitCapture={() => setNotice(null)}
        onInvalidCapture={() => setNotice(null)}
      >
        {setupRequired ? (
          <AdminSetupForm
            onDone={async () => {
              await refresh();
              await loadUsers();
            }}
          />
        ) : session?.user.role === "admin" ? (
          <div className="stack">
            <AccountsTable
              users={users}
              currentUserId={session.user.id}
              onRoleChange={handleRoleChange}
              onDelete={handleDelete}
            />
            <CreateUserForm
              onCreated={async (message) => {
                setNotice({ tone: "ok", text: message });
                await loadUsers();
              }}
            />
          </div>
        ) : session ? (
          <section className="panel">
            <div className="panel-head">
              <h2>Your account</h2>
              <span className="pill ok">{session.user.role}</span>
            </div>
            <dl className="kv">
              <dt>Name</dt>
              <dd>{session.user.name}</dd>
              <dt>Email</dt>
              <dd className="mono">{session.user.email}</dd>
              <dt>Permissions</dt>
              <dd>{roleDescriptions[session.user.role]}</dd>
            </dl>
          </section>
        ) : (
          <SignInForm
            onSignedIn={async () => {
              await refresh();
              await loadUsers();
            }}
          />
        )}
      </div>
    </Page>
  );
}
