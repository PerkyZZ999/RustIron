// W631 (P29 Slice 11): CyberPanel-grade Self-Hosted Postfix + Dovecot Email Manager
// (Mailboxes CRUD, Aliases & Forwarders, Per-Site Outbound Relay, and MX/SPF/DKIM/DMARC DNS).
import { AnswerLine, SimpleHeader } from "@/components/console/simple";
import { consoleRequest, failureText } from "./console-request";
import { Link } from "@tanstack/react-router";
import {
  AlertCircle,
  Check,
  Copy,
  Download,
  KeyRound,
  Lock,
  Mail,
  MailPlus,
  Pencil,
  Plus,
  Trash2,
} from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { useData } from "./data";
import type { MailAliasRow, MailboxRow, MailStatePayload } from "./mail-backend";
import { ConfirmDeleteButton, copyText, Crumbs, EmptyState, Glyph, Page, TableScroll } from "./ui";

type MailTab = "mailboxes" | "aliases" | "relay" | "dns";

type MailLoadResult =
  | { ok: true; state: MailStatePayload; writesEnabled: boolean }
  | { ok: false; error: string };

async function fetchMailState(): Promise<MailLoadResult> {
  const reply = await consoleRequest<
    (Partial<MailStatePayload> & { writesEnabled?: boolean }) | null
  >("/api/mail/state");
  if (!reply.ok) {
    return {
      ok: false,
      error:
        reply.status === null
          ? "Could not reach /api/mail/state."
          : `Mail catalog request returned HTTP ${reply.status}.`,
    };
  }
  const body = reply.data;
  if (
    body &&
    Array.isArray(body.domains) &&
    Array.isArray(body.mailboxes) &&
    Array.isArray(body.aliases)
  ) {
    return {
      ok: true,
      state: { domains: body.domains, mailboxes: body.mailboxes, aliases: body.aliases },
      writesEnabled: body.writesEnabled === true,
    };
  }
  return { ok: false, error: "Mail catalog returned an unexpected response shape." };
}

function generateStrongPassword(): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*";
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => chars[b % chars.length]).join("");
}

function downloadJson(filename: string, data: unknown) {
  const blob = new Blob([JSON.stringify(data, null, 2)], {
    type: "application/json;charset=utf-8",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function MailFeedback({ notice }: { notice: { tone: "err" | "ok"; text: string } | null }) {
  if (!notice) return null;
  return (
    <div className={notice.tone === "err" ? "attention err" : "attention info"} role="alert">
      <Glyph icon={notice.tone === "err" ? AlertCircle : Check} />
      <div className="att-body">{notice.text}</div>
    </div>
  );
}

/**
 * W743 (QA-12): the domains of sites this host serves. A quarantined site is
 * "err" and an ejected one "muted"; neither receives mail here.
 */
export function servedSiteDomains(sites: { domain: string; servingKind: string }[]): string[] {
  return sites
    .filter((site) => site.servingKind !== "err" && site.servingKind !== "muted")
    .map((site) => site.domain);
}

function CreateMailboxCard({
  domains,
  servedDomains,
  onCreated,
}: {
  domains: string[];
  servedDomains: string[];
  onCreated: (msg: string) => Promise<void>;
}) {
  const [localPart, setLocalPart] = useState("");
  const [domain, setDomain] = useState("");
  const typedDomain = domain.trim().toLowerCase();
  const notServed = typedDomain !== "" && !servedDomains.includes(typedDomain);
  const [password, setPassword] = useState("");
  const [quotaMb, setQuotaMb] = useState("1024");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    const reply = await consoleRequest("/api/mail/mailboxes", {
      method: "POST",
      json: { localPart, domain, password, quotaMb: Number(quotaMb) },
    });
    if (!reply.ok) {
      setBusy(false);
      setErr(failureText(reply, "Failed to create mailbox.", "Could not reach the Mail API."));
      return;
    }
    const createdAddr = `${localPart.trim().toLowerCase()}@${domain.trim().toLowerCase()}`;
    setLocalPart("");
    setPassword("");
    try {
      await onCreated(`Mailbox ${createdAddr} created.`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form
      className="panel stack"
      onSubmit={(e) => void handleSubmit(e)}
      onInvalidCapture={() => setErr(null)}
    >
      <div className="panel-head">
        <div className="row" style={{ gap: 8 }}>
          <Glyph icon={MailPlus} />
          <h2>Create mailbox</h2>
        </div>
        <span className="meta">Postfix + Dovecot virtual mailbox (IMAPS 993 · SMTP 587)</span>
      </div>
      {err ? <MailFeedback notice={{ tone: "err", text: err }} /> : null}
      <div className="form-grid">
        <div className="form-row">
          <label htmlFor="mb-local">Mailbox name</label>
          <input
            id="mb-local"
            className="input mono"
            required
            placeholder="info"
            value={localPart}
            onChange={(e) => setLocalPart(e.target.value)}
          />
        </div>
        <div className="form-row">
          <label htmlFor="mb-domain">Domain</label>
          <input
            id="mb-domain"
            list="mb-domain-list"
            className="input mono"
            required
            placeholder={domains[0] ?? "example.com"}
            aria-describedby={notServed ? "mb-domain-hint" : undefined}
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
          />
          {notServed ? (
            <span id="mb-domain-hint" className="hint">
              This host does not serve {typedDomain}. The mailbox is cataloged, but no mail arrives
              until the domain is a served site here.
            </span>
          ) : null}
          <datalist id="mb-domain-list">
            {domains.map((d) => (
              <option key={d} value={d}>
                {d}
              </option>
            ))}
          </datalist>
        </div>
        <div className="form-row">
          <label htmlFor="mb-pass">Password (min 8 characters)</label>
          <div className="row" style={{ gap: 6 }}>
            <input
              id="mb-pass"
              className="input mono"
              type="password"
              required
              minLength={8}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <button
              type="button"
              className="btn quiet sm"
              onClick={() => setPassword(generateStrongPassword())}
            >
              <Glyph icon={KeyRound} />
              Generate
            </button>
          </div>
        </div>
        <div className="form-row">
          <label htmlFor="mb-quota">Storage quota (MiB)</label>
          <input
            id="mb-quota"
            className="input tnum"
            type="number"
            min={50}
            max={102400}
            value={quotaMb}
            onChange={(e) => setQuotaMb(e.target.value)}
          />
        </div>
      </div>
      <div>
        <button type="submit" className="btn primary sm" disabled={busy}>
          <Glyph icon={Plus} />
          {busy ? "Creating…" : "Create mailbox"}
        </button>
      </div>
    </form>
  );
}

function EditMailboxModal({
  mailbox,
  onClose,
  onSaved,
}: {
  mailbox: MailboxRow;
  onClose: () => void;
  onSaved: (msg: string) => Promise<void>;
}) {
  const [quotaMb, setQuotaMb] = useState(String(mailbox.quotaMb));
  const [password, setPassword] = useState("");
  const [enabled, setEnabled] = useState(mailbox.enabled);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    const payload: Record<string, unknown> = { quotaMb: Number(quotaMb), enabled };
    if (password.trim()) payload.password = password;
    const reply = await consoleRequest(`/api/mail/mailboxes/${mailbox.id}`, {
      method: "PATCH",
      json: payload,
    });
    setBusy(false);
    if (!reply.ok) {
      setErr(
        reply.status === null
          ? "The Console server did not answer. Reload to see whether the update applied."
          : (reply.message ?? "Update failed."),
      );
      return;
    }
    await onSaved(`Updated ${mailbox.email}.`);
    onClose();
  }

  return (
    <form
      className="panel stack"
      onSubmit={(e) => void handleSave(e)}
      onInvalidCapture={() => setErr(null)}
    >
      <div className="panel-head">
        <h2>Edit {mailbox.email}</h2>
        <button type="button" className="btn quiet sm" onClick={onClose}>
          Close
        </button>
      </div>
      {err ? <MailFeedback notice={{ tone: "err", text: err }} /> : null}
      <div className="form-grid">
        <div className="form-row">
          <label htmlFor="ed-quota">Quota (MiB)</label>
          <input
            id="ed-quota"
            className="input tnum"
            type="number"
            min={50}
            max={102400}
            value={quotaMb}
            onChange={(e) => setQuotaMb(e.target.value)}
          />
        </div>
        <div className="form-row">
          <label htmlFor="ed-pass">New password (leave blank to keep)</label>
          <input
            id="ed-pass"
            className="input mono"
            type="password"
            minLength={8}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        <div className="form-row">
          <label htmlFor="ed-state">Mailbox status</label>
          <select
            id="ed-state"
            className="input"
            value={enabled ? "active" : "suspended"}
            onChange={(e) => setEnabled(e.target.value === "active")}
          >
            <option value="active">Active</option>
            <option value="suspended">Suspended</option>
          </select>
        </div>
      </div>
      <div className="row" style={{ gap: 8 }}>
        <button type="submit" className="btn primary sm" disabled={busy}>
          {busy ? "Saving…" : "Save changes"}
        </button>
        <button type="button" className="btn quiet sm" onClick={onClose}>
          Cancel
        </button>
      </div>
    </form>
  );
}

function AliasesTab({
  aliases,
  onChanged,
}: {
  aliases: MailAliasRow[];
  onChanged: (msg: string) => Promise<void>;
}) {
  const [source, setSource] = useState("");
  const [destination, setDestination] = useState("");
  const [err, setErr] = useState<string | null>(null);

  async function handleAdd(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    const reply = await consoleRequest("/api/mail/aliases", {
      method: "POST",
      json: { source, destination },
    });
    if (!reply.ok) {
      setErr(failureText(reply, "Failed to add forwarder."));
      return;
    }
    setSource("");
    setDestination("");
    await onChanged(`Added forwarder ${source} → ${destination}.`);
  }

  async function handleDelete(id: string) {
    const reply = await consoleRequest(`/api/mail/aliases/${id}`, { method: "DELETE" });
    if (reply.ok) await onChanged("Forwarder removed.");
    else setErr(failureText(reply, "Could not remove the forwarder."));
  }

  return (
    <div className="stack">
      <form
        className="panel stack"
        onSubmit={(e) => void handleAdd(e)}
        onInvalidCapture={() => setErr(null)}
      >
        <div className="panel-head">
          <h2>Add email forwarder / alias</h2>
        </div>
        {err ? <MailFeedback notice={{ tone: "err", text: err }} /> : null}
        <div className="form-grid">
          <div className="form-row">
            <label htmlFor="al-src">Source address</label>
            <input
              id="al-src"
              className="input mono"
              type="email"
              required
              placeholder="sales@example.com"
              value={source}
              onChange={(e) => setSource(e.target.value)}
            />
          </div>
          <div className="form-row">
            <label htmlFor="al-dst">Forward to</label>
            <input
              id="al-dst"
              className="input mono"
              type="email"
              required
              placeholder="admin@example.com"
              value={destination}
              onChange={(e) => setDestination(e.target.value)}
            />
          </div>
        </div>
        <div>
          <button type="submit" className="btn primary sm">
            <Glyph icon={Plus} />
            Add forwarder
          </button>
        </div>
      </form>

      {aliases.length === 0 ? (
        <EmptyState
          icon={Mail}
          title="No email aliases or forwarders yet"
          description="Create an alias above to forward incoming mail for one address to another mailbox."
        />
      ) : (
        <section className="panel flush" aria-label="Email aliases">
          <TableScroll label="Email aliases">
            <table className="data">
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Status</th>
                  <th>Remove</th>
                </tr>
              </thead>
              <tbody>
                {aliases.map((a) => (
                  <tr key={a.id}>
                    <td className="mono">{a.source}</td>
                    <td className="mono">{a.destination}</td>
                    <td>
                      <span className={a.enabled ? "pill ok" : "pill warn"}>
                        {a.enabled ? "Active" : "Paused"}
                      </span>
                    </td>
                    <td>
                      <ConfirmDeleteButton
                        label={`Delete alias ${a.source}`}
                        onConfirm={() => void handleDelete(a.id)}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableScroll>
        </section>
      )}
    </div>
  );
}

function MailDnsTab({ domains }: { domains: string[] }) {
  // W743 (QA-12): resolve against the current list; a first-render choice goes stale.
  const [chosen, setSelected] = useState("");
  const selected = domains.includes(chosen) ? chosen : (domains[0] ?? "example.com");
  const [copied, setCopied] = useState(false);
  const records = [
    { type: "MX", name: "@", value: `10 mail.${selected}.` },
    { type: "TXT", name: "@", value: '"v=spf1 mx a -all"' },
    {
      type: "TXT",
      name: "_dmarc",
      value: `"v=DMARC1; p=quarantine; rua=mailto:postmaster@${selected}"`,
    },
    { type: "TXT", name: "rustiron1._domainkey", value: '"v=DKIM1; k=rsa; p=<host-dkim-pubkey>"' },
  ];
  const snippet = records.map((r) => `${r.name} 3600 IN ${r.type} ${r.value}`).join("\n");

  return (
    <section className="panel stack">
      <div className="panel-head">
        <div>
          <h2>Mail authentication DNS (MX · SPF · DKIM · DMARC)</h2>
          <p className="cap">Required DNS records for reliable self-hosted inbox delivery.</p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <button
            type="button"
            className="btn quiet sm"
            onClick={async () => {
              if (await copyText(snippet, "DNS records copied")) setCopied(true);
            }}
          >
            <Glyph icon={copied ? Check : Copy} />
            {copied ? "Copied" : "Copy records"}
          </button>
          <Link
            className="btn primary sm"
            to="/domains/$hostname/dns"
            params={{ hostname: selected }}
          >
            Open DNS editor
          </Link>
        </div>
      </div>
      <div className="form-row" style={{ maxWidth: 320 }}>
        <label htmlFor="mdns-dom">Domain</label>
        <input
          id="mdns-dom"
          className="input mono"
          value={selected}
          onChange={(e) => setSelected(e.target.value)}
        />
      </div>
      <TableScroll label="Mail DNS records">
        <table className="data">
          <thead>
            <tr>
              <th>Type</th>
              <th>Name</th>
              <th>Recommended value</th>
            </tr>
          </thead>
          <tbody>
            {records.map((r) => (
              <tr key={`${r.type}-${r.name}`}>
                <td className="mono">{r.type}</td>
                <td className="mono">{r.name}</td>
                <td className="mono">{r.value}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableScroll>
    </section>
  );
}

function OutboundRelayTab() {
  const { sites } = useData();
  return (
    <section className="panel flush" aria-label="Per-site outbound mail relay sockets">
      <div className="panel-head" style={{ padding: "14px 16px 10px" }}>
        <div className="row" style={{ gap: 8 }}>
          <Glyph icon={Mail} />
          <h2>Website outbound relay sockets</h2>
        </div>
        <span className="meta">Confined per-site Postfix sockets with sender-spoof rejection</span>
      </div>
      <TableScroll label="Per-site outbound mail relay sockets">
        <table className="data">
          <thead>
            <tr>
              <th>Website</th>
              <th>Relay socket</th>
              <th>Isolation</th>
              <th>Mail DNS</th>
            </tr>
          </thead>
          <tbody>
            {sites.map((site) => (
              <tr key={site.id}>
                <td>
                  <Link className="mono" to="/sites/$siteId" params={{ siteId: site.id }}>
                    {site.domain}
                  </Link>
                </td>
                <td className="mono">/run/rustiron-mail/rs_{site.id}/smtp</td>
                <td>
                  <span className="pill">
                    <Glyph icon={Lock} />
                    Not observed in summary
                  </span>
                </td>
                <td>
                  <Link
                    className="btn quiet sm"
                    to="/domains/$hostname/dns"
                    params={{ hostname: site.domain }}
                  >
                    MX / SPF / DMARC
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableScroll>
    </section>
  );
}

function MailLoadWarning({ error }: { error: string | null }) {
  if (!error) return null;
  return (
    <div className="attention warn" role="status">
      <Glyph icon={AlertCircle} />
      <div className="att-body">
        <strong>Mail catalog unavailable:</strong> {error}
      </div>
    </div>
  );
}

function MailboxesTabContent({
  mailboxes,
  knownDomains,
  servedDomains,
  editing,
  confirmDeleteId,
  onEdit,
  onCloseEdit,
  onSaved,
  onDelete,
}: {
  mailboxes: MailboxRow[];
  knownDomains: string[];
  servedDomains: string[];
  editing: MailboxRow | null;
  confirmDeleteId: string | null;
  onEdit: (m: MailboxRow) => void;
  onCloseEdit: () => void;
  onSaved: (msg: string) => Promise<void>;
  onDelete: (m: MailboxRow) => Promise<void>;
}) {
  return (
    <div className="stack">
      {editing ? (
        <EditMailboxModal mailbox={editing} onClose={onCloseEdit} onSaved={onSaved} />
      ) : null}
      <CreateMailboxCard domains={knownDomains} servedDomains={servedDomains} onCreated={onSaved} />
      {mailboxes.length === 0 ? (
        <EmptyState
          icon={Mail}
          title="No mailboxes created yet"
          description="Use the form above to register a mailbox in the Console-local Postfix/Dovecot catalog."
        />
      ) : (
        <section className="panel flush" aria-label="Mailboxes list">
          <TableScroll label="Mailboxes list">
            <table className="data">
              <thead>
                <tr>
                  <th>Email address</th>
                  <th>Quota</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {mailboxes.map((m) => (
                  <tr key={m.id}>
                    <td className="mono">{m.email}</td>
                    <td className="tnum">{m.quotaMb} MiB</td>
                    <td>
                      <span className={m.enabled ? "pill ok" : "pill warn"}>
                        {m.enabled ? "Cataloged (pending sync)" : "Suspended"}
                      </span>
                    </td>
                    <td>
                      <div className="row" style={{ gap: 4 }}>
                        <button
                          type="button"
                          className="icon-btn"
                          aria-label={`Edit ${m.email}`}
                          onClick={() => onEdit(m)}
                        >
                          <Glyph icon={Pencil} />
                        </button>
                        <button
                          type="button"
                          className={confirmDeleteId === m.id ? "btn danger sm" : "icon-btn"}
                          aria-label={
                            confirmDeleteId === m.id
                              ? `Confirm delete ${m.email}`
                              : `Delete ${m.email}`
                          }
                          onClick={() => void onDelete(m)}
                        >
                          <Glyph icon={Trash2} />
                          {confirmDeleteId === m.id ? "Confirm" : null}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableScroll>
        </section>
      )}
    </div>
  );
}

export function EmailManagementPage({ initialTab = "mailboxes" }: { initialTab?: MailTab }) {
  const { sites } = useData();
  const [tab, setTab] = useState<MailTab>(initialTab);
  const [mailState, setMailState] = useState<MailStatePayload>({
    domains: [],
    mailboxes: [],
    aliases: [],
  });
  const [loadError, setLoadError] = useState<string | null>(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [editing, setEditing] = useState<MailboxRow | null>(null);
  const [notice, setNotice] = useState<{ tone: "err" | "ok"; text: string } | null>(null);

  const reload = useCallback(async () => {
    const res = await fetchMailState();
    if (res.ok) {
      setMailState(res.state);
      setLoadError(null);
    } else {
      setLoadError(res.error);
    }
  }, []);

  useEffect(() => {
    let active = true;
    void fetchMailState().then((res) => {
      if (!active) return;
      if (res.ok) {
        setMailState(res.state);
        setLoadError(null);
      } else {
        setLoadError(res.error);
      }
    });
    return () => {
      active = false;
    };
  }, []);

  const servedDomains = servedSiteDomains(sites);
  const knownDomains = Array.from(
    new Set([...servedDomains, ...mailState.domains.map((d) => d.domain)]),
  );
  const totalQuotaMb = mailState.mailboxes.reduce((sum, m) => sum + m.quotaMb, 0);

  async function handleExport() {
    const res = await consoleRequest("/api/mail/export");
    if (res.ok) {
      downloadJson("rustiron-postfix-dovecot-bundle.json", res.data);
      setNotice({
        tone: "ok",
        text: "Exported Console-local Postfix/Dovecot catalog (pending host sync).",
      });
    } else {
      setNotice({ tone: "err", text: failureText(res, `Export failed (HTTP ${res.status}).`) });
    }
  }

  async function handleDeleteMailbox(m: MailboxRow) {
    if (confirmDeleteId !== m.id) {
      setConfirmDeleteId(m.id);
      return;
    }
    setConfirmDeleteId(null);
    const res = await consoleRequest(`/api/mail/mailboxes/${m.id}`, { method: "DELETE" });
    if (res.ok) {
      setNotice({ tone: "ok", text: `Deleted mailbox ${m.email} from local catalog.` });
      await reload();
    } else {
      setNotice({
        tone: "err",
        text: failureText(res, `Could not delete mailbox (HTTP ${res.status}).`),
      });
    }
  }

  return (
    <Page live>
      {/* W747 (QA-16): any form action replaces the page notice. */}
      <div
        style={{ display: "contents" }}
        onSubmitCapture={() => setNotice(null)}
        onInvalidCapture={() => setNotice(null)}
      >
        <Crumbs items={[{ href: "/", label: "Overview" }, { label: "Email" }]} />
        <div className="page-head">
          <SimpleHeader
            title="Email"
            answer={
              <AnswerLine tone="unknown">
                {mailState.mailboxes.length}{" "}
                {mailState.mailboxes.length === 1 ? "mailbox" : "mailboxes"} in the Console's
                catalog. They reach the server only after a host sync.
              </AnswerLine>
            }
          />
          <button type="button" className="btn sm" onClick={() => void handleExport()}>
            <Glyph icon={Download} />
            Export Postfix / Dovecot maps
          </button>
        </div>

        <MailLoadWarning error={loadError} />

        <section className="grid g4" aria-label="Email summary">
          <article className="panel metric">
            <div className="m-head">Mailboxes</div>
            <div className="m-val">{mailState.mailboxes.length}</div>
            <div className="m-detail">Dovecot Maildir virtual accounts</div>
          </article>
          <article className="panel metric">
            <div className="m-head">Allocated quota</div>
            <div className="m-val">{(totalQuotaMb / 1024).toFixed(1)} GiB</div>
            <div className="m-detail">Combined mailbox storage limit</div>
          </article>
          <article className="panel metric">
            <div className="m-head">Aliases &amp; forwarders</div>
            <div className="m-val">{mailState.aliases.length}</div>
            <div className="m-detail">Postfix virtual alias mappings</div>
          </article>
          <article className="panel metric">
            <div className="m-head">Mail services</div>
            <div className="m-val" style={{ fontSize: 18 }}>
              Postfix · Dovecot
            </div>
            <div className="m-detail">IMAPS 993 · Submission 587 · rustiron_mail_relay</div>
          </article>
        </section>

        <div
          className="row"
          style={{ gap: 6, flexWrap: "wrap" }}
          role="tablist"
          aria-label="Email sections"
        >
          {(
            [
              ["mailboxes", `Mailboxes (${mailState.mailboxes.length})`],
              ["aliases", `Aliases & Forwarders (${mailState.aliases.length})`],
              ["relay", "Outbound Relay"],
              ["dns", "MX / SPF / DKIM / DMARC"],
            ] as const
          ).map(([id, label]) => (
            <button
              key={id}
              type="button"
              role="tab"
              aria-selected={tab === id}
              className={tab === id ? "btn primary sm" : "btn quiet sm"}
              onClick={() => setTab(id)}
            >
              {label}
            </button>
          ))}
        </div>

        <MailFeedback notice={notice} />

        {tab === "mailboxes" ? (
          <MailboxesTabContent
            mailboxes={mailState.mailboxes}
            knownDomains={knownDomains}
            servedDomains={servedDomains}
            editing={editing}
            confirmDeleteId={confirmDeleteId}
            onEdit={setEditing}
            onCloseEdit={() => setEditing(null)}
            onSaved={async (msg) => {
              setNotice({ tone: "ok", text: msg });
              await reload();
            }}
            onDelete={handleDeleteMailbox}
          />
        ) : null}

        {tab === "aliases" ? (
          <AliasesTab
            aliases={mailState.aliases}
            onChanged={async (msg) => {
              setNotice({ tone: "ok", text: msg });
              await reload();
            }}
          />
        ) : null}

        {tab === "relay" ? <OutboundRelayTab /> : null}
        {tab === "dns" ? <MailDnsTab domains={knownDomains} /> : null}
      </div>
    </Page>
  );
}
