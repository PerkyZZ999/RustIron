// W631 (P29 Slice 11): Self-hosted Postfix + Dovecot virtual mailbox, alias/forwarder,
// and mail-domain management backed by Bun's built-in SQLite (bun:sqlite).
// Passwords are stored hashed only (never plaintext, never returned in read APIs).
import { Database } from "bun:sqlite";
import { randomUUID } from "node:crypto";
import { chmodSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

import { checkD090Request, checkSameOriginMutation, jsonReply } from "./backend-server";

export type MailDomainRow = {
  domain: string;
  enabled: boolean;
  dkimSelector: string;
  createdAt: string;
};

export type MailboxRow = {
  id: string;
  email: string;
  domain: string;
  localPart: string;
  quotaMb: number;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
};

export type MailAliasRow = {
  id: string;
  source: string;
  domain: string;
  destination: string;
  enabled: boolean;
  createdAt: string;
};

export type MailStatePayload = {
  domains: MailDomainRow[];
  mailboxes: MailboxRow[];
  aliases: MailAliasRow[];
};

const LOCAL_PART_RE = /^[a-z0-9][a-z0-9._+-]{0,62}$/i;
const DOMAIN_RE =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i;
const EMAIL_RE = /^[a-z0-9][a-z0-9._+-]{0,62}@[a-z0-9.-]+\.[a-z]{2,}$/i;
const ID_RE = /^[a-z0-9_-]{4,64}$/i;

function defaultMailDbPath(): string {
  return join(homedir(), ".config", "rustiron-console", "mail.sqlite");
}

const MAIL_SCHEMA_VERSION = 1;

function openMailDb(dbPath: string): Database {
  if (dbPath !== ":memory:") {
    mkdirSync(dirname(dbPath), { recursive: true, mode: 0o700 });
  }
  const db = new Database(dbPath);
  if (dbPath !== ":memory:") {
    try {
      chmodSync(dbPath, 0o600);
    } catch {
      // Created lazily on first write.
    }
  }
  // W644 (M-04): enforce durable WAL + FULL sync and fail-closed schema version check.
  db.exec(
    "PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;",
  );
  const row = db.query("PRAGMA user_version").get() as { user_version?: number } | null;
  const currentVersion = row?.user_version ?? 0;
  if (currentVersion > MAIL_SCHEMA_VERSION) {
    db.close();
    throw new Error(
      `Unsupported mail database schema version ${currentVersion}; expected <= ${MAIL_SCHEMA_VERSION}.`,
    );
  }
  db.exec(`
    CREATE TABLE IF NOT EXISTS mail_domains (
      domain TEXT PRIMARY KEY,
      enabled INTEGER NOT NULL DEFAULT 1,
      dkim_selector TEXT NOT NULL DEFAULT 'rustiron1',
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS mailboxes (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      domain TEXT NOT NULL,
      local_part TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      quota_mb INTEGER NOT NULL DEFAULT 1024,
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS mail_aliases (
      id TEXT PRIMARY KEY,
      source TEXT NOT NULL UNIQUE,
      domain TEXT NOT NULL,
      destination TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL
    );
  `);
  if (currentVersion < MAIL_SCHEMA_VERSION) {
    db.exec(`PRAGMA user_version = ${MAIL_SCHEMA_VERSION};`);
  }
  return db;
}

const MAX_MAIL_BODY_BYTES = 32_768;
const MAX_MAIL_PASSWORD_LENGTH = 128;

function checkWriteOrigin(
  req: Request,
  allowedHosts: ReadonlySet<string>,
  writesEnabled: boolean,
): Response | null {
  if (!writesEnabled) {
    return jsonReply(
      405,
      {
        error: "MAIL_WRITES_DISABLED",
        message: "Mail catalog writes are disabled under D-090 default read-only mode.",
      },
      { allow: "GET, HEAD" },
    );
  }
  return checkSameOriginMutation(req, allowedHosts);
}

async function readMailJson(req: Request): Promise<Record<string, unknown> | Response> {
  const ct = req.headers.get("content-type")?.toLowerCase() ?? "";
  if (!ct.includes("application/json")) {
    return jsonReply(415, { error: "UNSUPPORTED_MEDIA_TYPE" });
  }
  const raw = typeof req.text === "function" ? await req.text() : JSON.stringify(await req.json());
  if (Buffer.byteLength(raw, "utf8") > MAX_MAIL_BODY_BYTES) {
    return jsonReply(413, { error: "PAYLOAD_TOO_LARGE" });
  }
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return jsonReply(400, { error: "INVALID_JSON" });
    }
    return parsed as Record<string, unknown>;
  } catch {
    return jsonReply(400, { error: "INVALID_JSON" });
  }
}

function strVal(obj: Record<string, unknown> | null, key: string): string {
  const v = obj?.[key];
  return typeof v === "string" ? v : "";
}

function extractTailId(url: string, prefix: string): string | null {
  const path = new URL(url).pathname;
  if (!path.startsWith(prefix)) return null;
  const id = path.slice(prefix.length);
  return ID_RE.test(id) ? id : null;
}

function readStateFromDb(db: Database): MailStatePayload {
  const domains = (
    db
      .query("SELECT domain, enabled, dkim_selector, created_at FROM mail_domains ORDER BY domain")
      .all() as {
      domain: string;
      enabled: number;
      dkim_selector: string;
      created_at: string;
    }[]
  ).map((d) => ({
    domain: d.domain,
    enabled: d.enabled === 1,
    dkimSelector: d.dkim_selector,
    createdAt: d.created_at,
  }));

  const mailboxes = (
    db
      .query(
        "SELECT id, email, domain, local_part, quota_mb, enabled, created_at, updated_at FROM mailboxes ORDER BY domain, local_part",
      )
      .all() as {
      id: string;
      email: string;
      domain: string;
      local_part: string;
      quota_mb: number;
      enabled: number;
      created_at: string;
      updated_at: string;
    }[]
  ).map((m) => ({
    id: m.id,
    email: m.email,
    domain: m.domain,
    localPart: m.local_part,
    quotaMb: m.quota_mb,
    enabled: m.enabled === 1,
    createdAt: m.created_at,
    updatedAt: m.updated_at,
  }));

  const aliases = (
    db
      .query(
        "SELECT id, source, domain, destination, enabled, created_at FROM mail_aliases ORDER BY domain, source",
      )
      .all() as {
      id: string;
      source: string;
      domain: string;
      destination: string;
      enabled: number;
      created_at: string;
    }[]
  ).map((a) => ({
    id: a.id,
    source: a.source,
    domain: a.domain,
    destination: a.destination,
    enabled: a.enabled === 1,
    createdAt: a.created_at,
  }));

  return { domains, mailboxes, aliases };
}

function renderPostfixDovecotBundle(state: MailStatePayload) {
  const activeDomains = state.domains
    .filter((d) => d.enabled && DOMAIN_RE.test(d.domain))
    .map((d) => d.domain);
  const activeBoxes = state.mailboxes.filter(
    (m) =>
      m.enabled &&
      DOMAIN_RE.test(m.domain) &&
      LOCAL_PART_RE.test(m.localPart) &&
      EMAIL_RE.test(m.email),
  );
  const activeAliases = state.aliases.filter(
    (a) => a.enabled && EMAIL_RE.test(a.source) && EMAIL_RE.test(a.destination),
  );

  const virtualDomains = activeDomains.map((d) => `${d} OK`).join("\n");
  const virtualMailboxes = activeBoxes
    .map((m) => `${m.email} ${m.domain}/${m.localPart}/`)
    .join("\n");
  const virtualAliases = activeAliases.map((a) => `${a.source} ${a.destination}`).join("\n");
  const dovecotUsers = activeBoxes
    .map(
      (m) =>
        `${m.email}:<hashed-on-host>:5000:5000::/var/vmail/${m.domain}/${m.localPart}::userdb_quota_rule=*:storage=${m.quotaMb}M`,
    )
    .join("\n");

  return {
    schema: "rustiron-mail-bundle/1",
    sync_state: "pending_host_sync",
    note: "Console-local mailbox catalog export. Passwords are stored Argon2id-hashed in console SQLite; transfer hashes through a reviewed host procedure before enabling Dovecot auth.",
    postfix_virtual_domains: virtualDomains,
    postfix_virtual_mailboxes: virtualMailboxes,
    postfix_virtual_aliases: virtualAliases,
    dovecot_users_preview: dovecotUsers,
  };
}

function parseQuotaMb(raw: unknown): number | null {
  const q = Number(raw);
  return Number.isInteger(q) && q >= 50 && q <= 102400 ? q : null;
}

type NewMailboxInput = {
  localPart: string;
  domain: string;
  password: string;
  quotaMb: number;
};

function validateNewMailbox(body: Record<string, unknown> | null): NewMailboxInput | Response {
  const localPart = strVal(body, "localPart").trim().toLowerCase();
  const domain = strVal(body, "domain").trim().toLowerCase();
  const password = strVal(body, "password");
  const quotaMb = parseQuotaMb(body?.quotaMb ?? 1024);
  if (!LOCAL_PART_RE.test(localPart) || !DOMAIN_RE.test(domain)) {
    return jsonReply(400, {
      error: "INVALID_MAILBOX_ADDRESS",
      message: "Provide a valid mailbox name and domain.",
    });
  }
  if (password.length < 8 || password.length > MAX_MAIL_PASSWORD_LENGTH) {
    return jsonReply(400, {
      error: "WEAK_PASSWORD",
      message: "Mailbox password must be between 8 and 128 characters.",
    });
  }
  if (quotaMb === null) {
    return jsonReply(400, {
      error: "INVALID_QUOTA",
      message: "Quota must be between 50 and 102400 MiB.",
    });
  }
  return { localPart, domain, password, quotaMb };
}

export function createMailBackend(options: {
  dbPath?: string;
  writesEnabled?: boolean;
  getAllowedHosts: () => ReadonlySet<string>;
}) {
  const db = openMailDb(options.dbPath ?? defaultMailDbPath());
  const writesEnabled = options.writesEnabled ?? false;

  function ensureDomain(domain: string, now: string) {
    db.query(
      "INSERT OR IGNORE INTO mail_domains (domain, enabled, dkim_selector, created_at) VALUES (?, 1, 'rustiron1', ?)",
    ).run(domain, now);
  }

  async function getState(req: Request): Promise<Response> {
    const guard = checkD090Request(req, options.getAllowedHosts());
    if (guard) return guard;
    return jsonReply(200, { ...readStateFromDb(db), writesEnabled });
  }

  async function exportBundle(req: Request): Promise<Response> {
    const guard = checkD090Request(req, options.getAllowedHosts());
    if (guard) return guard;
    return jsonReply(200, renderPostfixDovecotBundle(readStateFromDb(db)));
  }

  async function createMailbox(req: Request): Promise<Response> {
    const guard = checkWriteOrigin(req, options.getAllowedHosts(), writesEnabled);
    if (guard) return guard;
    const body = await readMailJson(req);
    if (body instanceof Response) return body;
    const parsed = validateNewMailbox(body);
    if (parsed instanceof Response) return parsed;
    const { localPart, domain, password, quotaMb } = parsed;

    const email = `${localPart}@${domain}`;
    if (db.query("SELECT id FROM mailboxes WHERE email = ?").get(email)) {
      return jsonReply(409, {
        error: "MAILBOX_EXISTS",
        message: `Mailbox ${email} already exists.`,
      });
    }

    const now = new Date().toISOString();
    const id = `mb_${randomUUID().replace(/-/g, "").slice(0, 12)}`;
    const hash = await Bun.password.hash(password, { algorithm: "argon2id" });
    db.transaction(() => {
      ensureDomain(domain, now);
      db.query(
        "INSERT INTO mailboxes (id, email, domain, local_part, password_hash, quota_mb, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)",
      ).run(id, email, domain, localPart, hash, quotaMb, now, now);
    })();

    return jsonReply(201, {
      ok: true,
      mailbox: {
        id,
        email,
        domain,
        localPart,
        quotaMb,
        enabled: true,
        createdAt: now,
        updatedAt: now,
      } satisfies MailboxRow,
    });
  }

  // W635 (M-03): validate every patch field and hash password BEFORE committing in one transaction.
  async function patchMailbox(req: Request, id: string): Promise<Response> {
    const body = await readMailJson(req);
    if (body instanceof Response) return body;
    let nextQuota: number | null = null;
    if (body.quotaMb !== undefined) {
      nextQuota = parseQuotaMb(body.quotaMb);
      if (nextQuota === null) {
        return jsonReply(400, { error: "INVALID_QUOTA", message: "Quota must be 50–102400 MiB." });
      }
    }
    const nextEnabled = typeof body.enabled === "boolean" ? body.enabled : null;
    const nextPassword = strVal(body, "password");
    if (
      nextPassword &&
      (nextPassword.length < 8 || nextPassword.length > MAX_MAIL_PASSWORD_LENGTH)
    ) {
      return jsonReply(400, {
        error: "WEAK_PASSWORD",
        message: "Password must be between 8 and 128 characters.",
      });
    }
    const nextHash = nextPassword
      ? await Bun.password.hash(nextPassword, { algorithm: "argon2id" })
      : null;
    const now = new Date().toISOString();
    const applyPatch = db.transaction(() => {
      if (nextQuota !== null) {
        db.query("UPDATE mailboxes SET quota_mb = ?, updated_at = ? WHERE id = ?").run(
          nextQuota,
          now,
          id,
        );
      }
      if (nextEnabled !== null) {
        db.query("UPDATE mailboxes SET enabled = ?, updated_at = ? WHERE id = ?").run(
          nextEnabled ? 1 : 0,
          now,
          id,
        );
      }
      if (nextHash !== null) {
        db.query("UPDATE mailboxes SET password_hash = ?, updated_at = ? WHERE id = ?").run(
          nextHash,
          now,
          id,
        );
      }
    });
    applyPatch();
    return jsonReply(200, { ok: true, id });
  }

  async function mutateMailbox(req: Request): Promise<Response> {
    const guard = checkWriteOrigin(req, options.getAllowedHosts(), writesEnabled);
    if (guard) return guard;
    const id = extractTailId(req.url, "/api/mail/mailboxes/");
    if (!id) return jsonReply(400, { error: "INVALID_ID" });
    if (!db.query("SELECT id FROM mailboxes WHERE id = ?").get(id)) {
      return jsonReply(404, { error: "NOT_FOUND" });
    }
    if (req.method === "PATCH") return patchMailbox(req, id);
    if (req.method === "DELETE") {
      db.query("DELETE FROM mailboxes WHERE id = ?").run(id);
      return jsonReply(200, { ok: true, deleted: id });
    }
    return jsonReply(405, { error: "METHOD_NOT_ALLOWED" });
  }

  async function createAlias(req: Request): Promise<Response> {
    const guard = checkWriteOrigin(req, options.getAllowedHosts(), writesEnabled);
    if (guard) return guard;
    const body = await readMailJson(req);
    if (body instanceof Response) return body;
    const source = strVal(body, "source").trim().toLowerCase();
    const destination = strVal(body, "destination").trim().toLowerCase();
    if (!EMAIL_RE.test(source) || !EMAIL_RE.test(destination)) {
      return jsonReply(400, {
        error: "INVALID_ALIAS",
        message: "Provide valid source and destination email addresses.",
      });
    }
    if (db.query("SELECT id FROM mail_aliases WHERE source = ?").get(source)) {
      return jsonReply(409, {
        error: "ALIAS_EXISTS",
        message: `Forwarder for ${source} already exists.`,
      });
    }
    const domain = source.split("@")[1] ?? "";
    const now = new Date().toISOString();
    const id = `al_${randomUUID().replace(/-/g, "").slice(0, 12)}`;
    db.transaction(() => {
      ensureDomain(domain, now);
      db.query(
        "INSERT INTO mail_aliases (id, source, domain, destination, enabled, created_at) VALUES (?, ?, ?, ?, 1, ?)",
      ).run(id, source, domain, destination, now);
    })();
    return jsonReply(201, {
      ok: true,
      alias: {
        id,
        source,
        domain,
        destination,
        enabled: true,
        createdAt: now,
      } satisfies MailAliasRow,
    });
  }

  async function deleteAlias(req: Request): Promise<Response> {
    if (req.method !== "DELETE") return jsonReply(405, { error: "METHOD_NOT_ALLOWED" });
    const guard = checkWriteOrigin(req, options.getAllowedHosts(), writesEnabled);
    if (guard) return guard;
    const id = extractTailId(req.url, "/api/mail/aliases/");
    if (!id) return jsonReply(400, { error: "INVALID_ID" });
    if (!db.query("SELECT id FROM mail_aliases WHERE id = ?").get(id)) {
      return jsonReply(404, { error: "NOT_FOUND" });
    }
    db.query("DELETE FROM mail_aliases WHERE id = ?").run(id);
    return jsonReply(200, { ok: true, deleted: id });
  }

  async function mailboxesCollection(req: Request): Promise<Response> {
    if (req.method === "GET" || req.method === "HEAD") return getState(req);
    if (req.method === "POST") return createMailbox(req);
    return jsonReply(405, { error: "METHOD_NOT_ALLOWED" });
  }

  async function aliasesCollection(req: Request): Promise<Response> {
    if (req.method === "GET" || req.method === "HEAD") return getState(req);
    if (req.method === "POST") return createAlias(req);
    return jsonReply(405, { error: "METHOD_NOT_ALLOWED" });
  }

  return {
    getState,
    exportBundle,
    mailboxesCollection,
    mutateMailbox,
    aliasesCollection,
    deleteAlias,
    close: () => db.close(),
  };
}
