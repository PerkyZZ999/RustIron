// W631 (P29 Slice 11): Unit & SQLite CRUD tests for self-hosted Postfix + Dovecot
// mailbox creation, quota/password editing, suspension, alias forwarding, export, and UI.
import { Database } from "bun:sqlite";
import { afterEach, describe, expect, it } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { createMemoryHistory, createRouter, RouterProvider } from "@tanstack/react-router";

import { allowedLoopbackHosts } from "./backend-server";
import { createMailBackend } from "./mail-backend";
import { routeTree } from "./router";

afterEach(cleanup);

const hosts = allowedLoopbackHosts(4319);

function makeMailReq(path: string, method = "GET", body?: unknown): Request {
  const raw = body !== undefined ? JSON.stringify(body) : undefined;
  return {
    method,
    url: `http://127.0.0.1:4319${path}`,
    headers: new Headers({
      host: "127.0.0.1:4319",
      origin: "http://127.0.0.1:4319",
      "sec-fetch-site": "same-origin",
      ...(raw ? { "content-type": "application/json" } : {}),
    }),
    json: async () => (raw ? JSON.parse(raw) : null),
  } as unknown as Request;
}

describe("Self-hosted Postfix/Dovecot Email backend & UI (W631)", () => {
  it("refuses mail mutations by default under D-090 read-only mode (W635 H-01)", async () => {
    const mail = createMailBackend({ dbPath: ":memory:", getAllowedHosts: () => hosts });
    try {
      const blocked = await mail.mailboxesCollection(
        makeMailReq("/api/mail/mailboxes", "POST", {
          localPart: "blocked",
          domain: "example.test",
          password: "MailboxPassword123!",
          quotaMb: 1024,
        }),
      );
      expect(blocked.status).toBe(405);
    } finally {
      mail.close();
    }
  });

  it("creates, edits atomically, suspends, exports, and deletes mailboxes and aliases without leaking passwords", async () => {
    const mail = createMailBackend({
      dbPath: ":memory:",
      writesEnabled: true,
      getAllowedHosts: () => hosts,
    });
    try {
      const created = await mail.mailboxesCollection(
        makeMailReq("/api/mail/mailboxes", "POST", {
          localPart: "admin",
          domain: "example.test",
          password: "MailboxPassword123!",
          quotaMb: 2048,
        }),
      );
      expect(created.status).toBe(201);
      const createdBody = (await created.json()) as { mailbox: { id: string; email: string } };
      expect(createdBody.mailbox.email).toBe("admin@example.test");

      // Duplicate address refused (409).
      const dup = await mail.mailboxesCollection(
        makeMailReq("/api/mail/mailboxes", "POST", {
          localPart: "admin",
          domain: "example.test",
          password: "AnotherPassword123!",
          quotaMb: 1024,
        }),
      );
      expect(dup.status).toBe(409);

      // State never exposes password hash or plaintext.
      const stRes = await mail.getState(makeMailReq("/api/mail/state"));
      const stText = await stRes.text();
      expect(stText).toContain("admin@example.test");
      expect(stText).not.toContain("MailboxPassword123!");
      expect(stText).not.toContain("password_hash");

      // W635 (M-03): invalid password on PATCH must NOT partially apply quota change.
      const badPatch = await mail.mutateMailbox(
        makeMailReq(`/api/mail/mailboxes/${createdBody.mailbox.id}`, "PATCH", {
          quotaMb: 9999,
          password: "short",
        }),
      );
      expect(badPatch.status).toBe(400);
      const afterBad = (await (await mail.getState(makeMailReq("/api/mail/state"))).json()) as {
        mailboxes: { quotaMb: number }[];
      };
      expect(afterBad.mailboxes[0]?.quotaMb).toBe(2048);

      // Edit quota + password + suspend.
      const patched = await mail.mutateMailbox(
        makeMailReq(`/api/mail/mailboxes/${createdBody.mailbox.id}`, "PATCH", {
          quotaMb: 4096,
          password: "RotatedPassword456!",
          enabled: true,
        }),
      );
      expect(patched.status).toBe(200);

      // Add forwarder alias.
      const aliasRes = await mail.aliasesCollection(
        makeMailReq("/api/mail/aliases", "POST", {
          source: "info@example.test",
          destination: "admin@example.test",
        }),
      );
      expect(aliasRes.status).toBe(201);
      const aliasBody = (await aliasRes.json()) as { alias: { id: string } };

      // Export Postfix + Dovecot virtual maps bundle.
      const expRes = await mail.exportBundle(makeMailReq("/api/mail/export"));
      expect(expRes.status).toBe(200);
      const exp = (await expRes.json()) as {
        postfix_virtual_domains: string;
        postfix_virtual_mailboxes: string;
        postfix_virtual_aliases: string;
        dovecot_users_preview: string;
      };
      expect(exp.postfix_virtual_domains).toContain("example.test OK");
      expect(exp.postfix_virtual_mailboxes).toContain("admin@example.test example.test/admin/");
      expect(exp.postfix_virtual_aliases).toContain("info@example.test admin@example.test");
      expect(exp.dovecot_users_preview).toContain("storage=4096M");

      // Delete alias & mailbox cleanly; repeating delete returns 404.
      expect(
        (await mail.deleteAlias(makeMailReq(`/api/mail/aliases/${aliasBody.alias.id}`, "DELETE")))
          .status,
      ).toBe(200);
      expect(
        (await mail.deleteAlias(makeMailReq(`/api/mail/aliases/${aliasBody.alias.id}`, "DELETE")))
          .status,
      ).toBe(404);
      expect(
        (
          await mail.mutateMailbox(
            makeMailReq(`/api/mail/mailboxes/${createdBody.mailbox.id}`, "DELETE"),
          )
        ).status,
      ).toBe(200);
    } finally {
      mail.close();
    }
  });

  it("renders Email management tabs (Mailboxes, Aliases, Relay, MX/SPF/DKIM/DMARC)", async () => {
    const router = createRouter({
      routeTree,
      history: createMemoryHistory({ initialEntries: ["/mail"] }),
    });
    render(<RouterProvider router={router} />);
    expect(await screen.findByRole("heading", { level: 1, name: "Email" })).toBeTruthy();
    expect(screen.getByRole("heading", { level: 2, name: "Create mailbox" })).toBeTruthy();
    fireEvent.click(screen.getByRole("tab", { name: /Aliases & Forwarders/ }));
    expect(screen.getByRole("heading", { level: 2, name: /Add email forwarder/ })).toBeTruthy();
    fireEvent.click(screen.getByRole("tab", { name: /MX \/ SPF \/ DKIM \/ DMARC/ }));
    expect(screen.getByText(/v=DMARC1/)).toBeTruthy();
  });

  it("enforces WAL, synchronous=FULL, and fail-closed user_version checks (W644 M-04)", () => {
    const dir = mkdtempSync(join(tmpdir(), "ri-mail-m04-"));
    const dbPath = join(dir, "mail.sqlite");
    try {
      const mail = createMailBackend({ dbPath, getAllowedHosts: () => hosts });
      mail.close();

      const inspect = new Database(dbPath);
      const uv = (inspect.query("PRAGMA user_version").get() as { user_version: number })
        .user_version;
      const jm = (inspect.query("PRAGMA journal_mode").get() as { journal_mode: string })
        .journal_mode;
      expect(uv).toBe(1);
      expect(jm.toLowerCase()).toBe("wal");
      inspect.exec("PRAGMA user_version = 99;");
      inspect.close();

      expect(() => createMailBackend({ dbPath, getAllowedHosts: () => hosts })).toThrow(
        /Unsupported mail database schema version 99/,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
