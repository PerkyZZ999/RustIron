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
import { servedSiteDomains } from "./mail-pages";
import { routeTree } from "./router";

afterEach(cleanup);

const hosts = allowedLoopbackHosts(4319);

function makeMailReq(path: string, method = "GET", body?: unknown): Request {
  const raw = body !== undefined ? JSON.stringify(body) : undefined;
  // A plain object: Bun's Request drops the host header these routes check.
  return {
    method,
    url: `http://127.0.0.1:4319${path}`,
    headers: new Headers({
      host: "127.0.0.1:4319",
      origin: "http://127.0.0.1:4319",
      "sec-fetch-site": "same-origin",
      ...(raw ? { "content-type": "application/json" } : {}),
    }),
    text: async () => raw ?? "",
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

      // W681: strict schemas keep each field's refusal code and refuse unknown or mistyped fields.
      const refusals: [unknown, string][] = [
        [
          { localPart: "x y", domain: "example.test", password: "MailboxPassword123!" },
          "INVALID_MAILBOX_ADDRESS",
        ],
        [{ localPart: "ops", domain: "example.test", password: "short" }, "WEAK_PASSWORD"],
        [
          {
            localPart: "ops",
            domain: "example.test",
            password: "MailboxPassword123!",
            quotaMb: "2048",
          },
          "INVALID_QUOTA",
        ],
        [
          {
            localPart: "ops",
            domain: "example.test",
            password: "MailboxPassword123!",
            admin: true,
          },
          "INVALID_REQUEST",
        ],
        [["ops"], "INVALID_REQUEST"],
      ];
      for (const [body, code] of refusals) {
        const res = await mail.mailboxesCollection(
          makeMailReq("/api/mail/mailboxes", "POST", body),
        );
        expect([res.status, ((await res.json()) as { error: string }).error]).toEqual([400, code]);
      }
      const mistyped = await mail.mutateMailbox(
        makeMailReq(`/api/mail/mailboxes/${createdBody.mailbox.id}`, "PATCH", { enabled: "no" }),
      );
      expect(mistyped.status).toBe(400);

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

      // W740 (QA-09): no self-loop, no forwarder over a mailbox, no mailbox over a forwarder.
      const refusal = async (res: Response) => [
        res.status,
        ((await res.json()) as { error: string }).error,
      ];
      expect(
        await refusal(
          await mail.aliasesCollection(
            makeMailReq("/api/mail/aliases", "POST", {
              source: "loop@example.test",
              destination: "LOOP@example.test",
            }),
          ),
        ),
      ).toEqual([400, "ALIAS_LOOP"]);
      expect(
        await refusal(
          await mail.aliasesCollection(
            makeMailReq("/api/mail/aliases", "POST", {
              source: "admin@example.test",
              destination: "elsewhere@example.org",
            }),
          ),
        ),
      ).toEqual([409, "ADDRESS_IS_MAILBOX"]);
      expect(
        await refusal(
          await mail.mailboxesCollection(
            makeMailReq("/api/mail/mailboxes", "POST", {
              localPart: "info",
              domain: "example.test",
              password: "MailboxPassword123!",
              quotaMb: 512,
            }),
          ),
        ),
      ).toEqual([409, "ADDRESS_IS_FORWARDER"]);

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

describe("W743 (QA-12): mailbox domains", () => {
  it("suggests only served sites and names a domain the host does not serve", async () => {
    expect(
      servedSiteDomains([
        { domain: "served.test", servingKind: "ok" },
        { domain: "unknown.test", servingKind: "unknown" },
        { domain: "quarantined.test", servingKind: "err" },
        { domain: "ejected.test", servingKind: "muted" },
      ]),
    ).toEqual(["served.test", "unknown.test"]);
  });

  it("starts with no domain and explains one the host does not serve", async () => {
    const original = globalThis.fetch;
    globalThis.fetch = (async (input: string | URL | Request) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url.includes("/api/mail/state")) {
        return Response.json({ domains: [], mailboxes: [], aliases: [], writesEnabled: true });
      }
      return Response.json({ error: "NOT_FOUND" }, { status: 404 });
    }) as unknown as typeof fetch;
    try {
      const router = createRouter({
        routeTree,
        history: createMemoryHistory({ initialEntries: ["/mail"] }),
      });
      render(<RouterProvider router={router} />);
      const domain = (await screen.findByLabelText("Domain")) as HTMLInputElement;
      expect(domain.value).toBe("");
      fireEvent.change(domain, { target: { value: "Foreign.Example" } });
      expect(await screen.findByText(/This host does not serve foreign.example/)).toBeTruthy();
    } finally {
      globalThis.fetch = original;
    }
  });
});

describe("W747 (QA-16): one current message on the Email page", () => {
  it("clears the created notice when the next create is refused", async () => {
    const original = globalThis.fetch;
    let posts = 0;
    globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url.includes("/api/mail/mailboxes") && init?.method === "POST") {
        posts += 1;
        return posts === 1
          ? Response.json(
              { ok: true, mailbox: { id: "mb_1", email: "info@site.test" } },
              { status: 201 },
            )
          : Response.json(
              { error: "MAILBOX_EXISTS", message: "Mailbox info@site.test already exists." },
              { status: 409 },
            );
      }
      if (url.includes("/api/mail/state")) {
        return Response.json({ domains: [], mailboxes: [], aliases: [], writesEnabled: true });
      }
      return Response.json({ error: "NOT_FOUND" }, { status: 404 });
    }) as unknown as typeof fetch;
    try {
      const router = createRouter({
        routeTree,
        history: createMemoryHistory({ initialEntries: ["/mail"] }),
      });
      render(<RouterProvider router={router} />);
      const create = async () => {
        fireEvent.change(await screen.findByLabelText("Mailbox name"), {
          target: { value: "info" },
        });
        fireEvent.change(screen.getByLabelText("Domain"), { target: { value: "site.test" } });
        fireEvent.change(screen.getByLabelText(/Password/), { target: { value: "MailboxPass1!" } });
        const form = screen.getByLabelText("Mailbox name").closest("form");
        if (!form) throw new Error("no mailbox form");
        fireEvent.submit(form);
      };
      await create();
      expect(await screen.findByText("Mailbox info@site.test created.")).toBeTruthy();
      await create();
      expect(await screen.findByText("Mailbox info@site.test already exists.")).toBeTruthy();
      expect(screen.queryByText("Mailbox info@site.test created.")).toBeNull();
    } finally {
      globalThis.fetch = original;
    }
  });
});
