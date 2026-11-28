// W649: Tests for the integrated RustIron Documentation & Knowledge Base.
import { kbArticleTitle, kbArticleTitles, kbSearchTargets } from "./kb-index";
import { afterEach, describe, expect, it } from "bun:test";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { createMemoryHistory, createRouter, RouterProvider } from "@tanstack/react-router";

import { glossaryTerms, kbArticles, kbCategories, operatorRunbooks } from "./kb-data";
import { parseKbMarkdown } from "./kb-markdown";
import { routeTree } from "./router";

afterEach(cleanup);

describe("Integrated Documentation & Knowledge Base (W649)", () => {
  it("contains unique slugs, valid categories, all 38 runbooks, and zero fixture leakage", () => {
    const slugs = new Set(kbArticles.map((a) => a.slug));
    expect(slugs.size).toBe(kbArticles.length);
    expect(kbArticles.length).toBeGreaterThanOrEqual(14);
    expect(operatorRunbooks.length).toBe(38);
    expect(glossaryTerms.length).toBeGreaterThanOrEqual(12);

    const catIds = new Set(kbCategories.map((c) => c.id));
    for (const article of kbArticles) {
      expect(catIds.has(article.category)).toBe(true);
      expect(article.sections.length).toBeGreaterThan(0);
      const serialized = JSON.stringify(article);
      expect(serialized).not.toContain("lab-01");
      expect(serialized).not.toContain("op_7Q2KX9");
      expect(serialized).not.toContain("portfolio.lab.test");
    }
    for (const rb of operatorRunbooks) {
      expect(kbArticleTitle(rb.guideSlug)).toBeDefined();
    }
    // W715: the title index and the articles name the same slugs, once each.
    expect([...slugs].sort() as string[]).toEqual(Object.keys(kbArticleTitles).sort());
    expect(kbSearchTargets().length).toBe(kbArticles.length);
  });

  it("renders /help with instant search, topic filters, runbook index, and glossary tabs", async () => {
    const router = createRouter({
      routeTree,
      history: createMemoryHistory({ initialEntries: ["/help"] }),
    });
    render(<RouterProvider router={router} />);
    expect(
      await screen.findByRole("heading", { level: 1, name: "Docs & Knowledge Base" }),
    ).toBeTruthy();
    expect(screen.getByRole("link", { name: /How RustIron works/ })).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Updates & troubleshooting" }));
    expect(screen.getByRole("link", { name: /Update RustIron/ })).toBeTruthy();
    expect(screen.queryByRole("link", { name: /How RustIron works/ })).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: /All guides/ }));
    fireEvent.change(screen.getByLabelText(/Search docs, commands, runbooks, and terms/), {
      target: { value: "rustiron-updater.py" },
    });
    expect(screen.getByRole("link", { name: /Update RustIron/ })).toBeTruthy();
    expect(screen.queryByRole("link", { name: /WordPress sites/ })).toBeNull();

    fireEvent.change(screen.getByLabelText(/Search docs, commands, runbooks, and terms/), {
      target: { value: "" },
    });
    fireEvent.click(screen.getByRole("tab", { name: /Glossary/ }));
    expect(screen.getByText("Blast-radius envelope")).toBeTruthy();
  });

  it("renders individual KB guides at /help/$slug and handles unknown slugs cleanly", async () => {
    const router = createRouter({
      routeTree,
      history: createMemoryHistory({ initialEntries: ["/help/updates-and-releases"] }),
    });
    render(<RouterProvider router={router} />);
    expect(
      await screen.findByRole("heading", {
        level: 1,
        name: "Update RustIron",
      }),
    ).toBeTruthy();
    expect(screen.getByText(/packaging\/rustiron-updater\.py status/)).toBeTruthy();
    expect(screen.getByText(/scripts\/release\/bundle_release\.py pack/)).toBeTruthy();
    expect(screen.getByRole("link", { name: "Host updates" })).toBeTruthy();

    await act(() => router.navigate({ to: "/help/$slug", params: { slug: "does-not-exist" } }));
    expect(await screen.findByRole("heading", { level: 1, name: "Guide not found" })).toBeTruthy();
  });
});

describe("Docs & KB Markdown source (W769)", () => {
  it("keeps each file's title and order equal to the Console's index", async () => {
    const slugs = Object.keys(kbArticleTitles);
    for (const [index, slug] of slugs.entries()) {
      const text = await Bun.file(`${import.meta.dir}/../kb/${slug}.md`).text();
      const { meta } = parseKbMarkdown(text, slug);
      expect(meta.title).toBe(kbArticleTitles[slug as keyof typeof kbArticleTitles]);
      expect(meta.order).toBe(index + 1);
    }
    expect(kbArticles.map((a) => a.slug)).toEqual(slugs as (typeof kbArticles)[number]["slug"][]);
  });

  it("reads sections, escapes, callouts, and labelled commands", () => {
    const text = [
      "---",
      'title: "T"',
      "---",
      "",
      "## One \\<a\\> {#one}",
      "",
      "Line \\*one\\*",
      "goes on.",
      "",
      "- a \\_b",
      "",
      ":::caution[Careful]",
      "Body.",
      ":::",
      "",
      '```sh title="Run \\"it\\"" where="Server (root)"',
      "echo 1",
      "```",
    ].join("\n");
    const [section] = parseKbMarkdown(text, "t").sections;
    expect(section).toEqual({
      id: "one",
      heading: "One <a>",
      paragraphs: ["Line *one* goes on."],
      bullets: ["a _b"],
      callout: { tone: "warn", title: "Careful", body: "Body." },
      commands: [{ label: 'Run "it"', where: "Server (root)", code: "echo 1" }],
    });
  });

  it("refuses Markdown the Console cannot show", () => {
    const head = '---\ntitle: "T"\n---\n\n## S {#s}\n\n';
    expect(() => parseKbMarkdown(`${head}### Sub`, "t")).toThrow("unsupported");
    expect(() => parseKbMarkdown(`${head}> quote`, "t")).toThrow("unsupported");
    expect(() => parseKbMarkdown(`${head}\`\`\`sh\nx\n\`\`\``, "t")).toThrow("without title");
    expect(() => parseKbMarkdown("no frontmatter", "t")).toThrow("no frontmatter");
    expect(() => parseKbMarkdown('---\ntitle: "T"\n---\ntext', "t")).toThrow(
      "before the first section",
    );
    expect(() => parseKbMarkdown(`${head}1. step`, "t")).toThrow("unsupported");
    expect(() => parseKbMarkdown(`${head}- item\n\nafter the list`, "t")).toThrow("out of order");
    expect(() =>
      parseKbMarkdown(`${head}\`\`\`sh title="a" where="b"\nx\n\`\`\`\n\n- item`, "t"),
    ).toThrow("out of order");
  });
});
