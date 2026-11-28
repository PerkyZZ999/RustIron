// W769: the Docs & KB articles are Markdown files in `console/kb/`, shared with
// docs.rustiron.app (Astro Starlight). This parser reads only the fixed subset
// those files use (see `console/kb/README.md`) and throws on anything else, so a
// file the Console cannot show fails the tests and the build instead of the page.

export type ParsedCommand = { label: string; where: string; code: string };
export type ParsedCallout = { tone: "info" | "warn"; title: string; body: string };
export type ParsedSection = {
  id: string;
  heading: string;
  paragraphs: string[];
  bullets?: string[];
  callout?: ParsedCallout;
  commands?: ParsedCommand[];
};
export type ParsedArticle = { meta: Record<string, unknown>; sections: ParsedSection[] };

/** Undo the backslash escapes that keep plain text out of Markdown syntax. */
function unescapeText(text: string): string {
  return text.replace(/\\([\\`*_[\]<>#|!-])/g, "$1");
}

function parseFrontmatter(lines: string[], name: string): [Record<string, unknown>, number] {
  if (lines[0] !== "---") throw new Error(`${name}: no frontmatter`);
  const meta: Record<string, unknown> = {};
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i] ?? "";
    if (line === "---") return [meta, i + 1];
    // Each value is JSON, which is also valid YAML for Astro.
    const match = /^([A-Za-z]+): (.+)$/.exec(line);
    if (!match) throw new Error(`${name}: bad frontmatter line ${i + 1}`);
    meta[match[1] as string] = JSON.parse(match[2] as string);
  }
  throw new Error(`${name}: unclosed frontmatter`);
}

function attribute(meta: string, key: string, name: string): string {
  const match = new RegExp(`${key}=("(?:[^"\\\\]|\\\\.)*")`).exec(meta);
  if (!match) throw new Error(`${name}: code block without ${key}`);
  return JSON.parse(match[1] as string) as string;
}

/** A callout block from line `i`; returns it and the index of its closing `:::`. */
function readCallout(lines: string[], i: number, name: string): [ParsedCallout, number] {
  const open = /^:::(note|caution)\[(.*)\]$/.exec(lines[i] ?? "");
  const end = lines.indexOf(":::", i + 1);
  if (!open || end < 0) throw new Error(`${name}:${i + 1}: bad callout`);
  const tone = open[1] === "caution" ? "warn" : "info";
  const body = unescapeText(lines.slice(i + 1, end).join(" "));
  return [{ tone, title: unescapeText(open[2] as string), body }, end];
}

/** A labelled command block from line `i`; returns it and the index of its closing fence. */
function readCommand(lines: string[], i: number, name: string): [ParsedCommand, number] {
  const end = lines.indexOf("```", i + 1);
  if (end < 0) throw new Error(`${name}:${i + 1}: unclosed code block`);
  const info = (lines[i] ?? "").slice(3);
  const code = lines.slice(i + 1, end).join("\n");
  return [
    { label: attribute(info, "title", name), where: attribute(info, "where", name), code },
    end,
  ];
}

const HEADING = /^## (.+) \{#([a-z0-9-]+)\}$/;

export function parseKbMarkdown(text: string, name: string): ParsedArticle {
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  const [meta, start] = parseFrontmatter(lines, name);
  const sections: ParsedSection[] = [];
  let paragraph: string[] = [];
  // The Console shows a section's paragraphs, bullets, callout, and commands in that
  // order, so a file must use the same order for both sites to read alike.
  let rank = 0;
  const current = (i: number, blockRank = rank): ParsedSection => {
    const last = sections.at(-1);
    if (!last) throw new Error(`${name}:${i + 1}: content before the first section`);
    if (blockRank < rank)
      throw new Error(`${name}:${i + 1}: out of order (text, list, callout, commands)`);
    rank = blockRank;
    return last;
  };
  const flush = () => {
    if (paragraph.length) current(0, 0).paragraphs.push(unescapeText(paragraph.join(" ")));
    paragraph = [];
  };
  for (let i = start; i < lines.length; i++) {
    const line = lines[i] ?? "";
    const heading = HEADING.exec(line);
    if (heading || line.trim() === "" || /^(- |:::|```)/.test(line)) flush();
    if (heading) {
      rank = 0;
      sections.push({
        id: heading[2] as string,
        heading: unescapeText(heading[1] as string),
        paragraphs: [],
      });
    } else if (line.startsWith("- ")) {
      (current(i, 1).bullets ??= []).push(unescapeText(line.slice(2)));
    } else if (/^:::(note|caution)\[/.test(line)) {
      [current(i, 2).callout, i] = readCallout(lines, i, name);
    } else if (line.startsWith("```")) {
      const [command, end] = readCommand(lines, i, name);
      (current(i, 3).commands ??= []).push(command);
      i = end;
    } else if (/^[#>]|^:::|^\d+\. /.test(line)) {
      throw new Error(`${name}:${i + 1}: unsupported Markdown`);
    } else if (line.trim() !== "") {
      current(i, 0);
      paragraph.push(line);
    }
  }
  flush();
  if (!sections.length) throw new Error(`${name}: no sections`);
  return { meta, sections };
}

/** The glossary file: one `- **Term**: meaning` line per term. */
export function parseGlossary(text: string): [string, string][] {
  return text
    .split("\n")
    .filter((line) => line.startsWith("- **"))
    .map((line) => {
      const match = /^- \*\*(.+?)\*\*: (.+)$/.exec(line);
      if (!match) throw new Error(`glossary: bad line ${line}`);
      return [unescapeText(match[1] as string), unescapeText(match[2] as string)];
    });
}
