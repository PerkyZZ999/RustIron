// W781: a row of tabs scrolls sideways only. A 1px vertical overflow (a link's
// negative bottom margin) showed a vertical scrollbar beside the tabs.
import { describe, expect, it } from "bun:test";

const css = await Bun.file(`${import.meta.dir}/console.css`).text();

function rule(selector: string): string {
  const match = new RegExp(`\\n\\s*${selector.replace(".", "\\.")}\\s*\\{([^}]*)\\}`).exec(css);
  if (!match) throw new Error(`no rule for ${selector}`);
  return match[1] ?? "";
}

describe("tab rows (W781)", () => {
  for (const row of [".tabs", ".host-tabs"]) {
    it(`${row} scrolls sideways only`, () => {
      expect(rule(row)).toContain("overflow-x: auto");
      expect(rule(row)).toContain("overflow-y: hidden");
      expect(rule(`${row} a`)).not.toMatch(/margin-bottom:\s*-/);
    });
  }
});
