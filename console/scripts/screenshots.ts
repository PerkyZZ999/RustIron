// W799: Console screenshots for the public README (docs/assets/screenshots/) and
// rustiron.app (Rustiron_Web/site/public/), from fixture (*.lab.test) data only.
// Start `bun run dev` (fixture mode), then: bun run screenshots [console-url] [out-dir]
import { chromium, type Page } from "playwright";

const [base = "http://localhost:4319/", out = "../docs/assets/screenshots"] = process.argv.slice(2);

type Shot = {
  name: string;
  path: string;
  theme: "dark" | "light";
  prepare?: (page: Page) => Promise<void>;
};

const shots: Shot[] = [
  { name: "overview-dark", path: "", theme: "dark" },
  { name: "overview-light", path: "", theme: "light" },
  {
    name: "apps-drawer-dark",
    path: "apps",
    theme: "dark",
    prepare: async (page) => {
      await page.getByRole("button", { name: "Inspect emdash.lab.test" }).click();
      await page.getByRole("complementary").first().waitFor();
    },
  },
  {
    name: "websites-bulk-dark",
    path: "sites",
    theme: "dark",
    prepare: async (page) => {
      for (const host of ["status.lab.test", "blog.lab.test", "docs.lab.test"])
        await page.getByRole("checkbox", { name: `Choose ${host}` }).click();
      await page.getByRole("region", { name: /Actions for the chosen/ }).waitFor();
    },
  },
  { name: "kb-dark", path: "help", theme: "dark" },
];

const browser = await chromium.launch({
  executablePath: process.env.RUSTIRON_CHROMIUM ?? "/usr/bin/chromium",
});
try {
  for (const shot of shots) {
    const context = await browser.newContext({
      viewport: { width: 1440, height: 900 },
      deviceScaleFactor: 2,
      colorScheme: shot.theme,
      reducedMotion: "reduce",
    });
    const page = await context.newPage();
    await page.goto(new URL(shot.path, base).href);
    await page.locator("h1").first().waitFor();
    await page.waitForLoadState("networkidle");
    await shot.prepare?.(page);
    await page.mouse.move(0, 899);
    await page.waitForTimeout(800);
    const text = (await page.locator("body").textContent()) ?? "";
    // Fixture mode only: no real host names, addresses, or e-mail.
    if (!text.includes("lab-01") || /@(?!lab\.test)[a-z0-9-]+\.[a-z]/i.test(text))
      throw new Error(
        `${shot.name}: not on fixture data (${text.match(/[^ ]*@(?!lab\.test)[a-z0-9-]+\.[a-z][^ ]*/i)?.[0] ?? "no lab-01"})`,
      );
    await page.screenshot({ path: `${out}/console-${shot.name}.png` });
    console.log(`console-${shot.name}.png`);
    await context.close();
  }
} finally {
  await browser.close();
}
