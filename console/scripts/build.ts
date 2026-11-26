import { cpSync, existsSync, rmSync } from "node:fs";
import tailwind from "bun-plugin-tailwind";

if (existsSync("./dist")) {
  rmSync("./dist", { recursive: true, force: true });
}

const result = await Bun.build({
  entrypoints: ["./index.html"],
  outdir: "./dist",
  publicPath: "/",
  minify: true,
  plugins: [tailwind],
});

if (!result.success) {
  for (const log of result.logs) {
    console.error(log);
  }
  process.exit(1);
}

if (existsSync("./public")) {
  cpSync("./public", "./dist", { recursive: true });
}
