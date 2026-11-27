import { cpSync, existsSync, rmSync, writeFileSync } from "node:fs";
import tailwind from "bun-plugin-tailwind";

if (existsSync("./dist")) {
  rmSync("./dist", { recursive: true, force: true });
}

const result = await Bun.build({
  entrypoints: ["./index.html"],
  outdir: "./dist",
  publicPath: "/",
  minify: true,
  // W707: route page modules load on demand (router.tsx).
  splitting: true,
  // W683: without this the bundle ships React's development build (jsxDEV, warnings).
  define: { "process.env.NODE_ENV": JSON.stringify("production") },
  plugins: [tailwind],
});

if (!result.success) {
  for (const log of result.logs) {
    console.error(log);
  }
  process.exit(1);
}

for (const output of result.outputs) {
  if (!/\.(js|css)$/.test(output.path)) continue;
  const text = await output.text();
  // W683: fail the build rather than ship React's development runtime.
  if (output.path.endsWith(".js") && text.includes("jsxDEV")) {
    console.error(`${output.path} contains the React development runtime`);
    process.exit(1);
  }
  // W683: the Console is reached over SSH tunnels without a compressing proxy.
  writeFileSync(`${output.path}.gz`, Bun.gzipSync(text, { level: 9 }));
}

if (existsSync("./public")) {
  cpSync("./public", "./dist", { recursive: true });
}
