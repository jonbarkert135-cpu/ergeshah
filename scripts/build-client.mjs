/**
 * Client build: one esbuild pass, everything bundled locally. No CDN, no remote fonts,
 * no source maps in production (they leak paths), no analytics — there is nothing to
 * configure here because there is nothing external to configure.
 */
import { build } from "esbuild";
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(root, "public");
mkdirSync(out, { recursive: true });

const production = process.env.NODE_ENV === "production";

await build({
  entryPoints: [join(root, "src/client/main.ts")],
  bundle: true,
  format: "esm",
  target: ["es2022"],
  platform: "browser",
  outfile: join(out, "app.js"),
  minify: production,
  sourcemap: production ? false : "inline",
  legalComments: "none",
  define: { "process.env.NODE_ENV": JSON.stringify(production ? "production" : "development") },
});

copyFileSync(join(root, "src/client/styles/app.css"), join(out, "app.css"));
copyFileSync(join(root, "src/client/index.html"), join(out, "index.html"));
copyFileSync(join(root, "src/client/favicon.svg"), join(out, "favicon.svg"));

const size = readFileSync(join(out, "app.js")).length;
writeFileSync(join(out, ".build-info"), `${new Date().toISOString()} ${size} bytes\n`);
console.log(`client built: public/app.js (${(size / 1024).toFixed(0)} kB)`);
