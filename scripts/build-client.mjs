/**
 * Client build: one esbuild pass, everything bundled locally. No CDN, no remote fonts,
 * no source maps in production (they leak paths), no analytics — there is nothing to
 * configure here because there is nothing external to configure.
 *
 * The build is also reproducible: given the same source and the same locked dependency
 * versions (`npm ci`), it writes byte-identical files. It records their SHA-256 digests in
 * `public/BUILD.txt` and pins the script and stylesheet from `index.html` with subresource
 * integrity, so a browser refuses a bundle that does not match the page it came with, and
 * a reader can compare one hash instead of diffing a megabyte of JavaScript. See
 * `docs/AUDIT.md` for what that does and does not prove.
 */
import { build } from "esbuild";
import { createHash } from "node:crypto";
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
});

copyFileSync(join(root, "src/client/styles/app.css"), join(out, "app.css"));
copyFileSync(join(root, "src/client/favicon.svg"), join(out, "favicon.svg"));

/** `sha256-<base64>`: the subresource-integrity spelling, and what BUILD.txt lists. */
function digest(file) {
  return `sha256-${createHash("sha256").update(readFileSync(join(out, file))).digest("base64")}`;
}

const scriptHash = digest("app.js");
const styleHash = digest("app.css");

// index.html is written last, because its own hash has to cover the two it pins.
const shell = readFileSync(join(root, "src/client/index.html"), "utf8")
  .replace('<link rel="stylesheet" href="/assets/app.css" />', `<link rel="stylesheet" href="/assets/app.css" integrity="${styleHash}" />`)
  .replace('<script type="module" src="/assets/app.js"></script>', `<script type="module" src="/assets/app.js" integrity="${scriptHash}"></script>`);
if (!shell.includes(scriptHash) || !shell.includes(styleHash)) {
  // A silent failure here would ship a page with no integrity attributes at all.
  throw new Error("build: could not inject subresource integrity into index.html");
}
writeFileSync(join(out, "index.html"), shell);

const files = ["app.js", "app.css", "favicon.svg", "index.html"];
writeFileSync(
  join(out, "BUILD.txt"),
  `${files.map((file) => `${digest(file)}  ${file}`).join("\n")}\n`,
);

const size = readFileSync(join(out, "app.js")).length;
console.log(`client built: public/app.js (${(size / 1024).toFixed(0)} kB) ${scriptHash}`);
