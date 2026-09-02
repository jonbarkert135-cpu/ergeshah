/**
 * Client build: one esbuild pass, everything bundled locally. No CDN, no remote fonts,
 * no source maps in production (they leak paths), no analytics — there is nothing to
 * configure here because there is nothing external to configure.
 *
 * Three properties this script is responsible for:
 *
 * 1. **Reproducibility.** Given the same source and the same locked dependency versions
 *    (`npm ci`), it writes byte-identical files, and `npm run audit:bundle` builds twice
 *    to prove it. Filenames carry a content hash, so they are part of that guarantee.
 * 2. **Verifiability.** `public/BUILD.txt` lists the SHA-256 of every file served, and
 *    `index.html` pins the entry script and the stylesheet with subresource integrity.
 *    See `docs/AUDIT.md` for what that does and does not prove.
 * 3. **Weight.** The cryptography is a megabyte of WebAssembly and most visitors need it
 *    a second or two after the first paint, not before it, so it is a separate chunk
 *    (`splitting: true`) that the shell imports when it is first needed. Everything is
 *    also pre-compressed here rather than per-request at runtime.
 */
import { build } from "esbuild";
import { brotliCompressSync, gzipSync, constants as zlib } from "node:zlib";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(root, "public");
const assets = join(out, "assets");
rmSync(assets, { recursive: true, force: true });
mkdirSync(assets, { recursive: true });

const production = process.env.NODE_ENV === "production";

const result = await build({
  entryPoints: [join(root, "src/client/main.ts")],
  bundle: true,
  splitting: true,
  format: "esm",
  target: ["es2022"],
  platform: "browser",
  outdir: assets,
  entryNames: "app-[hash]",
  chunkNames: "chunk-[hash]",
  minify: production,
  sourcemap: production ? false : "inline",
  legalComments: "none",
  metafile: true,
});

/** The entry file esbuild wrote, whatever hash it chose. */
const entry = Object.keys(result.metafile.outputs)
  .map((path) => path.replace(/^public\/assets\//, ""))
  .find((name) => /^app-[A-Z0-9]+\.js$/i.test(name));
if (!entry) throw new Error("build: esbuild did not produce an app-*.js entry");

/** `sha256-<base64>`: the subresource-integrity spelling, and what BUILD.txt lists. */
function sri(bytes) {
  return `sha256-${createHash("sha256").update(bytes).digest("base64")}`;
}

/** Content-addressed name: a changed file is a new URL, so it can be cached forever. */
function hashedName(name, bytes) {
  const hash = createHash("sha256").update(bytes).digest("hex").slice(0, 16).toUpperCase();
  return name.replace("[hash]", hash);
}

const cssSource = readFileSync(join(root, "src/client/styles/app.css"));
const cssName = hashedName("app-[hash].css", cssSource);
writeFileSync(join(assets, cssName), cssSource);

const iconSource = readFileSync(join(root, "src/client/favicon.svg"));
writeFileSync(join(out, "favicon.svg"), iconSource);

const entryBytes = readFileSync(join(assets, entry));
const scriptHash = sri(entryBytes);
const styleHash = sri(cssSource);

// index.html is written last, because its own hash has to cover the two it pins.
const shell = readFileSync(join(root, "src/client/index.html"), "utf8")
  .replace("__STYLE__", `/assets/${cssName}" integrity="${styleHash}`)
  .replace("__SCRIPT__", `/assets/${entry}" integrity="${scriptHash}`);
if (!shell.includes(scriptHash) || !shell.includes(styleHash) || shell.includes("__S")) {
  // A silent failure here would ship a page with no integrity attributes at all.
  throw new Error("build: could not inject subresource integrity into index.html");
}
writeFileSync(join(out, "index.html"), shell);

/**
 * Pre-compressed copies. Compressing at build time rather than per request costs the
 * server nothing at runtime, and lets us use the slowest, smallest brotli setting.
 */
function precompress(path) {
  const bytes = readFileSync(path);
  if (bytes.length < 1024) return;
  writeFileSync(
    `${path}.br`,
    brotliCompressSync(bytes, {
      params: {
        [zlib.BROTLI_PARAM_QUALITY]: 11,
        [zlib.BROTLI_PARAM_SIZE_HINT]: bytes.length,
      },
    }),
  );
  writeFileSync(`${path}.gz`, gzipSync(bytes, { level: 9 }));
}

for (const name of readdirSync(assets)) precompress(join(assets, name));
precompress(join(out, "index.html"));

const served = [
  ...readdirSync(assets)
    .filter((name) => !name.endsWith(".br") && !name.endsWith(".gz"))
    .sort()
    .map((name) => [`assets/${name}`, readFileSync(join(assets, name))]),
  ["favicon.svg", iconSource],
  ["index.html", readFileSync(join(out, "index.html"))],
];
writeFileSync(
  join(out, "BUILD.txt"),
  `${served.map(([name, bytes]) => `${sri(bytes)}  ${name}`).join("\n")}\n`,
);

const kb = (bytes) => `${(bytes.length / 1024).toFixed(0)} kB`;
const brotli = readFileSync(join(assets, `${entry}.br`));
console.log(`client built: ${entry} ${kb(entryBytes)} (${kb(brotli)} brotli) ${scriptHash}`);
for (const [name, bytes] of served) {
  if (name.startsWith("assets/chunk")) console.log(`              ${name} ${kb(bytes)} (lazy)`);
}
