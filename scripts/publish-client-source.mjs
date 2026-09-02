/**
 * NOT ACTIVE YET. The owner's decision (ADR-0023) is that the whole project stays in one
 * private-when-ready repository for now, and the open/closed split happens at launch. This
 * script exists so that the split is a command rather than a project: it is verified on
 * every CI run, so the day it is switched on, the published half is already known to be
 * complete and to build exactly what the service serves.
 *
 * Assemble the publishable half of this repository — the client, the shared protocol code,
 * and everything needed to build them — into `dist-oss/`, then prove the assembly is
 * complete by building it and comparing the result with the real build, byte for byte.
 *
 * The proof is the point. An open client that cannot be shown to produce the bundle the
 * service actually serves is a press release: it invites the reader to compare something
 * they were given with something they cannot reproduce. So this script fails if the
 * published subset builds anything other than the bytes in `public/BUILD.txt`, and it runs
 * as part of `npm run audit`, which means the two halves cannot quietly drift apart.
 *
 *   node scripts/publish-client-source.mjs            assemble + verify
 *   node scripts/publish-client-source.mjs --check     verify only, leave no output behind
 *
 * What is published is decided here and nowhere else. Adding a directory to PUBLISH is a
 * deliberate act; adding a file the client needs and forgetting this list makes the build
 * comparison fail, which is the intended failure mode.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cpSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const outDir = join(root, "dist-oss");

/** Whole directories that go out, copied verbatim. */
const PUBLISH_DIRS = ["src/client", "src/shared"];

/**
 * Individual files that go out. The build inputs are here because the client cannot be
 * rebuilt without them; the tests are here because test vectors are the only part of a
 * cryptographic claim a reader can check in a minute; the docs are here because a threat
 * model nobody can read is not a threat model.
 */
const PUBLISH_FILES = [
  "scripts/build-client.mjs",
  "tsconfig.json",
  "package.json",
  "package-lock.json",
  "test/hkdf.test.ts",
  "test/padding.test.ts",
  "test/protocol.test.ts",
  "test/verification.test.ts",
  "docs/CRYPTO.md",
  "docs/THREAT_MODEL.md",
  "docs/PRIVACY.md",
  "docs/AUDIT.md",
  "SECURITY.md",
  "THIRD_PARTY.md",
];

/** Renamed on the way out: the mirror's LICENSE is the AGPL, not the proprietary one. */
const PUBLISH_RENAMED = [["deploy/client-mirror/LICENSE-AGPL.txt", "LICENSE"]];

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(join(root, dir)).sort()) {
    const rel = `${dir}/${entry}`;
    if (statSync(join(root, rel)).isDirectory()) out.push(...walk(rel));
    else out.push(rel);
  }
  return out;
}

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function buildIn(dir) {
  execFileSync(process.execPath, [join(dir, "scripts/build-client.mjs")], {
    cwd: dir,
    env: { ...process.env, NODE_ENV: "production" },
    stdio: "pipe",
  });
  return readFileSync(join(dir, "public/BUILD.txt"), "utf8");
}

function assemble(files) {
  rmSync(outDir, { recursive: true, force: true });
  for (const file of files) {
    mkdirSync(join(outDir, dirname(file.as)), { recursive: true });
    cpSync(join(root, file.from), join(outDir, file.as));
  }
  // The published tree builds with the same locked dependencies as the real one; borrowing
  // the installed copy keeps this check offline. A reader runs `npm ci` instead.
  if (!existsSync(join(outDir, "node_modules"))) {
    symlinkSync(join(root, "node_modules"), join(outDir, "node_modules"), "dir");
  }
}

function readme(bundleDigests) {
  const script = bundleDigests.match(/^(\S+)\s+app\.js$/m)?.[1] ?? "(see BUILD.txt)";
  return `# Symvolon — client source

This is the published half of Symvolon: the code that runs in your browser, the protocol
code it shares with the server, and enough of the build to reproduce it. The server is not
here and is not open (see \`../LICENSE\` in the private repository, and the note below).

## Why the client and not the server

Everything that decides whether your messages stay private happens here. Keys are generated
in the browser, the vault is sealed in the browser, messages are encrypted before they are
sent, and the safety numbers you compare with a contact are computed from this code. If
this code is honest, a dishonest server can still learn who talks to whom and when — that
is written down in \`docs/THREAT_MODEL.md\` — but it cannot read what you wrote. If this
code is dishonest, nothing else matters. So this is the code you are invited to check.

The server's job is accounts, delivery, the marketplace and moderation. It is closed for
commercial reasons, and no security claim in these documents rests on it being trustworthy.

## Verifying that the service runs this code

The build is reproducible: the same source and the same locked dependencies produce
byte-identical output.

\`\`\`bash
npm ci
NODE_ENV=production node scripts/build-client.mjs
cat public/BUILD.txt
curl -s https://<the-deployment>/build.txt
\`\`\`

The two files must match. As published, the script digest is:

    ${script}

\`MANIFEST.txt\` in this directory lists the SHA-256 of every published file, and
\`index.html\` pins the script and stylesheet with subresource integrity, so a browser
refuses a bundle that does not match the page it arrived with.

**What this proves, precisely:** that a given deployment served the client built from this
source *to whoever asked*. It does not prove what it serves to someone else — a server can
send one bundle to an auditor and another to one user. Comparing the digest at
\`/build.txt\` across people and networks is what narrows that gap. \`docs/AUDIT.md\` is
blunt about the rest.

## Running the tests

\`\`\`bash
npm test
\`\`\`

The published tests are the ones that need no server: HKDF against RFC 5869 vectors, the
padding buckets, the X3DH-like handshake and Double Ratchet properties (out-of-order
delivery, forward secrecy, tampered ciphertext), and the safety-number/QR encoding.

## License

The client and shared protocol code are licensed under the GNU Affero General Public
License v3 — see \`LICENSE\`. The copyright holder also uses this code under separate
proprietary terms in the closed server; contributions therefore require a licensing
agreement. Third-party dependencies keep their own licences (\`THIRD_PARTY.md\`).
`;
}

function main() {
  const checkOnly = process.argv.includes("--check");

  const files = [
    ...PUBLISH_DIRS.flatMap(walk).map((f) => ({ from: f, as: f })),
    ...PUBLISH_FILES.map((f) => ({ from: f, as: f })),
    ...PUBLISH_RENAMED.map(([from, as]) => ({ from, as })),
  ];

  const missing = files.filter((f) => !existsSync(join(root, f.from)));
  if (missing.length) {
    console.error(`publish: missing ${missing.map((f) => f.from).join(", ")}`);
    process.exit(1);
  }

  assemble(files);

  const expected = buildIn(root);
  let actual;
  try {
    actual = buildIn(outDir);
  } catch (error) {
    // The usual cause: an import that reaches a file nobody remembered to publish.
    console.error(
      "publish: the published subset does not build at all.\n" +
        `${error.stderr?.toString() ?? error.message}` +
        "\nAdd the missing file to PUBLISH_DIRS/PUBLISH_FILES, or keep it out of the " +
        "client's import graph if it is meant to stay closed.",
    );
    process.exit(1);
  }
  if (actual !== expected) {
    console.error(
      "publish: the published subset does not build the same client.\n" +
        `--- repository ---\n${expected}--- dist-oss ---\n${actual}` +
        "\nA file the client needs is missing from PUBLISH_DIRS/PUBLISH_FILES, " +
        "or the build depends on something outside them.",
    );
    process.exit(1);
  }

  if (checkOnly) {
    rmSync(outDir, { recursive: true, force: true });
    console.log(`open-source subset: ${files.length} files, builds the served client exactly`);
    return;
  }

  writeFileSync(join(outDir, "README.md"), readme(actual));
  rmSync(join(outDir, "public"), { recursive: true, force: true });
  rmSync(join(outDir, "node_modules"), { force: true }); // a symlink, not the directory

  const published = [...walk(relative(root, outDir))].map((f) => relative("dist-oss", f));
  const manifest =
    published
      .sort()
      .filter((f) => f !== "MANIFEST.txt")
      .map((f) => `${sha256(readFileSync(join(outDir, f)))}  ${f}`)
      .join("\n") + `\n\n# built from the above, with \`npm ci\`:\n${actual}`;
  writeFileSync(join(outDir, "MANIFEST.txt"), manifest);

  console.log(
    `open-source subset written to dist-oss/ (${published.length} files); ` +
      "verified to build the served client byte for byte",
  );
}

main();
