# Performance

Speed is a privacy feature here, not only a comfort one: this client is meant to be usable
over Tor, where a megabyte costs seconds and a round trip costs hundreds of milliseconds.
The numbers below are enforced by `test/audit.test.ts`, so they cannot quietly regress.

## What a first visit costs

| | Before (2026-09) | Now |
| --- | --- | --- |
| JavaScript before first paint | 1 164 kB | **88 kB** (25 kB brotli) |
| Cryptography (libsodium WASM) | in that bundle | separate chunk, loaded when first needed |
| Stylesheet | 6 kB, uncompressed | 8 kB, **1.8 kB brotli** |
| Shell HTML | 1 kB | 1 kB |
| Requests to third parties | 0 | 0 |
| Repeat visit | full re-download | **304 / cache hit** — assets are content-addressed |

**Budgets** (`test/audit.test.ts`): entry under 150 kB, stylesheet under 48 kB, shell under
4 kB, and the crypto chunk must be at least five times the entry — that last one is how the
test notices if libsodium ever creeps back into the first load.

## The ten items from the brief

**Initial load.** The shell paints before the cryptography exists. `main()` starts
`sodiumReady()` and renders a skeleton immediately; every flow that touches a key awaits
that memoised promise first. A visitor reading the sign-in page never waits for a megabyte
of WebAssembly to be compiled before seeing anything.

**JavaScript.** No framework, no runtime dependency in the browser at all — the client is
`src/client/**` plus libsodium. Code splitting (`splitting: true`) separates the crypto
chunk. esbuild minifies; there is no polyfill bundle, because the target is ES2022 and the
browsers that lack it also lack the crypto this needs.

**CSS.** One stylesheet, one file, no framework, no build step beyond a copy. Everything is
custom properties and plain selectors: no preprocessor, no utility-class explosion, nothing
to purge.

**Images.** There are none. The brand mark and the theme icons are inline SVG built in
code, so they inherit `currentColor`, cost no request, and change with the theme. The QR
code for safety numbers is generated in the browser as an SVG data URL.

**Database queries.** Twenty indexes cover every column a hot query filters or sorts on, and
`test/migrations.test.ts` asserts the five that matter most still exist — a missing index is
a denial-of-service surface, not just a slow page. Every list query has a `LIMIT`. Listing
search used to be the one scan in the system (`LIKE '%term%'`, unindexable by construction);
since point 47 it reads the `listing_terms` inverted index, one range scan per word, and
pages by cursor — `test/search.test.ts` reads the query plan and fails if the listings table
is ever scanned again. The `search` bucket stays, because search is still the most expensive
read here.

**API latency.** The session is resolved once per request in a `preHandler` and reused by
`authenticate`, instead of a lookup per call site. Screens that need two independent reads
issue them with `Promise.all` — the moderation queue used to wait twice for one page.

**Rendering.** Direct DOM construction through one helper (`el()`); no virtual DOM, no
diffing, no hydration. Lists render into a fragment and are appended once. Skeletons keep
layout stable, so nothing jumps when data lands.

**Bundle size.** Above, and budgeted. `npm run audit:bundle` also proves the build is
reproducible, so a size change is always traceable to a source change.

**Caching.** Assets are content-addressed (`app-<hash>.js`) and served
`Cache-Control: public, max-age=31536000, immutable`; the shell is `no-store`, and so is
everything under `/api/`. A new deployment changes the names, so a stale mix is impossible
and a returning visitor downloads nothing but the shell.

**Server resources.** Assets are read into memory once at boot and served from there, with
brotli and gzip **pre-compressed at build time** — the server spends no CPU per request and
can afford the slowest, smallest brotli setting. Housekeeping (expiring envelopes,
deliveries, sessions, audit rows) runs on one unref'd interval, so an idle deployment is
genuinely idle.

## Where the remaining weight is

libsodium is 1.1 MB of WebAssembly (about 300 kB compressed) and it is not optional: it
provides Argon2id, XChaCha20-Poly1305, X25519 and Ed25519, and WebCrypto has neither of the
first two. Splitting it out means it is fetched once, in the background, and then cached for
a year. Replacing it with WebCrypto plus a smaller Argon2 build is the only remaining lever,
and it would be a cryptographic change, not a performance tweak — see `docs/ROADMAP.md`.

## What it costs to run (point 105)

A security architecture that needs a cluster is not a security architecture for this project,
so the cost of running it is a requirement like any other. Measured on 2026-09-03 from a clean
clone of `main` on an x86_64 development machine with a warm package cache — an ordinary VPS
will be slower on the install and the build, and roughly the same on the rest:

| | Measured |
| --- | --- |
| Clone → `npm ci` → `npm run check` → `npm test` → `npm run build` | about 30 s total (install 4 s, types + lint 3 s, 470 tests 8 s, build 13 s) |
| Production dependencies on disk (`npm ci --omit=dev`) | 28 MB, 177 locked packages, 4 direct |
| Repository without `node_modules` | 2.8 MB |
| Time from process start to `/healthz` answering | 0.4 s, migrations included |
| Resident memory after boot | ~185 MB (Node 22, Fastify, libsodium WASM) |
| Resident memory after serving pages | unchanged to within a megabyte |
| Empty database file | 348 kB |
| Page served locally | 2.6 ms |

That is the whole footprint: one Node process, one file, no queue, no cache server, no
sidecar, no external service that has to be reachable for a login to work. **1 GB of RAM is
enough** with room for the SQLite page cache and an upload or two; 2 GB is comfortable. Nothing
here needs a second machine until availability itself becomes the requirement, which is
`docs/ROADMAP.md`, not this page.

Two honest caveats. These numbers come from a development machine, not from production —
nobody has run this service on a real VPS yet (roadmap OPS-6), and the numbers under real
concurrency are unknown rather than estimated (`docs/SOURCES.md`). And the memory figure is
what Node reserves, not what the application needs; the useful comparison is between two runs
of the same build, which is what `GET /api/admin/health` is for.

## Measuring it yourself

```
npm run build:client        # prints entry size, brotli size and the lazy chunks
npm run audit:bundle        # rebuilds twice, compares digests, scans for external URLs
npm run audit:deployment https://host   # confirms a deployment serves exactly this build
```
