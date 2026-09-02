# Third-party components

Symvolon itself is proprietary (see `LICENSE`). Everything it depends on is not, and those
licences continue to apply. This file exists so that the obligations are written down
before they are breached rather than after.

## Production dependencies (ship with the running service)

| Component | Licence | What it obliges us to do |
| --- | --- | --- |
| `fastify` | MIT | Keep the copyright notice with any copy of the library |
| `libsodium-wrappers-sumo` | ISC | Same |
| `pg` | MIT | Same |
| `openpgp` | **LGPL-3.0+** | Use it *unmodified* and keep it replaceable — see below |

## The one that has teeth: `openpgp`

LGPL-3.0 allows proprietary software to use the library, on two conditions that matter
here:

1. **We do not modify it.** It stays an ordinary dependency installed from the registry.
   If we ever patch it, the patched library itself becomes LGPL source we must publish.
2. **A user of a distributed copy must be able to replace it.** We satisfy this the easy
   way: the server is *operated*, not distributed — nobody receives a binary — and the
   library is loaded from `node_modules` at runtime, so relinking is `npm install`. It
   never reaches the browser bundle (ADR-0015, enforced by `npm run audit:bundle`).

If Symvolon is ever shipped as a self-contained artefact (a bundled binary, a desktop app,
a container image handed to a customer as a product rather than run as a service), that
artefact must either keep `openpgp` as a separate replaceable module or drop it.

## Development-only dependencies

`esbuild`, `typescript`, `vitest` (MIT/Apache-2.0), `@scure/bip39` (MIT) and `jsqr`
(Apache-2.0) are used to build and test, and are not part of what is served. The two
reference implementations — `@scure/bip39` and `jsqr` — exist to check our own code in
tests and must stay development dependencies.

Apache-2.0 components (`typescript`, `jsqr`) also carry a patent grant and a requirement to
preserve their NOTICE files; both are satisfied by leaving them untouched in `node_modules`.
