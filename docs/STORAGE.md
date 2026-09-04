# Storage

Everything a user uploads to this service is a file the server cannot read. There are
exactly two kinds, they share one code path, and there is no third: an **attachment** (a
picture, a recording, a document, sent inside a conversation) and an **order delivery** (the
digital good a seller hands to a buyer). Both are encrypted in the browser before anything
leaves it, and the key travels to the other party inside the encrypted channel — never
beside the bytes, never to the server (`src/shared/crypto/file.ts`, ADR-0043).

This page is the answer to the storage half of the brief: where the bytes go, what is
checked on the way in, what is removed, what is left, and what an attacker gets who steals
the disk.

## The path an upload takes

```
browser                        server                        database
  │  choose a file
  │  strip image metadata      (src/shared/media.ts, ADR-0092)
  │  pad to a bucket           (64 / 256 / 1024 / 4096·n bytes)
  │  encrypt: XChaCha20-Poly1305, fresh key, id as associated data
  ▼
  POST  { id, ciphertext }  ──▶ authenticate
                                rate limit: attachment (calls)
                                rate limit: upload_bytes (bytes, ADR-0093)
                                size cap: MAX_DELIVERY_BYTES, in decoded bytes
                                reject any other field (unexpected_field)
                                free-space floor: 503 storage_full below it
                                                              ──▶ INSERT one row
                                                                  id · ciphertext · created · expires
```

There is no filesystem in that diagram, and that is the design: **a blob is a row**. No
upload is written to a path, so there is no webroot to escape, no directory traversal to
attempt, no execute bit to clear and no static handler that could ever serve a stored byte
as a document. `test/uploads.test.ts` asserts the upload route imports no file API at all.

## What the server may know about a file

| | Attachment | Delivery |
| --- | --- | --- |
| Identifier | 192 bits of the *client's* randomness — it is the associated data, so the browser must know it before it encrypts | the order id |
| Owner | **no column** | buyer and seller, because an order has parties |
| Filename | no column — the name is inside the encrypted message, and `safeFileName` sanitises it when a browser saves it | same |
| Media type | no column. The server never sniffs, never transcodes and never renders | same |
| Plaintext length | no column; the stored length is a padding bucket | same |
| Retention | `DELIVERY_TTL_MS` (30 days), or deleted by anyone holding the id | deleted on pickup, on a terminal status, or at the TTL |

Consequences, stated rather than implied: an attachment is not reached by account deletion
(there is no owner to cascade from — the absence of that column is the point), and the
expiry is what bounds it (`docs/DELETION.md`).

## Checks on the way in

The brief's upload pipeline — authorisation, size, extension, MIME, magic bytes, content
validation — is written for a server that receives *files*. This one receives ciphertext,
so half of those steps are not weakened here, they are impossible: there is no extension to
allow-list, no media type to trust and no magic bytes to read, because every byte is
indistinguishable from noise. What remains is what can be checked, and it is all enforced at
the trust boundary:

- **Authorisation.** Every upload needs a session; a delivery additionally needs to be the
  seller of an order in `accepted`.
- **Shape.** `base64url` only, and the body may carry no other field: a request with
  `filename`, `mimeType` or `path` is refused with `unexpected_field` rather than ignored.
- **Size**, in decoded bytes, not characters (`MAX_DELIVERY_BYTES`, 5 MB by default).
- **Volume.** Two ceilings, answering different questions: the `attachment` bucket bounds
  how often a blob may be posted, and `upload_bytes` (ADR-0093) bounds how much disk one
  account may turn into rows — 128 MiB at once, refilling at 2 MiB a minute. It is a
  rate-limit bucket keyed by an HMAC of the account under a pepper that rotates daily, so it
  charges an account without linking it to a blob.
- **The disk itself.** Below `STORAGE_FLOOR_BYTES` an upload is refused with
  `503 storage_full` and the rest of the service keeps working (ADR-0057).

Archives are not supported and are not extracted: nothing here opens a zip, so path
traversal, zip bombs and nested archives have no code to attack. An archive is bytes like
any other file, and it is the recipient's own machine that decides what to do with it.

## Image metadata (ADR-0092)

Encryption does not help against the person you are sending the picture to, and they are the
ones holding the key. A photograph from a phone carries GPS coordinates, the camera model
and serial, the capture time to the second, and often an embedded thumbnail of a frame that
was cropped out. So the bytes are cleaned in the browser, before they are encrypted:

- **JPEG** — APP1 (EXIF and XMP), APP3–APP13 (IPTC, Photoshop resources), APP15 and COM
  segments are dropped, as is an APP2 that is a multi-picture index rather than an ICC
  profile. JFIF density, ICC colour and the Adobe marker stay: they say how to display the
  image, not who took it.
- **PNG** — everything except the critical chunks, the chunks a decoder needs to draw
  correctly (`tRNS`, `gAMA`, `cHRM`, `sRGB`, `iCCP`, `bKGD`, `pHYs`, `sBIT`, `hIST`) and the
  three that make an animation animate. `eXIf`, `tEXt`, `zTXt`, `iTXt`, `tIME` and private
  chunks are gone.
- **WebP** — the `EXIF` and `XMP ` chunks are removed and the RIFF length is rewritten.

The image is **not** decoded and re-encoded. A re-encode would need a canvas, would lose a
generation of quality on every JPEG, and would still not touch anything hidden in the pixels
— so this removes containers, not content. Anything that is not one of those three formats,
and anything malformed, is passed through byte for byte: corrupting a file somebody is
trying to send is a worse failure than a metadata block in a format this code does not parse.

What this does not do, in the words a user deserves: it **reduces exposure**. It does not
make a photograph anonymous. Faces, screens, street signs, the room, the filename and the
compression history all survive it.

A format the stripper does not parse — HEIC and HEIF from an iPhone camera, AVIF, TIFF and
raw, GIF, PDF, SVG — is passed through byte for byte, because corrupting a file someone is
trying to send is the worse failure. Silence about that would be dishonest: a sender told
nothing reasonably assumes the file was cleaned like the others. So both upload paths say so,
from one sentence (`METADATA_KEPT_NOTE`) gated by one check (`metadataUnhandled`) in
`src/shared/media.ts`. The chat attachment path says it after the send; the marketplace
delivery path asks the seller to confirm before the bytes leave the browser, because a
delivery is a deliberate act that can still be cancelled (roadmap UI-4).

## Integrity, and why there is no content hash column

Every blob is sealed with XChaCha20-Poly1305, whose authentication tag *is* the integrity
check: a byte flipped in the database, in a backup or on a stolen disk fails to open rather
than decrypting into something plausible. The id is authenticated as associated data, so a
blob served under the wrong id fails too.

There is deliberately no stored hash of the plaintext. A content hash is a cross-account
join key — it says "these two people hold the same file", which is the deduplication feature
and the correlation attack at once — and the server has no plaintext to hash anyway.

## Encryption at rest, and the keys

| Layer | Key | Where the key is |
| --- | --- | --- |
| Attachment / delivery | one random 32-byte key per file | in the recipient's client, delivered inside the encrypted channel. Never on the server |
| Vault (private keys) | master key, wrapped by a key derived from the password with Argon2id | in the browser |
| Backup | AES-256-GCM data key from a key file | with the operator, on a path the service cannot read — a compromised running service cannot decrypt its own backups (`docs/BACKUPS.md`) |
| The disk under all of it | operator's full-disk encryption | with the operator (`docs/HARDENING.md`) |

The separation the brief asks for — a data key distinct from the key that encrypts it —
exists where a server-held key exists: the backup. For user files it goes further, because
the server holds no key at all for them.

## Private files are private by authorisation, not by obscurity

- A delivery is fetched through a controller that checks, on every single request, that the
  caller is the **buyer** of that order. A seller asking for it back gets 403; a stranger
  gets the same 404 as a wrong id, so order ids are not an oracle.
- An attachment is fetched by an id that is 192 bits of client randomness and is the
  capability. It is authenticated — the store is not open to the internet — but deliberately
  not scoped to a party, because scoping it means storing who may read it, and that column
  is the social graph.
- There is no `/uploads/…` URL, no signed CDN link, no public bucket and nothing served from
  a directory. A short-lived download token would be a way to *widen* access here, not to
  narrow it, so there is none.

## If the storage volume is stolen (point 90)

`test/compromise.test.ts` plays a full session — a message, an attachment, an order and its
delivery, a sealed vault — and then reads every column of every table looking for the
plaintext it planted, in four encodings. What a thief holding the volume gets:

| | |
| --- | --- |
| Private objects | ciphertext, with no key anywhere on the volume |
| Names | none — no filename, no media type, no owner column on attachments |
| Sizes | a padding bucket, not the artefact's length |
| Application secrets | none: the rate-limit pepper, the payout worker's token and the backup key are configuration, not rows |
| Sessions | SHA-256 of a cookie that only ever existed in a browser |
| Passwords | Argon2id on the client, hashed again on the server; the password itself never arrives |

What it *does* get, and what no design here hides: that a blob exists, how large its padded
form is, when it arrived, and — for a delivery — which order it belongs to and therefore
which two accounts. That is the residual risk, and it is in `docs/THREAT_MODEL.md` rather
than in a sentence that promises more than the code does.
