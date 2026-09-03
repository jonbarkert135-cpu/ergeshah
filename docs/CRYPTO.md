# Cryptographic design

Everything below is implemented in `src/shared/crypto` and exercised by
`test/hkdf.test.ts` and `test/protocol.test.ts`. No primitive is hand-rolled: all of them
come from libsodium. What *is* written here is the protocol composition, and it follows
published specifications rather than invention.

## Primitives

| Purpose | Primitive | Source |
| --- | --- | --- |
| Key agreement | X25519 (`crypto_scalarmult`) | libsodium |
| Signatures | Ed25519 (`crypto_sign_detached`) | libsodium |
| Ed25519 → X25519 | `crypto_sign_ed25519_{pk,sk}_to_curve25519` | libsodium |
| AEAD | XChaCha20-Poly1305-IETF | libsodium |
| Hash | BLAKE2b (`crypto_generichash`) | libsodium |
| MAC / KDF | HMAC-SHA256, HKDF-SHA256 (RFC 5869) | libsodium HMAC + our RFC-verified HKDF |
| Password stretching (client) | Argon2id (`crypto_pwhash`) | libsodium |
| Password hash at rest (server) | scrypt, N=2¹⁵ r=8 p=1 (RFC 7914) | Node standard library |
| Randomness | `randombytes_buf` | libsodium (OS CSPRNG) |

HKDF is the one composed construction. libsodium's JavaScript wrapper does not export
`crypto_kdf_hkdf_*`, so `hkdf.ts` implements RFC 5869 extract-and-expand on top of
libsodium's HMAC-SHA256 and is checked against the RFC's own test vectors (A.1–A.3).

## Key hierarchy

```
password
  └── Argon2id(salt = BLAKE2b("ergeshah-password-salt-v1" ‖ username))
        ├── HKDF(info="ergeshah-auth-secret-v1")  → authSecret → server: scrypt → DB
        └── HKDF(info="ergeshah-vault-key-v1")    → vaultKey   → never leaves the device
                                                        │
                                                        ▼ XChaCha20-Poly1305
                                          vault { identity key, prekeys, sessions, history }

device identity (Ed25519)
  ├── X25519 identity key (converted)          used in DH1/DH2
  ├── signed prekey (X25519, signed, rotated weekly — in the browser, on a live session too)
  └── one-time prekeys (X25519, deleted on use)
```

The account password and the cryptographic identity are separate assets: stealing the
database gives an attacker a doubly-hashed `authSecret`, which unlocks no key material.

## Session establishment (X3DH-style)

Following the X3DH specification with X25519 and HKDF-SHA256:

```
DH1 = DH(IK_A_x, SPK_B)
DH2 = DH(EK_A,   IK_B_x)
DH3 = DH(EK_A,   SPK_B)
DH4 = DH(EK_A,   OPK_B)          (omitted if no one-time prekey is available)
SK  = HKDF(ikm = 0xFF*32 ‖ DH1 ‖ DH2 ‖ DH3 ‖ DH4, salt = 0*32, info = "ergeshah-x3dh-v1")
AD  = IK_A_ed ‖ IK_B_ed
```

The initiator verifies the Ed25519 signature over the responder's signed prekey (and its
key id) before any of this runs; an invalid signature aborts the session rather than
downgrading it. If no one-time prekey is available the session still opens, with the
weaker forward-secrecy guarantee the specification describes for that case.

**Deviations from X3DH as published:** identity keys are Ed25519 and converted to X25519
rather than being stored as separate keys; the "F ‖ DH…" prefix uses 32 bytes because the
curve is X25519; there is no server-side one-time prekey signature. This is not an
interoperable Signal implementation and does not claim to be.

## Key separation

Five kinds of secret, so that losing one does not lose the rest:

| Secret | Derived from | Where it lives | What it unlocks |
| --- | --- | --- | --- |
| `authSecret` | password (Argon2id → HKDF) | server, hashed again with scrypt | a session |
| password wrap key | password (Argon2id → HKDF) | the browser, in memory | one wrapped copy of the master key |
| recovery wrap key | phrase (Argon2id → HKDF) | derived on demand, never stored | the other wrapped copy |
| recovery signing key | phrase (Argon2id → HKDF → Ed25519) | derived on demand | proof of ownership to the server |
| master key | 32 random bytes | in the backup, wrapped twice | the vault, and nothing else |
| identity + ratchet keys | inside the vault | the device | messages |

```
phrase   --Argon2id--> HKDF --> recovery wrap key ---\
                            \-> Ed25519 signing pair  \
                                                       +-> master key -> vault -> identity keys
password --Argon2id--> HKDF --> password wrap key ----/
                            \-> authSecret --> (server) scrypt --> session
```

The master key is the only thing that encrypts the vault, and it is never derived from
anything a human types. Changing a password rewraps 32 bytes; a recovery phrase opens the
second wrap, which is why recovery restores conversations rather than only access. The
server holds both wrapped blobs and no key to either.

## Recovery phrases

12 or 24 words in the BIP-39 encoding (24 by default), generated from the OS CSPRNG in the
browser. Only the encoding is borrowed: the phrase's *entropy* — not its text — feeds
Argon2id at the same cost as the password path, instead of BIP-39's PBKDF2-SHA512, which is
far too weak for a secret that must survive an offline attack on a leaked backup.

The checksum bits mean a mistyped or reordered phrase is rejected rather than silently
deriving the wrong key. The words are shown once, confirmed locally (three positions,
checked in the browser), and never transmitted: the server receives an Ed25519 public key
derived from the phrase and, later, signatures over its own challenges.

Consequence, stated plainly because it cannot be engineered away: whoever holds the phrase
can take the account and read its history. There is no email reset and no administrator
override — see `docs/THREAT_MODEL.md`.

## PGP as a second factor

An OpenPGP key is an *authentication* factor here, never a password and never a way to
encrypt anything in this system. The flow is challenge–response:

1. The password is verified first. If the account carries a PGP key, no session is created;
   the response is a 32-byte random challenge with an id and a five-minute life.
2. The user signs those exact bytes on their own machine — `printf %s '<challenge>' | gpg
   --detach-sign --armor` — and pastes the armoured detached signature back.
3. The server verifies it against the stored public key, then mints the session.

Enrolment needs three things at once: a session, the current password, and a signature over
a challenge made by the key being added. The last one is proof of possession — enabling a
key whose private half the user cannot actually use would only lock the account out of
itself. A private key block is refused with an explanation rather than parsed, and nothing
about the private half is ever requested, transmitted or stored.

Challenges are single-use and deleted the moment they are answered, valid or not, so a
signature cannot be replayed and a challenge cannot be ground against guesses. Enrolment
challenges are bound to the account that asked for them.

**Ordering, stated deliberately:** a recovery phrase clears the PGP factor. Someone
recovering an account has lost their password, and there is no reason to assume they still
hold the signing key; leaving the factor in place would turn a recoverable account into an
unreachable one. The phrase is already the strongest secret in the system, so this grants
it nothing it did not have — but it does mean PGP protects against a stolen password, not
against a stolen phrase.

## Message encryption (Double Ratchet)

```
KDF_RK(rk, dh)  = HKDF(ikm = dh, salt = rk, info = "ergeshah-root-he-v1", 96)
                  → (rk', ck, next header key)
KDF_CK(ck)      = (HMAC(ck, 0x01), HMAC(ck, 0x02))            → (message key, ck')
message key     = HKDF(mk, salt = 0*32, info = "ergeshah-message-key-v1", 56)
                  → 32-byte AEAD key ‖ 24-byte nonce
enc_header      = nonce ‖ AEAD(HKs, header(ratchet key ‖ pn ‖ n), AD)   (always 80 bytes)
AAD             = AD ‖ enc_header
plaintext       = message ‖ 0x80 ‖ 0x00…    padded to 64 / 256 / 1024 / 4096·n bytes
```

- **Forward secrecy**: chain keys advance one way; a message key is wiped after use.
- **Post-compromise security**: every reply performs a DH ratchet step with a fresh
  X25519 key, mixing new entropy into the root key.
- **Out-of-order delivery**: skipped message keys are stored (≤1000 per chain, ≤2000
  total) and deleted after use, so a replay of a consumed message fails authentication.
- **Atomic decryption**: the ratchet advances on a *copy* of the session; state is
  committed only after the AEAD tag verifies. Without this, an attacker who can post an
  envelope could desynchronise a conversation with a forged header.
- **Header encryption** (the specification's header-encryption variant): each direction
  holds a current and a next header key (`HKs`/`NHKs`, `HKr`/`NHKr`). The first two are
  derived from the X3DH secret with the labels `ergeshah-header-key-initiator-v1` and
  `…-responder-v1` — the specification expects the handshake to supply `shared_hka` and
  `shared_nhkb`, and separate HKDF labels give the same independence without adding a
  handshake field. Every later header key falls out of the root KDF, and both sides
  promote "next" to "current" in the same ratchet step, which keeps the two schedules
  aligned with no extra round trip. A receiver trials `HKr` then `NHKr`; success with the
  latter *is* the signal that a DH ratchet step happened. Out-of-order messages keep the
  header key alongside the stored message key, so a delayed message from a retired chain
  still opens exactly once.
- **Length hiding**: plaintext is padded to buckets (64, 256, 1024, then multiples of
  4096) with ISO/IEC 7816-4 padding *inside* the AEAD. A sealed header is always 80
  bytes, so an envelope reveals a bucket rather than a byte count.

## File delivery

```
key             = 32 random bytes, used for exactly one file
nonce           = 24 random bytes
plaintext       = file ‖ 0x80 ‖ 0x00…   padded to 64 / 256 / 1024 / 4096·n bytes
ciphertext      = XChaCha20-Poly1305(key, padded plaintext, AD = order id)
```

The key and nonce are then sent to the buyer as an ordinary ratchet message in the order's
channel, so the file inherits the messaging layer's forward secrecy and authentication
without a second key-agreement protocol. The order id as associated data binds the
ciphertext to the order it was uploaded for. The server holds the ciphertext and nothing
else; it cannot distinguish a PDF from a zip, and sees a size rounded up to 4 KB.

Limits, stated rather than hidden: a delivery is a single buffer in memory on both sides
(cap: 3 MB of plaintext), there is no chunking, no resumption, and no streaming, and a
seller who is willing to lie can upload the wrong file — this is a delivery mechanism, not
an escrow (roadmap MKT-1).

## Safety numbers

```
safety number = base64url(BLAKE2b-240(sort(identity_a, identity_b)))[0..40]
                shown as five groups of eight characters
```

Both sides sort the two identity keys before hashing, so both see the same string without
exchanging anything. The client renders it as text *and* as a QR code (`src/shared/qr.ts`,
version 3, level M, ~180 lines and no dependency) so it can be compared across the room
with a phone camera rather than read out character by character.

Verification is recorded per *identity key*, not per person, in the local vault: a peer
with two devices has two safety numbers. If a conversation that had verified devices gains
an unverified one, the chat says so instead of quietly accepting it — that event is either
a new device or a substituted key, and only the two humans can tell which. The record
never reaches the server, and no message is blocked by it: this is a signal to the user,
not an enforcement mechanism the operator could switch off.

## Known limitations

1. **Traffic analysis is only partly addressed.** Headers are encrypted and lengths are
   bucketed, so a server no longer sees ratchet keys, counters, chain boundaries or exact
   sizes. It still sees *which device* an envelope is for, and *when* — the count and
   timing of messages, and their bucket. Hiding those needs cover traffic and delayed
   delivery, which is roadmap item MD-2 and is not implemented.
2. **Classical only.** No post-quantum component today; recorded ciphertext is exposed to
   a future quantum adversary ("harvest now, decrypt later"). Roadmap item PQ-1 is a
   hybrid X25519 + ML-KEM handshake, in the PQXDH style, once a reviewed WASM
   implementation is available that does not compromise the "no unaudited crypto" rule.
3. **No multi-device key sharing.** Each device has its own identity; a message is
   encrypted separately per recipient device. There is no cross-device history sync
   beyond restoring the sealed vault with the password.
4. **No deniable authentication beyond X3DH's own property.** We inherit exactly what the
   specification provides — no more.
5. **Not audited.** Property tests are not proofs, and this code has had no external
   review.

## What the tests actually prove

`test/protocol.test.ts` asserts, against the real implementation: session agreement in
both directions; unique ciphertext per message; root-key change per ratchet step;
out-of-order and dropped-message handling; replay rejection; header and ciphertext
tamper rejection; rejection of a header sealed by a foreign session; that the wire format
carries no ratchet key or counter; that padding collapses lengths into buckets; that a
skipped message from a chain three ratchet steps old still opens exactly once; rejection
of a forged signed prekey; failure for a third party holding the full public bundle;
bounded skipped-key derivation; and vault round-trips. These are
properties, not a security proof — but a change that breaks one of them fails CI.
