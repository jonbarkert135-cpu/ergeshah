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
| Password hashing | Argon2id (`crypto_pwhash`, `@node-rs/argon2`) | libsodium / Rust argon2 |
| Randomness | `randombytes_buf` | libsodium (OS CSPRNG) |

HKDF is the one composed construction. libsodium's JavaScript wrapper does not export
`crypto_kdf_hkdf_*`, so `hkdf.ts` implements RFC 5869 extract-and-expand on top of
libsodium's HMAC-SHA256 and is checked against the RFC's own test vectors (A.1–A.3).

## Key hierarchy

```
password
  └── Argon2id(salt = BLAKE2b("ergeshah-password-salt-v1" ‖ username))
        ├── HKDF(info="ergeshah-auth-secret-v1")  → authSecret → server: Argon2id → DB
        └── HKDF(info="ergeshah-vault-key-v1")    → vaultKey   → never leaves the device
                                                        │
                                                        ▼ XChaCha20-Poly1305
                                          vault { identity key, prekeys, sessions, history }

device identity (Ed25519)
  ├── X25519 identity key (converted)          used in DH1/DH2
  ├── signed prekey (X25519, signed, rotated weekly)
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

## Message encryption (Double Ratchet)

```
KDF_RK(rk, dh)  = HKDF(ikm = dh, salt = rk, info = "ergeshah-root-v1", 64) → (rk', ck)
KDF_CK(ck)      = (HMAC(ck, 0x01), HMAC(ck, 0x02))            → (message key, ck')
message key     = HKDF(mk, salt = 0*32, info = "ergeshah-message-key-v1", 56)
                  → 32-byte AEAD key ‖ 24-byte nonce
AAD             = AD ‖ header(ratchet public key ‖ pn ‖ n)
```

- **Forward secrecy**: chain keys advance one way; a message key is wiped after use.
- **Post-compromise security**: every reply performs a DH ratchet step with a fresh
  X25519 key, mixing new entropy into the root key.
- **Out-of-order delivery**: skipped message keys are stored (≤1000 per chain, ≤2000
  total) and deleted after use, so a replay of a consumed message fails authentication.
- **Atomic decryption**: the ratchet advances on a *copy* of the session; state is
  committed only after the AEAD tag verifies. Without this, an attacker who can post an
  envelope could desynchronise a conversation with a forged header.

## Known limitations

1. **Headers are not encrypted.** The ratchet public key, previous-chain length and
   message counter travel in the clear inside the envelope. A server operator can
   therefore count messages per chain. Header encryption is roadmap item MD-3.
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
tamper rejection; rejection of a forged signed prekey; failure for a third party holding
the full public bundle; bounded skipped-key derivation; and vault round-trips. These are
properties, not a security proof — but a change that breaks one of them fails CI.
