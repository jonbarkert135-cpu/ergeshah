# Threat model

This document is the contract. Any security claim elsewhere in this repository is only
valid in the terms defined here, and anything not listed as mitigated should be assumed
to be a residual risk.

## What we do *not* claim

- Not anonymous. The platform reduces what the *server* learns; it cannot hide you from
  your ISP, your device, or someone standing behind you.
- Not unbreakable. It is an implementation of well-studied constructions; implementations
  have bugs, and this one has not been externally audited.
- Not free of metadata. Connection timing, message timing and message size *buckets* remain
  observable to the operator and to a network observer.
- Not resistant to a compromised endpoint. Malware on your device reads your messages
  before any encryption happens.
- Not resistant to a malicious *client build*. If the operator serves modified
  JavaScript, that JavaScript can exfiltrate keys. See "Residual risks".

## Assets

| Asset | Where it lives | Consequence if lost |
| --- | --- | --- |
| Message plaintext | Client devices only | Full loss of confidentiality for those messages |
| Identity / prekey private keys | Client vault (encrypted) | Impersonation, decryption of future messages |
| Vault key (from password) | Client memory, never sent | Attacker can decrypt vault backups |
| Session tokens | Client cookie, hash in DB | Account takeover until revoked |
| Social graph (who talks to whom) | Partly inferable server-side | Deanonymisation pressure |
| Marketplace records | Server database | Commercial exposure, correlation |
| Audit log | Server database | Reveals moderator behaviour |

## Attackers and what the design does about them

### Network attacker (passive observer, active MITM, hostile Wi-Fi, ISP)

| Attack | Mitigation | Residual |
| --- | --- | --- |
| Passive interception | TLS 1.3 at the proxy; content is *additionally* end-to-end encrypted | Traffic timing and volume are visible |
| Active MITM on TLS | HSTS (2 years, includeSubDomains), automatic certificate management | A malicious CA plus HSTS bypass on first visit; onion service avoids CAs entirely |
| Downgrade | `upgrade-insecure-requests`, HSTS, no HTTP-only fallback in the app | First-visit downgrade before HSTS is pinned |
| Replay of a captured request | Session cookie + CSRF token + per-message ratchet counters | — |
| Injection into the page | `default-src 'self'` CSP; no inline script; no third-party origin | A compromised server can still change the CSP it sends |

### Server attacker (compromised VPS, malicious operator, stolen backup, leaked database)

| Attack | Mitigation | Residual |
| --- | --- | --- |
| Read stored messages | Server stores ciphertext only; keys never reach it | Server sees the size bucket and the arrival time |
| Crack passwords from a dump | Client-side Argon2id, then server-side Argon2id over the derived half | A weak password is still a weak password |
| Steal sessions from a dump | Only SHA-256 hashes of tokens are stored | A live attacker can steal cookies in transit on a compromised server |
| Reconstruct a user's activity | Coarse (day) timestamps on long-lived rows; no access log; no read receipts | `envelopes.created_at` is millisecond-precise while undelivered |
| Learn who talks to whom | No sender column; sender identity is inside the ciphertext | Timing correlation of send/fetch, and the recipient device is necessarily known |
| Silently substitute keys | Signed prekeys verified by the client; safety numbers for out-of-band comparison | Users who never compare safety numbers will not notice |
| Serve backdoored client code | Same-origin CSP, reproducible build from this repository | **Unmitigated by design.** A web client cannot defend against its own server. This is the single largest residual risk. |

### Application attacker

| Class | Mitigation |
| --- | --- |
| SQL injection | Every query parameterised; no string interpolation of values anywhere |
| XSS | No `innerHTML` in the client; DOM built from text nodes; strict CSP with no inline script |
| CSRF | SameSite=Strict cookies + Origin/Host check + double-submit token |
| SSRF | The server makes no outbound HTTP requests at all; the container is on an internal network with no egress |
| Path traversal | Static assets are read from an explicit allowlist at boot; no path is derived from a request |
| IDOR | Every object lookup is scoped by owner; covered by tests for devices, envelopes, listings, orders and vaults |
| Authentication bypass | Single code path (`authenticate`), opaque tokens, suspended accounts rejected on every request |
| Privilege escalation | Roles checked per route; moderators cannot touch admins; nobody can promote themselves |
| Race conditions | One-time prekey claiming and order transitions run inside transactions |
| Brute force | Token-bucket limits on login, registration, sending and writes |
| User enumeration | Login is constant-work and returns one message for both cases; registration necessarily reveals a taken username (accepted, documented) |
| Request smuggling | Single proxy hop, no request rewriting, Node's own HTTP parser in strict mode |
| Deserialization | JSON only, size-limited, schema-validated field by field |
| Prototype pollution | No recursive merge of user input; validators return primitives |

### Cryptographic attacker

| Attack | Mitigation | Residual |
| --- | --- | --- |
| Stolen device key | Double Ratchet gives post-compromise security: the next DH ratchet step re-keys the session | Messages already on the device are readable |
| Compromise of one message key | Per-message keys derived from a one-way chain | The chain's future keys are safe; that single message is not |
| Nonce reuse | Nonce derived from the unique per-message key, never a counter | — |
| Weak randomness | `randombytes_buf` from libsodium (OS CSPRNG) | Broken OS entropy breaks everything, as always |
| Malicious public keys | Signed prekeys verified before any session opens; sessions refuse to start on a bad signature | Identity keys are trust-on-first-use unless verified out of band |
| Session desynchronisation attack | Decryption ratchets a copy and commits only after authentication | — |
| Harvest now, decrypt later | Documented explicitly: the current handshake is classical X25519 | **Real.** A hybrid PQ handshake is roadmap item PQ-1, not a shipped feature |

### Privacy attacker

| Vector | Status |
| --- | --- |
| IP addresses | Never stored. Used in memory for rate limiting, immediately HMACed with a daily-rotating pepper |
| Access logs | Disabled in the app and in the proxy configuration |
| Analytics, pixels, session replay | None. The CSP forbids any third-party origin, so a future mistake fails loudly |
| Cookies | Two: an opaque session token and a CSRF token. No tracking identifiers |
| Local storage | One entry: the encrypted vault |
| Fonts / CDN | System fonts only; every asset self-hosted |
| Referrers | `Referrer-Policy: no-referrer` plus a meta tag; the proxy strips `Referer` upstream |
| Error logs | Method, route and error message only — no bodies, no identifiers |
| Backups | Contain no plaintext messages by construction; still encrypt them (see DEPLOYMENT.md) |
| Message timing/size | Sizes are padded to buckets (64/256/1024/4096·n) and headers are encrypted, so ratchet keys, counters and exact lengths are hidden. **Timing, count and bucket remain visible to the operator** — no cover traffic or delayed delivery (roadmap MD-2) |
| Browser fingerprinting | Not performed by us; not preventable by us |

## Residual risks, stated plainly

1. **Server-served client code.** The operator can ship a malicious bundle to a specific
   user. Mitigation is procedural (published builds, third-party audit) and partial.
2. **Metadata.** Who is online, when, how often, and roughly how large their messages
   are (the bucket, not the byte count).
3. **Classical-only handshake.** Recorded traffic today may be decryptable by a future
   quantum adversary.
4. **Unverified identities.** Without a safety-number comparison, a first contact is
   trust-on-first-use.
5. **No external audit.** The cryptography follows published specifications and is
   property-tested, but it has not been reviewed by anyone outside this repository.
6. **Availability.** A single VPS is a single point of failure, deliberately.

If any of these is unacceptable for your use case, the honest answer is that this
platform is not yet suitable for it.
