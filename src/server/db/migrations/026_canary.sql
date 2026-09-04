-- 026_canary: the operator's signed statement, kept with the dates it makes claims about
-- (OPS-7, ADR-0099).
--
-- A canary is only worth the signature on it, so the row is the signed text, the detached
-- signature, and the key material a reader needs to check both. Nothing here is derived by
-- the server: the two dates are parsed *out of the signed statement*, so a server that
-- rewrites them invalidates the signature it is publishing beside them.
--
--   * `statement`   — the signed text itself, exactly as it was signed. Line endings and
--                     spacing matter: a signature is over bytes.
--   * `signature`   — the armoured detached OpenPGP signature over `statement`.
--   * `public_key`  — the armoured public key it was verified against, copied from the
--                     publisher's enrolled key so that a reader can verify offline without
--                     an account. A reader still compares the fingerprint out of band; the
--                     server handing out a key proves nothing on its own.
--   * `pgp_fingerprint` — lower-case hex, matched against `CANARY_FINGERPRINT` at publish time.
--   * `signed_day`  — from the `Signed:` line. Publishing is refused for a date older than
--                     the newest row already here, so a still-valid older statement cannot
--                     be replayed to look fresh.
--   * `next_day`    — from the `Next:` line. What the client counts down to, and past which
--                     it says the canary is overdue.
--   * `published_day` — when this server was handed it. Day-granular like the rest of the
--                     schema: an exact time here would be a timeline of the operator.
--
-- The table is append-only in practice: every statement ever published stays, which is what
-- lets a reader check the series rather than one page. It is small — one row per period.
--
-- reversible: yes — drop the table; the client stops showing the canary line and nothing
-- else in the system depends on it.

CREATE TABLE canary_statements (
  id TEXT PRIMARY KEY,
  statement TEXT NOT NULL,
  signature TEXT NOT NULL,
  public_key TEXT NOT NULL,
  pgp_fingerprint TEXT NOT NULL,
  signed_day INTEGER NOT NULL,
  next_day INTEGER NOT NULL,
  published_day INTEGER NOT NULL
);
CREATE INDEX canary_statements_signed_idx ON canary_statements(signed_day);
