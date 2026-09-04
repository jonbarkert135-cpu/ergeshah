-- 029_send_token_epoch: a revocation epoch for sealed-sender tokens (MD-5, ADR-0111).
--
-- Sealed-sender tokens have no owner column by design (ADR-0084), so a suspension or an
-- account deletion cannot select one account's tokens, and an unspent stockpile keeps
-- posting envelopes until SEND_TOKEN_TTL_MS runs out (SEC-2026-023). This is the blunt
-- instrument the finding pointed at: a single, global epoch every token is minted under.
-- A token *carries* its epoch inside the token string the client holds — authenticated by
-- the hash already stored, so it cannot be forged upward — and a spend is refused when the
-- token's epoch is below the current floor. Raising the floor (an operator break-glass
-- command, like lockdown) invalidates every outstanding token at once; clients refetch a
-- fresh batch transparently on the next send.
--
--   * `id`        — the singleton guard: exactly one row, like `lockdown`.
--   * `min_epoch` — the floor. A token with a lower epoch is dead. Monotonic: it only ever
--                   goes up, so a bump can never resurrect a token an earlier bump killed.
--
-- The epoch is deliberately GLOBAL and COARSE. It is not per-batch and not on a timer: if
-- it changed often it would become a grouping key an operator could read off a spent token
-- to tie a batch together — the very owner-column-by-another-name MD-5 is written to avoid.
-- Everyone minting between two bumps shares one epoch, so the value carries no account in it.
-- Nothing about who minted a token is stored here or anywhere else.
--
-- reversible: yes — drop the table and the application treats every token's epoch as valid
-- (the floor reads as 0), which is exactly the pre-MD-5 behaviour.

CREATE TABLE send_token_epoch (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  min_epoch INTEGER NOT NULL DEFAULT 0
);

INSERT INTO send_token_epoch (id, min_epoch) VALUES (1, 0);
