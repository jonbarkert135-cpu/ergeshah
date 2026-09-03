-- 022_send_tokens: sealed sender (MD-4, ADR-0084).
--
-- `envelopes` has never had a sender column, so a stored message says nothing about who
-- wrote it. The request that stored it was another matter: it carried a session cookie, so
-- a server that chose to record the sender could. This table lets a client buy the right to
-- post an envelope while authenticated, and then spend it without a cookie.
--
--   * `token_hash` — SHA-256 of a random token the client keeps. Only the hash is stored,
--     the way sessions are, so a leaked backup hands nobody a usable token.
--   * `expires_at` — the only other column, and carrying a few minutes of per-token random
--     jitter: a batch that shared one expiry to the millisecond would be a grouping key
--     linking a person's tokens to each other.
--
-- What is deliberately absent: an owner, an issued-at, a spent-at, a counter. There is no
-- column here that can be joined to an account, which is the entire point — a token is
-- deleted by the request that spends it, so the table holds unspent tokens and no history.
--
-- Quota lives where it already lived: issuing is an authenticated, rate-limited endpoint
-- (`send_tokens` bucket). Sending is limited by the tokens in hand.
--
-- reversible: yes — drop the table and the send route falls back to session authentication.

CREATE TABLE send_tokens (
  token_hash TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
);
CREATE INDEX send_tokens_expiry_idx ON send_tokens(expires_at);
