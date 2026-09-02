-- 003_recovery: recovery public keys and one-time authentication challenges.
--
-- The server stores the *public* half of a keypair the user derives from their recovery
-- phrase, and nothing else about it: no phrase, no entropy, no wrapped private key. The
-- wrapped master key that a phrase unlocks lives inside `vaults.sealed`, which the server
-- cannot open either.

ALTER TABLE users ADD COLUMN recovery_public_key TEXT;

-- Challenges for signature-based authentication: recovery today, PGP next.
-- Random, single-use, short-lived, and deleted the moment they are answered.
CREATE TABLE auth_challenges (
  id TEXT PRIMARY KEY,
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  challenge TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX auth_challenges_expiry_idx ON auth_challenges(expires_at);
