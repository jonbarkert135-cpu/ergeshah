-- 004_pgp: OpenPGP public keys as a second authentication factor.
--
-- The armoured *public* key and its fingerprint, and nothing else. The private key stays
-- on the user's machine: the server hands out a challenge and checks a detached signature,
-- so it never needs, receives or stores signing material.

ALTER TABLE users ADD COLUMN pgp_public_key TEXT;
ALTER TABLE users ADD COLUMN pgp_fingerprint TEXT;
