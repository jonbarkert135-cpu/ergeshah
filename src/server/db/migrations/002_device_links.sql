-- 002_device_links: one-time authorisations that let a newly linked device open a session.
--
-- A device that is already signed in publishes the new device's public bundle and then
-- creates a row here, keyed by SHA-256 of a secret only the new device knows. The new
-- device redeems it once, and the row is deleted. No token is stored in plaintext: the
-- session is minted at redemption time.

CREATE TABLE device_links (
  link_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  label TEXT,
  expires_at INTEGER NOT NULL
);
CREATE INDEX device_links_expiry_idx ON device_links(expires_at);
