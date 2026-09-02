-- 001_init: accounts, cryptographic identities, store-and-forward envelopes,
-- marketplace, moderation, privacy-safe audit trail.
--
-- Conventions that exist for privacy reasons, not for style:
--   * timestamps that only need to be coarse are stored as `*_day` (unix day number),
--     so the database cannot be used to reconstruct a user's activity timeline;
--   * binary values are stored base64url-encoded TEXT so the schema is byte-identical
--     on SQLite and PostgreSQL;
--   * `envelopes` has no sender column: who wrote a message is inside the ciphertext;
--   * no table stores an IP address, a user agent, or a referrer, anywhere.

CREATE TABLE users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  status TEXT NOT NULL DEFAULT 'active',
  status_reason TEXT,
  created_day INTEGER NOT NULL
);

CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  label TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_seen_day INTEGER NOT NULL
);
CREATE INDEX sessions_user_idx ON sessions(user_id);

-- Encrypted backup of the client's private key material. The server cannot open it.
CREATE TABLE vaults (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  sealed TEXT NOT NULL,
  updated_day INTEGER NOT NULL
);

CREATE TABLE devices (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  label TEXT,
  identity_key TEXT NOT NULL UNIQUE,
  signed_prekey_id INTEGER NOT NULL,
  signed_prekey TEXT NOT NULL,
  signed_prekey_signature TEXT NOT NULL,
  created_day INTEGER NOT NULL,
  rotated_day INTEGER NOT NULL,
  revoked_at INTEGER
);
CREATE INDEX devices_user_idx ON devices(user_id);

CREATE TABLE one_time_prekeys (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  key_id INTEGER NOT NULL,
  public_key TEXT NOT NULL,
  claimed_at INTEGER,
  UNIQUE (device_id, key_id)
);
CREATE INDEX one_time_prekeys_device_idx ON one_time_prekeys(device_id, claimed_at);

CREATE TABLE envelopes (
  id TEXT PRIMARY KEY,
  recipient_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  channel TEXT NOT NULL,
  payload TEXT NOT NULL,
  invite TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX envelopes_recipient_idx ON envelopes(recipient_device_id, created_at);
CREATE INDEX envelopes_expiry_idx ON envelopes(expires_at);

CREATE TABLE seller_applications (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  display_name TEXT NOT NULL,
  statement TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  decision_note TEXT,
  decided_by TEXT REFERENCES users(id),
  created_day INTEGER NOT NULL,
  decided_day INTEGER
);
CREATE INDEX seller_applications_status_idx ON seller_applications(status);
CREATE INDEX seller_applications_user_idx ON seller_applications(user_id);

CREATE TABLE sellers (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  display_name TEXT NOT NULL UNIQUE,
  bio TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active',
  joined_day INTEGER NOT NULL
);

CREATE TABLE listings (
  id TEXT PRIMARY KEY,
  seller_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  category TEXT NOT NULL,
  kind TEXT NOT NULL,
  price_minor INTEGER NOT NULL,
  currency TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  created_day INTEGER NOT NULL,
  updated_day INTEGER NOT NULL
);
CREATE INDEX listings_status_idx ON listings(status, created_day);
CREATE INDEX listings_seller_idx ON listings(seller_user_id);

CREATE TABLE orders (
  id TEXT PRIMARY KEY,
  listing_id TEXT NOT NULL REFERENCES listings(id),
  buyer_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  seller_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  price_minor INTEGER NOT NULL,
  currency TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'placed',
  channel TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX orders_buyer_idx ON orders(buyer_user_id, created_at);
CREATE INDEX orders_seller_idx ON orders(seller_user_id, created_at);

CREATE TABLE order_events (
  id TEXT PRIMARY KEY,
  order_id TEXT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  actor_user_id TEXT NOT NULL REFERENCES users(id),
  from_status TEXT NOT NULL,
  to_status TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX order_events_order_idx ON order_events(order_id, created_at);

CREATE TABLE reviews (
  id TEXT PRIMARY KEY,
  order_id TEXT NOT NULL UNIQUE REFERENCES orders(id) ON DELETE CASCADE,
  listing_id TEXT NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
  seller_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  author_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  rating INTEGER NOT NULL,
  body TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'visible',
  created_day INTEGER NOT NULL
);
CREATE INDEX reviews_listing_idx ON reviews(listing_id, status);
CREATE INDEX reviews_seller_idx ON reviews(seller_user_id, status);

CREATE TABLE reports (
  id TEXT PRIMARY KEY,
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  reporter_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  reason TEXT NOT NULL,
  details TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'open',
  resolution_note TEXT,
  resolved_by TEXT REFERENCES users(id),
  created_day INTEGER NOT NULL,
  resolved_day INTEGER
);
CREATE INDEX reports_status_idx ON reports(status, created_day);

-- Administrative actions only: what a moderator did, never what a user read.
CREATE TABLE audit_log (
  id TEXT PRIMARY KEY,
  actor_user_id TEXT REFERENCES users(id),
  action TEXT NOT NULL,
  subject_type TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE INDEX audit_log_created_idx ON audit_log(created_at);

-- Token buckets keyed by HMAC(daily pepper, client address). No address is stored.
CREATE TABLE rate_limits (
  bucket TEXT PRIMARY KEY,
  tokens REAL NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX rate_limits_updated_idx ON rate_limits(updated_at);
