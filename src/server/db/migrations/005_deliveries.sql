-- 005_deliveries: blind storage for digital goods.
--
-- One row per delivered order, holding ciphertext the server cannot open. The key never
-- reaches this table: it travels to the buyer inside the order's encrypted channel.
--
-- Columns are the minimum the server needs to do its job (hand the blob to the buyer,
-- delete it afterwards): no uploader, because only the order's seller can write here and
-- that is already in `orders`; no filename, media type, or hash, because all three are
-- content and live inside the ciphertext.

CREATE TABLE deliveries (
  id TEXT PRIMARY KEY,
  order_id TEXT NOT NULL UNIQUE REFERENCES orders(id) ON DELETE CASCADE,
  ciphertext TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX deliveries_expires_at ON deliveries(expires_at);
