-- 011_attachments: blind blob storage for message attachments (point 78).
--
-- A picture, a recording, a document — the same problem as an order delivery, and the same
-- answer: the client encrypts the bytes, the server stores a blob it cannot open, and the
-- key travels to the recipient inside the encrypted conversation.
--
-- The interesting part is the columns that are *not* here. There is no sender, no
-- recipient, no conversation, no file name, no media type and no plaintext length: those
-- are exactly the fields that would turn attachments into the social graph the messaging
-- design refuses to keep. What remains is an unguessable id, the ciphertext, and two
-- timestamps, and the id itself is the capability — whoever the sender gave it to can
-- fetch the blob, and nobody else can find it.
--
-- Consequences, stated because they are the trade: the server can count how many blobs
-- exist and how large each padded one is, and an account that uploads and never sends the
-- key wastes disk until the row expires. Rate limits and the expiry are what bound that;
-- there is no per-account quota, because a quota needs an owner column.
CREATE TABLE attachments (
  id TEXT PRIMARY KEY,
  ciphertext TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

-- Housekeeping deletes by expiry, so that is what is indexed.
CREATE INDEX attachments_expiry_idx ON attachments(expires_at);
