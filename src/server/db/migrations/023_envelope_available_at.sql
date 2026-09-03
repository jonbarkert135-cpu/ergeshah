-- 023_envelope_available_at: delivery timing noise (MD-2, ADR-0085).
--
-- Padding hid how long a message is; sealed sender took the sender out of the request. What
-- is left in an envelope row is *when*: a post at 12:00:03 and a fetch at 12:00:05 correlate
-- two accounts even though neither row names the pair. This column lets a sender ask that
-- their envelope not be handed over immediately.
--
--   * `available_at` — when the fetch route may return this row. Zero on every existing row,
--     and on every envelope from a sender who did not ask for a delay, which means "now".
--
-- The delay is chosen by the sending client, quantised to fifteen seconds and capped by
-- `MAX_DELIVERY_DELAY_SECONDS`: a precise millisecond delay would be a per-client
-- fingerprint, which is the opposite of the point. The expiry is unchanged — a delay of a
-- minute against a lifetime of hours does not need arithmetic.
--
-- reversible: yes — drop the column and every envelope is available the moment it arrives,
-- which is what a deployment without this behaves like anyway.

ALTER TABLE envelopes ADD COLUMN available_at INTEGER NOT NULL DEFAULT 0;
