# Deletion and retention

What "delete" means here, one layer at a time, and — the part most products skip — what it
does not mean. Point 74 is explicit about this: **do not promise cryptographic destruction
of data whose copies cannot all be reached.** Nothing in this document claims a message is
unrecoverable. It says which copy is removed, by whom, and what remains.

## The four layers

| Layer | What it holds | What removes it |
| --- | --- | --- |
| Server, undelivered | The ciphertext of an envelope | The recipient's acknowledgement (immediately), or the envelope's expiry |
| Server, delivered | Nothing | Already gone: acknowledgement deletes the row |
| Recipient device | Plaintext in the encrypted vault | The disappearing-message timer, "delete", or deleting the conversation |
| Sender device | Their own copy, same vault | The same three, on their device only |

There is deliberately no fifth layer. No archive, no analytics copy, no object store, no
message broker, no "deleted" flag that keeps the row.

## Disappearing messages

A per-conversation lifetime in whole hours, chosen from a short list (1 hour, 24 hours, 7
days, 30 days, or keep). What happens when it is set:

1. The lifetime travels **inside the ciphertext** as an expiry timestamp, so both clients
   agree on it without the server being told what it is.
2. Both clients drop the plaintext from their vault when the time passes — on the poll, on
   the next load, and before anything is drawn.
3. The sender also asks the server for a **shorter envelope expiry**, rounded to whole
   hours, so that an undelivered copy is not held for the default thirty days.
4. If the two sides disagree, the sooner one wins: a sender can shorten the life of what
   they wrote, and a reader can shorten it further, but a sender cannot extend it past what
   the reader chose.

Two honest details:

- **The server learns the hour.** Asking for a shorter TTL tells the operator that this
  conversation uses disappearing messages and roughly how short. That is why the granularity
  is hours rather than seconds, and why *every* envelope in the conversation — including
  typing and read signals — carries the same TTL, so the expiry cannot be used to tell
  control messages from sentences.
- **It is not enforcement.** Anyone who can read a message can screenshot it, photograph it,
  or run a modified client that ignores the timer. Disappearing messages are an agreement
  between two clients about tidiness, not a control over the other person.

## Deleting on your own device

- **One message** — removed from this device's vault. Nobody is asked and nobody is told:
  there is no "delete for everyone", because it cannot be honoured. A recipient's client may
  cooperate or may not, and a product that shows "deleted for everyone" while a copy sits on
  someone's disk is lying in the reassuring direction.
- **A conversation** — history *and* ratchet state. Removing the session keys is the part
  that matters: they are what could open anything still in flight for that conversation.

## Key destruction, and its ceiling

Where key material is destroyed on purpose:

| Key | Destroyed when | Method |
| --- | --- | --- |
| Vault master key | Lock, sign-out, reload | Zeroed in memory (`lock()`), never written unwrapped |
| One-time prekey (private) | The session that used it is accepted | Removed from the vault; the public half was already deleted server-side on claim |
| Skipped message key | Its message arrives, 2000 newer keys arrive, **or seven days pass** | Zeroed and dropped (`MAX_SKIPPED_KEY_AGE_MS`) |
| Ratchet chain keys | Every message, by construction | The chain KDF is one-way: a used key cannot be re-derived |
| Session state | Deleting the conversation | Removed from the vault before it is resealed |

And the ceiling, stated plainly:

- **JavaScript cannot reliably zero a string.** Key material serialised into the vault has
  been a string; `fill(0)` on the byte array does not reach copies the runtime made. Zeroing
  is done where it is possible and is not a guarantee.
- **`localStorage` is not a shredder.** Rewriting the sealed vault leaves the old blob to
  the browser's storage layer and the filesystem underneath it. The blob is encrypted, which
  is the actual defence; deletion is not.
- **Backups.** An operator's encrypted database backup can contain envelopes that were
  deleted afterwards. They expire (`docs/BACKUPS.md`), and until they do, they are ciphertext
  nobody in this system can open.
- **Other devices.** Deleting on one device deletes on one device. There is no remote wipe,
  because the mechanism that would make one possible — a server that can reach into a
  client's storage — is the mechanism this architecture exists to avoid.

## Retention, in one table

Live values are in `docs/ENVIRONMENT.md`; these are the defaults.

| Data | Kept |
| --- | --- |
| Undelivered envelope | Until acknowledged, at most `ENVELOPE_TTL_MS` (30 days) — less if the sender set a shorter lifetime |
| Delivered envelope | Deleted at acknowledgement |
| Order delivery blob | Until the buyer saves it, the order ends, or `DELIVERY_TTL_MS` (30 days) |
| Message attachment blob | Until someone holding its id deletes it, or `DELIVERY_TTL_MS` (30 days) |
| Notification | `NOTIFICATION_RETENTION_MS` (90 days) |
| Session | Logout, `SESSION_TTL_MS` (30 days), or `SESSION_IDLE_DAYS` (14) unused |
| Rate-limit bucket | 24 hours |
| One-time prekey | Until claimed |
| Audit entry | `AUDIT_RETENTION_MS` (1 year) |
| Account, listings, orders, reviews | Until deleted by the user or by moderation |
| Local plaintext history | The disappearing timer, or until deleted on that device |

## Deleting the account

`POST /api/auth/delete` removes the account row, the sealed vault, devices and prekeys,
undelivered envelopes addressed to them, sessions, listings, orders, order events, reviews
and reports — in one transaction, with no tombstone. `docs/PRIVACY.md` covers the three
references that are unlinked rather than deleted (they record what a *moderator* did) and
the two consequences: a counterparty loses shared history, and messages already delivered
to other people stay with them.

Attachments are the one blob not reached by account deletion, because the table has no owner
column *by design* — an owner column would tie every picture to the account that sent it.
They expire on their own. Deleting the conversation removes the only copy of the key, so
what remains is bytes nobody can open, on a clock.
