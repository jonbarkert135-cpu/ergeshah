# Message metadata

End-to-end encryption settles the *content* question and leaves the harder one open: who
talked to whom, when, how often, how much, and who was at the keyboard. This document takes
each metadata feature a messenger normally has, one at a time (point 75), and answers three
questions about it — what the server learns, what the peer learns, and whether it happens
at all unless someone asks for it.

The rule the table below is built on: **a metadata feature is opt-in, or it is
privacy-preserving by construction, or it does not exist here.**

## The inventory

| Feature | Where it lives | What the **server** learns | What the **peer** learns | Default |
| --- | --- | --- | --- | --- |
| **Sender** | Inside the ciphertext | Nothing at rest. `envelopes` has no sender column, and since ADR-0084 the sending *request* carries no session either: the client spends a single-use token and omits its cookies. What remains is that an account asked for a batch of tokens at some earlier moment — visible to an operator watching the running server, absent from every stored row | Who wrote to them, which is the point | Always |
| **Recipient** | `envelopes.recipient_device_id` | The device an envelope is for. Unavoidable: store-and-forward has to know where to forward | — | Always |
| **Timestamp** | `envelopes.created_at`, `available_at`, and `at` inside the ciphertext | When an undelivered envelope arrived, to the millisecond, until it is collected and deleted. Long-lived rows elsewhere keep only a *day*. The poll that collects it no longer runs on a fixed beat, and a sender may ask that collection be held back by up to two minutes (ADR-0085) | The time the sender's clock claimed | Jittered poll always; the delay is **off** |
| **Size** | `envelopes.payload` | A padding bucket — 64/256/1024/4096·n bytes — not the length of what was written | The message | Always |
| **Delivery state** | Nowhere | That an envelope was fetched, because it is deleted at that moment. There is no `delivered` column and no delivery history | Nothing. There is no "delivered" tick: the client is not told, because the only honest source would be a receipt the peer chose to send | — |
| **Typing indicator** | An encrypted message | That an envelope was sent, in the same padding bucket as a short sentence. No column, no flag, no way to sort signals from messages | That you are typing, for eight seconds | **Off** |
| **Read receipt** | An encrypted message | Same: one more envelope, indistinguishable by shape | The timestamp you have read up to | **Off** |
| **Online status** | Does not exist | Connection times, as any server does. There is no presence table, no "last seen", no heartbeat and no route that answers "is she online" | Nothing, except that a typing signal implies somebody is there right now | **Absent** |

### Sealed sender, and what it is worth (ADR-0084)

The sender row above used to end with a caveat: the database knew nothing, but the request
did. That is now split in two. Sending is authorised by a single-use token minted earlier by
an authenticated call, and the send itself goes out with no cookie, so there is no session
for the server to attribute the envelope to and nothing in `send_tokens` that can be joined
to an account.

The limit is worth stating plainly, because "anonymous" is the word this is not. An adversary
reading data at rest — a backup, a seized disk, a demand for stored records — cannot tell who
sent what. An operator who *modifies the running server* still can: they see which account
requests tokens, and could record the tokens as they are handed out. Closing that needs
unlinkable issuance — a blind signature — which is a primitive this project will not
hand-roll for one route. Batches are minted when the pouch runs low rather than at send time,
and expiries are jittered so a batch is not one grouping key, but neither of those turns the
mechanism into something it is not.

### Timing, and the defence that is not here (ADR-0085)

Two things changed and one deliberately did not. The client's poll interval is redrawn from
the CSPRNG after every fetch, so it neither identifies this client by its cadence nor makes
the next fetch predictable. And a sender may ask the server to hold an envelope for a
quantised delay of fifteen seconds to two minutes, which separates the post from the fetch
that collects it; it is opt-in, in the account screen, because it makes messages arrive
later.

What is *not* here is cover traffic — a padded envelope on a fixed schedule whether or not
anybody typed — and that is the only mechanism that actually defeats an observer watching
the whole service. It costs battery and bandwidth without pause, and a half-hearted version
teaches an analyst the shape of the exception. So the claim for timing is small and stated
as such: the easy correlations are noisier, and someone who can watch both ends of this
service for a week can still do traffic analysis on it.

`test/metadata.test.ts` checks the parts of that table a test can check: that no route
reports presence or read state, that the schema has no column for either, that the settings
are off in a fresh vault, and that a signal envelope is byte-for-byte the same shape as a
message envelope.

## Why presence is not a harmless feature (point 76)

"Online now" reads like a convenience. It is a continuous, high-resolution record of when a
person is awake, at their desk, travelling, or asleep — and it is one that can be *polled*
by anyone who is allowed to ask, without them sending anything and without leaving a trace.
Correlate two accounts' presence for a week and you learn whether they are the same person;
correlate presence with an event and you learn who was there. A conventional
implementation makes the server the broker of all of it.

So there is no presence in this system. What replaces it is narrower on purpose:

- **No server state.** No `last_seen`, no heartbeat, no websocket registry. The nearest
  thing in the schema is `sessions.last_seen_day`, which is a *day*, is used only to expire
  idle sessions, and is not readable by anybody but the account itself.
- **The only presence signal is a typing indicator**, and it is a message: encrypted end to
  end, addressed to one conversation, off by default, sent at most once every six seconds
  while you type, and shown for eight seconds. It is never written to the vault — it lives
  in a variable and is gone on reload, because a presence *history* is what this feature
  turns into if nobody stops it.
- **It costs something, and we say so.** Turning it on means the operator sees you send
  envelopes while you are composing. Content stays unreadable and a signal carries no field
  that marks it as one — same columns, same channel, same expiry, and the same padding
  buckets every message uses. What padding has never hidden is the bucket itself, and that
  is as true of a signal as of a sentence: an observer who sees a burst of small envelopes
  followed by one larger one can guess what happened, without being able to confirm it.
  That is the trade, and it is why the switch is off until a person decides otherwise.

## Read receipts (point 77)

Configurable, off by default, and coarse on purpose: the receipt says "read up to this
timestamp", once per batch, not once per message. A per-message receipt is a keystroke-level
record of someone's attention.

Two consequences worth stating:

- Turning receipts off costs you nothing except symmetry — you still see receipts from
  people who send them, because their client sent them and they meant to.
- A receipt is a claim, not a proof. It says a client displayed the message. Nothing here
  can tell you a human read it.

## Where the settings live

In the encrypted vault, with everything else that describes you (`state.ts`). Not in a
`user_settings` table. Two reasons, and the second is the one that matters:

1. The server cannot enforce a preference it cannot read, and it does not need to — both
   sides of these features are client code.
2. A settings table is itself metadata. "This account has read receipts off" and "this
   account changed its typing setting on Tuesday" are facts about a person, and the cheapest
   way not to leak them is not to have them.

The cost is honest: settings do not follow you to a second device, because the vault a
linked device holds is its own. A device you link starts with everything off, which is the
right direction for a default to fail in.

## Push notifications (point 80)

**There are none, and this is a design decision rather than an unfinished feature.**

A push notification is delivered by Apple, Google, Mozilla or whoever operates the endpoint.
Using one means a third party learns that *this device* received *something* at *this
moment*, and — if the payload is not opaque — what it said. Even an empty payload hands a
company outside this system a timing feed of one person's conversations, keyed to a stable
device token that survives reinstalls. For a product whose whole claim is that the operator
learns as little as possible, adding a second operator who learns more is not a trade worth
making for a notification tone.

Instead: the client polls, and the internal inbox (ADR-0032) says "something arrived" and
nothing else — no sender, no channel, no count, one coalesced unread row per account.

If push is ever added, this is the shape it has to have, and anything less is a regression:

| Requirement | Why |
| --- | --- |
| Opaque payload, always | No sender, no preview, no channel, no count. Ideally a fixed-size random blob the client uses only as "go and poll" |
| No plaintext, ever, of anything private | Not the message, not a name, not a listing title. HTTPS to a push service is not end-to-end encryption |
| Self-hosted first | A web-push endpoint the operator runs, or nothing. A third-party gateway is the last resort and must be named in `THIRD_PARTY.md` |
| Opt-in per device | A device token is an identifier. It is not created unless someone asks for it |
| Deletable | Removing a device removes its token in the same transaction |
| Documented residual | The push endpoint sees timing and volume for that device. That cannot be fixed by us, only disclosed |

Until all six hold, polling is the more private answer, and it is what ships.

## What remains observable

Nothing here hides traffic analysis. The operator, and a network observer, still see
connection times, envelope counts and padding buckets; correlating a send with a fetch is
possible and no feature in this document prevents it (roadmap MD-2). The point of the design
is that everything *else* — content, sender, participants, presence, read state — is either
encrypted, absent, or something the two people involved chose to reveal to each other.
