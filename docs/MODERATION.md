# Moderation and abuse prevention

Privacy is not the absence of enforcement (point 84), and moderation is not a licence to
read private messages (point 83). This document separates the four things that get confused
with each other, and then lists what actually stops abuse here.

## Four lanes, kept apart

| Lane | What a moderator can see | What they can do | Where it lives |
| --- | --- | --- | --- |
| **Marketplace moderation** | Listings, prices, categories, seller applications and their statements, seller records | Remove a listing, approve or reject an application, suspend a seller | `routes/moderation.ts` |
| **Public content moderation** | Reviews and their text — published content, visible to everyone already | Hide a review | `routes/moderation.ts` |
| **User reports and disputes** | The report: target, reason, and **the words the reporter chose to write** | Resolve, action, dismiss; settle a disputed order | `reports`, `routes/moderation.ts` |
| **Private E2EE messages** | *Nothing* | *Nothing* | Not implemented, in the strong sense: there is no route, no key, and no column |

The last row is the one that has to be structural rather than promised. What makes it true:

- The server has no key that opens an envelope, and no code path that tries. Keys exist in
  browsers.
- No moderation route touches `envelopes`, `vaults`, `deliveries` or `attachments`.
  `test/abuse.test.ts` reads the module and fails if one appears.
- The order channel is not in the moderation queue's response. A moderator settling a
  dispute sees the order's public facts — title, price, status, parties, the seller's record
  — and the buyer's stated reason. Not the conversation.
- There is no impersonation, no "log in as", and no way to disable a user's encryption.

## Reporting private abuse

Someone who is harassed in private can report the *person*: `POST /api/moderation/reports`
with the target `user`, a reason, and free text they write themselves. That text is the only
part of a private exchange a moderator ever sees, and it is there because the reporter chose
to put it there — copied out of their own client, in their own words.

This is the honest limit of moderating an encrypted channel. A moderator cannot verify a
quoted message, so a report is a *claim*, and decisions rest on the account's record, the
pattern of reports, and what the reporter can show voluntarily. The alternatives all require
the server to read messages, which is the property the product exists to have.

The client-side answer is stronger for the person actually being harassed, and it needs no
moderator at all: **block**. A blocked peer's envelopes are decrypted (the ratchet has to
advance) and then discarded without being stored or shown. The block lives in the vault and
the server is never told — it never knew who was writing to you, and a block list it could
see would be exactly the social graph the messaging design refuses to keep. The cost, stated:
a blocked sender can still spend your rate-limit allowance and briefly occupy storage, and
"blocked" is per device rather than per account.

## What stops abuse

| Class | Control | Where |
| --- | --- | --- |
| Bulk account creation | `register` bucket (5 burst, 0.5/min) *plus* a proof of work on unauthenticated account endpoints (ADR-0039) | `lib/rate_limit.ts`, `lib/pow.ts` |
| Credential stuffing | `login` and `account_attempt` buckets — the second counts against the targeted *username*, so many addresses do not help | `lib/rate_limit.ts` |
| Message spam | `message_send` bucket per account, and client-side blocking | `lib/rate_limit.ts`, `client/messaging.ts` |
| Storage flooding | `attachment` bucket (12 burst, 3/min), a byte-exact size cap, and a 30-day expiry. There is no per-account quota, because a quota needs an owner column | `routes/deliveries.ts`, migration 011 |
| Listing spam | `listing_write`, `seller_application` buckets, and seller applications are approved by a human before anything can be listed | `routes/market.ts` |
| Fake reputation | A review requires a *completed order*, counts once per buyer per seller, and the buyer count is published beside the average (ADR-0029) | `lib/reputation.ts` |
| Bad sellers | Suspension, which also suspends the seller record, destroys their sessions and costs a standing level that reinstatement does not return (ADR-0072); listing removal; the dispute record | `routes/moderation.ts` |
| Transaction disputes | A buyer moves the order to `disputed` with a reason, which files a report; a moderator settles it to `completed` or `cancelled`, and the settlement is audited | `routes/market.ts` |
| Search and read abuse | `search`, `read` and `key_bundle` buckets; keyset pagination with no `OFFSET` and no total count | `lib/search.ts` |
| Staff abuse | Every privileged action is written to `audit_log`, readable by all staff rather than only admins, and refusals are logged as route *patterns* | `lib/audit.ts` |

## What abuse detection is *not* allowed to become

The line, written down so that a future feature has to argue against it:

- **No content scanning.** Not of messages, not of attachments, not of order chats. It is
  impossible here by construction and would not be added if it were possible.
- **No behavioural profiling.** No per-account activity timeline, no "risk score" built from
  reading habits, no device fingerprint, no IP history. Rate-limit buckets are HMACs that
  rotate daily and hold a token count, not a log.
- **No identity as a spam filter.** No phone number, no email, no ID document, no third-party
  CAPTCHA — each of those defends the service by identifying the user, which is the trade
  this project refuses (ADR-0039).
- **No shadow bans.** A suspended account is told it is suspended, and a removed listing
  notifies its seller.

The residual is real and is the price: an attacker willing to spend CPU on proofs of work
and to create accounts slowly can still be a nuisance, and ten patient puppet accounts can
still lift a seller's rating (`THREAT_MODEL.md`, residual risk 7). The counter-signals a
reader gets are public — buyer count, completed orders, dispute count — rather than a
verdict from a system that watched everyone to produce it.

## What a listing may not say (ADR-0069)

A listing is a public advertisement this server holds in the clear, which makes it the only
text a rule can apply to. `POST`/`PATCH /api/market/listings` and a seller application's
statement are refused with `off_platform_offer` when they carry:

- a Monero or Bitcoin address,
- an email address,
- a named third-party messenger (Telegram, WhatsApp, Jabber/XMPP, Matrix, Signal, Discord,
  and the Russian spellings of the common ones),
- a "pay me directly", "outside the platform", «напрямую», «мимо площадки» phrase.

The error names the rule and never the pattern that matched, because a filter that explains
how it was tripped ships with its own bypass guide.

**Messages are not touched.** The chat is end-to-end encrypted and the server holds
ciphertext; no moderation rule here reads it, now or later. The filter is evadable by anyone
who wants to evade it — the point is that the bypass cannot be *advertised* to strangers, and
that a seller who takes the deal off the platform loses their level, their catalogue position
and their buyer's protection (ADR-0068).
