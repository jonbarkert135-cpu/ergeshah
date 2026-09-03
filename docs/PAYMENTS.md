# Payments

**Prices are Monero. Settlement is not implemented, and no money moves through this server
today.** No card fields, no wallet, no balance, no invoice, no processor, no node. An order
records what was bought, by whom, from whom, at what price in XMR, and how it ended; how the
money moves is arranged by the two parties in their encrypted channel, outside this platform.

Two halves of that sentence changed on different days, and the difference matters:

- **The currency is decided and shipped.** `listings.price_pico` and `orders.price_pico` hold
  piconero — 10⁻¹² XMR, the unit the protocol itself uses — as integers. There is no
  `currency` column, no USD, no EUR, no BTC, and no exchange rate anywhere in the codebase
  (ADR-0064). `test/payments.test.ts` fails if any of them come back.
- **The settlement mechanism is designed, not built.** This document is the architecture it
  must follow, written before the feature exists (point 82) and revised into a Monero-specific
  design (ADR-0065) so the decisions are not made under delivery pressure with a wallet
  daemon already running. Roadmap PAY-1 is the work.

## The rule

**Payment state and private messaging never touch.** Separate module, separate tables,
separate lifetime, and no foreign key from one to the other beyond an order id.

```
MARKETPLACE            PAYMENTS  (if added)             MESSAGING
orders ─── id ────────► payments(order_id, …)           envelopes
                          │                             (ciphertext, no sender,
                          └─► subaddress index          deleted on delivery)
                              (an integer, not an identity)
```

Concretely:

- A payment row may hold: an order id, a status from a closed set, an amount in piconero
  already known to the order, a subaddress index, a confirmation count, timestamps, and a
  transaction hash.
- A payment row may **not** hold: a card number, an expiry, a CVV, a bank account, an IBAN,
  a billing address, a name, an email, a phone number, a raw webhook body, a wallet seed, a
  private spend key, or anything copied out of a conversation.
- The messaging domain must not import the payment module, and the payment module must not
  read `envelopes`, `vaults`, `attachments` or a channel id. `test/architecture.test.ts`
  already enforces the domain boundary this would live inside.
- A payment failure must not leak into a chat, and a chat must not be able to move a payment.

## Card data

**Never stored, never transmitted through this server, never logged.** If a card is ever
accepted, the browser talks to the processor directly and this server sees only a token and
a status callback. That is not merely a PCI-scope argument: card data is identity, and a
system that holds it can be compelled to hand over a name for every order.

`Permissions-Policy: payment=()` is already sent on every response, so the browser refuses
the Payment Request API outright until that is deliberately changed.

## Choosing a processor

Order of preference, and the reasoning:

1. **No processor.** Out-of-band settlement between buyer and seller: the seller puts an
   address in the encrypted order channel, the buyer pays it, and the seller confirms it in
   their own wallet. Zero data, zero dependency, zero custody, zero compelled-disclosure
   surface. This is today's answer, and it is a real answer rather than a placeholder — a
   Monero payment needs no third party by design, so the platform's absence costs the parties
   almost nothing beyond doing the confirming themselves.
2. **A self-hosted Monero gateway** (PAY-1) — the operator runs the node; nobody else learns
   who paid whom. The design is below.
3. **A conventional processor**, last, and only if a deployment genuinely needs cards. Then:
   one processor, named in `THIRD_PARTY.md`, hosted fields or a redirect so no card byte
   reaches this origin, webhooks verified by signature, no analytics script from them on any
   page, and a line in `THREAT_MODEL.md` saying plainly that the processor learns the
   buyer's identity and the transaction — because it does, and no architecture here changes
   that.

**A swap service is not option 2.5.** Accepting BTC through FixedFloat, ChangeNOW or any
similar API means a third party learns the order, the amount and both legs of the swap, can
freeze funds mid-order, and can be compelled for records this project would then be unable to
produce or deny. Bitcoin is also a public ledger: a buyer who pays in BTC has published the
purchase. One currency, chosen for the property this product is about (ADR-0064).

## How a Monero gateway must work here

Five constraints from this repository decide most of the design before any Monero-specific
choice is made. They are not preferences:

| Constraint | Where it comes from | What it rules out |
| --- | --- | --- |
| The application container has no route to the internet | `docs/NETWORK.md`, `test/deployment.test.ts` | Any price oracle, any remote node, any exchange API. A node is a *new tier* on the internal network with its own egress, not an outbound call from `app` |
| There are no WebSockets, and `connect-src` is `'self'` | ADR-0042, `docs/METADATA.md`, `test/api.test.ts` | Socket-based payment monitoring. Also: `monerod` has no WebSocket interface at all — it offers JSON-RPC, ZMQ pub/sub and `--block-notify` (`docs/SOURCES.md`) |
| The server keeps no key that moves anything valuable | `docs/CRYPTO.md`, threat model | A private spend key in an environment variable. The server gets the **private view key only**: enough to see a payment arrive, useless for spending it |
| Four runtime dependencies, each justified | `docs/DEPENDENCIES.md`, `npm run audit:dependencies` | A wallet library. `monero-wallet-rpc` speaks JSON-RPC over HTTP; that is `fetch` and a typed client, not a WebAssembly build of the whole wallet |
| Money is an integer | ADR-0064, `src/shared/money.ts` | Floating-point amounts, at any layer, in any direction |

Given those, the design:

**One address per order, from a view-only wallet.** The wallet RPC's `create_address` on a
dedicated account returns a subaddress and its index; the index goes in the payment row and
the address goes to the buyer. Subaddresses are the mechanism Monero documents for exactly
this ("businesses accepting payments in an automated way"), they cost nothing to generate, and
they are unlinkable to each other on the chain. Note the vocabulary the requirements often
confuse: *stealth addresses* are the protocol's one-time output keys, automatic in every
Monero transaction and not something an integration creates; *subaddresses* are what a
merchant issues per order; *integrated addresses* embed a payment id and cannot be used for
more than one payment at a time. This design issues subaddresses.

**Detection is polling, and it has to be.** A payment cannot be recognised by reading a block
and comparing an address to a transaction, because a Monero transaction contains no recipient
address — that is the entire point of the chain. Only a wallet holding the view key can scan
outputs and say "this one is yours". So the loop is: `get_transfers`/`get_payments` against
the wallet RPC on an interval (30–60 s is ample against a 2-minute block time), inside the
existing housekeeping timer, with the wallet daemon on the internal network. Optionally
`monero-wallet-rpc --tx-notify` can wake the loop early; it is an optimisation, never the
mechanism.

**Confirmations, and what they are for.** One confirmation is roughly two minutes. Ten is
when Monero itself unlocks the funds for spending (`CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE`), so
"paid" and "spendable" are not the same moment and the operator's cash flow follows the
second one. The gate for releasing a digital good should be configurable, defaulting to 3
confirmations (~6 minutes) for ordinary amounts, with the row also recording that the amount
matched exactly. An amount that arrives short is not a payment; it is a partial payment, and
the order stays unpaid with the shortfall shown.

**A quote expires; an address does not.** A subaddress cannot be revoked — the wallet will
receive on it forever, and a design that "invalidates" one is lying to the buyer. What expires
is the *quote*: after 30 minutes the payment row moves to `expired`, a new one is issued for
the next attempt, and a late arrival on an expired subaddress is still credited to the order
it belonged to, because the money genuinely arrived and losing it would be theft.

**Refunds are not automatic, and cannot be.** There is no sender address in a Monero
transaction, so "refund to the address the payment came from" is not a feature that was
skipped — it is not expressible. A refund therefore needs a destination the buyer supplies
(through the encrypted order channel) and a signature from a key the server does not hold.
The platform's part is to record that a refund is owed and to whom, in XMR, and to show it to
the operator; the transfer is made from the wallet that holds the spend key, which is not this
one. Anything else is a hot wallet with an HTTP interface, which is how such systems are
robbed.

**What the audit trail may say.** Order id, subaddress index, amount expected, amount seen,
confirmation count, transaction hash, and timestamps. Not an IP address, not a user agent, not
a name — the log rules in `docs/LOGGING.md` apply here exactly as elsewhere, and a payment log
is the most tempting place in a private system to start keeping identities "for accounting".
Tax export, if it is ever wanted, is a report over these columns and needs no extra field.

## What escrow would require

Escrow is the feature people ask for next, and it is blocked on payments, not on disputes.
If it arrives: funds held by the processor rather than the operator, release conditioned on
the order's own state machine, and a moderator's power limited to moving the *order* to
`completed` or `cancelled` — the same two verbs they have now — with the payment side
reacting to that transition. A moderator who can move money directly is a target; a
moderator who can only settle a dispute is a role.

For a Monero gateway, "held by the processor" has a specific meaning worth writing down before
someone implements the easy version: the operator's own wallet holding buyers' funds is
custody, with everything that follows from it — a hot wallet worth stealing, a legal position
that varies by jurisdiction, and a compelled-disclosure surface this document spent its whole
length avoiding. The non-custodial alternative is 2-of-3 multisig between buyer, seller and
platform, where the platform alone can move nothing; Monero supports it, tooling for it is
young, and that is the trade to weigh when MKT-1 is picked up.
