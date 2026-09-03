# Payments

**There is no payment functionality in this system today.** No card fields, no wallet, no
balance, no invoice, no processor. An order records what was bought, by whom, from whom, at
what price, and how it ended; how money moved is arranged by the two parties, in their
encrypted channel, outside this platform.

That is a deliberate position and not an oversight: payment is the single feature most
likely to drag identity, address, and a third party's tracking into a system built to avoid
all three. This document is the architecture payments must follow *if* they are added
(point 82), written now so the decision is not made under delivery pressure later.
`test/payments.test.ts` enforces the parts of it that can be enforced before the feature
exists — no card-shaped column, no route that accepts one.

## The rule

**Payment state and private messaging never touch.** Separate module, separate tables,
separate lifetime, and no foreign key from one to the other beyond an order id.

```
MARKETPLACE            PAYMENTS  (if added)             MESSAGING
orders ─── id ────────► payments(order_id, …)           envelopes
                          │                             (ciphertext, no sender,
                          └─► processor reference        deleted on delivery)
                              (opaque string)
```

Concretely:

- A payment row may hold: an order id, a status from a closed set, an amount and currency
  already known to the order, timestamps, and one opaque processor reference.
- A payment row may **not** hold: a card number, an expiry, a CVV, a bank account, an IBAN,
  a billing address, a name, an email, a phone number, a raw webhook body, or anything
  copied out of a conversation.
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

1. **No processor.** Out-of-band settlement between buyer and seller. Zero data, zero
   dependency, zero compelled-disclosure surface. This is today's answer.
2. **A self-hosted cryptocurrency gateway** — the roadmap's PAY-1 names Monero precisely
   because it needs no third-party identity and no account with anyone. The operator runs
   the node; nobody else learns who paid whom.
3. **A conventional processor**, last, and only if a deployment genuinely needs cards. Then:
   one processor, named in `THIRD_PARTY.md`, hosted fields or a redirect so no card byte
   reaches this origin, webhooks verified by signature, no analytics script from them on any
   page, and a line in `THREAT_MODEL.md` saying plainly that the processor learns the
   buyer's identity and the transaction — because it does, and no architecture here changes
   that.

## What escrow would require

Escrow is the feature people ask for next, and it is blocked on payments, not on disputes.
If it arrives: funds held by the processor rather than the operator, release conditioned on
the order's own state machine, and a moderator's power limited to moving the *order* to
`completed` or `cancelled` — the same two verbs they have now — with the payment side
reacting to that transition. A moderator who can move money directly is a target; a
moderator who can only settle a dispute is a role.
