# Payments

**Prices are Monero, and the marketplace holds balances.** A buyer tops up in XMR, the price
is held in escrow while the order runs, and on completion the seller is credited the price
minus the marketplace fee. There are no cards, no processor, no invoices, and no fiat
anywhere in the schema.

The payment state is in three places and nowhere else: `balances` (what each account holds),
`ledger_entries` (every movement, append-only), and `deposits` / `withdrawals` (the two points
where money crosses the boundary between this database and the Monero network). Migration 014
creates them; ADR-0066 records why the platform is custodial at all.

**The Monero tier exists as of ADR-0070**: a view-only watcher inside the application, a
subaddress per account, a scan that credits confirmed transfers, a solvency comparison on the
same clock, and a payout worker on another host that pulls the queue. It has never run against
a real node — every test uses a fake `monero-wallet-rpc` — so the first stagenet run is roadmap
PAY-6. A deployment with no `MONERO_WALLET_RPC_URL` behaves exactly as before: no address is
handed out and `GET /api/wallet` reports that top-ups are not open.

## The rule that has not changed

**Payment state and private messaging never touch.** Separate module, separate tables,
separate lifetime, and no foreign key from one to the other beyond an order id.

```
MARKETPLACE            MONEY                             MESSAGING
orders ─── id ────────► ledger_entries(order_id, …)      envelopes
                        balances(account_id)             (ciphertext, no sender,
deposits ─┐              ▲                                deleted on delivery)
withdrawals┴─ subaddress index, txid — never an identity
```

- A money row may hold: an account id, an order id, a status from a closed set, an amount in
  piconero, a subaddress index, a confirmation count, a transaction id, and timestamps.
- A money row may **not** hold: a card number, an expiry, a CVV, a bank account, an IBAN, a
  billing address, a name, an email, a phone number, a raw webhook body, a wallet seed, a
  private spend key, or anything copied out of a conversation.
- The messaging domain must not import the money module, and the money module must not read
  `envelopes`, `vaults`, `attachments` or a channel id. `test/architecture.test.ts` enforces
  the boundary.
- A payment failure must not leak into a chat, and a chat must not be able to move money.

## Card data

**Never stored, never transmitted through this server, never logged.** There is no card path
at all, and `Permissions-Policy: payment=()` on every response means the browser refuses the
Payment Request API outright. If cards were ever accepted, the browser would talk to the
processor directly and this server would see a token and a status. That is not merely a
PCI-scope argument: card data is identity, and a system that holds it can be compelled to
hand over a name for every order.

## Balances, and why they are a ledger

`balances` is a running total; `ledger_entries` is the truth. Nothing writes one without the
other in the same transaction, every operation either sums to zero or names the outside world,
and `test/wallet.test.ts` re-adds the entries and compares. Two columns per account:

- **available** — spendable: can buy, can be withdrawn.
- **held** — committed: escrowed against an open order, or waiting inside a payout that has
  not been sent. It moves back to available if the order is cancelled or the payout refused.

The platform is an account in the same table (`account_id = 'platform'`), so fee revenue is a
balance that has to reconcile rather than a number computed by summing orders. `GET
/api/admin/treasury` adds it up: user available + user held + platform earned is what the
wallet must hold for this marketplace to be solvent.

## The order lifecycle, in money

| Transition | Money |
| --- | --- |
| Buyer places an order | Price moves from the buyer's available to held. No balance, no order — 402, before the seller is told anything |
| Seller accepts, delivers | Nothing moves. The hold is the seller's assurance that the money exists |
| Buyer completes | Hold leaves the buyer; seller is credited the price minus the fee; the fee lands on the platform account |
| Cancelled, by either party or a moderator | The hold returns to the buyer, whole. A sale that did not happen earns nothing |
| Disputed, then settled by a moderator | Whichever of the two above the moderator chooses. A moderator moves the *order*; the money follows the order's state machine and cannot be moved directly |

A price of zero moves nothing and writes no ledger row: free is a legitimate price and needs
no escrow.

## The fee

`ORDER_FEE_BPS`, default 500 = **5% of a completed order, charged to the seller**, deducted at
settlement, rounded down so the odd piconero stays with the seller. Nothing is charged on a
top-up, on a payout, or on a cancelled order. The Monero network fee follows the same rule as
the movement: a payer's own wallet pays to send a top-up, and on a payout **the platform pays
it out of the float** — the payee receives the amount they asked for, to the piconero, and
`withdrawals.network_fee_pico` records what the sending cost so an operator can see what the
float is spending. (This corrects the earlier claim that the fee was deducted from the amount:
`scripts/payout-worker.mjs` has always sent the full amount, and the sentence was wrong rather
than the code. It is also why a refund of uncredited dust has a floor of its own — ADR-0071.) Boot refuses a fee above 20%, because `5000` where `500` was meant
is a typo nothing downstream would question.

## Limits

The minimums exist because a payment smaller than the fee to move it is not a payment:
both `MIN_WITHDRAWAL_XMR` and `MIN_DEPOSIT_XMR` (default 0.02 each) are enforced (ADR-0067).
A payout below the floor is refused at the request. A top-up below it is *recorded and not
credited*: the row is written with status `below_minimum`, its total appears on the owner's own
wallet screen, and its owner can send it back to an address they name (`POST
/api/wallet/refunds`, ADR-0071) once the uncredited total reaches `MIN_REFUND_XMR` (default
0.001, about twenty network fees, because the platform pays the fee on the way out). Below that
floor an operator settles it by hand — the money is never
quietly kept, because Monero gives no sender address to refund to automatically.

Payout ceilings are about automation, never about the money:

- Each account has an optional `payout_limit_pico`. Absent, it is `AUTO_PAYOUT_MAX_XMR`
  (default 2 XMR) — what an ordinary buyer gets.
- A seller's is set by hand when their application is approved
  (`payoutLimitXmr` on the decide route) and changed later through
  `POST /api/admin/users/:username/payout-limit`. Both are audited with the amount.
- Requests up to the limit, and up to that same amount per rolling 24 hours, are queued
  automatically. **Anything larger is queued for an administrator, not refused**: a seller
  withdrawing a year of earnings gets one approval click and one transaction, and an attacker
  who owns this process gets neither.
- There are no limits on topping up, for anyone.

## Keys, and the three wallets

The web application holds **no spend key**. `test/payments.test.ts` greps the whole of `src`
for one, and for the RPC calls that spend (`sweep_all`, `transfer_split`).

| Wallet | Holds | Where | Can |
| --- | --- | --- | --- |
| Watcher | private **view key** only | beside the app, internal network | see confirmed top-ups and credit them; spend nothing, ever |
| Payout | a spend key with a working float | separate host or container, no inbound reachability, pulls the queue | send queued payouts up to the float |
| **Cold** reserve | the main spend key | offline, operator's own hardware, seed written down and never typed into a browser or a chat | hold everything above the float |

The float is sized so that a total compromise of both online tiers costs the float, not the
marketplace: keep 1–2% of liabilities hot, sweep the rest to cold, and top the payout wallet up
by hand. That is the whole answer to "one key per address so a breach exposes one of a
thousand" — Monero derives every subaddress of a wallet from **one** private spend key, so a
thousand independent keys means a thousand wallets, a thousand backups and a thousand
processes. Splitting hot from cold buys the same protection with one moving part.

The seed is generated by the operator and never passes through this repository, this database,
a support channel or a chat. A key that has been in a message is a key an attacker may already
have.

## How the Monero tier must work

Five constraints from this repository decide most of the design before any Monero-specific
choice is made. They are not preferences:

| Constraint | Where it comes from | What it rules out |
| --- | --- | --- |
| The application container has no route to the internet | `docs/NETWORK.md`, `test/deployment.test.ts` | Any price oracle, any remote node, any exchange API. A node is a *new tier* on the internal network with its own egress, not an outbound call from `app` |
| There are no WebSockets, and `connect-src` is `'self'` | ADR-0042, `docs/METADATA.md`, `test/api.test.ts` | Socket-based payment monitoring. Also: `monerod` has no WebSocket interface at all — it offers JSON-RPC, ZMQ pub/sub and `--block-notify` (`docs/SOURCES.md`) |
| The server keeps no key that moves anything valuable | `docs/CRYPTO.md`, threat model | A private spend key in an environment variable. The application tier gets the **private view key only** |
| Four runtime dependencies, each justified | `docs/DEPENDENCIES.md`, `npm run audit:dependencies` | A wallet library. `monero-wallet-rpc` speaks JSON-RPC over HTTP; that is `fetch` and a typed client, not a WebAssembly build of the whole wallet |
| Money is an integer | ADR-0064, `src/shared/money.ts` | Floating-point amounts, at any layer, in any direction |

**One address per account, from a view-only wallet.** `create_address` on a dedicated wallet
account returns a subaddress and its index; the pair goes in `deposit_addresses` and the
address is shown to its owner. Subaddresses are the mechanism Monero documents for exactly
this ("businesses accepting payments in an automated way"), they cost nothing to generate, and
they are unlinkable to each other on the chain. The vocabulary that requirements documents
usually confuse: *stealth addresses* are the protocol's one-time output keys, automatic in
every transaction and not something an integration creates; *subaddresses* are what a merchant
issues; *integrated addresses* embed a payment id and cannot serve two payments at once.

## The watcher, the worker, and what each may do

| | Watcher | Payout worker |
| --- | --- | --- |
| Where | inside the application process (`lib/monero.ts`, `lib/deposits.ts`) | its own host, no inbound reachability (`scripts/payout-worker.mjs`) |
| Key | private **view key**, in the wallet it talks to | a spend key with a working float |
| Calls it may make | `create_address`, `get_transfers`, `get_balance` — and `test/monero.test.ts` fails if a fourth appears | `validate_address`, `transfer`, against its own wallet |
| Direction | polls the wallet every `WALLET_POLL_SECONDS` | polls *the marketplace* for a payout; nothing calls it |
| Worst case if compromised | reads what arrived, hands out addresses | loses the float, which is why the float is 1–2% of liabilities |

The worker claims one payout at a time (`POST /api/payouts/claim`), which marks the row
`sending` and stamps `claimed_at` in the same statement. **Nothing moves it back.** A worker that dies after signing
and before reporting leaves a row an operator resolves by reading their own wallet history —
slower than an automatic retry, and it does not pay anybody twice. The moderation screen is
where that happens (ADR-0073): the payout queue shows how long a row has been `sending`,
flags it over two hours, and offers exactly the two answers an operator can verify in the
wallet's own history — sent, with the transaction id, or never left, which returns the money. A payout larger than the
worker's own float is reported failed, which returns the money to its owner's spendable
balance and tells the operator to top the float up.

Solvency runs beside the scan: liabilities (every balance, the platform's fee account
included) against `get_balance`. The difference is on `GET /api/admin/treasury` as
`walletXmr` and `shortfallXmr`, and a shortfall writes an error line an operator can alert on.

**Detection is polling, and it has to be.** A payment cannot be recognised by reading a block
and comparing an address to a transaction, because a Monero transaction contains no recipient
address — that is the entire point of the chain. Only a wallet holding the view key can scan
outputs and say "this one is yours". So the loop is `get_transfers` against the wallet RPC on
an interval (30–60 s is ample against a 2-minute block time), inside the existing housekeeping
timer, with the wallet daemon on the internal network. `monero-wallet-rpc --tx-notify` can wake
the loop early; it is an optimisation, never the mechanism.

**Confirmations.** One confirmation is roughly two minutes. A top-up is credited at three
(~6 minutes), which is the gate `deposits.confirmations` records. Ten blocks (~20 minutes) is
when Monero itself unlocks funds for spending
(`CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE`), so "credited" and "spendable by the platform" are
different moments and the operator's float has to cover the gap.

**A below-minimum top-up is refunded by hand.** It is a `below_minimum` row in `deposits`, an
uncredited amount on the payer's wallet screen, and a payout the operator makes to an address
that person supplies in support. There is no automatic path, for the reason in the next
paragraph.

**Refunds are not automatic, and cannot be.** There is no sender address in a Monero
transaction, so "refund to the address the payment came from" is not a feature that was
skipped — it is not expressible. Inside the platform a refund is a cancellation: the hold goes
back to the buyer's balance, which is where their money already is. Leaving the platform
requires an address the owner supplies, which is exactly what a payout is.

**What the audit trail may say.** Account id, order id, subaddress index, amount, confirmation
count, transaction id, timestamps, and — for an administrator's decision — who decided and
what they set. Not an IP address, not a user agent, not a name. A payout's destination is kept
only until it is sent and then deleted; what remains is `address_hint`, the first and last six
characters, which is what a support conversation needs. A Monero address appears nowhere in the
blockchain, so a hint correlates with nothing.

## Custody, stated plainly

Holding other people's money is the largest risk in this repository, and the honest list is
short:

- **A hot wallet is worth stealing.** Mitigated by the float, the cold reserve, the payout
  limits and the approval gate above them — not eliminated.
- **Holding and transferring other people's funds is regulated activity in most
  jurisdictions** (the EU's CASP/MiCA regime, FinCEN's money-transmitter rules in the US).
  This document is not legal advice and this repository contains no legal opinion; the
  operator's exposure is a decision made outside the code, and ADR-0066 records that it was
  made deliberately.
- **A solvency bug is indistinguishable from theft, from the outside.** Hence the ledger, the
  reconciliation test, and the treasury endpoint that shows liabilities as one number.
- **The non-custodial alternative exists and was rejected**, with reasons, in ADR-0066: 2-of-3
  multisig between buyer, seller and platform, where the platform alone can move nothing.
  Monero supports it and the tooling is young. It remains the right long-term target for large
  orders.

## Choosing a processor

Unchanged, and now moot for the default path:

1. **This gateway** — the operator runs the node; nobody else learns who paid whom.
2. **No processor** — out-of-band settlement between buyer and seller, which is what this
   marketplace did before migration 014 and what it falls back to if the wallet tier is down.
3. **A conventional processor**, last, and only if a deployment genuinely needs cards. Then:
   one processor named in `THIRD_PARTY.md`, hosted fields or a redirect so no card byte reaches
   this origin, webhooks verified by signature, no analytics script from them on any page, and
   a line in `THREAT_MODEL.md` saying plainly that the processor learns the buyer's identity.

**A swap service is not option 1.5.** Accepting BTC through FixedFloat, ChangeNOW or any
similar API means a third party learns the order, the amount and both legs of the swap, can
freeze funds mid-order, and can be compelled for records this project would then be unable to
produce or deny. Bitcoin is also a public ledger: a buyer who pays in BTC has published the
purchase. One currency, chosen for the property this product is about (ADR-0064).

## Guarantee, and what it does not cover (ADR-0068, ADR-0069)

The protection this marketplace offers is the escrow and nothing else: the price is held from
the moment the order is placed, a dispute freezes it, and a moderator's decision on the *order*
is what moves it. That protection exists for an order placed here, and for no other
arrangement.

A payment made directly to a seller has no hold, no dispute and no refund, and this platform
cannot even see it. The order screen and every listing card say so before the money moves,
rather than in a help page afterwards.

Because the chat is end-to-end encrypted and stays unread, the rules that keep trade on the
platform are incentives and publishing rules, not surveillance:

- a seller's **level** (0–3) comes only from settled on-platform orders, and the catalogue is
  sorted by it, so a deal taken off the platform costs visibility (ADR-0068). It also **falls**:
  one step per `SELLER_LEVEL_DECAY_DAYS` (90) without a settled sale, and one step per
  suspension that reinstatement does not return (ADR-0072). The volume earned is never deleted
  — one sale restores what dormancy took — so the catalogue answers "who is trading here" and
  not "who once did";
- a **listing** may not carry a wallet address, an email address, another messenger or a "pay
  me directly" offer (ADR-0069);
- **reviews and ratings** count only completed on-platform orders, once per buyer (ADR-0029).
