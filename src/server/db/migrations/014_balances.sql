-- 014_balances: money inside the platform — balances, a ledger, deposits, withdrawals.
--
-- The marketplace holds funds now (ADR-0066): a buyer tops up in Monero, the price is held
-- while the order runs, and on completion the seller is credited the price minus the
-- platform fee. Three properties are worth stating because the schema is what enforces them:
--
--  1. **Every balance is derived from an append-only ledger.** `balances` is the running
--     total, `ledger_entries` is the history, and no code writes one without the other in
--     the same transaction. `test/wallet.test.ts` re-adds the ledger and compares; a
--     balance that does not equal the sum of its entries is a bug that shows up as a
--     failing test rather than as an argument with a seller.
--  2. **Money cannot go negative.** The CHECK constraints are the second line of defence
--     behind the conditional UPDATEs in lib/ledger.ts: an overdrawn account is refused by
--     the database even if two requests race past the application check.
--  3. **The platform is an account like any other.** Fees are moved to `account_id =
--     'platform'`, not counted by summing orders — so revenue is a balance that has to
--     reconcile, and a fee that was charged twice cannot hide.
--
-- reversible: yes — drop the five tables in reverse dependency order (withdrawals, deposits,
-- deposit_addresses, ledger_entries, balances; nothing else references them). Doing so destroys
-- the record of who is owed what, so the real rollback is a restore (docs/BACKUPS.md).

CREATE TABLE balances (
  -- A user id, or the single literal 'platform'. One table, so the platform's own money
  -- obeys the same constraints and appears in the same ledger as everybody else's.
  account_id TEXT PRIMARY KEY,
  user_id TEXT UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  available_pico BIGINT NOT NULL DEFAULT 0 CHECK (available_pico >= 0),
  held_pico BIGINT NOT NULL DEFAULT 0 CHECK (held_pico >= 0),
  -- How much this account may take out without an administrator looking at it: per request,
  -- and per rolling 24 hours. NULL means the deployment default (AUTO_PAYOUT_MAX_XMR), which
  -- is what an ordinary buyer gets; a seller's is set by hand when their application is
  -- approved and can be raised later. It is a ceiling on *automation*, never on the money —
  -- a larger payout is queued for approval, not refused.
  payout_limit_pico BIGINT CHECK (payout_limit_pico IS NULL OR payout_limit_pico >= 0),
  updated_at BIGINT NOT NULL,
  CHECK ((user_id IS NULL AND account_id = 'platform') OR user_id = account_id)
);

INSERT INTO balances (account_id, user_id, available_pico, held_pico, updated_at)
VALUES ('platform', NULL, 0, 0, 0);

CREATE TABLE ledger_entries (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES balances(account_id) ON DELETE CASCADE,
  -- deposit | order_hold | order_release | order_earnings | order_fee | withdrawal |
  -- withdrawal_returned. A closed set, checked in lib/ledger.ts; the column is text so a
  -- new kind is a code change and a migration, not a silent integer.
  kind TEXT NOT NULL,
  -- Signed deltas, in piconero. `available` is spendable, `held` is committed to an open
  -- order or a queued payout. A hold moves value between the two columns of one account
  -- and sums to zero; a settlement moves it between accounts.
  available_delta BIGINT NOT NULL,
  held_delta BIGINT NOT NULL,
  order_id TEXT REFERENCES orders(id) ON DELETE SET NULL,
  deposit_id TEXT,
  withdrawal_id TEXT,
  created_at BIGINT NOT NULL
);

CREATE INDEX ledger_entries_account ON ledger_entries (account_id, created_at DESC);
CREATE INDEX ledger_entries_order ON ledger_entries (order_id);

-- One Monero subaddress per account, handed out once and never reused: two accounts sharing
-- a deposit address would make an incoming payment unattributable, and reusing an old
-- account's address would credit the wrong person.
CREATE TABLE deposit_addresses (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  subaddress_index INTEGER NOT NULL UNIQUE,
  address TEXT NOT NULL UNIQUE,
  created_at BIGINT NOT NULL
);

-- An incoming transfer the wallet has seen. `detected_at` is when our own wallet noticed
-- it, not a claim about the network; `confirmations` is copied from the wallet and is what
-- the credit waits on.
CREATE TABLE deposits (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  amount_pico BIGINT NOT NULL CHECK (amount_pico > 0),
  -- The transaction as our wallet sees it. A Monero transaction names no sender and no
  -- recipient, so this is the whole of what can be recorded about where money came from —
  -- and it is enough for the payer to prove the payment with their transaction key.
  txid TEXT NOT NULL,
  subaddress_index INTEGER NOT NULL,
  confirmations INTEGER NOT NULL DEFAULT 0,
  -- seen | credited
  status TEXT NOT NULL,
  detected_at BIGINT NOT NULL,
  credited_at BIGINT,
  -- One credit per output. A watcher that re-reads the same transfer after a restart, or
  -- twice in one sweep, cannot credit it twice.
  UNIQUE (txid, subaddress_index, amount_pico)
);

CREATE INDEX deposits_user ON deposits (user_id, detected_at DESC);
CREATE INDEX deposits_pending ON deposits (status);

CREATE TABLE withdrawals (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  amount_pico BIGINT NOT NULL CHECK (amount_pico > 0),
  -- The destination, kept only until the payout leaves: after that the transaction id is
  -- the record, and a stored address is a permanent link between an account and a wallet
  -- nobody needs. `address_hint` is the first and last few characters, which is what a
  -- support conversation needs and what the owner can recognise.
  address TEXT,
  address_hint TEXT NOT NULL,
  -- queued | approval_required | sending | sent | failed | rejected | cancelled
  status TEXT NOT NULL,
  txid TEXT,
  -- What the network charged, filled in when the payout is sent: the payee pays it.
  network_fee_pico BIGINT,
  requested_at BIGINT NOT NULL,
  decided_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  settled_at BIGINT
);

CREATE INDEX withdrawals_user ON withdrawals (user_id, requested_at DESC);
CREATE INDEX withdrawals_queue ON withdrawals (status, requested_at);
