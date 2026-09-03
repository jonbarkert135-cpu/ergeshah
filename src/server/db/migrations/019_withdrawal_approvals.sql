-- 019_withdrawal_approvals: one administrator is not enough for a large payout (ADR-0076).
--
-- Until now a parked payout needed one click from one admin account. That makes a single
-- stolen admin session worth the whole float: the attacker raises the account's ceiling or
-- simply approves their own withdrawal, and every control behind it — the worker's float cap,
-- the solvency check — only tells the operator afterwards.
--
-- The rule this table implements is the boring institutional one: **above a threshold, two
-- different people**. It is the part of a 2-of-3 escrow that can be built today without
-- Monero multisig (which needs interactive setup between wallets and a buyer who runs one),
-- and it defends the same thing: no single key, no single account.
--
-- Refusing still takes one admin, on purpose. A refusal returns the money to its owner's
-- spendable balance; it moves nothing out of the platform, so requiring a quorum to say "no"
-- would only slow down the safe answer.
--
-- One row per (payout, admin), so an admin clicking twice is one approval and the count is
-- the number of distinct people who have signed off.
--
-- reversible: yes — drop the table and the threshold check falls back to one approval.

CREATE TABLE withdrawal_approvals (
  withdrawal_id TEXT NOT NULL REFERENCES withdrawals(id) ON DELETE CASCADE,
  admin_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (withdrawal_id, admin_user_id)
);
