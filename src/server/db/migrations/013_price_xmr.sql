-- Prices become Monero, and nothing else (ADR-0059 is the timestamp precedent for the type).
--
-- `price_minor` held minor units of a currency named in a `currency` column: cents, and a
-- code from a list that included USD, EUR, XMR and BTC. Four currencies in the schema were
-- four settlement stories, three of which need somebody to tell this server an exchange
-- rate — and this server has no route to the internet by design (docs/NETWORK.md). One
-- currency, priced in its own protocol unit, removes the rate, the oracle and the egress it
-- would need.
--
-- `price_pico` is piconero, 10^-12 XMR, the unit Monero itself uses. BIGINT because 64 bits
-- is what an amount takes: SQLite's INTEGER is already 64-bit, PostgreSQL's INTEGER is not,
-- and 1,000 XMR (the application ceiling in src/shared/money.ts) is 1e15 — a hundred
-- thousand times past the int4 limit the old column lived inside.
--
-- Existing prices are not converted, they are zeroed, and every live listing is paused.
-- Converting would require an exchange rate for a historical day, from a source this
-- deployment cannot reach, applied to somebody else's price without asking them. Zero and
-- paused is the honest outcome: a seller re-prices in the currency they are now paid in,
-- and nothing is silently for sale at a number nobody chose.

-- destructive: the four fiat-era columns are dropped, not kept. A `currency` column whose only
-- legal value is 'XMR' invites the exchange rate back, and a `price_minor` nothing reads is a
-- number that will one day be believed. Nothing converts back, which is why every listing is
-- paused for its seller to re-price.
-- reversible: no — the amounts are not recoverable from `price_pico`, and no rate exists to
-- recover them with. Rolling back means restoring from a backup (docs/BACKUPS.md).

ALTER TABLE listings ADD COLUMN price_pico BIGINT NOT NULL DEFAULT 0;
ALTER TABLE orders ADD COLUMN price_pico BIGINT NOT NULL DEFAULT 0;

UPDATE listings SET status = 'paused' WHERE status = 'active';

ALTER TABLE listings DROP COLUMN price_minor;
ALTER TABLE listings DROP COLUMN currency;
ALTER TABLE orders DROP COLUMN price_minor;
ALTER TABLE orders DROP COLUMN currency;
