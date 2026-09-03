/**
 * Money in this system is Monero, and Monero is an integer.
 *
 * One XMR is 10^12 piconero, the unit the protocol and every wallet RPC actually speak, and
 * the only representation prices are stored or compared in here. A fractional amount is a
 * decimal *string* on the way in and on the way out — never a JSON number, because
 * `0.1 + 0.2` is not `0.3` in binary floating point and a price a seller typed must survive a
 * round trip byte for byte. This is the ordinary rule for money; it is merely more visible
 * with twelve decimals than with two.
 *
 * Two ceilings, both deliberate:
 *
 * - `MAX_PRICE_PICO` is 1,000 XMR. Piconero fits a 64-bit integer (`BIGINT` in PostgreSQL,
 *   `INTEGER` in SQLite), but JavaScript's safe integer range stops at 2^53-1 ≈ 9.007e15
 *   piconero ≈ 9,007 XMR, so a price is capped an order of magnitude below the point where
 *   arithmetic would start lying. A listing that needs more than 1,000 XMR is a negotiation,
 *   not a price tag.
 * - `MIN_PRICE_PICO` is 0.001 XMR. A Monero transfer costs the *sender* a network fee on the
 *   order of 1e-5 to 1e-4 XMR (`docs/SOURCES.md`), so a smaller price is a payment whose fee
 *   is the payment — and a refund of it would arrive as nothing. Free is still allowed: zero
 *   is a legitimate price for a sample, and it needs no transfer at all.
 */

/** Piconero in one XMR. The protocol's unit, not a display choice. */
export const PICO_PER_XMR = 1_000_000_000_000;

/** Decimal places one XMR has, exactly. Not a formatting preference. */
export const XMR_DECIMALS = 12;

/** Ceiling on a listing price: 1,000 XMR, an order of magnitude inside `Number.MAX_SAFE_INTEGER`. */
export const MAX_PRICE_PICO = 1_000 * PICO_PER_XMR;

/** Smallest non-zero price: 0.001 XMR, roughly ten to a hundred times a network fee. */
export const MIN_PRICE_PICO = PICO_PER_XMR / 1_000;

/**
 * What a price may look like written down: up to four integer digits (the cap is 1,000) and
 * up to twelve decimals. No exponent, no sign, no thousands separator, no whitespace — a
 * price is not an expression to evaluate.
 */
const AMOUNT = /^(\d{1,4})(?:\.(\d{1,12}))?$/;

/**
 * Parses a decimal XMR amount into piconero, or returns `null` if it is not one.
 *
 * String arithmetic rather than `Number(text) * 1e12`: the multiplication introduces exactly
 * the rounding error this type exists to avoid (`0.045 * 1e12` is 45000000000.00001), and a
 * price that is off by one piconero is a payment that never matches.
 */
export function parseXmr(text: string): number | null {
  const match = AMOUNT.exec(text.trim());
  if (!match) return null;
  const whole = Number(match[1]);
  const fraction = Number((match[2] ?? "").padEnd(XMR_DECIMALS, "0"));
  const pico = whole * PICO_PER_XMR + fraction;
  return Number.isSafeInteger(pico) ? pico : null;
}

/**
 * Piconero as the decimal string this API speaks: exact, trailing zeros trimmed, no unit.
 * `45_000_000_000` becomes `"0.045"`, `PICO_PER_XMR` becomes `"1"`.
 */
export function xmrString(pico: number): string {
  if (!Number.isSafeInteger(pico) || pico < 0) throw new Error("piconero must be a non-negative safe integer");
  const whole = Math.floor(pico / PICO_PER_XMR);
  const fraction = String(pico % PICO_PER_XMR).padStart(XMR_DECIMALS, "0").replace(/0+$/, "");
  return fraction === "" ? String(whole) : `${whole}.${fraction}`;
}

/** The same amount with its unit, for a person to read: `"0.045 XMR"`. */
export function formatXmr(pico: number): string {
  return `${xmrString(pico)} XMR`;
}
