/**
 * The canary (OPS-7, ADR-0099): a statement the operator signs and refreshes, published
 * with the dates it covers.
 *
 * What it is for is narrow and worth stating plainly. A canary cannot stop a demand for
 * data, and a canary that has been refreshed proves nothing at all — the operator may have
 * been compelled and told to keep signing. What it can do is make *silence* visible: a
 * statement nobody has refreshed since the date it promised is a fact every visitor can see
 * for themselves, and a signature nobody but the operator can produce is a fact this server
 * cannot fake, because it never holds the private key.
 *
 * So the two things that make it real are here, not in the interface:
 *
 * 1. **The dates are inside the signature.** They are parsed out of the signed text rather
 *    than taken from the request or the clock, so a server that wanted to make a stale
 *    canary look fresh would have to forge a signature to do it.
 * 2. **The key is pinned by configuration.** `CANARY_FINGERPRINT` names the one key whose
 *    signature this deployment will publish. Without it the feature is off, and an
 *    administrator with a stolen session still cannot publish a statement: they would need
 *    the operator's PGP key, which lives on the operator's machine (ADR-0087, ADR-0088).
 */
import type { Db } from "../db/index.ts";
import { newId } from "./ids.ts";
import { dayToIsoDate, today } from "./time.ts";
import { verifyDetachedSignature } from "./pgp.ts";

/** A canary is a paragraph. Anything longer is a document, and a document is not read. */
export const MAX_STATEMENT_CHARS = 4000;
/**
 * How old the signature may be when it arrives. A statement signed three weeks ago says
 * something about three weeks ago; publishing it today would let an operator pre-sign a
 * stack of them, which is exactly the failure a canary exists to make visible.
 */
export const MAX_SIGNATURE_AGE_DAYS = 7;
/** And a statement due again in two years is a promise nobody will notice being broken. */
export const MAX_INTERVAL_DAYS = 90;

export class CanaryError extends Error {}

export interface CanaryDates {
  signedDay: number;
  nextDay: number;
}

export interface CanaryRow {
  statement: string;
  signature: string;
  public_key: string;
  pgp_fingerprint: string;
  signed_day: number;
  next_day: number;
}

/** `Signed: 2026-09-04` and `Next: 2026-09-18`, each on its own line of the signed text. */
function isoDay(statement: string, label: string): number {
  const match = statement.match(new RegExp(`^${label}:[ \\t]*(\\d{4}-\\d{2}-\\d{2})[ \\t]*$`, "m"));
  if (!match) {
    throw new CanaryError(`the statement needs a line reading "${label}: YYYY-MM-DD"`);
  }
  const iso = match[1] as string;
  const day = Math.floor(Date.parse(`${iso}T00:00:00Z`) / 86_400_000);
  // A date that does not survive the round trip is not a date: `2026-02-31` parses in
  // JavaScript and means March, which would silently move a canary's deadline.
  if (!Number.isFinite(day) || dayToIsoDate(day) !== iso) {
    throw new CanaryError(`${label}: ${iso} is not a real date`);
  }
  return day;
}

/**
 * Read the two dates out of the signed text and check they describe a canary rather than an
 * archive entry or an open-ended promise. Throws `CanaryError` with a message the operator
 * can act on — this runs on a route only an administrator reaches.
 */
export function readCanaryDates(statement: string, now = today()): CanaryDates {
  const signedDay = isoDay(statement, "Signed");
  const nextDay = isoDay(statement, "Next");
  if (signedDay > now) throw new CanaryError("the statement is signed with a future date");
  if (now - signedDay > MAX_SIGNATURE_AGE_DAYS) {
    throw new CanaryError(
      `the statement was signed ${now - signedDay} days ago; sign a fresh one (the limit is ${MAX_SIGNATURE_AGE_DAYS} days)`,
    );
  }
  if (nextDay <= signedDay) throw new CanaryError("the next date must be after the signing date");
  if (nextDay - signedDay > MAX_INTERVAL_DAYS) {
    throw new CanaryError(
      `a canary due in ${nextDay - signedDay} days is not a canary; the limit is ${MAX_INTERVAL_DAYS} days`,
    );
  }
  return { signedDay, nextDay };
}

/** The newest statement, by the date it was signed. */
export async function latestCanary(db: Db): Promise<CanaryRow | null> {
  const row = await db.get<CanaryRow>(
    `SELECT statement, signature, public_key, pgp_fingerprint, signed_day, next_day
       FROM canary_statements ORDER BY signed_day DESC, published_day DESC LIMIT 1`,
  );
  return row ?? null;
}

/**
 * Verify and store. The signature is checked against the key the caller enrolled, and that
 * key against the fingerprint in the configuration: two different failures, two different
 * messages, and neither of them writes a row.
 */
export async function publishCanary(
  db: Db,
  input: {
    statement: string;
    signature: string;
    publicKey: string;
    fingerprint: string;
    expectedFingerprint: string;
  },
  now = today(),
): Promise<CanaryDates> {
  if (input.fingerprint.toLowerCase() !== input.expectedFingerprint.toLowerCase()) {
    throw new CanaryError(
      "your enrolled PGP key is not the key this deployment publishes canaries with (CANARY_FINGERPRINT)",
    );
  }
  const dates = readCanaryDates(input.statement, now);
  const previous = await latestCanary(db);
  // Replay: an older statement is still correctly signed forever. Publishing one would make
  // an unrefreshed canary look refreshed, which is the one lie this feature must not tell.
  if (previous && dates.signedDay <= previous.signed_day) {
    throw new CanaryError(
      `the newest published statement is signed ${dayToIsoDate(previous.signed_day)}; this one is not newer`,
    );
  }
  if (!(await verifyDetachedSignature(input.publicKey, input.statement, input.signature))) {
    throw new CanaryError("that signature does not verify against your enrolled PGP key");
  }
  await db.run(
    `INSERT INTO canary_statements
       (id, statement, signature, public_key, pgp_fingerprint, signed_day, next_day, published_day)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      newId(),
      input.statement,
      input.signature,
      input.publicKey,
      input.fingerprint.toLowerCase(),
      dates.signedDay,
      dates.nextDay,
      now,
    ],
  );
  return dates;
}
