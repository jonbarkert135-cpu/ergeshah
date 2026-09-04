/**
 * Two routes for the canary (OPS-7, ADR-0099): the operator publishes, everybody reads.
 *
 * The reading half is deliberately public and deliberately unauthenticated. A canary an
 * account has to be created to see is a canary almost nobody looks at, and there is nothing
 * private in it — it is a statement about the operator, signed by the operator, meant to be
 * copied and compared.
 *
 * The response carries the key it was verified against so that a reader can check the
 * signature offline with `gpg --verify`. That is a convenience, not a trust anchor: a server
 * that lies about the statement would hand out a key to match it. The fingerprint is
 * published out of band (`SECURITY.md`), and comparing the two is the reader's job.
 */
import type { FastifyInstance } from "fastify";
import { badRequest, conflict } from "../lib/errors.ts";
import { asText, onlyKeys } from "../lib/validate.ts";
import { recordAudit } from "../lib/audit.ts";
import { readableFingerprint } from "../lib/pgp.ts";
import { dayToIsoDate, today } from "../lib/time.ts";
import { CanaryError, latestCanary, MAX_STATEMENT_CHARS, publishCanary } from "../lib/canary.ts";

/** Armoured signatures are text, and a long one is a parser stress test, not a signature. */
const MAX_SIGNATURE_CHARS = 8000;

export async function registerCanaryRoutes(app: FastifyInstance): Promise<void> {
  const { db, config } = app;

  /** The current statement, its dates, and how late it is. */
  app.get("/api/canary", async (request) => {
    await app.limit(request, "read");
    const row = await latestCanary(db);
    if (!config.canaryFingerprint || !row) {
      // Two different absences, one answer: this deployment publishes no canary. Saying
      // "configured but never published" would only tell a visitor about the operator's
      // configuration file, and it is not a state they can do anything with.
      return { published: false };
    }
    const now = today();
    return {
      published: true,
      statement: row.statement,
      signature: row.signature,
      publicKey: row.public_key,
      fingerprint: readableFingerprint(row.pgp_fingerprint),
      signedDate: dayToIsoDate(row.signed_day),
      nextDate: dayToIsoDate(row.next_day),
      ageDays: now - row.signed_day,
      overdueDays: Math.max(0, now - row.next_day),
    };
  });

  /**
   * Publish. Only an administrator reaches the route, and only the operator's key can
   * satisfy it: the signature is checked against the PGP key that administrator enrolled
   * (ADR-0087), and that key against `CANARY_FINGERPRINT`. A stolen admin session is not
   * enough, which is the point — the canary would be worth nothing if this server could
   * write one on its own.
   */
  app.post("/api/admin/canary", async (request) => {
    const admin = await app.requireRole(request, ["admin"]);
    await app.limit(request, "sensitive");
    const body = (request.body ?? {}) as Record<string, unknown>;
    onlyKeys(body, ["statement", "signature"]);
    const statement = asText(body.statement, "statement", MAX_STATEMENT_CHARS, 20);
    const signature = asText(body.signature, "signature", MAX_SIGNATURE_CHARS, 20);

    if (!config.canaryFingerprint) {
      throw conflict(
        "this deployment publishes no canary: set CANARY_FINGERPRINT to the operator's key",
        "canary_not_configured",
      );
    }
    const key = await db.get<{ pgp_public_key: string | null; pgp_fingerprint: string | null }>(
      "SELECT pgp_public_key, pgp_fingerprint FROM users WHERE id = ?",
      [admin.id],
    );
    if (!key?.pgp_public_key || !key.pgp_fingerprint) {
      throw conflict(
        "enrol the operator's PGP key on your account before publishing a canary",
        "canary_not_configured",
      );
    }

    try {
      const dates = await publishCanary(db, {
        statement,
        signature,
        publicKey: key.pgp_public_key,
        fingerprint: key.pgp_fingerprint,
        expectedFingerprint: config.canaryFingerprint,
      });
      await recordAudit(db, {
        actorUserId: admin.id,
        action: "canary.published",
        subjectType: "canary",
        subjectId: dayToIsoDate(dates.signedDay),
      });
      return {
        signedDate: dayToIsoDate(dates.signedDay),
        nextDate: dayToIsoDate(dates.nextDay),
      };
    } catch (error) {
      if (!(error instanceof CanaryError)) throw error;
      // A refused canary is recorded: an administrator failing to publish one is exactly
      // the kind of attempt an operator wants to see in the log afterwards.
      await recordAudit(db, {
        actorUserId: admin.id,
        action: "canary.published",
        subjectType: "canary",
        subjectId: "refused",
        result: "denied",
      });
      throw badRequest(error.message, "canary_invalid");
    }
  });
}
