/**
 * Store-and-forward for ciphertext the server cannot read.
 *
 * What the server stores per message: the recipient *device*, an opaque channel id the
 * clients chose, the ciphertext, and an expiry. What it does not store: the sender, the
 * plaintext, a conversation participant list, a read state, or a delivery history.
 * Envelopes are deleted the moment the recipient acknowledges them.
 *
 * Read receipts, typing indicators and presence are absent from this file on purpose
 * (points 75-77). They exist in the product as ordinary encrypted messages between the two
 * clients, so there is no state here to leak and no route to ask "is she online".
 */
import type { FastifyInstance } from "fastify";
import { badRequest, notFound, unauthorized } from "../lib/errors.ts";
import { newId } from "../lib/ids.ts";
import { asArray, asBase64Url, asId, asInteger, asString, asUsername } from "../lib/validate.ts";
import { notifyQuietly } from "../lib/notify.ts";
import { issueSendTokens, spendSendToken } from "../lib/send_tokens.ts";

/**
 * The session invite is opaque to the server, but it is still parsed and re-serialised
 * rather than stored verbatim: an untrusted blob that other clients will parse should
 * never be echoed back unchecked.
 */
function validateInvite(value: unknown): {
  identityKey: string;
  ephemeralKey: string;
  signedPreKeyId: number;
  oneTimePreKeyId: number | null;
} {
  const invite = (value ?? {}) as Record<string, unknown>;
  return {
    identityKey: asBase64Url(invite.identityKey, "invite.identityKey", 32),
    ephemeralKey: asBase64Url(invite.ephemeralKey, "invite.ephemeralKey", 32),
    signedPreKeyId: asInteger(invite.signedPreKeyId, "invite.signedPreKeyId", 0, 2 ** 31 - 1),
    oneTimePreKeyId:
      invite.oneTimePreKeyId === null || invite.oneTimePreKeyId === undefined
        ? null
        : asInteger(invite.oneTimePreKeyId, "invite.oneTimePreKeyId", 0, 2 ** 31 - 1),
  };
}

export async function registerMessageRoutes(app: FastifyInstance): Promise<void> {
  const { db, config } = app;

  /**
   * Mint sealed-sender tokens (MD-4, ADR-0084). This is the one call in the sending path
   * that identifies the caller, and it is charged for: one batch, rate-limited, with
   * nothing written down but the hashes.
   */
  app.post("/api/messages/tokens", async (request) => {
    await app.authenticate(request);
    await app.limit(request, "send_tokens");
    const tokens = await issueSendTokens(app.db, config.sendTokenBatch, config.sendTokenTtlMs);
    return { tokens, expiresInMs: config.sendTokenTtlMs };
  });

  /** Send one ciphertext to every active device of a recipient. */
  app.post("/api/messages", async (request) => {
    // Two ways in. With a sealed-sender token (ADR-0084) the request carries no cookie at
    // all: the token is spent, and this server never held a fact about who sent it. With a
    // session — an older client, or one whose tokens ran out — it is authenticated and
    // rate-limited as before, and the identity is still dropped rather than stored.
    const sealed = request.headers["x-send-token"];
    if (typeof sealed === "string" && sealed !== "") {
      if (!(await spendSendToken(db, sealed))) {
        // Deliberately the same answer as a missing session: whether a token was once
        // valid, already spent, or never existed is not a distinction worth publishing.
        throw unauthorized("this request needs a session or an unspent send token");
      }
    } else {
      await app.authenticate(request);
      await app.limit(request, "message_send");
    }
    const body = (request.body ?? {}) as Record<string, unknown>;
    const username = asUsername(body.to);
    const channel = asBase64Url(body.channel, "channel", 32);
    const messages = asArray(body.messages, "messages", 20);
    if (messages.length === 0) throw badRequest("messages must contain at least one entry");
    // Disappearing messages, server side (point 74): a sender may ask for an expiry shorter
    // than the default. Whole hours only — a precise TTL would be a per-conversation
    // fingerprint — and never longer than the deployment's own limit.
    const ttlMs =
      body.ttlHours === undefined || body.ttlHours === null
        ? config.envelopeTtlMs
        : Math.min(asInteger(body.ttlHours, "ttlHours", 1, 720) * 3_600_000, config.envelopeTtlMs);
    // Delivery timing noise (MD-2, ADR-0085): a sender may ask that this envelope not be
    // handed over for a while, so that a post and the fetch that follows it do not pin two
    // accounts to the same second. Quantised to fifteen seconds — a delay of 3_471 ms is a
    // fingerprint of the client that chose it — and capped by the deployment.
    const delaySeconds =
      body.delaySeconds === undefined || body.delaySeconds === null
        ? 0
        : Math.min(
            // Rounded *up*: a delay is a request to wait, and rounding one down to zero
            // would quietly turn the feature off for anyone who asked for a few seconds.
            Math.ceil(asInteger(body.delaySeconds, "delaySeconds", 0, config.maxDeliveryDelaySeconds) / 15) * 15,
            Math.floor(config.maxDeliveryDelaySeconds / 15) * 15,
          );

    const target = await db.get<{ id: string; status: string }>(
      "SELECT id, status FROM users WHERE username = ?",
      [username],
    );
    if (!target || target.status !== "active") throw notFound("no such user");

    const devices = await db.all<{ id: string }>(
      "SELECT id FROM devices WHERE user_id = ? AND revoked_at IS NULL",
      [target.id],
    );
    const deviceIds = new Set(devices.map((device) => device.id));
    const now = Date.now();
    const accepted: string[] = [];

    await db.transaction(async (tx) => {
      for (const entry of messages) {
        const message = entry as Record<string, unknown>;
        const deviceId = asId(message.deviceId, "messages[].deviceId");
        if (!deviceIds.has(deviceId)) continue; // device revoked between bundle fetch and send
        const payload = asString(message.payload, "messages[].payload", config.maxEnvelopeBytes);
        const invite =
          message.invite === undefined || message.invite === null
            ? null
            : JSON.stringify(validateInvite(message.invite));
        const id = newId();
        await tx.run(
          `INSERT INTO envelopes (id, recipient_device_id, channel, payload, invite, created_at, expires_at, available_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          [id, deviceId, channel, payload, invite, now, now + ttlMs, now + delaySeconds * 1000],
        );
        accepted.push(id);
      }
    });

    if (accepted.length === 0) {
      throw notFound("that user has no device that can receive this message");
    }
    // "Something arrived for you", and nothing else: no sender, no channel, no count. The
    // recipient's client already knows how to find out what it was — by decrypting it
    // (point 48). One unread row per account, enforced by a partial unique index.
    await notifyQuietly(db, { userId: target.id, kind: "message" });
    // The sender is not recorded anywhere: this response is the only acknowledgement.
    return { delivered: accepted.length };
  });

  /** Fetch pending envelopes for one of my devices. */
  app.get("/api/messages", async (request) => {
    const user = await app.authenticate(request);
    await app.limit(request, "read");
    const { deviceId } = request.query as { deviceId?: string };
    const device = await ownDevice(app, user.id, deviceId);
    await db.run("DELETE FROM envelopes WHERE expires_at < ?", [Date.now()]);
    const rows = await db.all<{
      id: string;
      channel: string;
      payload: string;
      invite: string | null;
      created_at: number;
    }>(
      // `available_at` is zero for anything sent without a delay and for every envelope
      // written before ADR-0085, so the common case is one extra comparison.
      `SELECT id, channel, payload, invite, created_at FROM envelopes
        WHERE recipient_device_id = ? AND available_at <= ? ORDER BY created_at LIMIT 200`,
      [device.id, Date.now()],
    );
    return {
      envelopes: rows.map((row) => ({
        id: row.id,
        channel: row.channel,
        payload: row.payload,
        invite: row.invite ? JSON.parse(row.invite) : null,
        receivedAt: row.created_at,
      })),
    };
  });

  /** Acknowledge delivery: the server forgets the envelope immediately. */
  app.post("/api/messages/ack", async (request) => {
    const user = await app.authenticate(request);
    const body = (request.body ?? {}) as Record<string, unknown>;
    const device = await ownDevice(app, user.id, body.deviceId);
    const ids = asArray(body.ids, "ids", 200).map((id) => asId(id, "ids[]"));
    let deleted = 0;
    await db.transaction(async (tx) => {
      for (const id of ids) {
        // RETURNING, so the count is what was actually deleted rather than what was asked
        // for: an id belonging to another device must not be reported as acknowledged.
        const gone = await tx.all<{ id: string }>(
          "DELETE FROM envelopes WHERE id = ? AND recipient_device_id = ? RETURNING id",
          [id, device.id],
        );
        deleted += gone.length;
      }
    });
    return { deleted };
  });
}

async function ownDevice(
  app: FastifyInstance,
  userId: string,
  deviceId: unknown,
): Promise<{ id: string }> {
  if (typeof deviceId !== "string") throw badRequest("deviceId is required");
  const device = await app.db.get<{ id: string }>(
    "SELECT id FROM devices WHERE id = ? AND user_id = ? AND revoked_at IS NULL",
    [deviceId, userId],
  );
  if (!device) throw notFound("no such device on this account");
  return device;
}
