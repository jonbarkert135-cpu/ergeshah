/**
 * Store-and-forward for ciphertext the server cannot read.
 *
 * What the server stores per message: the recipient *device*, an opaque channel id the
 * clients chose, the ciphertext, and an expiry. What it does not store: the sender, the
 * plaintext, a conversation participant list, a read state, or a delivery history.
 * Envelopes are deleted the moment the recipient acknowledges them.
 */
import type { FastifyInstance } from "fastify";
import { badRequest, notFound } from "../lib/errors.ts";
import { newId } from "../lib/ids.ts";
import { asArray, asBase64Url, asId, asInteger, asString, asUsername } from "../lib/validate.ts";

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

  /** Send one ciphertext to every active device of a recipient. */
  app.post("/api/messages", async (request) => {
    // Authenticated so that only accounts can post envelopes, but the identity is
    // deliberately dropped here: nothing about the sender reaches the database.
    await app.authenticate(request);
    await app.limit(request, "message_send");
    const body = (request.body ?? {}) as Record<string, unknown>;
    const username = asUsername(body.to);
    const channel = asBase64Url(body.channel, "channel", 32);
    const messages = asArray(body.messages, "messages", 20);
    if (messages.length === 0) throw badRequest("messages must contain at least one entry");

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
          `INSERT INTO envelopes (id, recipient_device_id, channel, payload, invite, created_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [id, deviceId, channel, payload, invite, now, now + config.envelopeTtlMs],
        );
        accepted.push(id);
      }
    });

    if (accepted.length === 0) {
      throw notFound("that user has no device that can receive this message");
    }
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
      `SELECT id, channel, payload, invite, created_at FROM envelopes
        WHERE recipient_device_id = ? ORDER BY created_at LIMIT 200`,
      [device.id],
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
        await tx.run("DELETE FROM envelopes WHERE id = ? AND recipient_device_id = ?", [
          id,
          device.id,
        ]);
        deleted += 1;
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
