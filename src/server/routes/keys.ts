/**
 * Key directory: devices publish public prekey material, other clients claim a bundle.
 *
 * The server is an untrusted directory. It never holds a private key, and it cannot
 * forge a bundle undetectably: the signed prekey carries a signature by the device's
 * long-term identity key, which clients verify (`x3dhInitiate` refuses otherwise) and
 * users can compare out of band as a safety number.
 */
import type { FastifyInstance } from "fastify";
import { badRequest, conflict, notFound } from "../lib/errors.ts";
import { newId } from "../lib/ids.ts";
import { today } from "../lib/time.ts";
import { recordSecurityEvent } from "../lib/security_events.ts";
import { SIGNED_PREKEY_ROTATION_MS } from "../../shared/crypto/identity.ts";

/** The client's own rotation window, in days: the server reports staleness against it. */
const SIGNED_PREKEY_ROTATION_DAYS = Math.floor(SIGNED_PREKEY_ROTATION_MS / 86_400_000);
import {
  asArray,
  asBase64Url,
  asInteger,
  asOptionalString,
  asSealedVault,
  asUsername,
} from "../lib/validate.ts";

const MAX_ONE_TIME_PREKEYS = 200;

export async function registerKeyRoutes(app: FastifyInstance): Promise<void> {
  const { db } = app;

  /** Publish (or re-publish) this device's identity and prekeys. */
  app.post("/api/keys/device", async (request) => {
    const user = await app.authenticate(request);
    await app.limit(request, "sensitive");
    const body = (request.body ?? {}) as Record<string, unknown>;
    const identityKey = asBase64Url(body.identityKey, "identityKey", 32);
    const signedPreKeyId = asInteger(body.signedPreKeyId, "signedPreKeyId", 0, 2 ** 31 - 1);
    const signedPreKey = asBase64Url(body.signedPreKey, "signedPreKey", 32);
    const signature = asBase64Url(body.signedPreKeySignature, "signedPreKeySignature", 64);
    const label = asOptionalString(body.label, "label", 40) || null;
    const oneTimePreKeys = asArray(body.oneTimePreKeys ?? [], "oneTimePreKeys", MAX_ONE_TIME_PREKEYS);

    const owner = await db.get<{ user_id: string; id: string; revoked_at: number | null }>(
      "SELECT id, user_id, revoked_at FROM devices WHERE identity_key = ?",
      [identityKey],
    );
    if (owner && owner.user_id !== user.id) {
      throw conflict("that identity key belongs to another account", "identity_key_taken");
    }
    // Revocation is final. Re-publishing the same identity key used to clear `revoked_at`,
    // which handed a stolen device its own undo button: the thief still holds the identity
    // private key, and one publish would put the device back in every prekey bundle. A new
    // device is a new identity, which is what the client generates on a fresh install.
    if (owner && owner.revoked_at !== null) {
      throw conflict(
        "that device identity was revoked; generate a new device identity instead",
        "device_revoked",
      );
    }

    const deviceId = owner?.id ?? newId();
    await db.transaction(async (tx) => {
      if (owner) {
        await tx.run(
          `UPDATE devices SET signed_prekey_id = ?, signed_prekey = ?, signed_prekey_signature = ?,
                              label = ?, rotated_day = ?
             WHERE id = ?`,
          [signedPreKeyId, signedPreKey, signature, label, today(), deviceId],
        );
      } else {
        await tx.run(
          `INSERT INTO devices (id, user_id, label, identity_key, signed_prekey_id, signed_prekey,
                                signed_prekey_signature, created_day, rotated_day)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [deviceId, user.id, label, identityKey, signedPreKeyId, signedPreKey, signature, today(), today()],
        );
      }
      await insertOneTimePreKeys(tx, deviceId, oneTimePreKeys);
    });

    return { deviceId, oneTimePreKeysStored: await countUnclaimed(db, deviceId) };
  });

  /** Top up one-time prekeys. Clients do this when the server reports a low count. */
  app.post("/api/keys/one-time", async (request) => {
    const user = await app.authenticate(request);
    await app.limit(request, "write");
    const body = (request.body ?? {}) as Record<string, unknown>;
    const device = await requireOwnDevice(app, user.id, body.deviceId);
    const keys = asArray(body.oneTimePreKeys, "oneTimePreKeys", MAX_ONE_TIME_PREKEYS);
    await db.transaction((tx) => insertOneTimePreKeys(tx, device.id, keys));
    return { oneTimePreKeysStored: await countUnclaimed(db, device.id) };
  });

  /**
   * How healthy is this device's key material? Drives client-side top-up and rotation.
   *
   * `signedPreKeyStale` is the fact that was missing (ADR-0078): the age was published and
   * nothing acted on it, so a browser left signed in for months kept one signed prekey the
   * whole time. The threshold is the client's own rotation window, imported rather than
   * repeated, because two copies of a number like this drift and the drift is invisible.
   */
  app.get("/api/keys/status", async (request) => {
    const user = await app.authenticate(request);
    await app.limit(request, "read");
    const devices = await db.all<{ id: string; label: string | null; rotated_day: number }>(
      "SELECT id, label, rotated_day FROM devices WHERE user_id = ? AND revoked_at IS NULL",
      [user.id],
    );
    return {
      devices: await Promise.all(
        devices.map(async (device) => ({
          deviceId: device.id,
          label: device.label,
          signedPreKeyAgeDays: today() - device.rotated_day,
          signedPreKeyStale: today() - device.rotated_day >= SIGNED_PREKEY_ROTATION_DAYS,
          oneTimePreKeysAvailable: await countUnclaimed(db, device.id),
        })),
      ),
    };
  });

  /**
   * The identity keys of a user's active devices, and nothing else. The same public facts
   * the bundle route publishes, minus the one-time prekey it would consume — so a client
   * that only needs to ask "is this key one of theirs?" (an invite arriving inside an
   * existing conversation, MD-6 / SEC-2026-024, ADR-0112) does not spend the peer's prekeys
   * or the tight `key_bundle` bucket to find out.
   */
  app.get("/api/keys/identity/:username", async (request) => {
    await app.authenticate(request);
    await app.limit(request, "read");
    const username = asUsername((request.params as { username: string }).username);
    const rows = await db.all<{ identity_key: string }>(
      `SELECT d.identity_key FROM devices d JOIN users u ON u.id = d.user_id
        WHERE u.username = ? AND u.status = 'active' AND d.revoked_at IS NULL`,
      [username],
    );
    if (rows.length === 0) throw notFound("no such user");
    return { username, identityKeys: rows.map((row) => row.identity_key) };
  });

  /** Claim a prekey bundle for every active device of a user. One-time keys are consumed. */
  app.get("/api/keys/bundle/:username", async (request) => {
    await app.authenticate(request);
    // Its own bucket, and a tight one: every call consumes one one-time prekey per device
    // of the target, so the ordinary `read` allowance would let one account drain another
    // account's prekeys in seconds and force every new session onto the signed prekey
    // alone (weaker forward secrecy for the first message). ADR-0035.
    await app.limit(request, "key_bundle");
    const username = asUsername((request.params as { username: string }).username);
    const target = await db.get<{ id: string; status: string }>(
      "SELECT id, status FROM users WHERE username = ?",
      [username],
    );
    if (!target || target.status !== "active") throw notFound("no such user");

    const devices = await db.all<{
      id: string;
      identity_key: string;
      signed_prekey_id: number;
      signed_prekey: string;
      signed_prekey_signature: string;
    }>(
      `SELECT id, identity_key, signed_prekey_id, signed_prekey, signed_prekey_signature
         FROM devices WHERE user_id = ? AND revoked_at IS NULL`,
      [target.id],
    );
    if (devices.length === 0) throw notFound("that user has no device that can receive messages");

    const bundles = [];
    for (const device of devices) {
      const oneTime = await claimOneTimePreKey(app, device.id);
      bundles.push({
        deviceId: device.id,
        identityKey: device.identity_key,
        signedPreKeyId: device.signed_prekey_id,
        signedPreKey: device.signed_prekey,
        signedPreKeySignature: device.signed_prekey_signature,
        oneTimePreKeyId: oneTime?.key_id ?? null,
        oneTimePreKey: oneTime?.public_key ?? null,
      });
    }
    return { username, bundles };
  });

  app.post("/api/keys/revoke", async (request) => {
    const user = await app.authenticate(request);
    await app.limit(request, "sensitive");
    const body = (request.body ?? {}) as Record<string, unknown>;
    const device = await requireOwnDevice(app, user.id, body.deviceId);
    await db.transaction(async (tx) => {
      await tx.run("UPDATE devices SET revoked_at = ? WHERE id = ?", [Date.now(), device.id]);
      await tx.run("DELETE FROM one_time_prekeys WHERE device_id = ?", [device.id]);
      // Undelivered envelopes for a revoked device are unreadable: drop them.
      await tx.run("DELETE FROM envelopes WHERE recipient_device_id = ?", [device.id]);
    });
    // The one destructive key-directory action; the owner's history had a label for it
    // (`device.revoked`) that nothing wrote until SEC-2026-019.
    await recordSecurityEvent(db, user.id, "device.revoked");
    return { ok: true };
  });

  /** Encrypted key backup. The server stores a blob it cannot open. */
  app.put("/api/keys/vault", async (request) => {
    const user = await app.authenticate(request);
    await app.limit(request, "sensitive");
    const body = (request.body ?? {}) as { sealedVault?: unknown };
    const sealed = asSealedVault(body.sealedVault);
    const existing = await db.get("SELECT user_id FROM vaults WHERE user_id = ?", [user.id]);
    if (existing) {
      await db.run("UPDATE vaults SET sealed = ?, updated_day = ? WHERE user_id = ?", [
        sealed,
        today(),
        user.id,
      ]);
    } else {
      await db.run("INSERT INTO vaults (user_id, sealed, updated_day) VALUES (?, ?, ?)", [
        user.id,
        sealed,
        today(),
      ]);
    }
    return { ok: true };
  });

  app.get("/api/keys/vault", async (request) => {
    const user = await app.authenticate(request);
    await app.limit(request, "read");
    const row = await db.get<{ sealed: string }>("SELECT sealed FROM vaults WHERE user_id = ?", [
      user.id,
    ]);
    return { sealedVault: row ? JSON.parse(row.sealed) : null };
  });
}

async function insertOneTimePreKeys(
  tx: FastifyInstance["db"],
  deviceId: string,
  keys: unknown[],
): Promise<void> {
  for (const entry of keys) {
    const key = entry as { keyId?: unknown; publicKey?: unknown };
    const keyId = asInteger(key.keyId, "oneTimePreKeys[].keyId", 0, 2 ** 31 - 1);
    const publicKey = asBase64Url(key.publicKey, "oneTimePreKeys[].publicKey", 32);
    const existing = await tx.get("SELECT id FROM one_time_prekeys WHERE device_id = ? AND key_id = ?", [
      deviceId,
      keyId,
    ]);
    if (existing) continue;
    await tx.run(
      "INSERT INTO one_time_prekeys (id, device_id, key_id, public_key) VALUES (?, ?, ?, ?)",
      [newId(), deviceId, keyId, publicKey],
    );
  }
}

async function countUnclaimed(db: FastifyInstance["db"], deviceId: string): Promise<number> {
  const row = await db.get<{ count: number }>(
    "SELECT COUNT(*) AS count FROM one_time_prekeys WHERE device_id = ? AND claimed_at IS NULL",
    [deviceId],
  );
  return Number(row?.count ?? 0);
}

/**
 * Two people fetching a bundle at the same moment must never receive the same one-time
 * prekey: the whole value of the key is that it is used once, and handing one out twice
 * costs the forward secrecy it exists to provide.
 *
 * This used to be SELECT, then DELETE, inside a transaction — which is not the same thing
 * as atomic. On SQLite it was safe by accident, because that driver serialises every write
 * behind one handle; on PostgreSQL at READ COMMITTED, two transactions read the same row
 * and both returned it, and the suite proved it the first time it ran against a real
 * PostgreSQL (`docs/SELF_CRITIQUE.md`, finding 8).
 *
 * The fix is one statement: the delete chooses the row, and `RETURNING` says whether *this*
 * caller is the one that took it. A caller that loses the race gets nothing back and tries
 * again — three times, because losing three in a row means the device is out of keys rather
 * than busy, and the bundle is still usable without one (the signed prekey covers it, with
 * weaker forward secrecy, which is exactly what the protocol documents).
 */
async function claimOneTimePreKey(
  app: FastifyInstance,
  deviceId: string,
): Promise<{ key_id: number; public_key: string } | null> {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const claimed = await app.db.all<{ key_id: number; public_key: string }>(
      `DELETE FROM one_time_prekeys
        WHERE id = (SELECT id FROM one_time_prekeys
                     WHERE device_id = ? AND claimed_at IS NULL
                     ORDER BY key_id LIMIT 1)
        RETURNING key_id, public_key`,
      [deviceId],
    );
    if (claimed.length > 0) return claimed[0]!;
    if ((await countUnclaimed(app.db, deviceId)) === 0) return null;
  }
  return null;
}

async function requireOwnDevice(
  app: FastifyInstance,
  userId: string,
  deviceId: unknown,
): Promise<{ id: string }> {
  if (typeof deviceId !== "string") throw badRequest("deviceId is required");
  const device = await app.db.get<{ id: string }>(
    "SELECT id FROM devices WHERE id = ? AND user_id = ?",
    [deviceId, userId],
  );
  if (!device) throw notFound("no such device on this account");
  return device;
}
