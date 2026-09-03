import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { register, startTestServer, type TestServer } from "./helpers.ts";
import { listColumns } from "./database.ts";

let server: TestServer;

beforeEach(async () => {
  server = await startTestServer();
});
afterEach(async () => {
  await server.close();
});

/** One device for the recipient, so an envelope has somewhere to go. */
async function deviceFor(username: string): Promise<string> {
  const client = await register(server, username);
  const { body } = await client.post<{ deviceId: string }>("/api/keys/device", {
    identityKey: "A".repeat(43),
    signedPreKeyId: 1,
    signedPreKey: "B".repeat(43),
    signedPreKeySignature: "C".repeat(86),
    oneTimePreKeys: [],
  });
  return body.deviceId;
}

/** A send with no cookies at all: the token is the only authority in the request. */
async function sealedSend(token: string, to: string, deviceId: string) {
  const response = await server.app.inject({
    method: "POST",
    url: "/api/messages",
    headers: {
      "content-type": "application/json",
      "x-send-token": token,
      origin: "http://localhost",
      host: "localhost",
    },
    payload: JSON.stringify({
      to,
      channel: "z".repeat(43),
      messages: [{ deviceId, payload: "ciphertext-the-server-cannot-read" }],
    }),
  });
  return { status: response.statusCode, body: response.json() as Record<string, unknown> };
}

describe("sealed sender (ADR-0084)", () => {
  it("delivers an envelope for a request that carries no session at all", async () => {
    const deviceId = await deviceFor("alice");
    const sender = await register(server, "bob");
    const minted = await sender.post<{ tokens: string[] }>("/api/messages/tokens", {});
    expect(minted.status).toBe(200);
    expect(minted.body.tokens.length).toBe(server.config.sendTokenBatch);

    const token = minted.body.tokens[0] as string;
    const sent = await sealedSend(token, "alice", deviceId);
    expect(sent.status).toBe(200);
    expect(sent.body.delivered).toBe(1);

    // And the row it wrote knows no more than it did before: the sender is not a column
    // here, and now it was never in the request either.
    const columns = await listColumns(server.db, "envelopes");
    expect(columns).not.toContain("sender_user_id");
    expect(columns).not.toContain("sender_id");
  });

  it("spends a token once, and refuses one it never issued", async () => {
    const deviceId = await deviceFor("carol");
    const sender = await register(server, "dave");
    const minted = await sender.post<{ tokens: string[] }>("/api/messages/tokens", {});
    const token = minted.body.tokens[1] as string;

    expect((await sealedSend(token, "carol", deviceId)).status).toBe(200);
    // The same token again is worth nothing: accepting it *is* deleting it.
    const replay = await sealedSend(token, "carol", deviceId);
    expect(replay.status).toBe(401);
    expect(replay.body.error).toBe("unauthorized");
    // An invented token is refused with the same answer, which is the point of the answer.
    const forged = await sealedSend("f".repeat(43), "carol", deviceId);
    expect(forged.status).toBe(401);
    expect(forged.body.error).toBe("unauthorized");
  });

  it("stores nothing that can be joined to the account that asked for the tokens", async () => {
    const sender = await register(server, "erin");
    await sender.post("/api/messages/tokens", {});
    const columns = await listColumns(server.db, "send_tokens");
    expect([...columns].sort()).toEqual(["expires_at", "token_hash"]);

    // The plain tokens are not in the table — only their hashes, the way sessions work —
    // and the expiries are jittered, so a batch is not one grouping key.
    const rows = await server.db.all<{ expires_at: number }>("SELECT expires_at FROM send_tokens");
    expect(rows.length).toBe(server.config.sendTokenBatch);
    expect(new Set(rows.map((row) => row.expires_at)).size).toBeGreaterThan(1);
  });

  it("refuses an expired token, and housekeeping deletes it", async () => {
    const deviceId = await deviceFor("frank");
    const sender = await register(server, "grace");
    const minted = await sender.post<{ tokens: string[] }>("/api/messages/tokens", {});
    await server.db.run("UPDATE send_tokens SET expires_at = ?", [Date.now() - 1000]);

    expect((await sealedSend(minted.body.tokens[0] as string, "frank", deviceId)).status).toBe(401);
    const { pruneSendTokens } = await import("../src/server/lib/send_tokens.ts");
    await pruneSendTokens(server.db);
    const left = await server.db.get<{ count: number }>("SELECT COUNT(*) AS count FROM send_tokens");
    expect(Number(left?.count ?? -1)).toBe(0);
  });

  it("still refuses an anonymous send with no token and no session", async () => {
    const deviceId = await deviceFor("heidi");
    const response = await server.app.inject({
      method: "POST",
      url: "/api/messages",
      headers: { "content-type": "application/json", origin: "http://localhost", host: "localhost" },
      payload: JSON.stringify({
        to: "heidi",
        channel: "y".repeat(43),
        messages: [{ deviceId, payload: "ciphertext" }],
      }),
    });
    // No token means the old rule applies: this request has no cookies, so it fails the
    // CSRF check that the sealed shape — and only the sealed shape — is exempt from.
    expect(response.statusCode).toBe(403);
  });

  it("does not let a token stand in for a session anywhere else", async () => {
    const sender = await register(server, "judy");
    const minted = await sender.post<{ tokens: string[] }>("/api/messages/tokens", {});
    const token = minted.body.tokens[0] as string;
    for (const url of ["/api/wallet/withdrawals", "/api/market/listings", "/api/messages/tokens"]) {
      const response = await server.app.inject({
        method: "POST",
        url,
        headers: {
          "content-type": "application/json",
          "x-send-token": token,
          origin: "http://localhost",
          host: "localhost",
        },
        payload: JSON.stringify({}),
      });
      expect([401, 403]).toContain(response.statusCode);
    }
  });
});
