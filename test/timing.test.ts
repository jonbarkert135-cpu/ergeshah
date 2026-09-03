import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { register, startTestServer, type TestClient, type TestServer } from "./helpers.ts";
import { delayStepsSeconds, jitteredInterval } from "../src/shared/jitter.ts";

let server: TestServer;

beforeEach(async () => {
  server = await startTestServer();
});
afterEach(async () => {
  await server.close();
});

async function deviceFor(username: string): Promise<{ client: TestClient; deviceId: string }> {
  const client = await register(server, username);
  const { body } = await client.post<{ deviceId: string }>("/api/keys/device", {
    identityKey: "A".repeat(43),
    signedPreKeyId: 1,
    signedPreKey: "B".repeat(43),
    signedPreKeySignature: "C".repeat(86),
    oneTimePreKeys: [],
  });
  return { client, deviceId: body.deviceId };
}

describe("delivery timing noise (ADR-0085)", () => {
  it("holds a delayed envelope until its moment, then hands it over", async () => {
    const { client: recipient, deviceId } = await deviceFor("nina");
    const sender = await register(server, "omar");
    const sent = await sender.post("/api/messages", {
      to: "nina",
      channel: "q".repeat(43),
      messages: [{ deviceId, payload: "ciphertext" }],
      delaySeconds: 60,
    });
    expect(sent.status).toBe(200);

    const early = await recipient.get<{ envelopes: unknown[] }>(`/api/messages?deviceId=${deviceId}`);
    expect(early.body.envelopes).toHaveLength(0);
    // The row is there and is simply not available yet: a delay is not a deletion.
    const pending = await server.db.get<{ count: number }>("SELECT COUNT(*) AS count FROM envelopes");
    expect(Number(pending?.count)).toBe(1);

    await server.db.run("UPDATE envelopes SET available_at = ?", [Date.now() - 1]);
    const later = await recipient.get<{ envelopes: unknown[] }>(`/api/messages?deviceId=${deviceId}`);
    expect(later.body.envelopes).toHaveLength(1);
  });

  it("delivers immediately when no delay was asked for", async () => {
    const { client: recipient, deviceId } = await deviceFor("pia");
    const sender = await register(server, "quinn");
    await sender.post("/api/messages", {
      to: "pia",
      channel: "r".repeat(43),
      messages: [{ deviceId, payload: "ciphertext" }],
    });
    const now = await recipient.get<{ envelopes: unknown[] }>(`/api/messages?deviceId=${deviceId}`);
    expect(now.body.envelopes).toHaveLength(1);
  });

  it("quantises the delay and refuses one longer than the deployment allows", async () => {
    const { deviceId } = await deviceFor("rosa");
    const sender = await register(server, "sam");
    await sender.post("/api/messages", {
      to: "rosa",
      channel: "s".repeat(43),
      messages: [{ deviceId, payload: "ciphertext" }],
      delaySeconds: 37,
    });
    const row = await server.db.get<{ created_at: number; available_at: number }>(
      "SELECT created_at, available_at FROM envelopes",
    );
    // 37 seconds is not a value anybody else would have picked; 45 is one of eight.
    expect(Number(row?.available_at) - Number(row?.created_at)).toBe(45_000);

    const tooLong = await sender.post("/api/messages", {
      to: "rosa",
      channel: "s".repeat(43),
      messages: [{ deviceId, payload: "ciphertext" }],
      delaySeconds: server.config.maxDeliveryDelaySeconds + 60,
    });
    expect(tooLong.status).toBe(400);
  });

  it("draws poll intervals around the base without ever reaching zero", () => {
    expect(jitteredInterval(10_000, 0)).toBe(6_000);
    expect(jitteredInterval(10_000, 1)).toBe(14_000);
    expect(jitteredInterval(10_000, 0.5)).toBe(10_000);
    // Out-of-range input cannot produce a hot loop or a stalled client.
    expect(jitteredInterval(10_000, -5)).toBe(6_000);
    expect(jitteredInterval(10_000, 5)).toBe(14_000);
  });

  it("draws delays in whole steps, never zero, never over the cap", () => {
    const drawn = new Set<number>();
    for (let unit = 0; unit < 1; unit += 0.01) drawn.add(delayStepsSeconds(120, unit));
    expect([...drawn].sort((a, b) => a - b)).toEqual([15, 30, 45, 60, 75, 90, 105, 120]);
    // A deployment that caps below one step has the feature switched off, not rounded up.
    expect(delayStepsSeconds(10, 0.9)).toBe(0);
  });
});
