/**
 * Points 83 and 84: moderation that cannot reach a private message, and abuse controls that
 * do not turn the platform into a surveillance system.
 *
 * The structural assertions matter more than the behavioural ones here. "A moderator cannot
 * read your messages" is only worth writing down if something fails when a future route
 * quietly starts selecting from `envelopes`.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import {
  approveSeller,
  promote,
  fund,
  register,
  startTestServer,
  type TestClient,
  type TestServer,
} from "./helpers.ts";
import { actAs, installBrowserGlobals, installFetch, signUp, type Persona } from "./browser.ts";
import { generatePhrase } from "../src/shared/crypto/mnemonic.ts";
import { lock, ready, state } from "../src/client/state.ts";
import {
  blockedPeers,
  conversations,
  isBlocked,
  receiveMessages,
  sendMessage,
  setBlocked,
  startConversation,
} from "../src/client/messaging.ts";
import { listColumns } from "./database.ts";

const read = (path: string) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

let server: TestServer;
let recoveryPhrase = "";

beforeEach(async () => {
  await ready();
  recoveryPhrase ||= generatePhrase(24);
  server = await startTestServer();
  installBrowserGlobals();
  installFetch(server);
  lock();
});
afterEach(async () => {
  await server.close();
});

describe("the four moderation lanes stay apart", () => {
  it("has no moderation code path that touches a private store", () => {
    const moderation = read("src/server/routes/moderation.ts");
    for (const table of ["envelopes", "vaults", "attachments", "deliveries"]) {
      expect(moderation, `moderation must not read ${table}`).not.toContain(table);
    }
    // And no route anywhere claims to decrypt anything.
    expect(moderation).not.toMatch(/decrypt|plaintext/i);
  });

  it("never puts an order's channel in front of a moderator", async () => {
    const seller = await register(server, "seller");
    const buyer = await register(server, "buyer");
    await fund(server, buyer, "5");
    await approveSeller(server, seller, "Seller Co");
    const listing = await seller.post<{ id: string }>("/api/market/listings", {
      title: "A careful piece of software",
      description: "Written slowly, and documented properly, by a person.",
      category: "software",
      kind: "digital_good",
      priceXmr: "0.025",
    });
    const order = await buyer.post<{ id: string; channel: string }>("/api/market/orders", {
      listingId: listing.body.id,
    });
    await seller.post(`/api/market/orders/${order.body.id}/status`, { status: "accepted" });
    await buyer.post(`/api/market/orders/${order.body.id}/status`, {
      status: "disputed",
      reason: "The seller has not answered for a week and the goods never arrived.",
    });

    const moderator = await register(server, "mod");
    await promote(server, "mod", "moderator");
    const queue = await moderator.get<{ reports: Array<Record<string, unknown>> }>(
      "/api/moderation/queue",
    );
    const body = JSON.stringify(queue.body);
    expect(body).toContain("has not answered for a week"); // the buyer's own words
    expect(body).not.toContain(order.body.channel); // and nothing that opens the conversation
  });

  it("takes a report about private abuse as the reporter's words, and nothing else", async () => {
    const victim = await register(server, "victim");
    await register(server, "pest");
    const report = await victim.post<{ id: string }>("/api/moderation/reports", {
      targetType: "user",
      targetId: "pest",
      reason: "harassment",
      details: "They have sent me twenty messages tonight. I have not replied to any of them.",
    });
    expect(report.status).toBe(200);

    const row = await server.db.get<{ details: string; target_id: string }>(
      "SELECT details, target_id FROM reports WHERE id = ?",
      [report.body.id],
    );
    expect(row!.target_id).toBe("pest");
    expect(row!.details).toContain("twenty messages");
    // The report is the only trace; no message was copied anywhere by the server.
    const envelopes = await server.db.get<{ n: number }>("SELECT COUNT(*) AS n FROM envelopes");
    expect(envelopes!.n).toBe(0);
  });

  it("keeps a dispute out of the plain report route", async () => {
    const user = await register(server, "someone");
    const response = await user.post("/api/moderation/reports", {
      targetType: "order",
      targetId: "aaaaaaaaaaaa",
      reason: "dispute",
      details: "trying to file a dispute against an order that is not mine",
    });
    expect(response.status).toBe(400);
  });
});

describe("blocking is the recipient's decision", () => {
  let alice: Persona;
  let bob: Persona;

  beforeEach(async () => {
    await fetch("/");
    alice = await signUp("alice", recoveryPhrase);
    lock();
    localStorage.clear();
    await fetch("/");
    bob = await signUp("bob", recoveryPhrase);
  });

  it("discards a blocked peer's messages without telling the server", async () => {
    await actAs(alice);
    const conversation = await startConversation("bob");
    await sendMessage(conversation, "first one, before the block");

    await actAs(bob);
    await receiveMessages();
    const incoming = conversations()[0]!;
    await setBlocked("alice", true);
    expect(isBlocked("Alice")).toBe(true);
    expect(blockedPeers()).toEqual(["alice"]);

    await actAs(alice);
    await sendMessage(conversations()[0]!, "and one after it");

    await actAs(bob);
    // Decrypted (the ratchet has to advance) and then dropped: nothing stored, nothing shown.
    expect(await receiveMessages()).toBe(0);
    expect(conversations()[0]!.messages.map((message) => message.text)).toEqual([
      "first one, before the block",
    ]);
    // Acknowledged all the same, so the server does not keep it either.
    const left = await server.db.get<{ n: number }>("SELECT COUNT(*) AS n FROM envelopes");
    expect(left!.n).toBe(0);

    // Unblocking restores the conversation, and the session survived the block.
    await setBlocked("alice", false);
    await actAs(alice);
    await sendMessage(conversations()[0]!, "still here?");
    await actAs(bob);
    expect(await receiveMessages()).toBe(1);
    expect(conversations()[0]!.messages.at(-1)!.text).toBe("still here?");
    void incoming;
  });

  it("refuses to write to someone this device blocked", async () => {
    await actAs(alice);
    const conversation = await startConversation("bob");
    await setBlocked("bob", true);
    await expect(sendMessage(conversation, "hello again")).rejects.toThrow(/unblock/);
  });

  it("keeps the block list out of every request and out of the server", async () => {
    await actAs(alice);
    await setBlocked("bob", true);
    const rows = await server.db.all<{ sealed: string }>("SELECT sealed FROM vaults");
    // The vault holds it, sealed. Nothing else does: no table, no column, no route.
    expect(JSON.stringify(rows)).not.toContain("blocked");
    expect(state.vault!.blocked).toEqual(["bob"]);
    const routes = server.app.routeInventory.map((route) => route.url);
    expect(routes.filter((url) => /block/i.test(url))).toEqual([]);
  });
});

describe("abuse controls exist without watching anybody", () => {
  it("keeps the tightest buckets on the cheapest things to automate", async () => {
    const { DEFAULT_LIMITS } = await import("../src/server/lib/rate_limit.ts");
    expect(DEFAULT_LIMITS.register.burst).toBeLessThanOrEqual(5);
    expect(DEFAULT_LIMITS.seller_application.perMinute).toBeLessThanOrEqual(0.5);
    expect(DEFAULT_LIMITS.attachment.perMinute).toBeLessThanOrEqual(3);
  });

  it("stores no behavioural profile: the rate limiter holds hashes and a count", async () => {
    const user = await register(server, "watched");
    await user.get("/api/market/listings");
    const columns = await listColumns(server.db, "rate_limits");
    expect([...columns].sort()).toEqual([
      "bucket",
      "tokens",
      "updated_at",
    ]);
    const rows = await server.db.all<{ bucket: string }>("SELECT bucket FROM rate_limits");
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) expect(row.bucket).not.toContain("watched");
  });

  it("documents every control, and the line abuse detection may not cross", () => {
    const doc = read("docs/MODERATION.md");
    for (const control of [
      "spam",
      "report",
      "seller",
      "dispute",
      "rate-limit",
      "No content scanning",
      "No behavioural profiling",
      "No shadow bans",
    ]) {
      expect(doc.toLowerCase(), control).toContain(control.toLowerCase());
    }
  });
});

/** Kept so the import of `TestClient` stays meaningful to a reader of the signatures above. */
export type { TestClient };
