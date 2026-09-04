/**
 * Dispute evidence, without the evidence (MKT-1, ADR-0074).
 *
 * The interesting tests here are the negative ones. A commitment scheme on a server that
 * cannot read the file is worth having only if it is honest about its limits, so these check
 * that the server stores a digest and nothing else, that it cannot be used as a channel or as
 * storage, that a stranger cannot even learn the order exists, and that a party cannot commit
 * to a closed case or rewrite what they committed to.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createHmac } from "node:crypto";
import {
  approveSeller,
  fund,
  promote,
  register,
  startTestServer,
  type TestClient,
  type TestServer,
} from "./helpers.ts";
import { MAX_EVIDENCE_PER_PARTY } from "../src/server/lib/evidence.ts";
import { listColumns } from "./database.ts";

let server: TestServer;

beforeEach(async () => {
  server = await startTestServer();
  await register(server, "root"); // the first account is the instance's administrator
});
afterEach(async () => {
  await server.close();
});

/** The digest the browser computes: HMAC-SHA256 over the bytes, keyed with the order id. */
const digestFor = (orderId: string, bytes: string) =>
  createHmac("sha256", orderId).update(bytes).digest("hex");

interface Deal {
  orderId: string;
  buyer: TestClient;
  seller: TestClient;
}

async function acceptedOrder(prefix: string): Promise<Deal> {
  const seller = await register(server, `${prefix}seller`);
  await approveSeller(server, seller, `${prefix} Works`);
  const listing = await seller.post<{ id: string }>("/api/market/listings", {
    title: `${prefix} service`,
    description: "Work delivered through this platform, honestly described in full.",
    category: "consulting",
    kind: "digital_good",
    priceXmr: "0.2",
  });
  const buyer = await register(server, `${prefix}buyer`);
  await fund(server, buyer, "1");
  const order = await buyer.post<{ id: string }>("/api/market/orders", {
    listingId: listing.body.id,
  });
  const accepted = await seller.post(`/api/market/orders/${order.body.id}/status`, {
    status: "accepted",
  });
  expect(accepted.status).toBe(200);
  return { orderId: order.body.id, buyer, seller };
}

describe("a party can commit to bytes the server never sees", () => {
  it("records both sides, says who committed and whether it was before the dispute", async () => {
    const { orderId, buyer, seller } = await acceptedOrder("commit");
    const good = digestFor(orderId, "the file the seller says they sent");

    const sellerCommit = await seller.post(`/api/market/orders/${orderId}/evidence`, {
      digest: good,
      kind: "delivery",
    });
    expect(sellerCommit.status).toBe(200);

    // The buyer opens a dispute, then commits to what they say they received.
    const disputed = await buyer.post(`/api/market/orders/${orderId}/status`, {
      status: "disputed",
      reason: "The archive will not open and the seller has stopped replying to me.",
    });
    expect(disputed.status).toBe(200);
    // Requests in one test land inside the same millisecond, and a tie counts as "before"
    // (the committer gets the benefit of a 1 ms doubt — `lib/evidence.ts`). Age the seller's
    // commitment by a second so the sequence under test is the real one: committed, then
    // disputed, then the buyer's digest published after the argument started.
    await server.db.run(
      "UPDATE order_evidence SET created_at = created_at - 2000 WHERE kind = 'delivery'",
    );
    // The dispute itself moves back too. Without this the buyer's commitment can land in the
    // *same millisecond* as the dispute event, which the rule above counts as "before" — a
    // real property, and a flaky assertion. Ageing both rows puts the three moments in the
    // order the test is about, whatever the machine's timing.
    await server.db.run(
      "UPDATE order_events SET created_at = created_at - 1000 WHERE to_status = 'disputed'",
    );
    const buyerCommit = await buyer.post(`/api/market/orders/${orderId}/evidence`, {
      digest: digestFor(orderId, "the broken file the buyer received"),
      kind: "attachment",
    });
    expect(buyerCommit.status).toBe(200);

    const view = await buyer.get<{
      evidence: Array<{ by: string; kind: string; digest: string; beforeDispute: boolean }>;
    }>(`/api/market/orders/${orderId}/evidence`);
    expect(view.body.evidence).toHaveLength(2);
    // Oldest first, with the side and the fact a moderator uses: the seller's digest existed
    // before the argument, the buyer's did not.
    expect(view.body.evidence[0]).toMatchObject({ by: "seller", kind: "delivery", beforeDispute: true });
    expect(view.body.evidence[1]).toMatchObject({ by: "buyer", kind: "attachment", beforeDispute: false });
    // Both parties see the same list — a dispute where they see different records is one
    // nobody can trust.
    const asSeller = await seller.get<{ evidence: unknown[] }>(`/api/market/orders/${orderId}/evidence`);
    expect(asSeller.body.evidence).toEqual(view.body.evidence);

    // And the digest is the *keyed* one: the same bytes under a different order id do not
    // match, which is what stops this table being an index of who holds which known file.
    expect(digestFor("some-other-order", "the file the seller says they sent")).not.toBe(good);
  });

  it("treats a repeated commitment of the same bytes as one commitment", async () => {
    const { orderId, seller } = await acceptedOrder("twice");
    const digest = digestFor(orderId, "one file, two clicks");
    expect((await seller.post(`/api/market/orders/${orderId}/evidence`, { digest, kind: "delivery" })).status).toBe(200);
    const again = await seller.post<{ error: string }>(`/api/market/orders/${orderId}/evidence`, {
      digest,
      kind: "delivery",
    });
    expect(again.status).toBe(409);
    expect(again.body.error).toBe("already_committed");
    expect(await server.db.all("SELECT id FROM order_evidence")).toHaveLength(1);
  });

  it("refuses anything that is not a digest, and refuses to be storage", async () => {
    const { orderId, buyer } = await acceptedOrder("shapes");
    for (const digest of ["not-a-digest", "A".repeat(64), "ab".repeat(40), 42, null]) {
      const refused = await buyer.post<{ error: string }>(`/api/market/orders/${orderId}/evidence`, {
        digest,
        kind: "other",
      });
      expect(refused.status, String(digest)).toBe(400);
      expect(refused.body.error).toBe("invalid_digest");
    }
    // A kind is a word from a list, not the party's prose: there is no free-text field on
    // this route at all, so it cannot become a second, unmoderated message channel.
    const prose = await buyer.post<{ error: string }>(`/api/market/orders/${orderId}/evidence`, {
      digest: digestFor(orderId, "x"),
      kind: "here is what actually happened, at length",
    });
    expect(prose.status).toBe(400);

    // Nor unbounded: a party gets ten commitments on an order.
    for (let index = 0; index < MAX_EVIDENCE_PER_PARTY; index += 1) {
      const response = await buyer.post(`/api/market/orders/${orderId}/evidence`, {
        digest: digestFor(orderId, `file ${index}`),
        kind: "other",
      });
      expect(response.status).toBe(200);
    }
    const full = await buyer.post<{ error: string }>(`/api/market/orders/${orderId}/evidence`, {
      digest: digestFor(orderId, "one too many"),
      kind: "other",
    });
    expect(full.status).toBe(409);
    expect(full.body.error).toBe("evidence_full");
  });

  it("has nowhere to put a file even if somebody wanted to", async () => {
    const columns = await listColumns(server.db, "order_evidence");
    expect(columns.sort()).toEqual(
      ["created_at", "digest", "id", "kind", "order_id", "user_id"].sort(),
    );
  });
});

describe("who may commit, and when", () => {
  it("gives a stranger the same answer as a wrong order id", async () => {
    const { orderId } = await acceptedOrder("stranger");
    const nosy = await register(server, "nosyparker");
    const read = await nosy.get(`/api/market/orders/${orderId}/evidence`);
    expect(read.status).toBe(404);
    const write = await nosy.post(`/api/market/orders/${orderId}/evidence`, {
      digest: digestFor(orderId, "not mine"),
      kind: "other",
    });
    expect(write.status).toBe(404);
  });

  it("lets a moderator read a dispute's digests and never add one", async () => {
    const { orderId, buyer, seller } = await acceptedOrder("moderated");
    await seller.post(`/api/market/orders/${orderId}/evidence`, {
      digest: digestFor(orderId, "the delivery"),
      kind: "delivery",
    });
    await buyer.post(`/api/market/orders/${orderId}/status`, {
      status: "disputed",
      reason: "What arrived is not what the listing described, and I want a refund.",
    });

    const moderator = await register(server, "evidencemod");
    await promote(server, "evidencemod", "moderator");
    const read = await moderator.get<{ evidence: Array<{ by: string }> }>(
      `/api/market/orders/${orderId}/evidence`,
    );
    expect(read.status).toBe(200);
    expect(read.body.evidence).toHaveLength(1);

    // A moderator putting a fact into a case they are about to decide: not a route.
    const attempt = await moderator.post(`/api/market/orders/${orderId}/evidence`, {
      digest: digestFor(orderId, "a moderator's own file"),
      kind: "other",
    });
    expect(attempt.status).toBe(404);

    // The dispute in the moderation queue carries the same records the parties see.
    const queue = await moderator.get<{
      reports: Array<{ order: { evidence: Array<{ by: string; beforeDispute: boolean }> } | null }>;
    }>("/api/moderation/queue");
    const dispute = queue.body.reports.find((report) => report.order?.evidence.length);
    expect(dispute?.order?.evidence[0]).toMatchObject({ by: "seller", beforeDispute: true });
  });

  it("refuses a commitment on an order that is over", async () => {
    const { orderId, buyer, seller } = await acceptedOrder("finished");
    await seller.post(`/api/market/orders/${orderId}/delivery`, { manual: true });
    const completed = await buyer.post(`/api/market/orders/${orderId}/status`, { status: "completed" });
    expect(completed.status).toBe(200);

    const late = await buyer.post<{ error: string }>(`/api/market/orders/${orderId}/evidence`, {
      digest: digestFor(orderId, "an afterthought"),
      kind: "other",
    });
    expect(late.status).toBe(409);
    expect(late.body.error).toBe("stale_status");
  });
});
