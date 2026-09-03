/**
 * Point 49: every upload is hostile.
 *
 * The eight vectors from the brief, each checked against the thing that actually stops it
 * here — which for most of them is the shape of the system (the server stores ciphertext it
 * cannot open, names nothing after a request, and serves no stored bytes as a document)
 * rather than an inspection step that could be bypassed.
 */
import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  approveSeller,
  register,
  startTestServer,
  type TestClient,
  type TestServer,
} from "./helpers.ts";
import { DEFAULT_LIMITS } from "../src/server/lib/rate_limit.ts";
import { base64UrlBytes, safeFileName } from "../src/shared/uploads.ts";
import { listColumns } from "./database.ts";

const read = (path: string) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

let server: TestServer;
let seller: TestClient;
let buyer: TestClient;

/** Base64url of arbitrary bytes, the only shape this API accepts for a delivery. */
function b64(bytes: Uint8Array | string): string {
  const buffer = typeof bytes === "string" ? Buffer.from(bytes, "binary") : Buffer.from(bytes);
  return buffer.toString("base64url");
}

/** A fresh order in `accepted`, ready to be delivered. */
async function acceptedOrder(title: string): Promise<string> {
  const listing = await seller.post<{ id: string }>("/api/market/listings", {
    title,
    description: "Something digital, delivered as bytes the server cannot read.",
    category: "software",
    kind: "digital_good",
    priceMinor: 500,
    currency: "USD",
  });
  const order = await buyer.post<{ id: string }>("/api/market/orders", {
    listingId: listing.body.id,
  });
  const accepted = await seller.post(`/api/market/orders/${order.body.id}/status`, {
    status: "accepted",
  });
  expect(accepted.status, JSON.stringify(accepted.body)).toBe(200);
  return order.body.id;
}

beforeAll(async () => {
  server = await startTestServer({
    rateLimits: { ...DEFAULT_LIMITS, register: { burst: 50, perMinute: 50 } },
  });
  seller = await register(server, "uploadseller");
  await approveSeller(server, seller, "Upload Seller");
  buyer = await register(server, "uploadbuyer");
});

afterAll(async () => {
  await server.close();
});

describe("MIME and extension spoofing", () => {
  it("refuses a body that tries to tell the server about a file", async () => {
    const order = await acceptedOrder("Spoofing Probe One");
    for (const extra of [
      { filename: "invoice.pdf" },
      { mimeType: "image/png" },
      { contentType: "text/html" },
      { path: "../../etc/passwd" },
      { name: "payload.svg" },
    ]) {
      const response = await seller.post(`/api/market/orders/${order}/delivery`, {
        ciphertext: b64("harmless-bytes"),
        ...extra,
      });
      expect(response.status, JSON.stringify(extra)).toBe(400);
      expect(response.body).toMatchObject({ error: "unexpected_field" });
    }
  });

  it("stores no type, no name and no extension anywhere", async () => {
    const columns = await listColumns(server.db, "deliveries");
    expect([...columns].sort()).toEqual([
      "ciphertext",
      "created_at",
      "expires_at",
      "id",
      "order_id",
    ]);
  });
});

describe("what the server does with hostile bytes", () => {
  it("stores an SVG with a script, an ELF header and a zip bomb identically: as opaque base64", async () => {
    for (const [label, payload] of [
      ["svg", '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'],
      ["elf", "\x7fELF\x02\x01\x01\x00 executable"],
      ["zip", "PK\x03\x04 followed by a petabyte of zeroes, allegedly"],
      ["html", "<html><script>fetch('http://elsewhere')</script>"],
    ] as const) {
      const order = await acceptedOrder(`Hostile Bytes ${label}`);
      const delivered = await seller.post(`/api/market/orders/${order}/delivery`, {
        ciphertext: b64(payload),
      });
      expect(delivered.status, label).toBe(200);

      const collected = await server.app.inject({
        method: "GET",
        url: `/api/market/orders/${order}/delivery`,
        headers: { cookie: `session=${buyer.cookie("session")}` },
      });
      expect(collected.statusCode, label).toBe(200);
      // JSON, base64, nosniff, no filename, nothing a browser would ever render.
      expect(collected.headers["content-type"], label).toMatch(/application\/json/);
      expect(collected.headers["x-content-type-options"], label).toBe("nosniff");
      expect(collected.headers["content-disposition"], label).toBeUndefined();
      const body = collected.json() as { ciphertext: string };
      expect(Buffer.from(body.ciphertext, "base64url").toString("binary"), label).toBe(payload);
      // The raw markup never appears in a response body outside the base64 field.
      expect(collected.body, label).not.toContain("<script>");
    }
  });

  it("refuses a blob larger than the configured cap, counted in bytes and not characters", async () => {
    const order = await acceptedOrder("Oversized Probe");
    const cap = server.config.maxDeliveryBytes;
    const tooBig = "A".repeat(Math.ceil(((cap + 1024) * 4) / 3));
    const response = await seller.post(`/api/market/orders/${order}/delivery`, {
      ciphertext: tooBig,
    });
    expect([400, 413]).toContain(response.status);
    // A payload just under the character cap but over the byte cap used to pass: 4 characters
    // of base64 are 3 bytes, so a character limit is a third too generous.
    expect(base64UrlBytes("A".repeat(Math.ceil((cap * 4) / 3) + 8))).toBeGreaterThan(cap);
    expect(base64UrlBytes("AAAAA")).toBeNull();
  });

  it("refuses a string that is not base64 at all", async () => {
    const order = await acceptedOrder("Not Base64 Probe");
    for (const bad of ["AAAAA", "not base64!", "%2e%2e%2f", "AAAA===="]) {
      const response = await seller.post(`/api/market/orders/${order}/delivery`, {
        ciphertext: bad,
      });
      expect(response.status, bad).toBe(400);
    }
  });

  it("never accepts a second blob for one order", async () => {
    const order = await acceptedOrder("One Blob Probe");
    expect(
      (await seller.post(`/api/market/orders/${order}/delivery`, { ciphertext: b64("first") }))
        .status,
    ).toBe(200);
    const second = await seller.post(`/api/market/orders/${order}/delivery`, {
      ciphertext: b64("second"),
    });
    expect(second.status).toBeGreaterThanOrEqual(400);
  });
});

describe("path traversal", () => {
  it("has no filesystem path derived from a request anywhere in the server", () => {
    // The static route reads an explicit directory listing at boot; a path built from a URL
    // is what makes traversal possible, so its absence is the control being asserted.
    const statics = read("src/server/routes/static.ts");
    expect(statics).not.toMatch(/join\([^)]*request/);
    expect(statics).not.toMatch(/readFileSync\([^)]*request/);
  });

  it("answers a traversal attempt with 404, not with a file", async () => {
    for (const url of [
      "/assets/../package.json",
      "/assets/..%2f..%2fpackage.json",
      "/../../etc/passwd",
      "/api/market/orders/..%2f..%2fetc%2fpasswd/delivery",
      "/api/market/orders/....//....//package.json/delivery",
    ]) {
      const response = await server.app.inject({ method: "GET", url });
      expect([400, 401, 404], url).toContain(response.statusCode);
      expect(response.body, url).not.toContain("\"dependencies\"");
      expect(response.body, url).not.toContain("root:x:");
    }
  });
});

describe("names that arrive from a peer", () => {
  it("strips paths, traversal, control characters and bidi overrides", () => {
    expect(safeFileName("../../etc/passwd")).toBe("etc_passwd");
    expect(safeFileName("..\\..\\windows\\system32\\cmd")).toBe("windows_system32_cmd");
    expect(safeFileName("C:\\Users\\me\\report.pdf")).toBe("C_Users_me_report.pdf");
    expect(safeFileName("....//....//package.json")).toBe("package.json");
    // The bidi trick: this renders as "annexfdp.exe" and saves as what it really is.
    expect(safeFileName("annex\u202Eexe.pdf")).toBe("annexexe.pdf");
    expect(safeFileName("quiet\u0000name.txt")).toBe("quietname.txt");
    expect(safeFileName(".hidden")).toBe("hidden");
    expect(safeFileName("   ")).toBe("delivery.bin");
    expect(safeFileName(undefined)).toBe("delivery.bin");
    expect(safeFileName({ evil: true })).toBe("delivery.bin");
    expect(safeFileName("NUL.txt")).toBe("_NUL.txt");
    expect(safeFileName("a".repeat(500)).length).toBeLessThanOrEqual(80);
  });

  it("is applied where a peer's name enters the vault and where a download is named", () => {
    expect(read("src/client/messaging.ts")).toContain("name: safeFileName(name)");
    const orders = read("src/client/views/orders.ts");
    expect(orders).toContain('download: safeFileName(name)');
    // Downloaded bytes are never given a type a browser would render, and never navigated to.
    expect(orders).toContain('type: "application/octet-stream"');
    expect(orders).not.toMatch(/window\.open|location\.href\s*=\s*url/);
  });
});

describe("storage", () => {
  it("keeps blobs in the database, not on a disk that could be served or executed", () => {
    const route = read("src/server/routes/deliveries.ts");
    expect(route).not.toMatch(/writeFile|createWriteStream|node:fs/);
    // Every id this server generates is random; nothing is named after user input.
    expect(read("src/server/lib/ids.ts")).toMatch(/randomUUID|randomBytes|getRandomValues/);
  });

  it("serves stored bytes only as JSON, only to the buyer, and deletes them on collection", async () => {
    const order = await acceptedOrder("Collection Probe");
    await seller.post(`/api/market/orders/${order}/delivery`, { ciphertext: b64("payload") });
    // The seller cannot fetch it back, and a stranger gets the same answer as a wrong id.
    expect((await seller.get(`/api/market/orders/${order}/delivery`)).status).toBe(403);
    const stranger = await register(server, "uploadstranger");
    expect((await stranger.get(`/api/market/orders/${order}/delivery`)).status).toBe(404);
    expect((await buyer.get(`/api/market/orders/${order}/delivery`)).status).toBe(200);
    expect((await buyer.del(`/api/market/orders/${order}/delivery`)).status).toBe(200);
    expect((await buyer.get(`/api/market/orders/${order}/delivery`)).status).toBe(404);
  });
});
