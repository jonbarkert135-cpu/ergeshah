/**
 * Point 78: media is encrypted in the browser before it is uploaded, and the store the
 * server runs is blind — no sender, no recipient, no filename, no media type, no length.
 *
 * HTTPS is explicitly not the control being tested here. Every assertion below is about what
 * the *server* holds and what it refuses to accept.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { register, startTestServer, type TestServer } from "./helpers.ts";
import { DEFAULT_LIMITS } from "../src/server/lib/rate_limit.ts";
import { actAs, installBrowserGlobals, installFetch, signUp, type Persona } from "./browser.ts";
import { generatePhrase } from "../src/shared/crypto/mnemonic.ts";
import { lock, ready, state } from "../src/client/state.ts";
import {
  conversations,
  openAttachment,
  receiveMessages,
  sendAttachment,
  startConversation,
} from "../src/client/messaging.ts";
import { toBase64Url } from "../src/shared/encoding.ts";
import { listColumns } from "./database.ts";

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

const id = () => toBase64Url(crypto.getRandomValues(new Uint8Array(24)));

describe("the blind attachment store", () => {
  it("stores what it is given and knows nothing about it", async () => {
    const alice = await register(server, "alice");
    const attachmentId = id();
    const response = await alice.post<{ id: string; expiresAt: number }>("/api/attachments", {
      id: attachmentId,
      ciphertext: toBase64Url(new Uint8Array(4096).fill(9)),
    });
    expect(response.status).toBe(200);
    expect(response.body.id).toBe(attachmentId);

    const columns = await listColumns(server.db, "attachments");
    expect([...columns].sort()).toEqual([
      "ciphertext",
      "created_at",
      "expires_at",
      "id",
    ]);
  });

  it("refuses every field that would describe the bytes", async () => {
    const alice = await register(server, "alice");
    for (const extra of [
      { filename: "cat.png" },
      { mimeType: "image/png" },
      { to: "bob" },
      { channel: "abc" },
      { bytes: 12 },
    ]) {
      const response = await alice.post<{ error: string }>("/api/attachments", {
        id: id(),
        ciphertext: toBase64Url(new Uint8Array(64)),
        ...extra,
      });
      expect(response.status, JSON.stringify(extra)).toBe(400);
      expect(response.body.error).toBe("unexpected_field");
    }
  });

  it("caps the size in decoded bytes, not characters", async () => {
    const alice = await register(server, "alice");
    const tooBig = toBase64Url(new Uint8Array(server.config.maxDeliveryBytes + 1));
    const response = await alice.post("/api/attachments", { id: id(), ciphertext: tooBig });
    expect(response.status).toBe(400);
  });

  it("refuses a colliding id rather than overwriting a blob", async () => {
    const alice = await register(server, "alice");
    const shared = id();
    await alice.post("/api/attachments", { id: shared, ciphertext: toBase64Url(new Uint8Array(64).fill(1)) });
    const second = await alice.post<{ error: string }>("/api/attachments", {
      id: shared,
      ciphertext: toBase64Url(new Uint8Array(64).fill(2)),
    });
    expect(second.status).toBe(409);
    expect(second.body.error).toBe("id_taken");
  });

  it("answers nobody who is not signed in, and 404 for an id that does not exist", async () => {
    const alice = await register(server, "alice");
    const stored = id();
    await alice.post("/api/attachments", { id: stored, ciphertext: toBase64Url(new Uint8Array(64)) });

    const anonymous = await server.app.inject({ method: "GET", url: `/api/attachments/${stored}` });
    expect(anonymous.statusCode).toBe(401);

    const missing = await alice.get(`/api/attachments/${id()}`);
    expect(missing.status).toBe(404);
  });

  it("lets anyone who holds the id fetch and delete it, because the id is the capability", async () => {
    const alice = await register(server, "alice");
    const bob = await register(server, "bob");
    const stored = id();
    await alice.post("/api/attachments", { id: stored, ciphertext: toBase64Url(new Uint8Array(64).fill(3)) });

    // Bob is not "the recipient" as far as the database is concerned — there is no such
    // column. He has the id, which is what the sender gave him inside the ciphertext.
    const fetched = await bob.get<{ ciphertext: string }>(`/api/attachments/${stored}`);
    expect(fetched.status).toBe(200);
    expect(fetched.body.ciphertext).toBe(toBase64Url(new Uint8Array(64).fill(3)));

    const deleted = await bob.del<{ deleted: number }>(`/api/attachments/${stored}`);
    expect(deleted.body.deleted).toBe(1);
    expect((await bob.get(`/api/attachments/${stored}`)).status).toBe(404);
  });

  it("expires a blob nobody collected", async () => {
    const alice = await register(server, "alice");
    const stored = id();
    await alice.post("/api/attachments", { id: stored, ciphertext: toBase64Url(new Uint8Array(64)) });
    await server.db.run("UPDATE attachments SET expires_at = ?", [Date.now() - 1]);

    expect((await alice.get(`/api/attachments/${stored}`)).status).toBe(404);
    const left = await server.db.get<{ n: number }>("SELECT COUNT(*) AS n FROM attachments");
    expect(left!.n).toBe(0);
  });

  it("has its own bucket, tighter than sending a message", () => {
    expect(DEFAULT_LIMITS.attachment.burst).toBeLessThan(DEFAULT_LIMITS.message_send.burst);
    expect(DEFAULT_LIMITS.attachment.perMinute).toBeLessThan(DEFAULT_LIMITS.message_send.perMinute);
  });
});

describe("a file sent between two browsers", () => {
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

  it("travels as ciphertext, and the server never sees the plaintext or the key", async () => {
    const plaintext = new TextEncoder().encode("the quick brown fox, in a file");

    await actAs(alice);
    const conversation = await startConversation("bob");
    await sendAttachment(conversation, plaintext, "notes.txt");

    const stored = await server.db.get<{ ciphertext: string }>("SELECT ciphertext FROM attachments");
    expect(stored!.ciphertext).not.toContain("quick brown fox");
    // Padded into a bucket (64/256/1024/4096·n), so the row does not hold the real length:
    // a 30-byte note and a 60-byte note are stored at the same size.
    const other = await sendAndRead("x".repeat(58));
    expect(other.length).toBe(stored!.ciphertext.length);
    const sentKey = conversations()[0]!.messages[0]!.attachment!.key;
    const everything = JSON.stringify([
      await server.db.all("SELECT * FROM attachments"),
      await server.db.all("SELECT * FROM envelopes"),
    ]);
    expect(everything).not.toContain(sentKey);
    expect(everything).not.toContain("notes.txt");

    await actAs(bob);
    // Two: the note, and the second attachment the padding comparison above needed.
    expect(await receiveMessages()).toBe(2);
    const received = conversations()[0]!.messages[0]!;
    expect(received.attachment?.name).toBe("notes.txt");
    expect(received.attachment?.bytes).toBe(plaintext.length);
    expect(new TextDecoder().decode(await openAttachment(received.attachment!))).toBe(
      "the quick brown fox, in a file",
    );
  });

  /** Stores a second attachment of a different plaintext length and returns its ciphertext. */
  async function sendAndRead(text: string): Promise<string> {
    const conversation = conversations()[0]!;
    await sendAttachment(conversation, new TextEncoder().encode(text), "second.txt");
    const rows = await server.db.all<{ ciphertext: string }>(
      "SELECT ciphertext FROM attachments ORDER BY created_at DESC LIMIT 1",
    );
    return rows[0]!.ciphertext;
  }

  /**
   * Point 88, end to end: what leaves this browser is the picture without the metadata, and
   * what the peer opens is the same bytes. The unit cases for every container are in
   * `test/images.test.ts`; this one proves the strip is actually wired into the send path.
   */
  it("sends a photograph without the coordinates it was taken at", async () => {
    const exif = [...'Exif\0\0II'].map((character) => character.charCodeAt(0));
    const gps = [...'GPSLatitude 51.5074 Canon EOS 5D'].map((character) => character.charCodeAt(0));
    const payload = [...exif, ...gps];
    const photograph = new Uint8Array([
      0xff, 0xd8, // SOI
      0xff, 0xe1, ((payload.length + 2) >> 8) & 0xff, (payload.length + 2) & 0xff, ...payload, // APP1
      0xff, 0xda, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3f, 0x00, 0x2a, 0x2b, // SOS + scan
      0xff, 0xd9, // EOI
    ]);

    await actAs(alice);
    const conversation = await startConversation("bob");
    await sendAttachment(conversation, photograph, "holiday.jpg");

    await actAs(bob);
    expect(await receiveMessages()).toBe(1);
    const opened = await openAttachment(conversations()[0]!.messages[0]!.attachment!);
    const received = Buffer.from(opened).toString("latin1");
    expect(received).not.toContain("Exif");
    expect(received).not.toContain("GPSLatitude");
    expect(received).not.toContain("Canon EOS 5D");
    // Still a JPEG, and still the same picture: the scan and the markers around it survive.
    expect([...opened.subarray(0, 2)]).toEqual([0xff, 0xd8]);
    expect([...opened.subarray(-2)]).toEqual([0xff, 0xd9]);
    expect(received).toContain(Buffer.from([0xff, 0xda, 0x00, 0x08]).toString("latin1"));
  });

  it("sanitises a name a peer chose before it can reach a download", async () => {
    await actAs(alice);
    const conversation = await startConversation("bob");
    await sendAttachment(conversation, new TextEncoder().encode("x"), "../../etc/passwd");
    expect(conversations()[0]!.messages[0]!.attachment!.name).not.toContain("/");
    expect(state.vault!.conversations[conversation.channel]!.messages[0]!.attachment!.name).toBe(
      "etc_passwd",
    );
  });
});
