/**
 * Points 90–92: assume the attacker already won.
 *
 * Three thefts, one question each. *Storage* — the raw volume, which in this system is the
 * database file, because blobs are rows and nothing is ever written to a filesystem path a
 * request can influence. *Database* — a complete dump. *Backup* — an off-host copy.
 *
 * The method is deliberately blunt: play a realistic session, planting a distinctive string
 * in every place a user's own data enters the system, then read every column of every table
 * and fail if any marker survives anywhere, in any encoding. A test that asserted "the
 * message column is encrypted" would pass forever while a new feature quietly copied the
 * plaintext into a notification, an audit note or a search index; this one would not.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import {
  approveSeller,
  authSecretFor,
  fund,
  publishDevice,
  register,
  startTestServer,
  type TestClient,
  type TestServer,
} from "./helpers.ts";
import { listColumns, listTables } from "./database.ts";
import { encryptFile } from "../src/shared/crypto/file.ts";
import { aeadEncrypt } from "../src/shared/crypto/aead.ts";
import { randomBytes } from "../src/shared/crypto/sodium.ts";
import { toBase64Url, utf8 } from "../src/shared/encoding.ts";
import { sealVault } from "../src/shared/crypto/vault.ts";

const read = (path: string) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

/** Everything a user believes is private, in a form that is trivial to grep for. */
const MARKER = {
  password: `PASSWORD-${randomUUID()}`,
  message: `MESSAGE-PLAINTEXT-${randomUUID()}`,
  attachment: `ATTACHMENT-PLAINTEXT-${randomUUID()}`,
  delivery: `DELIVERY-PLAINTEXT-${randomUUID()}`,
  filename: `FILENAME-${randomUUID()}.jpg`,
  address: `POSTAL-ADDRESS-${randomUUID()}`,
  vaultSecret: `PRIVATE-KEY-MATERIAL-${randomUUID()}`,
};

let server: TestServer;
let seller: TestClient;
let buyer: TestClient;

beforeAll(async () => {
  server = await startTestServer();
  seller = await register(server, "compromiseseller", MARKER.password);
  buyer = await register(server, "compromisebuyer", MARKER.password);
  const buyerDevice = await publishDevice(buyer);
  await publishDevice(seller);

  // A sealed vault: the private keys, encrypted under the master key the password wraps,
  // the way the browser writes them.
  await buyer.put("/api/keys/vault", {
    sealedVault: sealVault(randomBytes(32), utf8(JSON.stringify({ secret: MARKER.vaultSecret }))),
  });

  // A message: ciphertext produced exactly as the client produces it, with the plaintext
  // never leaving this test.
  await seller.post("/api/messages", {
    to: "compromisebuyer",
    channel: toBase64Url(randomBytes(16)),
    messages: [
      {
        deviceId: buyerDevice,
        payload: toBase64Url(
          aeadEncrypt(randomBytes(32), utf8(`${MARKER.message} ${MARKER.address}`), utf8("test"), randomBytes(24)),
        ),
      },
    ],
  });

  // An attachment, then an order and its delivery: the three blob paths that exist.
  await buyer.post("/api/attachments", {
    id: toBase64Url(randomBytes(24)),
    ciphertext: toBase64Url(encryptFile("blob", utf8(`${MARKER.attachment} ${MARKER.filename}`)).ciphertext),
  });

  await approveSeller(server, seller, "Compromise Wares");

  const listing = await seller.post<{ id: string }>("/api/market/listings", {
    title: "A digital good",
    description: "Delivered as bytes the server cannot read.",
    category: "software",
    kind: "digital_good",
    priceXmr: "0.10",
  });
  await fund(server, buyer, "1");
  const order = await buyer.post<{ id: string }>("/api/market/orders", { listingId: listing.body.id });
  await seller.post(`/api/market/orders/${order.body.id}/status`, { status: "accepted" });
  const delivered = await seller.post(`/api/market/orders/${order.body.id}/delivery`, {
    ciphertext: toBase64Url(encryptFile(order.body.id, utf8(MARKER.delivery)).ciphertext),
  });
  // The journey has to actually happen: a test that silently played half of it would assert
  // that markers are absent from rows nobody wrote.
  for (const [what, step] of [["listing", listing], ["order", order], ["delivery", delivered]] as const) {
    if (step.status !== 200) throw new Error(`${what} failed with ${step.status}: ${JSON.stringify(step.body)}`);
  }
});

afterAll(async () => {
  await server.close();
});

/** Every value in the database, as text: what a `pg_dump` or a stolen SQLite file contains. */
async function dumpEverything(): Promise<string> {
  const parts: string[] = [];
  for (const table of await listTables(server.db)) {
    const columns = await listColumns(server.db, table);
    const rows = await server.db.all<Record<string, unknown>>(`SELECT * FROM ${table}`); // audit:allow — the name comes from the schema, never from input
    for (const row of rows) {
      for (const column of columns) parts.push(`${table}.${column}=${String(row[column] ?? "")}`);
    }
  }
  return parts.join("\n");
}

/** The same string in the three encodings a value could plausibly be stored in. */
function encodings(value: string): string[] {
  return [value, Buffer.from(value).toString("base64"), Buffer.from(value).toString("base64url"), Buffer.from(value).toString("hex")];
}

describe("an attacker with the whole database (point 91)", () => {
  it("finds no plaintext of anything a user considered private", async () => {
    const dump = await dumpEverything();
    expect(dump.length).toBeGreaterThan(1000); // the journey above really did write rows
    const leaked: string[] = [];
    for (const [name, value] of Object.entries(MARKER)) {
      for (const encoded of encodings(value)) {
        if (dump.includes(encoded)) leaked.push(name);
      }
    }
    expect(leaked, "these were recoverable from a database dump").toEqual([]);
  });

  it("finds no secret of the server's own, and no session it could replay", async () => {
    const dump = await dumpEverything();
    // The rate-limit pepper is what would turn a table of HMACs back into an access log.
    expect(dump).not.toContain(server.config.bucketPepper);
    // A session cookie is stored as its SHA-256; the cookie itself is only ever in a browser.
    const session = await server.db.get<{ token_hash: string }>("SELECT token_hash FROM sessions LIMIT 1");
    expect(session?.token_hash).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(buyer.cookie("session")).toBeTruthy();
    expect(dump).not.toContain(buyer.cookie("session"));
    // And no table has a column that could hold a private key or a phrase in the first place.
    for (const table of await listTables(server.db)) {
      const columns = await listColumns(server.db, table);
      expect(columns.filter((c) => /private_key|mnemonic|phrase|passphrase|plaintext/.test(c)), table).toEqual([]);
    }
  });

  it("holds a password only as a hash of a secret the password never became", async () => {
    const row = await server.db.get<{ password_hash: string }>(
      "SELECT password_hash FROM users WHERE username = ?",
      ["compromisebuyer"],
    );
    expect(row?.password_hash).toBeTruthy();
    expect(row!.password_hash).not.toContain(MARKER.password);
    // What the browser sends is already stretched with Argon2id; the server hashes *that*.
    expect(row!.password_hash).not.toContain(authSecretFor("compromisebuyer", MARKER.password));
  });
});

describe("an attacker with the raw storage volume (point 90)", () => {
  it("gets ciphertext, because every stored blob is a row and every row is opaque", async () => {
    // Nothing is written to a filesystem path in the first place: the upload route touches
    // no file API, so "the storage volume" and "the database file" are the same theft.
    expect(read("src/server/routes/deliveries.ts")).not.toMatch(/writeFile|createWriteStream|node:fs/);

    const blobs = [
      ...(await server.db.all<{ ciphertext: string }>("SELECT ciphertext FROM attachments")),
      ...(await server.db.all<{ ciphertext: string }>("SELECT ciphertext FROM deliveries")),
    ];
    expect(blobs.length).toBe(2);
    for (const blob of blobs) {
      for (const marker of [MARKER.attachment, MARKER.delivery, MARKER.filename]) {
        for (const encoded of encodings(marker)) expect(blob.ciphertext).not.toContain(encoded);
      }
      // Padded to a bucket before encryption, so the stored length is not the artefact's
      // length: what a thief measures is 64, 256, 1024 or a multiple of 4096, plus the tag.
      const padded = Buffer.from(blob.ciphertext, "base64url").length - 16;
      expect([64, 256, 1024].includes(padded) || padded % 4096 === 0, `stored length ${padded}`).toBe(true);
    }
  });

  it("learns nothing from the names of things, because there are none", async () => {
    // No filename, no media type, no owner: the columns that would carry them do not exist.
    expect(await listColumns(server.db, "attachments")).toEqual(["id", "ciphertext", "created_at", "expires_at"]);
    const columns = await listColumns(server.db, "deliveries");
    expect(columns.filter((c) => /name|mime|type|path/.test(c))).toEqual([]);
  });
});

describe("an attacker with a backup (point 92)", () => {
  it("cannot decrypt it with anything the running service holds", () => {
    // The application never reads the backup key: it is a file the operator owns, passed to
    // a script, and a compromised server therefore cannot hand over the backup history.
    const config = read("src/server/config.ts");
    expect(config).not.toMatch(/BACKUP_KEY/);
    // Both backup tools take the key through the one shared envelope, from a file only.
    const envelope = read("scripts/backup-envelope.mjs");
    expect(envelope).toMatch(/BACKUP_KEY_FILE/);
    expect(envelope).toMatch(/aes-256-gcm/);
    // A key on the command line is visible in `ps`; the envelope refuses to take one there.
    expect(envelope).toMatch(/--key <file>/);
    for (const tool of ["scripts/backup.mjs", "scripts/backup-postgres.mjs"]) {
      const source = read(tool);
      expect(source, tool).toMatch(/from "\.\/backup-envelope\.mjs"/);
      expect(source, tool).not.toMatch(/createCipheriv|createDecipheriv/);
    }
    expect(read("docs/BACKUPS.md")).toMatch(/does not hold the backup key/);
  });

  it("unlocks no session, no key and no message, because the dump it holds has none", async () => {
    // A backup is the database, so the guarantee is the one asserted above — stated here as
    // its own case because "restore the backup and log in as somebody" is the question an
    // operator is actually asked.
    const dump = await dumpEverything();
    for (const value of Object.values(MARKER)) {
      for (const encoded of encodings(value)) expect(dump).not.toContain(encoded);
    }
    const vault = await server.db.get<{ sealed: string }>("SELECT sealed FROM vaults LIMIT 1");
    expect(vault?.sealed).toBeTruthy();
    expect(vault!.sealed).not.toContain(MARKER.vaultSecret);
  });
});
