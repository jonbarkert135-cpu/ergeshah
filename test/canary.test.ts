/**
 * The canary (OPS-7, ADR-0099).
 *
 * What is worth testing here is not that a row can be written. It is the four ways a canary
 * turns into theatre: a statement this server could have written itself, a date this server
 * could have chosen, an old statement replayed to look fresh, and a deployment that shows a
 * canary widget while nobody has ever signed one.
 */
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createMessage, generateKey, readPrivateKey, sign } from "openpgp";
import { promote, register, startTestServer, TestClient, type TestServer } from "./helpers.ts";
import { inspectPublicKey } from "../src/server/lib/pgp.ts";
import { dayToIsoDate, today } from "../src/server/lib/time.ts";
import { readCanaryDates, CanaryError } from "../src/server/lib/canary.ts";

interface Keypair {
  publicKey: string;
  privateKey: string;
}

let operator: Keypair;
let stranger: Keypair;
let operatorFingerprint = "";
let server: TestServer;
/** The last block here tests a pure function and starts no server; closing twice throws. */
let running = false;

/** What `gpg --detach-sign --armor` produces, over exactly this text. */
async function signStatement(pair: Keypair, text: string): Promise<string> {
  return (await sign({
    message: await createMessage({ text }),
    signingKeys: await readPrivateKey({ armoredKey: pair.privateKey }),
    detached: true,
    format: "armored",
  })) as string;
}

/** A statement shaped the way the documentation tells an operator to write one. */
function statementFor(signedDay: number, nextDay: number): string {
  return [
    "Symvolon canary",
    `Signed: ${dayToIsoDate(signedDay)}`,
    `Next: ${dayToIsoDate(nextDay)}`,
    "",
    "No warrant, subpoena or other demand for user data has been received.",
    "No key has been handed to anyone.",
  ].join("\n");
}

/** An admin whose account carries the operator's PGP key, which is what publishing needs. */
async function operatorAdmin(pair = operator): Promise<TestClient> {
  const admin = await register(server, "canary-operator");
  await promote(server, admin.username, "admin");
  const facts = await inspectPublicKey(pair.publicKey);
  await server.db.run("UPDATE users SET pgp_public_key = ?, pgp_fingerprint = ? WHERE username = ?", [
    pair.publicKey,
    facts.fingerprint,
    admin.username,
  ]);
  return admin;
}

beforeAll(async () => {
  [operator, stranger] = (await Promise.all([
    generateKey({ userIDs: [{ name: "operator" }], type: "ecc", format: "armored" }),
    generateKey({ userIDs: [{ name: "stranger" }], type: "ecc", format: "armored" }),
  ])) as unknown as [Keypair, Keypair];
  operatorFingerprint = (await inspectPublicKey(operator.publicKey)).fingerprint;
}, 30_000);

afterEach(async () => {
  if (!running) return;
  running = false;
  await server.close();
});

describe("a deployment that publishes no canary", () => {
  beforeEach(async () => {
    server = await startTestServer();
    running = true;
  });

  it("says so plainly rather than showing an empty widget", async () => {
    const anonymous = new TestClient(server);
    const response = await anonymous.request<{ published: boolean }>("GET", "/api/canary", {});
    expect(response.status).toBe(200);
    expect(response.body.published).toBe(false);
  });

  it("refuses to publish one, naming the missing configuration", async () => {
    const admin = await operatorAdmin();
    const signedDay = today();
    const statement = statementFor(signedDay, signedDay + 14);
    const response = await admin.request("POST", "/api/admin/canary", {
      statement,
      signature: await signStatement(operator, statement),
    });
    expect(response.status).toBe(409);
    expect((response.body as { error: string }).error).toBe("canary_not_configured");
  });
});

describe("publishing, and everything that must not publish", () => {
  beforeEach(async () => {
    server = await startTestServer({ canaryFingerprint: operatorFingerprint });
    running = true;
  });

  it("publishes a signed statement and serves it to a caller with no account", async () => {
    const admin = await operatorAdmin();
    const signedDay = today();
    const statement = statementFor(signedDay, signedDay + 14);
    const published = await admin.request("POST", "/api/admin/canary", {
      statement,
      signature: await signStatement(operator, statement),
    });
    expect(published.status).toBe(200);

    const anonymous = new TestClient(server);
    const response = await anonymous.request<{
      published: boolean;
      statement: string;
      signature: string;
      publicKey: string;
      fingerprint: string;
      signedDate: string;
      nextDate: string;
      ageDays: number;
      overdueDays: number;
    }>("GET", "/api/canary", {});
    expect(response.status).toBe(200);
    expect(response.body.published).toBe(true);
    // The statement is served byte for byte, because the signature is over those bytes.
    expect(response.body.statement).toBe(statement);
    expect(response.body.signature).toContain("BEGIN PGP SIGNATURE");
    expect(response.body.publicKey).toContain("BEGIN PGP PUBLIC KEY BLOCK");
    expect(response.body.fingerprint.replace(/ /g, "").toLowerCase()).toBe(operatorFingerprint);
    expect(response.body.signedDate).toBe(dayToIsoDate(signedDay));
    expect(response.body.ageDays).toBe(0);
    expect(response.body.overdueDays).toBe(0);

    const entry = await server.db.get<{ action: string; subject_id: string; result: string }>(
      "SELECT action, subject_id, result FROM audit_log ORDER BY created_at DESC LIMIT 1",
    );
    expect(entry?.action).toBe("canary.published");
    expect(entry?.subject_id).toBe(dayToIsoDate(signedDay));
    // The audit entry records the date, never the text: an operator's statement is not
    // content for a log that outlives it.
    expect(JSON.stringify(entry)).not.toContain("warrant");
  });

  it("refuses a statement signed by a key that is not the configured one", async () => {
    const admin = await operatorAdmin(stranger);
    const signedDay = today();
    const statement = statementFor(signedDay, signedDay + 14);
    const response = await admin.request("POST", "/api/admin/canary", {
      statement,
      signature: await signStatement(stranger, statement),
    });
    expect(response.status).toBe(400);
    expect((response.body as { error: string }).error).toBe("canary_invalid");
    expect(await server.db.get("SELECT id FROM canary_statements")).toBeNull();
  });

  it("refuses an unsigned edit: the text and the signature must belong together", async () => {
    const admin = await operatorAdmin();
    const signedDay = today();
    const statement = statementFor(signedDay, signedDay + 14);
    const signature = await signStatement(operator, statement);
    const response = await admin.request("POST", "/api/admin/canary", {
      statement: `${statement}\nWe have received nothing at all, honestly.`,
      signature,
    });
    expect(response.status).toBe(400);
    expect(await server.db.get("SELECT id FROM canary_statements")).toBeNull();
  });

  it("refuses to replay an older statement over a newer one", async () => {
    const admin = await operatorAdmin();
    const old = statementFor(today() - 5, today() + 9);
    const current = statementFor(today(), today() + 14);
    expect(
      (await admin.request("POST", "/api/admin/canary", {
        statement: old,
        signature: await signStatement(operator, old),
      })).status,
    ).toBe(200);
    expect(
      (await admin.request("POST", "/api/admin/canary", {
        statement: current,
        signature: await signStatement(operator, current),
      })).status,
    ).toBe(200);
    const replay = await admin.request("POST", "/api/admin/canary", {
      statement: old,
      signature: await signStatement(operator, old),
    });
    expect(replay.status).toBe(400);
    const rows = await server.db.all("SELECT id FROM canary_statements");
    expect(rows.length).toBe(2);
  });

  it("shows an overdue canary as overdue, counted from the date in the signed text", async () => {
    const admin = await operatorAdmin();
    // Signed a week ago and due three days ago: the case the whole feature exists for.
    const statement = statementFor(today() - 7, today() - 3);
    expect(
      (await admin.request("POST", "/api/admin/canary", {
        statement,
        signature: await signStatement(operator, statement),
      })).status,
    ).toBe(200);
    const anonymous = new TestClient(server);
    const response = await anonymous.request<{ ageDays: number; overdueDays: number }>(
      "GET",
      "/api/canary",
      {},
    );
    expect(response.body.ageDays).toBe(7);
    expect(response.body.overdueDays).toBe(3);
  });

  it("refuses a moderator, and an ordinary account", async () => {
    const moderator = await register(server, "canary-moderator");
    await promote(server, moderator.username, "moderator");
    const user = await register(server, "canary-user");
    const statement = statementFor(today(), today() + 14);
    const signature = await signStatement(operator, statement);
    for (const client of [moderator, user]) {
      const response = await client.request("POST", "/api/admin/canary", { statement, signature });
      expect(response.status).toBe(403);
    }
  });
});

describe("the dates come out of the signed text, not out of the request", () => {
  it("reads them, and refuses what a canary must not say", () => {
    const now = today();
    expect(readCanaryDates(statementFor(now - 1, now + 13), now)).toEqual({
      signedDay: now - 1,
      nextDay: now + 13,
    });
    // No dates at all.
    expect(() => readCanaryDates("Nothing has happened.", now)).toThrow(CanaryError);
    // A date that parses in JavaScript and means a different month.
    expect(() => readCanaryDates("Signed: 2026-02-31\nNext: 2026-03-14", now)).toThrow(/real date/);
    // Signed in the future, signed too long ago, and due before it was signed.
    expect(() => readCanaryDates(statementFor(now + 1, now + 14), now)).toThrow(/future/);
    expect(() => readCanaryDates(statementFor(now - 30, now - 16), now)).toThrow(/30 days ago/);
    expect(() => readCanaryDates(statementFor(now, now - 1), now)).toThrow(/must be after/);
    // An open-ended promise is not a canary.
    expect(() => readCanaryDates(statementFor(now, now + 400), now)).toThrow(/not a canary/);
  });
});
