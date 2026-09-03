/**
 * Recovery phrases and the recovery flow.
 *
 * The BIP-39 encoding is checked against `@scure/bip39` — a reference implementation kept
 * as a *dev* dependency only, so production ships our ~50 lines and the vendored
 * wordlist, while the tests still prove those lines agree with the specification.
 */
import { randomBytes } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { generateMnemonic, mnemonicToEntropy, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { authSecretFor, FAST_KDF, register, startTestServer, TestClient, type TestServer } from "./helpers.ts";
import {
  decodePhrase,
  encodePhrase,
  generatePhrase,
  normalizePhrase,
  phraseIsValid,
} from "../src/shared/crypto/mnemonic.ts";
import {
  deriveAccountKeys,
  deriveRecoveryKeys,
  generateMasterKey,
  openVault,
  sealVault,
  signWithRecoveryKey,
  unwrapMasterKey,
  wrapMasterKey,
  type VaultBackup,
} from "../src/shared/crypto/vault.ts";
import { WORDLIST } from "../src/shared/crypto/bip39-wordlist.ts";
import { fromUtf8, toBase64Url, utf8 } from "../src/shared/encoding.ts";
import { sodiumReady } from "../src/shared/crypto/sodium.ts";

let server: TestServer;

beforeEach(async () => {
  await sodiumReady();
  server = await startTestServer();
});
afterEach(async () => {
  await server.close();
});

describe("recovery phrases", () => {
  it("uses the specification's wordlist and encoding", () => {
    expect(WORDLIST.length).toBe(2048);
    expect([...WORDLIST]).toEqual([...wordlist]);

    // Our encoder against the reference decoder, and the reference encoder against ours.
    for (const size of [16, 32]) {
      for (let round = 0; round < 5; round += 1) {
        const entropy = randomBytes(size);
        const ours = encodePhrase(entropy);
        expect(validateMnemonic(ours, wordlist)).toBe(true);
        expect([...mnemonicToEntropy(ours, wordlist)]).toEqual([...entropy]);

        const theirs = generateMnemonic(wordlist, size * 8);
        expect([...decodePhrase(theirs)]).toEqual([...mnemonicToEntropy(theirs, wordlist)]);
      }
    }
  });

  it("generates 12 or 24 words from the system CSPRNG, and never repeats", () => {
    const phrases = new Set([...Array(8)].map(() => generatePhrase(24)));
    expect(phrases.size).toBe(8);
    expect(generatePhrase(12).split(" ").length).toBe(12);
    expect(generatePhrase(24).split(" ").length).toBe(24);
    for (const phrase of phrases) expect(phraseIsValid(phrase)).toBe(true);
  });

  it("rejects a phrase with a typo, a wrong word, or the wrong length", () => {
    // Fixed vectors, not a generated phrase: a random 24-word phrase whose last word is
    // replaced still passes the 8-bit checksum about once in 256 runs, and this test used
    // to fail in CI at exactly that rate. `abandon…art` and `abandon…about` are the
    // all-zero-entropy phrases from the BIP-39 test vectors.
    const words = [...Array<string>(23).fill("abandon"), "art"];
    expect(phraseIsValid(words.join(" "))).toBe(true);
    expect(phraseIsValid([...Array<string>(11).fill("abandon"), "about"].join(" "))).toBe(true);

    // Swapping two words keeps every word legal but breaks the checksum.
    const swapped = [...words];
    [swapped[0], swapped[23]] = [swapped[23]!, swapped[0]!];
    expect(phraseIsValid(swapped.join(" "))).toBe(false);

    expect(() => decodePhrase([...words.slice(0, 23), "notaword"].join(" "))).toThrow(/not a word/);
    expect(() => decodePhrase(words.slice(0, 23).join(" "))).toThrow(/12 or 24/);
    expect(() => decodePhrase([...words.slice(0, 23), "abandon"].join(" "))).toThrow(/typo/);
  });

  it("survives the way people actually write it down", () => {
    const phrase = generatePhrase(12);
    const messy = `  ${phrase.toUpperCase().split(" ").join(",  ")}. `;
    expect(normalizePhrase(messy)).toBe(phrase);
    expect(phraseIsValid(messy)).toBe(true);
  });
});

describe("recovery key derivation", () => {
  it("separates the wrap key, the signing key and the password keys", () => {
    const phrase = generatePhrase(24);
    const recovery = deriveRecoveryKeys("alice", phrase, FAST_KDF);
    const account = deriveAccountKeys("alice", "correct horse battery staple", FAST_KDF);

    const pairs: Array<[Uint8Array, Uint8Array]> = [
      [recovery.wrapKey, recovery.signPrivateKey.subarray(0, 32)],
      [recovery.wrapKey, account.wrapKey],
      [recovery.wrapKey, account.authSecret],
    ];
    for (const [left, right] of pairs) {
      expect(toBase64Url(left)).not.toBe(toBase64Url(right));
    }

    // Deterministic for the same phrase, and bound to the username.
    const again = deriveRecoveryKeys("alice", phrase, FAST_KDF);
    expect(toBase64Url(again.wrapKey)).toBe(toBase64Url(recovery.wrapKey));
    expect(toBase64Url(again.signPublicKey)).toBe(toBase64Url(recovery.signPublicKey));
    const elsewhere = deriveRecoveryKeys("bob", phrase, FAST_KDF);
    expect(toBase64Url(elsewhere.wrapKey)).not.toBe(toBase64Url(recovery.wrapKey));

    // Case and spacing do not change the keys; a different phrase does.
    const messy = deriveRecoveryKeys("alice", ` ${phrase.toUpperCase()} `, FAST_KDF);
    expect(toBase64Url(messy.signPublicKey)).toBe(toBase64Url(recovery.signPublicKey));
    const other = deriveRecoveryKeys("alice", generatePhrase(24), FAST_KDF);
    expect(toBase64Url(other.signPublicKey)).not.toBe(toBase64Url(recovery.signPublicKey));
  });

  it("opens the same master key from either route", () => {
    const phrase = generatePhrase(24);
    const recovery = deriveRecoveryKeys("alice", phrase, FAST_KDF);
    const account = deriveAccountKeys("alice", "correct horse battery staple", FAST_KDF);
    const masterKey = generateMasterKey();
    const backup: VaultBackup = {
      v: 3,
      vault: sealVault(masterKey, utf8("the keys")),
      password: wrapMasterKey(account.wrapKey, masterKey),
      recovery: wrapMasterKey(recovery.wrapKey, masterKey),
    };

    for (const key of [account.wrapKey, recovery.wrapKey]) {
      const envelope = key === account.wrapKey ? backup.password : backup.recovery!;
      const opened = unwrapMasterKey(key, envelope);
      expect(fromUtf8(openVault(opened, backup.vault))).toBe("the keys");
    }
    // Neither envelope leaks the master key, and the wrong key opens neither.
    expect(JSON.stringify(backup)).not.toContain(toBase64Url(masterKey));
    expect(() => unwrapMasterKey(account.wrapKey, backup.recovery!)).toThrow();
  });
});

/** The whole flow, as the browser drives it: phrase in, account and history back. */
describe("recovering an account", () => {
  const PASSWORD = "correct horse battery staple";

  async function registerWithRecovery(username: string, phrase: string) {
    const account = deriveAccountKeys(username, PASSWORD, FAST_KDF);
    const recovery = deriveRecoveryKeys(username, phrase, FAST_KDF);
    const masterKey = generateMasterKey();
    const backup: VaultBackup = {
      v: 3,
      vault: sealVault(masterKey, utf8(JSON.stringify({ secret: "identity keys" }))),
      password: wrapMasterKey(account.wrapKey, masterKey),
      recovery: wrapMasterKey(recovery.wrapKey, masterKey),
    };

    const client = new TestClient(server);
    await client.get("/");
    const response = await client.post("/api/auth/register", {
      username,
      authSecret: authSecretFor(username, PASSWORD),
      recoveryPublicKey: toBase64Url(recovery.signPublicKey),
      sealedVault: backup,
    });
    if (response.status !== 200) throw new Error(JSON.stringify(response.body));
    client.username = username;
    return { client, backup, masterKey };
  }

  async function signChallenge(client: TestClient, username: string, phrase: string) {
    const challenge = await client.post<{ challengeId: string; challenge: string }>(
      "/api/auth/recovery/challenge",
      { username },
    );
    const recovery = deriveRecoveryKeys(username, phrase, FAST_KDF);
    return {
      challengeId: challenge.body.challengeId,
      signature: toBase64Url(signWithRecoveryKey(recovery.signPrivateKey, utf8(challenge.body.challenge))),
    };
  }

  it("takes the account back with the phrase and keeps the vault readable", async () => {
    const phrase = generatePhrase(24);
    const { masterKey } = await registerWithRecovery("alice", phrase);

    // A second session that must not survive the recovery.
    const other = new TestClient(server);
    await other.get("/");
    expect((await other.post("/api/auth/login", {
      username: "alice",
      authSecret: authSecretFor("alice", PASSWORD),
    })).status).toBe(200);

    const rescue = new TestClient(server);
    await rescue.get("/");
    const { challengeId, signature } = await signChallenge(rescue, "alice", phrase);
    const completed = await rescue.post<{ username: string; sealedVault: VaultBackup | null }>(
      "/api/auth/recovery/complete",
      { challengeId, signature, newAuthSecret: authSecretFor("alice", "a brand new long passphrase") },
    );
    expect(completed.status).toBe(200);
    expect(completed.body.username).toBe("alice");

    // The phrase opens the master key out of the returned backup — the same master key.
    const recovery = deriveRecoveryKeys("alice", phrase, FAST_KDF);
    const recovered = unwrapMasterKey(recovery.wrapKey, completed.body.sealedVault!.recovery!);
    expect(toBase64Url(recovered)).toBe(toBase64Url(masterKey));
    expect(JSON.parse(fromUtf8(openVault(recovered, completed.body.sealedVault!.vault)))).toEqual({
      secret: "identity keys",
    });

    // Rewrap under the new password and store it, which is what the client does next.
    const next = deriveAccountKeys("alice", "a brand new long passphrase", FAST_KDF);
    const rewrapped: VaultBackup = {
      ...completed.body.sealedVault!,
      password: wrapMasterKey(next.wrapKey, recovered),
    };
    expect((await rescue.put("/api/keys/vault", { sealedVault: rewrapped })).status).toBe(200);

    // Old password gone, old session gone, new password opens the vault.
    expect((await other.get("/api/auth/me")).status).toBe(401);
    const stale = new TestClient(server);
    await stale.get("/");
    expect((await stale.post("/api/auth/login", {
      username: "alice",
      authSecret: authSecretFor("alice", PASSWORD),
    })).status).toBe(401);

    const back = new TestClient(server);
    await back.get("/");
    const login = await back.post<{ sealedVault: VaultBackup }>("/api/auth/login", {
      username: "alice",
      authSecret: authSecretFor("alice", "a brand new long passphrase"),
    });
    expect(login.status).toBe(200);
    const fromPassword = unwrapMasterKey(next.wrapKey, login.body.sealedVault.password);
    expect(JSON.parse(fromUtf8(openVault(fromPassword, login.body.sealedVault.vault)))).toEqual({
      secret: "identity keys",
    });
  });

  it("refuses a wrong phrase, a reused challenge and an expired one", async () => {
    const phrase = generatePhrase(24);
    await registerWithRecovery("alice", phrase);
    const rescue = new TestClient(server);
    await rescue.get("/");

    // Someone else's phrase produces a valid-looking signature that does not verify.
    const wrong = await signChallenge(rescue, "alice", generatePhrase(24));
    expect((await rescue.post("/api/auth/recovery/complete", {
      ...wrong,
      newAuthSecret: authSecretFor("alice", "an attacker chosen passphrase"),
    })).status).toBe(401);
    // ...and it burned the challenge, so grinding signatures against it is pointless.
    const right = deriveRecoveryKeys("alice", phrase, FAST_KDF);
    expect((await rescue.post("/api/auth/recovery/complete", {
      challengeId: wrong.challengeId,
      signature: toBase64Url(signWithRecoveryKey(right.signPrivateKey, utf8("anything"))),
      newAuthSecret: authSecretFor("alice", "an attacker chosen passphrase"),
    })).status).toBe(401);
    // The password still works: nothing changed.
    const check = new TestClient(server);
    await check.get("/");
    expect((await check.post("/api/auth/login", {
      username: "alice",
      authSecret: authSecretFor("alice", PASSWORD),
    })).status).toBe(200);

    // A challenge that aged out is refused before any signature is looked at.
    const stale = await signChallenge(rescue, "alice", phrase);
    await server.db.run("UPDATE auth_challenges SET expires_at = ? WHERE id = ?", [
      Date.now() - 1,
      stale.challengeId,
    ]);
    expect((await rescue.post("/api/auth/recovery/complete", {
      ...stale,
      newAuthSecret: authSecretFor("alice", "another long passphrase here"),
    })).status).toBe(401);
  });

  it("hands out a challenge for any username, so it cannot be used to enumerate accounts", async () => {
    const phrase = generatePhrase(24);
    await registerWithRecovery("alice", phrase);
    const client = new TestClient(server);
    await client.get("/");

    const known = await client.post<{ challengeId: string; challenge: string }>(
      "/api/auth/recovery/challenge",
      { username: "alice" },
    );
    const unknown = await client.post<{ challengeId: string; challenge: string }>(
      "/api/auth/recovery/challenge",
      { username: "nobody-here" },
    );
    expect(known.status).toBe(unknown.status);
    expect(Object.keys(known.body).sort()).toEqual(Object.keys(unknown.body).sort());
    expect(unknown.body.challenge.length).toBe(known.body.challenge.length);

    // Both wrote a row: the decoy has a null user_id and can never be completed, but it
    // costs the same insert, so the server does not answer "does this account exist?" in
    // timing or in table growth either (point 70).
    const rows = await server.db.all<{ user_id: string | null }>(
      "SELECT user_id FROM auth_challenges WHERE kind = 'recovery'",
    );
    expect(rows.length).toBe(2);
    expect(rows.filter((row) => row.user_id === null).length).toBe(1);
  });

  it("stores only the public half, and no path from the database to the phrase", async () => {
    const phrase = generatePhrase(24);
    await registerWithRecovery("alice", phrase);
    const recovery = deriveRecoveryKeys("alice", phrase, FAST_KDF);

    const dump = JSON.stringify([
      await server.db.all("SELECT * FROM users"),
      await server.db.all("SELECT * FROM vaults"),
      await server.db.all("SELECT * FROM auth_challenges"),
    ]);
    // The public key is there; the phrase, its words, the wrap key and the signing key
    // are not — an administrator with the whole database has nothing to recover with.
    expect(dump).toContain(toBase64Url(recovery.signPublicKey));
    expect(dump).not.toContain(toBase64Url(recovery.wrapKey));
    expect(dump).not.toContain(toBase64Url(recovery.signPrivateKey));
    for (const word of phrase.split(" ").slice(0, 4)) {
      expect(dump).not.toContain(` ${word} `);
    }
  });

  it("only sets a recovery key for someone who knows the current password", async () => {
    const client = await register(server, "bob");
    const phrase = generatePhrase(12);
    const recovery = deriveRecoveryKeys("bob", phrase, FAST_KDF);

    const wrong = await client.post("/api/auth/recovery/key", {
      authSecret: authSecretFor("bob", "not the password"),
      recoveryPublicKey: toBase64Url(recovery.signPublicKey),
    });
    expect(wrong.status).toBe(401);
    expect(
      (await server.db.get<{ recovery_public_key: string | null }>(
        "SELECT recovery_public_key FROM users WHERE username = 'bob'",
      ))?.recovery_public_key,
    ).toBeNull();

    const right = await client.post("/api/auth/recovery/key", {
      authSecret: authSecretFor("bob", PASSWORD),
      recoveryPublicKey: toBase64Url(recovery.signPublicKey),
    });
    expect(right.status).toBe(200);
    const me = await client.get<{ recoveryConfigured: boolean }>("/api/auth/me");
    expect(me.body.recoveryConfigured).toBe(true);
  });
});
