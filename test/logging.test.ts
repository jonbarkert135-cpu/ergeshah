/**
 * Point 51: logging that helps security without destroying privacy.
 *
 * The forbidden list from the brief — passwords, private keys, session tokens, plaintext
 * messages, cryptographic material — is checked twice here: against the scrubber directly, and
 * against a real 500 raised by a real route with secrets in the error, captured off stderr.
 */
import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { startTestServer, register, type TestServer } from "./helpers.ts";
import { log, scrub } from "../src/server/lib/log.ts";

const read = (path: string) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

let server: TestServer;

/** Everything the server writes to stderr while `body` runs. */
async function captureStderr(body: () => Promise<void>): Promise<string> {
  const written: string[] = [];
  const spy = vi
    .spyOn(process.stderr, "write")
    .mockImplementation((chunk: string | Uint8Array) => {
      written.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8"));
      return true;
    });
  try {
    await body();
  } finally {
    spy.mockRestore();
  }
  return written.join("");
}

beforeAll(async () => {
  server = await startTestServer({}, (app) => {
    // A handler that fails the way real handlers fail: with a message someone pasted a
    // secret into. The scrubber is the last line of defence, and this is where it is tested.
    app.get("/api/test/explode", async () => {
      throw new Error(
        "upstream refused: session=9f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d password=correct-horse " +
          "key=MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDb from 203.0.113.7",
      );
    });
  });
});

afterAll(async () => {
  await server.close();
});

describe("the scrubber", () => {
  it("removes anything that names a secret", () => {
    for (const text of [
      "password=hunter2",
      "session token expired",
      "cookie: session=abc",
      "Authorization: Bearer abc",
      "private_key could not be parsed",
      "failed to decrypt ciphertext",
      "recoveryPhrase invalid",
      "bucketPepper missing",
    ]) {
      expect(scrub(text), text).toBe("[redacted]");
    }
  });

  it("removes long opaque strings and addresses from an otherwise useful message", () => {
    expect(scrub("row 41 rejected: MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDb")).toBe(
      "row 41 rejected: [redacted]",
    );
    expect(scrub("connection reset by 203.0.113.7")).toBe("connection reset by [address]");
    expect(scrub("connection reset by 2001:db8::1")).toContain("[address]");
  });

  it("keeps a message that carries no secret, so a log is still useful", () => {
    expect(scrub("UNIQUE constraint failed: listings.id")).toBe(
      "UNIQUE constraint failed: listings.id",
    );
  });
});

describe("what a real failure writes", () => {
  it("logs the route pattern, the reference and nothing else", async () => {
    const client = await register(server, "logprobe");
    let ref = "";
    const output = await captureStderr(async () => {
      const response = await client.get<{ ref: string }>("/api/test/explode");
      expect(response.status).toBe(500);
      ref = response.body.ref;
    });
    const line = JSON.parse(output.trim().split("\n").at(-1)!) as Record<string, unknown>;
    expect(line).toMatchObject({
      level: "error",
      event: "request.failed",
      method: "GET",
      route: "/api/test/explode",
      name: "Error",
      ref,
    });
    // The message named a password and a session, so all of it is gone.
    expect(line.message).toBe("[redacted]");
    expect(Object.keys(line).sort()).toEqual([
      "at",
      "event",
      "level",
      "message",
      "method",
      "name",
      "ref",
      "route",
    ]);
    for (const forbidden of [
      "correct-horse",
      "9f2b3c4d",
      "MIIEvQIBADAN",
      "203.0.113.7",
      "logprobe",
      client.cookie("session") ?? "session-cookie",
    ]) {
      expect(output, forbidden).not.toContain(forbidden);
    }
    // No stack trace: a stack is a filesystem layout and a dependency inventory.
    expect(output).not.toContain("at Object.");
    expect(output).not.toContain(".ts:");
  });

  it("writes nothing at all for an ordinary request", async () => {
    const client = await register(server, "quietprobe");
    const output = await captureStderr(async () => {
      expect((await client.get("/api/market/listings?q=quietude")).status).toBe(200);
      expect((await client.get("/api/notifications")).status).toBe(200);
      expect((await client.get("/api/market/orders")).status).toBe(200);
      expect((await client.get("/api/does-not-exist")).status).toBe(404);
      expect((await client.post("/api/market/orders", { listingId: "nope-nope-nope" })).status).toBe(
        404,
      );
    });
    expect(output).toBe("");
  });

  it("logs a structured line for a failure outside a request, too", async () => {
    const output = await captureStderr(async () => {
      log({ level: "error", event: "housekeeping.failed", message: "database is locked" });
    });
    expect(JSON.parse(output.trim())).toMatchObject({
      level: "error",
      event: "housekeeping.failed",
      message: "database is locked",
    });
  });
});

describe("the rules, not the good intentions", () => {
  it("routes every server write through lib/log.ts", () => {
    // The lint rule enforces this; the assertion documents it and catches a waived line.
    const lint = read("scripts/lint.mjs");
    expect(lint).toContain("unstructured-log");
    expect(lint).toContain("console-in-server");
  });

  it("keeps request logging off in Fastify", () => {
    const app = read("src/server/app.ts");
    expect(app).toContain("logger: false");
    expect(app).toContain("disableRequestLogging: true");
  });

  it("accepts no free-form context field, so nothing can be added by accident", () => {
    const source = read("src/server/lib/log.ts");
    expect(source).not.toMatch(/\bextra\b|\bcontext\b|Record<string, unknown>\s*;/);
    expect(source).toMatch(/metrics\?: Record<string, number>/);
  });

  it("answers the five questions in docs/LOGGING.md", () => {
    const doc = read("docs/LOGGING.md");
    for (const heading of [
      "## What we log",
      "## What we never log",
      "## Why we log it",
      "## How long we retain it",
      "## Who can access it",
      "## When it is deleted",
    ]) {
      expect(doc, heading).toContain(heading);
    }
    for (const forbidden of ["passwords", "private keys", "session tokens", "recovery phrases"]) {
      expect(doc, forbidden).toContain(forbidden);
    }
  });
});
