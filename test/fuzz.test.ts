/**
 * Fuzzing the parsers, points 160 and 161.
 *
 * Every other suite here feeds this code inputs somebody thought of. This one feeds it
 * inputs nobody thought of: malformed, truncated, duplicated, oversized, wrongly typed,
 * invalidly encoded, and on the boundary. The property under test is the one point 161
 * states — **reject safely** — which for this codebase means three separate things:
 *
 *   1. a parser either returns a value or throws an `Error`. Not a string, not `undefined`
 *      dressed as success, and not a `TypeError` from reading a property of `null`, which is
 *      a crash wearing a rejection's clothes;
 *   2. it does so in bounded time and bounded memory. A hostile length field that turns into
 *      an allocation, or a scan that never advances, is a denial of service in a function
 *      with no authentication in front of it;
 *   3. at a trust boundary — a cookie header, a request body — the answer is a 4xx. A 500 is
 *      this server admitting it did not expect the input, and it costs an error log line per
 *      request (docs/LOGGING.md), which is how a malformed header becomes an incident.
 *
 * The corpus is generated from a fixed seed, so a failure is reproducible from the name of
 * the case rather than from luck. Growing it is the point: a new parser gets a target here,
 * and a finding gets a named case beside the generated ones (`REGRESSIONS`).
 *
 * `docs/SECURITY_REVIEW.md` listed the absence of this file as the obvious next step for
 * `src/shared/media.ts`; `skills/vulnerability-remediation/SKILL.md` is the workflow a
 * finding from it goes through.
 */
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { register, startTestServer, type TestServer, TestClient } from "./helpers.ts";
import { parseCookies, serializeCookie } from "../src/server/lib/cookies.ts";
import { stripImageMetadata, metadataUnhandled } from "../src/shared/media.ts";
import { pad, unpad, paddedLength, MAX_PLAINTEXT_BYTES } from "../src/shared/crypto/padding.ts";
import { decodeMessage } from "../src/shared/crypto/ratchet.ts";
import { decodePhrase, phraseIsValid, normalizePhrase } from "../src/shared/crypto/mnemonic.ts";
import { base64UrlBytes, safeFileName } from "../src/shared/uploads.ts";
import { fromBase64Url, toBase64Url } from "../src/shared/encoding.ts";
import { parseXmr, xmrString } from "../src/shared/money.ts";
import { sodiumReady } from "../src/shared/crypto/sodium.ts";
import {
  asBase64Url,
  asCategory,
  asId,
  asInteger,
  asMoneroAddress,
  asString,
  asText,
  asUsername,
  asXmrAmount,
  asXmrPrice,
} from "../src/server/lib/validate.ts";
import { HttpError } from "../src/server/lib/errors.ts";

/**
 * A deterministic generator, because a fuzz suite that finds a bug on Tuesday and cannot
 * find it again on Wednesday is an anecdote. xorshift32: eleven lines, no dependency, and
 * the statistical quality of the stream does not matter — coverage of shapes does.
 */
function random(seed: number): () => number {
  let state = seed | 0 || 1;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) / 0x1_0000_0000;
  };
}

/** The shapes point 161 names, as bytes. */
function byteCorpus(next: () => number): Uint8Array[] {
  const out: Uint8Array[] = [
    new Uint8Array(0),
    new Uint8Array(1),
    new Uint8Array([0xff]),
    new Uint8Array([0xff, 0xd8, 0xff]), // JPEG magic and nothing else
    new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), // PNG signature alone
    new Uint8Array([...Buffer.from("RIFF"), 0xff, 0xff, 0xff, 0xff, ...Buffer.from("WEBP")]),
    new Uint8Array(64).fill(0x80),
  ];
  // Truncations and mutations of a plausible header, plus pure noise of assorted lengths.
  const headers = [
    [0xff, 0xd8, 0xff, 0xe1, 0x00, 0x10, ...Buffer.from("Exif\0\0")],
    [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, ...Buffer.from("IHDR")],
    [...Buffer.from("RIFF"), 0x20, 0x00, 0x00, 0x00, ...Buffer.from("WEBPVP8 ")],
  ];
  for (const header of headers) {
    for (let cut = 0; cut <= header.length; cut += 1) out.push(new Uint8Array(header.slice(0, cut)));
    for (let round = 0; round < 40; round += 1) {
      const bytes = new Uint8Array(header);
      const flips = 1 + Math.floor(next() * 4);
      for (let flip = 0; flip < flips; flip += 1) {
        bytes[Math.floor(next() * bytes.length)] = Math.floor(next() * 256);
      }
      out.push(bytes);
    }
  }
  for (const length of [3, 7, 16, 64, 255, 1024]) {
    const bytes = new Uint8Array(length);
    for (let index = 0; index < length; index += 1) bytes[index] = Math.floor(next() * 256);
    out.push(bytes);
  }
  return out;
}

/** The same shapes as text: empty, huge, duplicated, nested, invalid encoding, boundary. */
function stringCorpus(next: () => number): string[] {
  const out = [
    "",
    " ",
    "\u0000",
    "\uFFFD",
    "\uD800", // a lone surrogate: not valid UTF-8, and JSON.stringify will happily carry it
    "\u202Eexe.txt",
    "\uFEFF\uFEFF",
    "%",
    "%zz",
    "%C0%80",
    "%E0%A4%A",
    "a".repeat(100_000),
    "0".repeat(400),
    "-1",
    "1e3",
    "0x10",
    "NaN",
    "Infinity",
    "1_000",
    "١٢٣", // Arabic-Indic digits: digits to a human, not to a regular expression
    "e\u0301",
    "../../etc/passwd",
    "..\\..\\windows",
    "'; DROP TABLE users; --",
    "<script>alert(1)</script>",
    "{{7*7}}",
    "${jndi:ldap://x/y}",
    "\n".repeat(50),
    "a\r\nb",
    "0.".padEnd(20, "0"),
    "1000.000000000001",
    "999999999999999999999999",
    JSON.stringify({ v: 2 }),
    JSON.stringify({ v: 2, h: "!!!", ct: "!!!" }),
    "null",
    "[]",
    "{",
  ];
  for (let round = 0; round < 60; round += 1) {
    const length = Math.floor(next() * 40);
    let text = "";
    for (let index = 0; index < length; index += 1) {
      text += String.fromCharCode(Math.floor(next() * 0x2000));
    }
    out.push(text);
  }
  return out;
}

/** Nothing here may hang. Each target is called once per input, and the whole run is timed. */
const BUDGET_MS = 250;

/**
 * Call a target and judge how it ended. `ok` means it returned or threw an `Error`; the
 * detail is what we print when it did not.
 */
function safely(target: () => unknown): { ok: boolean; detail: string; ms: number } {
  const started = process.hrtime.bigint();
  try {
    target();
    return { ok: true, detail: "returned", ms: Number(process.hrtime.bigint() - started) / 1e6 };
  } catch (error) {
    const ms = Number(process.hrtime.bigint() - started) / 1e6;
    if (!(error instanceof Error)) return { ok: false, detail: `threw a non-Error: ${String(error)}`, ms };
    // A TypeError or a RangeError from inside a parser is not a rejection, it is the parser
    // being surprised: reading a property of `null`, indexing past an array, allocating a
    // length it read from the input. Those are the ones worth finding.
    if (error instanceof RangeError) return { ok: false, detail: `RangeError: ${error.message}`, ms };
    if (error instanceof TypeError) return { ok: false, detail: `TypeError: ${error.message}`, ms };
    return { ok: true, detail: `threw ${error.name}`, ms };
  }
}

let server: TestServer;

beforeAll(async () => {
  await sodiumReady();
  server = await startTestServer();
}, 60_000);

afterAll(async () => {
  await server.close();
});

describe("fuzzing the byte parsers (point 160)", () => {
  const corpus = byteCorpus(random(0x5eed_1));

  it("the image metadata walker never throws, never hangs, and never grows a file", () => {
    const failures: string[] = [];
    for (const bytes of corpus) {
      const result = safely(() => {
        const stripped = stripImageMetadata(bytes);
        // Stripping removes segments. A result longer than its input means a length field
        // from the file was believed, which is how a walker becomes an amplifier.
        if (stripped.length > bytes.length) throw new RangeError("output larger than input");
        metadataUnhandled(bytes);
      });
      if (!result.ok || result.ms > BUDGET_MS) {
        failures.push(`${bytes.length} bytes [${[...bytes.subarray(0, 8)].join(",")}]: ${result.detail} in ${result.ms.toFixed(1)}ms`);
      }
    }
    expect(failures).toEqual([]);
  });

  it("padding rejects malformed padding and round-trips everything it accepts", () => {
    const failures: string[] = [];
    for (const bytes of corpus) {
      const result = safely(() => {
        if (bytes.length <= MAX_PLAINTEXT_BYTES) {
          const padded = pad(bytes);
          if (padded.length !== paddedLength(bytes.length)) throw new RangeError("wrong bucket");
          if (toBase64Url(unpad(padded)) !== toBase64Url(bytes)) throw new RangeError("round trip");
        }
        try {
          // Unpadding hostile bytes: either the marker is there or it throws. Both are fine;
          // what would not be fine is a subarray of negative length or an infinite scan.
          unpad(bytes);
        } catch (error) {
          if (!(error instanceof Error)) throw error;
        }
      });
      if (!result.ok || result.ms > BUDGET_MS) failures.push(`${bytes.length} bytes: ${result.detail}`);
    }
    expect(failures).toEqual([]);
  });

  it("base64url decoding and its byte count agree, or refuse", () => {
    const failures: string[] = [];
    for (const text of stringCorpus(random(0x5eed_2))) {
      const result = safely(() => {
        const counted = base64UrlBytes(text);
        if (counted !== null && counted < 0) throw new RangeError(`negative length for ${JSON.stringify(text)}`);
        if (/^[A-Za-z0-9_-]*$/.test(text) && counted !== null) {
          const decoded = fromBase64Url(text);
          if (decoded.length !== counted) {
            throw new RangeError(`${JSON.stringify(text.slice(0, 12))}: counted ${counted}, decoded ${decoded.length}`);
          }
        }
      });
      if (!result.ok) failures.push(result.detail);
    }
    expect(failures).toEqual([]);
  });
});

describe("fuzzing the text parsers (point 161)", () => {
  const corpus = stringCorpus(random(0x5eed_3));

  it("every validator rejects with an HttpError or accepts, and nothing else", () => {
    const validators: Array<[string, (value: unknown) => unknown]> = [
      ["asString", (value) => asString(value, "field", 64)],
      ["asText", (value) => asText(value, "field", 4096)],
      ["asUsername", (value) => asUsername(value)],
      ["asId", (value) => asId(value, "id")],
      ["asInteger", (value) => asInteger(value, "n", 0, 100)],
      ["asBase64Url", (value) => asBase64Url(value, "blob", 1024)],
      ["asCategory", (value) => asCategory(value)],
      ["asMoneroAddress", (value) => asMoneroAddress(value, "address")],
      ["asXmrPrice", (value) => asXmrPrice(value, "priceXmr")],
      ["asXmrAmount", (value) => asXmrAmount(value, "amountXmr", 1)],
    ];
    const failures: string[] = [];
    const inputs: unknown[] = [...corpus, null, undefined, 0, -1, 1.5, true, [], {}, { toString: () => "x" }];
    for (const [name, validator] of validators) {
      for (const input of inputs) {
        const started = process.hrtime.bigint();
        try {
          validator(input);
        } catch (error) {
          if (!(error instanceof HttpError)) {
            failures.push(`${name}(${JSON.stringify(input)?.slice(0, 40)}): ${String(error)}`);
            continue;
          }
          // A validator's refusal is a 400 the client can act on, never a 500.
          if (error.statusCode >= 500) failures.push(`${name}: refused with ${error.statusCode}`);
        }
        const ms = Number(process.hrtime.bigint() - started) / 1e6;
        if (ms > BUDGET_MS) failures.push(`${name}: ${ms.toFixed(0)}ms on ${JSON.stringify(input)?.slice(0, 40)}`);
      }
    }
    expect(failures).toEqual([]);
  });

  it("money parsing is exact or refuses, and never returns an unsafe integer", () => {
    const failures: string[] = [];
    for (const text of corpus) {
      const result = safely(() => {
        const pico = parseXmr(text);
        if (pico === null) return;
        if (!Number.isSafeInteger(pico) || pico < 0) throw new RangeError(`${text} -> ${pico}`);
        // The string form has to survive the round trip, or a price a seller typed is not
        // the price that is stored.
        if (parseXmr(xmrString(pico)) !== pico) throw new RangeError(`${text} does not round-trip`);
      });
      if (!result.ok) failures.push(result.detail);
    }
    expect(failures).toEqual([]);
  });

  it("recovery phrases, file names and ratchet frames refuse hostile input", () => {
    const failures: string[] = [];
    for (const text of corpus) {
      for (const [name, target] of [
        ["decodePhrase", () => decodePhrase(text)],
        ["phraseIsValid", () => expect(typeof phraseIsValid(text)).toBe("boolean")],
        ["normalizePhrase", () => normalizePhrase(text)],
        ["safeFileName", () => {
          const name = safeFileName(text);
          // The one property of a name: it is a single segment, and it is not empty.
          if (name.length === 0 || /[/\\]/.test(name) || name.includes("..")) {
            throw new RangeError(`unsafe name from ${JSON.stringify(text.slice(0, 20))}: ${name}`);
          }
        }],
        ["decodeMessage", () => decodeMessage(text)],
      ] as Array<[string, () => unknown]>) {
        const result = safely(target);
        if (!result.ok) failures.push(`${name}: ${result.detail}`);
      }
    }
    expect(failures).toEqual([]);
  });
});

/**
 * Cookies are the fuzz target with a trust boundary in front of it: the header arrives from
 * a browser, is parsed before authentication, and is parsed on *every* request. Finding
 * SEC-2026-001 was here — `decodeURIComponent("%zz")` throws, so one malformed cookie made
 * every route answer 500 and wrote an error line per request.
 */
const REGRESSIONS = ["csrf=%zz", "session=%E0%A4%A", "a=%", "csrf=%C0%80", "session=%", "x=%%%"];

describe("fuzzing the cookie header (finding SEC-2026-001)", () => {
  it("parses or ignores every malformed value, and never throws", () => {
    const failures: string[] = [];
    const headers = [
      ...REGRESSIONS,
      "",
      ";",
      "=",
      "=value",
      "name=",
      "a=1; a=2",
      "a".repeat(5000) + "=b",
      "session=" + "%".repeat(200),
      `session=${encodeURIComponent("ünïcødé")}`,
      serializeCookie("session", "a=b; c", { secure: false }),
      ...stringCorpus(random(0x5eed_4)).map((value) => `session=${value}`),
    ];
    for (const header of headers) {
      const result = safely(() => {
        const parsed = parseCookies(header);
        if (typeof parsed !== "object" || parsed === null) throw new TypeError("not an object");
      });
      if (!result.ok) failures.push(`${JSON.stringify(header.slice(0, 30))}: ${result.detail}`);
    }
    expect(failures).toEqual([]);
  });

  it("a malformed cookie is answered by the check that was going to refuse it, not by a 500", async () => {
    const statuses: number[] = [];
    for (const cookie of REGRESSIONS) {
      const read = await server.app.inject({
        method: "GET",
        url: "/api/market/listings",
        headers: { cookie },
      });
      const write = await server.app.inject({
        method: "POST",
        url: "/api/auth/login",
        headers: { cookie, host: "localhost", origin: "http://localhost", "content-type": "application/json" },
        payload: "{}",
      });
      statuses.push(read.statusCode, write.statusCode);
    }
    // 200 for the public read, 403 for the write whose CSRF token did not match. Anything
    // in the 500s means the header reached code that did not expect it.
    expect(statuses.filter((status) => status >= 500)).toEqual([]);
    expect(new Set(statuses)).toEqual(new Set([200, 403]));
  });

  it("a session cookie that cannot be percent-decoded is not a valid session", async () => {
    const alice = await register(server, "fuzzalice");
    const token = alice.cookie("session");
    expect(token).toBeTruthy();
    const good = await server.app.inject({
      method: "GET",
      url: "/api/auth/me",
      headers: { cookie: `session=${token}` },
    });
    expect(good.statusCode).toBe(200);
    // The same token with a broken escape appended: it must not be truncated back into a
    // valid token by the decoder, and it must not be a 500 either.
    const mangled = await server.app.inject({
      method: "GET",
      url: "/api/auth/me",
      headers: { cookie: `session=${token}%zz` },
    });
    expect(mangled.statusCode).toBe(401);
  });
});

describe("fuzzing the request body at the trust boundary (point 161)", () => {
  it("no shape of body makes any route answer 500", async () => {
    const client = await register(server, "fuzzsweeper");
    const bodies: Array<[string, unknown]> = [
      ["empty", {}],
      ["null", null],
      ["array", []],
      ["string", "x"],
      ["number", 5],
      ["boolean", true],
      ["wrong types", { id: 1, username: 2, ciphertext: {}, status: [], priceXmr: 3, ids: {}, note: 9 }],
      ["huge", { title: "a".repeat(50_000), description: "b".repeat(50_000), ciphertext: "c".repeat(50_000) }],
      ["nested", { body: JSON.parse(`${"[".repeat(120)}1${"]".repeat(120)}`) }],
      ["duplicated keys", JSON.parse('{"id":"a","id":"b"}')],
      ["prototype", JSON.parse('{"__proto__":{"role":"admin"},"constructor":{"x":1}}')],
      ["invalid encoding", { title: "\uD800\uDC00\uD800", note: "\u0000\u0008" }],
      ["boundary numbers", { count: Number.MAX_SAFE_INTEGER, limit: -1, delaySeconds: 2 ** 53, amountXmr: "1e309" }],
      ["empty strings", { username: "", title: "", ciphertext: "", priceXmr: "", id: "" }],
    ];
    const params = ["does-not-exist", "../../../etc/passwd", "%2e%2e%2f", "a".repeat(200), "' OR 1=1 --", "%"];
    const failures: string[] = [];
    for (const route of server.app.routeInventory) {
      for (const param of route.url.includes(":") ? params : ["-"]) {
        const url = route.url.replace(/:[a-zA-Z]+/g, () => encodeURIComponent(param));
        for (const [label, body] of bodies) {
          if (route.method === "GET" && label !== "empty") continue;
          const response = await client.request(route.method, url, route.method === "GET" ? undefined : body);
          if (response.status >= 500) {
            failures.push(`${route.method} ${route.url} [${label}] -> ${response.status}`);
          }
        }
      }
    }
    expect(failures).toEqual([]);
  }, 180_000);

  it("no shape of query string makes a listing route answer 500", async () => {
    const anonymous = new TestClient(server);
    const queries = [
      "?q=" + "a".repeat(5000),
      "?limit=-1",
      "?limit=99999999999999999999",
      "?limit=NaN",
      "?cursor=%",
      "?cursor=" + "z".repeat(500),
      "?category=%00",
      "?q=%FF%FE",
      "?q[]=1&q[]=2",
      "?" + "a=1&".repeat(200),
    ];
    const failures: string[] = [];
    for (const route of server.app.routeInventory) {
      if (route.method !== "GET" || route.url.includes(":")) continue;
      for (const query of queries) {
        const response = await anonymous.request("GET", route.url + query);
        if (response.status >= 500) failures.push(`GET ${route.url}${query} -> ${response.status}`);
      }
    }
    expect(failures).toEqual([]);
  }, 120_000);
});
