/**
 * Point 91: development, test and production are three configurations, and the ways they
 * are allowed to differ are the ways written down in `docs/ENVIRONMENT.md`. What this file
 * defends is the direction of the mistakes — a missing secret must stop production, a
 * development placeholder must never be accepted there, and a typo in `NODE_ENV` must not
 * quietly select the permissive path.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { loadConfig, parseEnvironment } from "../src/server/config.ts";
import { TEST_DIALECT } from "./database.ts";

const read = (path: string) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

/** Runs `loadConfig()` against a chosen environment, leaving the real one untouched. */
function withEnv<T>(vars: Record<string, string | undefined>, fn: () => T): T {
  const saved = { ...process.env };
  for (const [key, value] of Object.entries(vars)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  try {
    return fn();
  } finally {
    for (const key of Object.keys(process.env)) if (!(key in saved)) delete process.env[key];
    Object.assign(process.env, saved);
  }
}

describe("there are three environments and no fourth", () => {
  it("accepts exactly the three, and defaults to the safe-to-be-loud one", () => {
    expect(parseEnvironment(undefined)).toBe("development");
    expect(parseEnvironment("")).toBe("development");
    expect(parseEnvironment("test")).toBe("test");
    expect(parseEnvironment("production")).toBe("production");
  });

  it("refuses a near miss instead of reading it as 'not production'", () => {
    for (const typo of ["prod", "Production", "PRODUCTION", "staging", "dev"]) {
      expect(() => parseEnvironment(typo), typo).toThrow(/NODE_ENV/);
    }
  });
});

describe("production secrets are production's own", () => {
  it("refuses to start without one", () => {
    expect(() =>
      withEnv({ NODE_ENV: "production", RATE_LIMIT_PEPPER: undefined, RATE_LIMIT_PEPPER_FILE: undefined }, () =>
        loadConfig(),
      ),
    ).toThrow(/RATE_LIMIT_PEPPER/);
  });

  it("refuses one that is long enough but is a development placeholder", () => {
    const placeholder = withEnv(
      { NODE_ENV: "development", RATE_LIMIT_PEPPER: undefined, RATE_LIMIT_PEPPER_FILE: undefined },
      () => loadConfig().bucketPepper,
    );
    expect(placeholder.length).toBeGreaterThanOrEqual(32);
    expect(placeholder).toContain("development-only-");

    // The same string, copied into a production .env — the failure mode this check exists
    // for, because the length check alone would pass it.
    expect(() =>
      withEnv({ NODE_ENV: "production", RATE_LIMIT_PEPPER: placeholder, RATE_LIMIT_PEPPER_FILE: undefined }, () =>
        loadConfig(),
      ),
    ).toThrow(/development placeholder/);
  });

  it("accepts a real one", () => {
    const config = withEnv(
      { NODE_ENV: "production", RATE_LIMIT_PEPPER: "x".repeat(48), RATE_LIMIT_PEPPER_FILE: undefined },
      () => loadConfig(),
    );
    expect(config.env).toBe("production");
    expect(config.bucketPepper).toBe("x".repeat(48));
  });

  it("ships an example file with the shape of the configuration and none of its values", () => {
    const example = read(".env.example");
    // Every secret in the example is empty or commented out: a filled-in one is a value
    // somebody will deploy, and `npm run audit:secrets` would be the only thing that ever
    // looked at it again.
    for (const [, , value] of example.matchAll(/^(RATE_LIMIT_PEPPER|DATABASE_URL)=(.*)$/gm)) {
      expect(value ?? "").toBe("");
    }
  });
});

describe("the test environment is isolated by construction", () => {
  it("keeps its database in memory and its pepper per run", async () => {
    const { startTestServer } = await import("./helpers.ts");
    const first = await startTestServer();
    const second = await startTestServer();
    try {
      expect(first.config.env).toBe("test");
      expect(first.config.bucketPepper).not.toBe(second.config.bucketPepper);
      // Two servers, two empty databases: a `:memory:` file each on SQLite, a schema each
      // on PostgreSQL (`test/database.ts`). Neither can see what the other writes, which is
      // what makes the suite safe to run in parallel.
      expect(first.db.dialect).toBe(TEST_DIALECT);
      await first.db.run("INSERT INTO users (id, username, password_hash, created_day) VALUES (?, ?, ?, ?)", [
        "isolation-probe",
        "isolation-probe",
        "x",
        20260903,
      ]);
      expect(await second.db.all("SELECT * FROM users WHERE id = 'isolation-probe'")).toEqual([]);
      const users = await second.db.all("SELECT * FROM users");
      expect(users).toEqual([]);
    } finally {
      await first.close();
      await second.close();
    }
  });

  it("documents how the three differ", () => {
    const doc = read("docs/ENVIRONMENT.md");
    const section = doc.slice(doc.indexOf("## Three environments"));
    for (const word of ["development", "test", "production", "NODE_ENV"]) {
      expect(section, word).toContain(word);
    }
  });
});

/**
 * SEC-2026-018: `SESSION_TTL_MS=30d` used to boot. `Number("30d")` is `NaN`, `NaN <= now` is
 * false, and a `NaN` idle limit is never exceeded — the ceiling a limit configures, silently
 * off, or (on SQLite) every sign-in failing with a 409 that blames the database. Every numeric
 * limit now goes through the strict parsers, and the typo stops the boot with its own name.
 */
describe("a numeric limit is a number or the boot fails", () => {
  const limits = [
    "PORT",
    "SESSION_TTL_MS",
    "SESSION_IDLE_DAYS",
    "ENVELOPE_TTL_MS",
    "MAX_ENVELOPE_BYTES",
    "SEND_TOKEN_TTL_MS",
    "SEND_TOKEN_BATCH",
    "MAX_DELIVERY_DELAY_SECONDS",
    "BOND_COOLOFF_DAYS",
    "MAX_DELIVERY_BYTES",
    "DELIVERY_TTL_MS",
    "AUDIT_RETENTION_MS",
    "NOTIFICATION_RETENTION_MS",
    "STORAGE_FLOOR_BYTES",
    "MAX_BLOB_ROWS",
  ];

  it("refuses a typo, a fraction and a negative number, naming the variable", () => {
    for (const name of limits) {
      for (const bad of ["30d", "two weeks", "1.5", "-1", "1e3x"]) {
        expect(
          () => withEnv({ NODE_ENV: "test", [name]: bad }, () => loadConfig({ dialect: TEST_DIALECT })),
          `${name}=${bad}`,
        ).toThrow(new RegExp(name));
      }
    }
  });

  it("keeps the documented off switches and the defaults", () => {
    const config = withEnv(
      { NODE_ENV: "test", STORAGE_FLOOR_BYTES: "0", MAX_BLOB_ROWS: "0", BOND_COOLOFF_DAYS: "0", SESSION_TTL_MS: undefined },
      () => loadConfig({ dialect: TEST_DIALECT }),
    );
    expect(config.storageFloorBytes).toBe(0);
    expect(config.maxBlobRows).toBe(0);
    expect(config.bondCooloffMs).toBe(0);
    expect(config.sessionTtlMs).toBe(30 * 24 * 60 * 60 * 1000);
    expect(() => withEnv({ NODE_ENV: "test", SESSION_TTL_MS: "0" }, () => loadConfig({ dialect: TEST_DIALECT }))).toThrow(
      /SESSION_TTL_MS/,
    );
  });
});
