/**
 * Break-glass tool for the procedures in `docs/INCIDENT_RESPONSE.md` (point 52).
 *
 * During an incident the operator needs three things the HTTP API cannot give them: they
 * need to act for *other people's* accounts, they need it to work when the application is
 * stopped, and they need it to be one command they can copy at 3am rather than SQL typed
 * into a shell that is already on fire. That is the whole scope of this file.
 *
 *   node scripts/incident.mjs status
 *   node scripts/incident.mjs sessions:revoke-all --yes          # every session, everywhere
 *   node scripts/incident.mjs sessions:revoke <username> --yes
 *   node scripts/incident.mjs devices:revoke <username> --yes [--device <id>]
 *   node scripts/incident.mjs suspend <username> --reason "under investigation" --yes
 *   node scripts/incident.mjs reinstate <username> --yes
 *   node scripts/incident.mjs links:purge --yes                  # pending device links
 *   node scripts/incident.mjs lockdown:on --yes [--note "…"]     # freeze every write
 *   node scripts/incident.mjs lockdown:off --yes                 # thaw
 *
 * What it deliberately cannot do: read a message, read a vault, change a password, or mint
 * a session. None of those would help an incident, and each would turn this file into the
 * backdoor the architecture spends its time not having. Everything here is destructive in
 * the safe direction — it takes access away.
 *
 * Every destructive command refuses to run without `--yes`, prints the row counts it
 * changed, and touches no table that holds ciphertext beyond the envelopes addressed to a
 * device that can no longer read them.
 */
import { DatabaseSync } from "node:sqlite";
import { randomUUID } from "node:crypto";
import { existsSync } from "node:fs";

const DESTRUCTIVE = new Set([
  "lockdown:on",
  "lockdown:off",
  "sessions:revoke-all",
  "sessions:revoke",
  "devices:revoke",
  "suspend",
  "reinstate",
  "links:purge",
  "send-tokens:revoke",
]);

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

/** Flags, the same deliberately dumb parser as scripts/backup.mjs. */
function parseArgs(argv) {
  const flags = {};
  const positional = [];
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token.startsWith("--")) {
      const next = argv[i + 1];
      if (next === undefined || next.startsWith("--")) flags[token.slice(2)] = true;
      else {
        flags[token.slice(2)] = next;
        i += 1;
      }
    } else positional.push(token);
  }
  return { flags, positional };
}

/**
 * PostgreSQL deployments are refused loudly instead of half-supported: this tool would
 * need the `pg` driver, a connection string on a command line, and a second code path
 * nobody exercises. The SQL is printed instead, because an operator with `psql` open needs
 * the statement, not an apology.
 */
function refusePostgres(flags) {
  const url = flags.database ?? process.env.DATABASE_URL;
  const dialect = process.env.DB_DIALECT;
  if (!url && dialect !== "postgres") return;
  fail(
    "this tool speaks SQLite only. On PostgreSQL run the equivalent statement with psql:\n" +
      "  every session:      DELETE FROM sessions;\n" +
      "  one account:        DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE username = '…');\n" +
      "  suspend:            UPDATE users SET status = 'suspended', status_reason = '…' WHERE username = '…';\n" +
      "  revoke devices:     UPDATE devices SET revoked_at = <epoch ms> WHERE user_id = (SELECT id FROM users WHERE username = '…');\n" +
      "                      DELETE FROM one_time_prekeys WHERE device_id IN (SELECT id FROM devices WHERE revoked_at IS NOT NULL);\n" +
      "                      DELETE FROM envelopes WHERE recipient_device_id IN (SELECT id FROM devices WHERE revoked_at IS NOT NULL);\n" +
      "  pending links:      DELETE FROM device_links;",
  );
}

function open(flags) {
  const path = flags.db ?? process.env.SQLITE_PATH ?? "data/symvolon.sqlite";
  // Without this, SQLite helpfully creates an empty database and every command reports
  // zero rows changed — the most dangerous possible answer during an incident.
  if (!existsSync(path)) fail(`${path}: no such database (pass --db <file> or set SQLITE_PATH)`);
  const handle = new DatabaseSync(path, { readOnly: false });
  handle.exec("PRAGMA foreign_keys = ON");
  return handle;
}

function count(db, sql, params = []) {
  return Number(db.prepare(sql).get(...params).n ?? 0);
}

function userIdOf(db, username) {
  const row = db.prepare("SELECT id FROM users WHERE username = ?").get(username);
  if (!row) fail(`no account named ${JSON.stringify(username)}`);
  return row.id;
}

function requireConfirmation(command, flags) {
  if (!DESTRUCTIVE.has(command) || flags.yes === true) return;
  fail(`${command} changes the live database — re-run with --yes when you mean it`);
}

function status(db) {
  const lines = [
    `accounts:          ${count(db, "SELECT COUNT(*) AS n FROM users")}`,
    `  suspended:       ${count(db, "SELECT COUNT(*) AS n FROM users WHERE status = 'suspended'")}`,
    `  staff:           ${count(db, "SELECT COUNT(*) AS n FROM users WHERE role <> 'user'")}`,
    `sessions:          ${count(db, "SELECT COUNT(*) AS n FROM sessions")}`,
    `devices:           ${count(db, "SELECT COUNT(*) AS n FROM devices WHERE revoked_at IS NULL")}`,
    `  revoked:         ${count(db, "SELECT COUNT(*) AS n FROM devices WHERE revoked_at IS NOT NULL")}`,
    `undelivered:       ${count(db, "SELECT COUNT(*) AS n FROM envelopes")}`,
    `pending links:     ${count(db, "SELECT COUNT(*) AS n FROM device_links")}`,
    `open challenges:   ${count(db, "SELECT COUNT(*) AS n FROM auth_challenges")}`,
    // First line an operator wants when the service is answering 503 to every write.
    `lockdown:          ${count(db, "SELECT COUNT(*) AS n FROM lockdown") > 0 ? "ON — every write refused" : "off"}`,
    `send-token epoch:  ${count(db, "SELECT min_epoch AS n FROM send_token_epoch WHERE id = 1")}`,
  ];
  return `${lines.join("\n")}\n`;
}

/**
 * An entry in the same audit log the application writes, with no actor: nobody was signed
 * in — this is a command run on the machine. An incident nobody can reconstruct afterwards
 * is an incident that happens twice.
 */
function audit(db, action, note) {
  db.prepare(
    `INSERT INTO audit_log (id, actor_user_id, action, subject_type, subject_id, note, result, created_at)
     VALUES (?, NULL, ?, 'platform', 'platform', ?, 'ok', ?)`,
  ).run(randomUUID(), action, note.slice(0, 64), Date.now());
}

function revokeDevices(db, username, deviceId) {
  const userId = userIdOf(db, username);
  const devices = deviceId
    ? db.prepare("SELECT id FROM devices WHERE id = ? AND user_id = ?").all(deviceId, userId)
    : db.prepare("SELECT id FROM devices WHERE user_id = ? AND revoked_at IS NULL").all(userId);
  if (devices.length === 0) fail("no matching device on that account");
  const now = Date.now();
  let envelopes = 0;
  let prekeys = 0;
  db.exec("BEGIN IMMEDIATE");
  try {
    for (const device of devices) {
      db.prepare("UPDATE devices SET revoked_at = ? WHERE id = ?").run(now, device.id);
      prekeys += db.prepare("DELETE FROM one_time_prekeys WHERE device_id = ?").run(device.id)
        .changes;
      envelopes += db.prepare("DELETE FROM envelopes WHERE recipient_device_id = ?").run(device.id)
        .changes;
    }
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
  return (
    `revoked ${devices.length} device(s) of @${username}; ` +
    `deleted ${prekeys} one-time prekeys and ${envelopes} undelivered envelopes\n` +
    "their sessions are separate: run sessions:revoke to end those too\n"
  );
}

function main(argv) {
  const command = argv[0];
  const { flags, positional } = parseArgs(argv.slice(1));
  if (!command || command === "help" || flags.help) {
    process.stdout.write(
      "usage: node scripts/incident.mjs <command> [--db <file>] [--yes]\n" +
        "  status                          counts, so the blast radius is visible first\n" +
        "  sessions:revoke-all             end every session on the deployment\n" +
        "  sessions:revoke <username>      end every session of one account\n" +
        "  devices:revoke <username>       revoke devices, drop their prekeys and envelopes\n" +
        "  suspend <username> --reason …   suspend an account (its sessions stop working)\n" +
        "  reinstate <username>            undo a suspension\n" +
        "  links:purge                     delete pending device-link authorisations\n" +
        "  send-tokens:revoke              invalidate every outstanding sealed-sender token\n" +
        "  lockdown:on --note …            freeze every write; reads keep working\n" +
        "  lockdown:off                    thaw\n",
    );
    return;
  }

  refusePostgres(flags);
  requireConfirmation(command, flags);
  const db = open(flags);
  try {
    switch (command) {
      case "status":
        process.stdout.write(status(db));
        return;
      case "sessions:revoke-all": {
        const gone = db.prepare("DELETE FROM sessions").run().changes;
        process.stdout.write(`revoked ${gone} session(s) across every account\n`);
        return;
      }
      case "sessions:revoke": {
        const username = positional[0] ?? fail("usage: sessions:revoke <username> --yes");
        const gone = db
          .prepare("DELETE FROM sessions WHERE user_id = ?")
          .run(userIdOf(db, username)).changes;
        process.stdout.write(`revoked ${gone} session(s) of @${username}\n`);
        return;
      }
      case "devices:revoke": {
        const username = positional[0] ?? fail("usage: devices:revoke <username> --yes");
        process.stdout.write(
          revokeDevices(db, username, typeof flags.device === "string" ? flags.device : null),
        );
        return;
      }
      case "suspend": {
        const username = positional[0] ?? fail("usage: suspend <username> --reason … --yes");
        const reason = typeof flags.reason === "string" ? flags.reason.slice(0, 200) : "incident";
        db.prepare("UPDATE users SET status = 'suspended', status_reason = ? WHERE id = ?").run(
          reason,
          userIdOf(db, username),
        );
        process.stdout.write(`suspended @${username} (${reason}); its sessions now fail closed\n`);
        return;
      }
      case "reinstate": {
        const username = positional[0] ?? fail("usage: reinstate <username> --yes");
        db.prepare("UPDATE users SET status = 'active', status_reason = NULL WHERE id = ?").run(
          userIdOf(db, username),
        );
        process.stdout.write(`reinstated @${username}\n`);
        return;
      }
      case "lockdown:on": {
        const note = typeof flags.note === "string" ? flags.note.slice(0, 200) : "incident";
        // A freeze is not destructive and not a deletion: it stops every write, keeps the
        // books and the evidence, and leaves reads working (ADR-0080).
        db.prepare(
          "INSERT INTO lockdown (id, engaged_at, note) VALUES (1, ?, ?) " +
            "ON CONFLICT (id) DO UPDATE SET engaged_at = excluded.engaged_at, note = excluded.note",
        ).run(Date.now(), note);
        audit(db, "platform.locked_down", note);
        process.stdout.write(
          `lockdown ON (${note}): every write is refused with 503, reads still work.\n` +
            "sessions are untouched — run sessions:revoke-all as well if you believe one was stolen.\n" +
            "the payout worker's queue is frozen too, so nothing leaves the wallet.\n",
        );
        return;
      }
      case "lockdown:off": {
        const gone = db.prepare("DELETE FROM lockdown").run().changes;
        if (gone > 0) audit(db, "platform.reopened", "lockdown lifted");
        process.stdout.write(
          gone > 0 ? "lockdown off: writes accepted again\n" : "lockdown was not on\n",
        );
        return;
      }
      case "links:purge": {
        const gone = db.prepare("DELETE FROM device_links").run().changes;
        process.stdout.write(`deleted ${gone} pending device-link authorisation(s)\n`);
        return;
      }
      case "send-tokens:revoke": {
        // Raise the global sealed-sender epoch (MD-5, ADR-0111): one O(1) write makes every
        // outstanding token unspendable on its next use. It names no account — a token has no
        // owner — so this invalidates everyone's stockpile at once; clients refetch silently.
        const row = db
          .prepare("UPDATE send_token_epoch SET min_epoch = min_epoch + 1 WHERE id = 1 RETURNING min_epoch")
          .get();
        if (!row) fail("send_token_epoch has no row — is this database migrated to 029?");
        audit(db, "platform.send_tokens_revoked", `epoch -> ${row.min_epoch}`);
        process.stdout.write(
          `sealed-sender epoch raised to ${row.min_epoch}: every outstanding token is now refused.\n` +
            "dead tokens are swept as they expire; clients mint a fresh batch on their next send.\n",
        );
        return;
      }
      default:
        fail(`unknown command ${JSON.stringify(command)} — try: node scripts/incident.mjs help`);
    }
  } finally {
    db.close();
  }
}

main(process.argv.slice(2));
