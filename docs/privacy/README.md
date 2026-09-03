# Privacy

- [`../PRIVACY.md`](../PRIVACY.md) — field by field: what the server stores, why, at what
  precision, and for how long. Also what it refuses to store, and the metadata that remains
  observable anyway.
- [`../THREAT_MODEL.md`](../THREAT_MODEL.md) — the privacy attacker, and the residual risks
  no design here removes (timing, volume, the fact that a recipient device is necessarily
  known to the server).
- [`../METADATA.md`](../METADATA.md) — the metadata inventory: sender, recipient, timestamp,
  size, delivery state, typing, read receipts, presence — what each one leaks, and why every
  optional one is off by default. Also why there is no push notification.
- [`../DELETION.md`](../DELETION.md) — what "delete" removes at each of the four layers,
  disappearing messages, key destruction and its ceiling, and the retention table.
- [`../LOGGING.md`](../LOGGING.md) — the absence of an access log is a privacy control, and
  this is where it is written down.
- [`../BACKUPS.md`](../BACKUPS.md) — retention, because a backup that never expires undoes
  every deletion the product promises.

**Code:** `src/client/messaging.ts` (signals, disappearing messages, blocking, client-side
search — the metadata features live on the client because that is the only place they can be
private), `src/server/lib/rate_limit.ts` (daily-rotating HMACs instead of addresses),
`lib/time.ts` (day-granular timestamps), `lib/notify.ts` (a notification that describes
nothing), `lib/audit.ts` (privileged actions only, and they expire), `routes/messages.ts`
(no sender column).

**Kept honest by:** `test/defaults.test.ts` (privacy is the default, not a setting),
`test/notifications.test.ts` (an inbox that carries no subject, sender or count),
`test/metadata.test.ts` (no presence, no read state, no push, signals indistinguishable),
`test/deletion.test.ts` (expiry, key destruction, retention), `test/attachments.test.ts`,
`test/logging.test.ts`, `test/delivery.test.ts` (dumps the whole schema and asserts a
shipping address appears nowhere), `test/security.test.ts` (no column anywhere holds a
message plaintext).
