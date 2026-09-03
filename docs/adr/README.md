# Architectural decision records

Point 94 asks for ADRs under `docs/adr/`. This directory is the index; the records
themselves live in [`../DECISIONS.md`](../DECISIONS.md), one file, in numeric order.

**Why one file.** Fifty-one records in fifty-one files is fifty-one places to grep, a
link-rot surface, and — since every record here cites the ones it supersedes or narrows —
a set of relative links to keep in step. One file is searchable in a single pass
(`grep -n "^## ADR-" docs/DECISIONS.md`), diffs as an append in the commit that made the
decision, and cannot drift from itself. What was actually missing was not files but a way
in, which is what this page is: every record, grouped by the area it belongs to. If a
record ever needs to be long enough to be its own document, it gets one and is linked from
here.

**Writing one.** A decision that is hard to reverse — a protocol change, a dependency, a
schema shape, anything that trades one property for another — is appended to
`DECISIONS.md` in the same commit that makes it, with the sections every record here uses:
*Status*, *Context*, *Decision*, *Rejected*, *Consequences*. Superseding an old record
means editing its status line and saying which record replaced it (see ADR-0002 and
ADR-0022), never deleting it. Then add the row here. `test/adr.test.ts` fails if a record
exists that this index does not list, if this index links to a record that does not exist,
or if a record is missing a section.

## By area

### Architecture

| ADR | Decision |
| --- | --- |
| [ADR-0001](../DECISIONS.md#adr-0001--node-22--typescript-executed-without-a-build-step-on-the-server) | Node 22 + TypeScript, executed without a build step on the server |
| [ADR-0013](../DECISIONS.md#adr-0013--the-project-is-called-symvolon-the-protocol-labels-keep-their-old-strings) | The project is called Symvolon; the protocol labels keep their old strings |
| [ADR-0050](../DECISIONS.md#adr-0050--one-version-in-the-path-one-envelope-for-every-error) | One version in the path, one envelope for every error |
| [ADR-0051](../DECISIONS.md#adr-0051--no-websocket-and-the-nine-things-one-would-have-to-do) | No WebSocket, and the nine things one would have to do |

### Cryptographic protocol

| ADR | Decision |
| --- | --- |
| [ADR-0003](../DECISIONS.md#adr-0003--libsodium-for-every-primitive-the-protocol-composed-from-published-specs) | libsodium for every primitive; the protocol composed from published specs |
| [ADR-0004](../DECISIONS.md#adr-0004--version-pin-libsodium-wrappers-sumo-0715-not-0716) | Version pin: `libsodium-wrappers-sumo` 0.7.15, not 0.7.16 |
| [ADR-0011](../DECISIONS.md#adr-0011--encrypt-ratchet-headers-and-pad-plaintexts-break-the-wire-format-to-do-it) | Encrypt ratchet headers and pad plaintexts; break the wire format to do it |
| [ADR-0014](../DECISIONS.md#adr-0014--a-random-master-key-wrapped-once-per-unlocking-route) | A random master key, wrapped once per unlocking route |
| [ADR-0035](../DECISIONS.md#adr-0035--revocation-is-final-and-claiming-a-prekey-is-not-an-ordinary-read) | Revocation is final, and claiming a prekey is not an ordinary read |

### Authentication and identity

| ADR | Decision |
| --- | --- |
| [ADR-0006](../DECISIONS.md#adr-0006--password-split-client-side-argon2id--auth-secret--vault-key) | Password split client-side (Argon2id → auth secret ‖ vault key) |
| [ADR-0012](../DECISIONS.md#adr-0012--hash-the-auth-secret-with-standard-library-scrypt-not-a-native-argon2-dependency) | Hash the auth secret with standard-library scrypt, not a native Argon2 dependency |
| [ADR-0015](../DECISIONS.md#adr-0015--openpgp-for-verifying-signatures-server-side-only) | `openpgp` for verifying signatures, server-side only |
| [ADR-0038](../DECISIONS.md#adr-0038--a-session-that-ends-of-neglect-and-a-token-that-does-not-last-a-month) | A session that ends of neglect, and a token that does not last a month |

### Database

| ADR | Decision |
| --- | --- |
| [ADR-0005](../DECISIONS.md#adr-0005--sqlite-by-default-postgresql-optional-behind-a-40-line-interface) | SQLite by default, PostgreSQL optional, behind a 40-line interface |
| [ADR-0028](../DECISIONS.md#adr-0028--integrity-under-concurrency-lives-in-the-database) | Integrity under concurrency lives in the database |
| [ADR-0030](../DECISIONS.md#adr-0030--search-is-an-index-and-a-page-is-a-cursor) | Search is an index, and a page is a cursor |
| [ADR-0036](../DECISIONS.md#adr-0036--one-writer-at-a-time-on-sqlite-because-handlers-are-not-synchronous) | One writer at a time on SQLite, because handlers are not synchronous |
| [ADR-0052](../DECISIONS.md#adr-0052--rolling-back-a-migration-is-a-restore-not-a-down-script) | Rolling back a migration is a restore, not a down script |

### Deployment and operations

| ADR | Decision |
| --- | --- |
| [ADR-0018](../DECISIONS.md#adr-0018--reproducible-client-build-verified-against-the-deployment) | Reproducible client build, verified against the deployment |
| [ADR-0019](../DECISIONS.md#adr-0019--one-instance-serves-both-the-clearnet-and-the-onion-service) | One instance serves both the clearnet and the onion service |
| [ADR-0034](../DECISIONS.md#adr-0034--backups-that-expire-and-logs-that-are-boring-on-purpose) | Backups that expire, and logs that are boring on purpose |
| [ADR-0037](../DECISIONS.md#adr-0037--a-break-glass-tool-that-can-only-take-access-away) | A break-glass tool that can only take access away |
| [ADR-0040](../DECISIONS.md#adr-0040--the-deployment-is-checked-by-tests-not-described-by-documents) | The deployment is checked by tests, not described by documents |
| [ADR-0048](../DECISIONS.md#adr-0048--health-is-two-endpoints-and-monitoring-counts-nothing-but-numbers) | Health is two endpoints, and monitoring counts nothing but numbers |
| [ADR-0053](../DECISIONS.md#adr-0053--three-environments-and-a-placeholder-that-says-what-it-is) | Three environments, and a placeholder that says what it is |

### Privacy model

| ADR | Decision |
| --- | --- |
| [ADR-0021](../DECISIONS.md#adr-0021--a-delivery-address-is-a-message-not-a-column) | A delivery address is a message, not a column |
| [ADR-0032](../DECISIONS.md#adr-0032--notifications-that-do-not-describe-messages) | Notifications that do not describe messages |
| [ADR-0041](../DECISIONS.md#adr-0041--disappearing-messages-are-an-agreement-not-a-guarantee) | Disappearing messages are an agreement, not a guarantee |
| [ADR-0042](../DECISIONS.md#adr-0042--typing-read-receipts-and-presence-are-messages-and-they-are-off) | Typing, read receipts and presence are messages, and they are off |
| [ADR-0043](../DECISIONS.md#adr-0043--attachments-are-blind-blobs-with-a-client-chosen-id) | Attachments are blind blobs with a client-chosen id |
| [ADR-0044](../DECISIONS.md#adr-0044--search-happens-in-the-browser-and-push-does-not-happen-at-all) | Search happens in the browser, and push does not happen at all |
| [ADR-0045](../DECISIONS.md#adr-0045--a-review-does-not-name-its-buyer) | A review does not name its buyer |
| [ADR-0047](../DECISIONS.md#adr-0047--blocking-is-the-recipients-decision-and-the-server-is-not-told) | Blocking is the recipient's decision, and the server is not told |

### Security and abuse

| ADR | Decision |
| --- | --- |
| [ADR-0008](../DECISIONS.md#adr-0008--rate-limiting-without-storing-addresses) | Rate limiting without storing addresses |
| [ADR-0024](../DECISIONS.md#adr-0024--authorization-is-proved-by-the-route-table-not-by-review) | Authorization is proved by the route table, not by review |
| [ADR-0025](../DECISIONS.md#adr-0025--rate-limits-per-operation-counted-against-the-account) | Rate limits per operation, counted against the account |
| [ADR-0033](../DECISIONS.md#adr-0033--uploads-are-hostile-and-this-server-refuses-to-know-anything-about-them) | Uploads are hostile, and this server refuses to know anything about them |
| [ADR-0039](../DECISIONS.md#adr-0039--arithmetic-instead-of-a-captcha) | Arithmetic instead of a CAPTCHA |
| [ADR-0049](../DECISIONS.md#adr-0049--ceilings-the-rate-limiter-cannot-enforce) | Ceilings the rate limiter cannot enforce |
| [ADR-0057](../DECISIONS.md#adr-0057--uploads-stop-before-the-disk-does-and-trust_proxy-names-the-proxy) | Uploads stop before the disk does, and `TRUST_PROXY` names the proxy |

### Marketplace

| ADR | Decision |
| --- | --- |
| [ADR-0009](../DECISIONS.md#adr-0009--payments-are-out-of-scope-for-now) | Payments are out of scope for now |
| [ADR-0017](../DECISIONS.md#adr-0017--digital-delivery-a-blind-blob-plus-a-key-sent-over-the-ratchet) | Digital delivery: a blind blob plus a key sent over the ratchet |
| [ADR-0029](../DECISIONS.md#adr-0029--goods-that-are-not-files-and-reputation-that-is-hard-to-buy) | Goods that are not files, and reputation that is hard to buy |
| [ADR-0046](../DECISIONS.md#adr-0046--payment-state-is-designed-before-it-is-built-and-stays-outside-the-messenger) | Payment state is designed before it is built, and stays outside the messenger |

### Client and interface

| ADR | Decision |
| --- | --- |
| [ADR-0007](../DECISIONS.md#adr-0007--no-framework-on-the-client-no-third-party-runtime-dependency-in-the-browser) | No framework on the client, no third-party runtime dependency in the browser |
| [ADR-0020](../DECISIONS.md#adr-0020--a-180-line-qr-encoder-instead-of-a-dependency-and-verification-per-device) | A 180-line QR encoder instead of a dependency, and verification per device |
| [ADR-0027](../DECISIONS.md#adr-0027--a-design-system-and-the-megabyte-that-was-in-front-of-it) | A design system, and the megabyte that was in front of it |
| [ADR-0031](../DECISIONS.md#adr-0031--accessibility-and-the-small-screen-as-properties-of-the-helpers) | Accessibility and the small screen as properties of the helpers |

### Process and governance

| ADR | Decision |
| --- | --- |
| [ADR-0002](../DECISIONS.md#adr-0002--agpl-30-only-superseded-by-adr-0022) | AGPL-3.0-only *(superseded by ADR-0022)* |
| [ADR-0010](../DECISIONS.md#adr-0010--dependency-budget) | Dependency budget |
| [ADR-0016](../DECISIONS.md#adr-0016--audits-as-ci-checks-written-in-the-repository-not-bought) | Audits as CI checks, written in the repository, not bought |
| [ADR-0022](../DECISIONS.md#adr-0022--proprietary-license-supersedes-adr-0002) | Proprietary license; supersedes ADR-0002 |
| [ADR-0023](../DECISIONS.md#adr-0023--one-project-one-tree-no-pre-built-openclosed-split) | One project, one tree: no pre-built open/closed split |
| [ADR-0026](../DECISIONS.md#adr-0026--project-hygiene-as-executable-checks-not-as-a-document) | Project hygiene as executable checks, not as a document |
| [ADR-0054](../DECISIONS.md#adr-0054--the-records-stay-in-one-file-and-docsadr-is-the-way-in) | The records stay in one file, and `docs/adr/` is the way in |
| [ADR-0055](../DECISIONS.md#adr-0055--two-questions-before-a-commit-and-one-order-when-requirements-disagree) | Two questions before a commit, and one order when requirements disagree |
| [ADR-0056](../DECISIONS.md#adr-0056--a-mechanism-carries-its-threat-and-a-file-has-a-ceiling) | A mechanism carries its threat, and a file has a ceiling |
| [ADR-0058](../DECISIONS.md#adr-0058--the-criticism-of-this-project-lives-in-this-project) | The criticism of this project lives in this project |
