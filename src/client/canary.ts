/**
 * The canary line in the footer (OPS-7, ADR-0099).
 *
 * The value of a canary is not in the statement, which says nothing has happened, but in
 * the *date*: a statement nobody has refreshed since the day it promised is the only thing
 * an operator under a gag order can say by staying quiet. That only works if the age is in
 * front of people who are not looking for it, so it lives in the footer of every screen
 * rather than on a page somebody has to find.
 *
 * The copy below says "PGP key", not "OpenPGP": the bundle audit greps the built client for
 * the string `openpgp`, because ADR-0015 promises that dependency never reaches the browser,
 * and prose would trip it as loudly as an import.
 *
 * Fetched once per page load and cached, because the footer is rebuilt on every navigation
 * and a request per redraw would be a beacon of its own. A deployment that publishes no
 * canary renders nothing at all: an empty widget saying "not configured" would train people
 * to ignore the line that matters.
 */
import { api } from "./api.ts";
import { clear, el } from "./ui.ts";

interface Canary {
  published: boolean;
  statement?: string;
  signature?: string;
  publicKey?: string;
  fingerprint?: string;
  signedDate?: string;
  nextDate?: string;
  ageDays?: number;
  overdueDays?: number;
}

let current: Canary | null = null;

/** Called once at boot. A failure is silence: the footer keeps its other line. */
export async function loadCanary(): Promise<void> {
  try {
    current = await api<Canary>("/api/canary");
  } catch {
    current = null;
  }
  document.querySelectorAll(".canary").forEach((slot) => fill(slot as HTMLElement));
}

/** The placeholder the footer holds; filled in when the fetch lands, and on every redraw. */
export function canarySlot(): HTMLElement {
  const slot = el("div", { class: "canary" });
  fill(slot);
  return slot;
}

function fill(slot: HTMLElement): void {
  clear(slot);
  if (!current?.published) return;
  const overdue = (current.overdueDays ?? 0) > 0;
  if (overdue) slot.classList.add("overdue");
  else slot.classList.remove("overdue");

  const summary = overdue
    ? `Operator canary: ${current.overdueDays} days overdue. Signed ${current.signedDate}, was due ${current.nextDate}.`
    : `Operator canary: signed ${current.signedDate} (${current.ageDays} days ago), next due ${current.nextDate}.`;

  const details = el("details");
  details.append(
    el("summary", {}, summary),
    el(
      "p",
      {},
      "Signed with the operator's PGP key, fingerprint ",
      el("span", { class: "mono" }, current.fingerprint ?? ""),
      ". This server hands you both the statement and the key, so check the fingerprint against the one in SECURITY.md — a server that lied about the statement would hand out a key to match it. Save the two blocks below and run gpg --verify.",
    ),
    el("pre", { class: "mono" }, current.statement ?? ""),
    el("pre", { class: "mono" }, current.signature ?? ""),
    el("pre", { class: "mono" }, current.publicKey ?? ""),
  );
  slot.append(details);
}
