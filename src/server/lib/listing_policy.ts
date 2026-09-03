/**
 * What a listing may not say (ADR-0069).
 *
 * The guarantee this marketplace offers is escrow: the price is held while the order runs,
 * and a dispute can move it. A deal settled off the platform gets none of that, and the
 * buyer usually discovers this after paying. The chat is end-to-end encrypted and will stay
 * unread, so the only place a rule can be enforced is the one text the server *does* hold in
 * the clear and publishes to strangers: the listing.
 *
 * So: a listing body may not carry a payment destination or an off-platform contact route.
 * That is a publishing rule about a public advertisement, not a filter on a conversation —
 * two sellers and a buyer may still say whatever they like to each other, and nothing here
 * can see it. The incentive in ADR-0068 is what does the work after that.
 *
 * Deliberately narrow, because a false positive here is a seller who cannot publish an
 * honest listing: an address shaped exactly like a Monero address, an email address, and a
 * short list of messenger names and "pay me directly" phrases in the two languages this
 * marketplace is used in. A determined seller can evade all of it — "my usual place, you
 * know where" — which is precisely why the level system exists instead of a cleverer filter.
 * ponytail: a regex list, not a classifier; the day it needs one, moderation is the answer.
 */
import { badRequest } from "./errors.ts";

/**
 * A Monero address as it is written down: 95 characters (106 integrated), base58, starting
 * with the network's own prefix. The same shape `asMoneroAddress` accepts, found anywhere
 * inside a longer text.
 */
const MONERO_ADDRESS = /[45789AB][1-9A-HJ-NP-Za-km-z]{94}/;

/** A Bitcoin address, for the seller who reads the rule as being about Monero. */
const OTHER_CHAIN = /\b(?:bc1[a-z0-9]{20,}|[13][1-9A-HJ-NP-Za-km-z]{25,34})\b/;

const EMAIL = /[^\s@]+@[^\s@]+\.[a-z]{2,}/i;

/** Contact routes that lead off this platform, in the two languages the catalogue is in. */
const OFF_PLATFORM_CONTACT =
  /\b(?:telegram|whatsapp|jabber|xmpp|matrix\.to|signal\.me|t\.me|wickr|discord)\b|телеграм|телега|вотсап|ватсап|вайбер|дискорд/i;

/** "Pay me directly", said the ways people say it. */
const OFF_PLATFORM_PAYMENT =
  /\b(?:pay(?:ment)? (?:me )?direct(?:ly)?|direct payment|outside the (?:platform|site|marketplace)|off[- ]?(?:platform|site)|write to me directly|contact me directly|dm me)\b|напряму[юя]|мимо (?:площадки|сайта|платформы)|вне (?:площадки|сайта|платформы)|пиши(?:те)? (?:мне )?(?:в|на) /i;

const RULES: Array<{ pattern: RegExp; message: string }> = [
  { pattern: MONERO_ADDRESS, message: "a listing may not contain a wallet address" },
  { pattern: OTHER_CHAIN, message: "a listing may not contain a wallet address" },
  { pattern: EMAIL, message: "a listing may not contain an email address" },
  {
    pattern: OFF_PLATFORM_CONTACT,
    message: "a listing may not point buyers to another messenger",
  },
  {
    pattern: OFF_PLATFORM_PAYMENT,
    message: "a listing may not offer payment outside the platform",
  },
];

/**
 * Refuses a listing text that advertises a way around the escrow. The error names the rule
 * rather than the pattern that matched: a filter that explains exactly how it was tripped is
 * a filter with a bypass guide attached.
 */
export function assertOnPlatform(text: string, field: string): string {
  const rule = RULES.find((candidate) => candidate.pattern.test(text));
  if (rule) throw badRequest(`${rule.message} (${field})`, "off_platform_offer");
  return text;
}
