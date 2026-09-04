import { api } from "../api.ts";
import { clear, el, emptyState, errorState, field, focusAnchor, formDialog, input, notice, price as formatPrice, say, skeletonCards, statusRegion, toast, withBusy } from "../ui.ts";
import { state } from "../state.ts";
import { sendShippingDetails, startConversation } from "../messaging.ts";

interface Listing {
  id: string;
  title: string;
  description: string;
  category: string;
  kind: string;
  priceXmr: string;
  seller: { username: string; displayName: string; level: number; bondXmr?: string };
  listedOn: string;
  reviewCount: number;
  distinctReviewers: number;
  averageRating: number | null;
}

export function renderMarket(root: HTMLElement, navigate: (route: string) => void): void {
  clear(root);
  const results = el("div", { class: "grid" });
  const search = input("q", { type: "search", placeholder: "Search listings…", "aria-label": "Search listings" });
  const status = statusRegion();

  // A form, so Enter and a phone keyboard's search key submit without a key handler.
  const toolbar = el(
    "form",
    { class: "row toolbar", role: "search" },
    el("div", { class: "grow" }, search),
    el("button", { type: "submit" }, "Search"),
    el("a", { class: "ghost", href: "#/sell" }, "Sell here"),
  );
  toolbar.addEventListener("submit", (event) => {
    event.preventDefault();
    void load();
  });
  // Categories are the sellers' own words, so the only honest list is the one the catalogue
  // actually contains (ADR-0082). Loaded once, beside the search box, as the entrance for
  // somebody who does not know what to type.
  const categories = el("div", { class: "row wrap" });
  let chosen: string | null = null;
  root.append(
    el("h1", {}, "Marketplace"),
    el(
      "p",
      { class: "lede" },
      "Digital goods and online services. Orders carry no address and no payment identity — terms are agreed in the encrypted channel attached to each order.",
    ),
    toolbar,
    categories,
    status,
    results,
  );
  void loadCategories();
  // The server pages by cursor, so the client keeps one: "more" asks for what comes after
  // the last row it has, never for page N (point 47).
  const more = el("button", { type: "button", class: "ghost" }, "Show more");
  const morerow = el("div", { class: "row center" }, more);
  morerow.hidden = true;
  root.append(morerow);
  let cursor: string | null = null;
  more.addEventListener("click", () => {
    void withBusy(more, () => load(cursor));
  });
  void load();

  async function loadCategories() {
    // The chip that was clicked is about to be replaced by its own redrawn twin.
    const restore = focusAnchor(categories);
    try {
      const { categories: rows } = await api<{
        categories: Array<{ category: string; listings: number }>;
      }>("/api/market/categories");
      clear(categories);
      if (rows.length === 0) return;
      for (const row of rows.slice(0, 12)) {
        const chip = el(
          "button",
          {
            type: "button",
            class: chosen === row.category ? "" : "ghost small",
            "aria-pressed": chosen === row.category ? "true" : "false",
          },
          `${row.category} (${row.listings})`,
        );
        chip.addEventListener("click", () => {
          // Clicking the chosen one clears it: a filter with no way off is a trap.
          chosen = chosen === row.category ? null : row.category;
          void loadCategories();
          void load();
        });
        categories.append(chip);
      }
      restore();
    } catch {
      // A missing category list is a missing convenience, not a broken page.
      clear(categories);
    }
  }

  async function load(after: string | null = null) {
    const term = search.value.trim();
    clear(status);
    morerow.hidden = true;
    if (!after) clear(results).append(skeletonCards(6));
    try {
      const query = new URLSearchParams();
      if (term) query.set("q", term);
      if (chosen) query.set("category", chosen);
      if (after) query.set("cursor", after);
      const suffix = query.size > 0 ? `?${query}` : "";
      const { listings, nextCursor } = await api<{ listings: Listing[]; nextCursor: string | null }>(
        `/api/market/listings${suffix}`,
      );
      cursor = nextCursor;
      morerow.hidden = nextCursor === null;
      if (!after) clear(results);
      // The result count is visible as a changed grid and silent otherwise, so it is said
      // rather than written: a sighted reader does not need a sentence to count cards.
      say(
        listings.length === 0
          ? "No listings match that"
          : after
            ? `${listings.length} more listings`
            : `${listings.length} listings${nextCursor ? ", more available" : ""}`,
      );
      if (listings.length === 0 && !after) {
        status.append(
          term
            ? emptyState(
                "No listings match that",
                `Nothing here matches “${term}”. Try a shorter word, or clear the search to see everything.`,
                el("button", { onclick: () => { search.value = ""; void load(); } }, "Clear search"),
              )
            : emptyState(
                "Nothing listed yet",
                "This marketplace is new. The first listing can be yours — applications are reviewed by a moderator.",
                el("button", { class: "primary", onclick: () => navigate("#/sell") }, "Sell here"),
              ),
        );
        return;
      }
      for (const listing of listings) results.append(card(listing));
    } catch {
      // The reader gets a cause they can act on; the reference for the real one is in the
      // response the API layer already surfaced (docs/API.md).
      if (after) clear(status).append(errorState("More listings did not load.", () => void load(after)));
      else clear(results).append(
        errorState("The listings did not load. Your connection, or ours.", () => void load()),
      );
    }
  }

  function card(listing: Listing): HTMLElement {
    const buy = el("button", { type: "button", class: "primary" }, "Order");
    const message = el("button", { type: "button", class: "ghost" }, "Message seller");
    const report = el("button", { type: "button", class: "ghost small", "aria-label": `Report ${listing.title}` }, "Report");
    const local = el("div", {});
    buy.addEventListener("click", () => {
      void order();
    });
    async function order() {
      // A physical order needs an address. It is collected here and sent through the order's
      // encrypted channel — the API call below carries the listing id and nothing else.
      let details: string | null = null;
      if (listing.kind === "physical_good") {
        const answer = await formDialog({
          title: "Where should it be sent?",
          body: "Encrypted for the seller in this browser. The server never sees it, and there is no column for it.",
          fields: [{ name: "address", label: "Delivery address", kind: "textarea", required: true, maxlength: 2000 }],
          confirmLabel: "Place order",
        });
        if (!answer?.address) return;
        details = answer.address;
      }
      try {
        const placed = await withBusy(buy, () =>
          api<{ id: string; channel: string }>("/api/market/orders", {
            method: "POST",
            body: { listingId: listing.id },
          }),
        );
        await startConversation(listing.seller.username);
        if (details) await sendShippingDetails(listing.seller.username, placed.channel, placed.id, details);
        toast(`Order ${placed.id.slice(0, 8)} placed`);
        clear(local).append(notice(`Order ${placed.id.slice(0, 8)} placed — see Orders.`, "ok"));
      } catch (error) {
        clear(local).append(notice((error as Error).message, "error"));
      }
    }
    message.addEventListener("click", () => {
      void startConversation(listing.seller.username).then(() => navigate("#/chat"));
    });
    report.addEventListener("click", () => {
      void formDialog({
        title: "Report this listing",
        body: "A moderator reads reports; sellers do not see who reported them.",
        fields: [
          {
            name: "reason",
            label: "Reason",
            kind: "select",
            options: [
              ["prohibited_goods", "Prohibited goods"],
              ["fraud", "Fraud or scam"],
              ["impersonation", "Impersonation"],
              ["spam", "Spam"],
              ["harassment", "Harassment"],
              ["other", "Something else"],
            ],
          },
          { name: "details", label: "Details (optional)", kind: "textarea", maxlength: 2000 },
        ],
        confirmLabel: "Send report",
        danger: true,
      }).then((answer) => {
        if (!answer) return;
        void api("/api/moderation/reports", {
          method: "POST",
          body: { targetType: "listing", targetId: listing.id, reason: answer.reason, details: answer.details },
        })
          .then(() => toast("Reported. Thank you."))
          .catch((error: Error) => clear(local).append(notice(error.message, "error")));
      });
    });

    return el(
      "article",
      { class: "card interactive" },
      el("h2", { class: "tight" }, listing.title),
      el(
        "div",
        { class: "row" },
        el("span", { class: "price" }, formatPrice(listing.priceXmr)),
        el("span", { class: "tag" }, KIND_LABELS[listing.kind] ?? listing.kind),
        el("span", { class: "tag" }, listing.category),
      ),
      el("p", { class: "muted" }, listing.description.slice(0, 220)),
      el(
        "div",
        { class: "row muted mono" },
        el(
          "span",
          {},
          `by ${listing.seller.displayName} (@${listing.seller.username}) · ${LEVEL_LABELS[listing.seller.level] ?? "new seller"}` +
            // Money this seller has staked against their own conduct, payable to a buyer a
            // moderator finds was harmed (ADR-0086). Shown only when there is one.
            (listing.seller.bondXmr ? ` · ${listing.seller.bondXmr} XMR bonded` : ""),
        ),
        el(
          "span",
          {},
          listing.averageRating === null
            ? "no reviews yet"
            // Buyers, not reviews: "5.0 from 1 buyer" says what it is (ADR-0029).
            : `★ ${listing.averageRating} from ${listing.distinctReviewers} ${listing.distinctReviewers === 1 ? "buyer" : "buyers"}`,
        ),
      ),
      el(
        "div",
        { class: "row" },
        state.account ? buy : el("span", { class: "muted" }, "sign in to order"),
        message,
        state.account ? report : null,
      ),
      // Said before the money moves, not in a help page after it (ADR-0069). The escrow is
      // the only protection this marketplace can offer, and it exists only for an order
      // placed here.
      el(
        "p",
        { class: "meta" },
        "Ordering here holds the price in escrow until you confirm. Pay a seller directly and there is no escrow, no dispute and no refund — we cannot see that payment and cannot return it.",
      ),
      local,
    );
  }
}

/**
 * A seller's level, in words. Earned only on completed orders paid through this platform
 * (ADR-0068), which is why the catalogue lists a level-3 seller above a newer one.
 */
const LEVEL_LABELS: Record<number, string> = {
  0: "new seller",
  1: "level 1 seller",
  2: "level 2 seller",
  3: "level 3 seller",
};

const KIND_LABELS: Record<string, string> = {
  digital_good: "digital good",
  service: "service",
  physical_good: "physical good",
};

export function renderSell(root: HTMLElement): void {
  clear(root);
  const status = statusRegion();
  root.append(el("h1", {}, "Sell on Symvolon"), status);
  void load();

  async function load() {
    const me = await api<{ seller: { displayName: string; status: string } | null }>("/api/auth/me");
    const applications = await api<{
      applications: Array<{ status: string; displayName: string; decisionNote: string | null }>;
    }>("/api/market/seller-applications/mine");
    clear(status);

    if (me.seller && me.seller.status === "active") {
      status.append(newListingForm(me.seller.displayName));
      return;
    }
    const pending = applications.applications.find((item) => item.status === "pending");
    if (pending) {
      status.append(
        notice(`Your application as “${pending.displayName}” is with moderation. You will see it here when it is decided.`),
      );
      return;
    }
    const rejected = applications.applications.find((item) => item.status === "rejected");
    if (rejected) status.append(notice(`Previous application rejected: ${rejected.decisionNote ?? "no reason given"}`, "error"));
    status.append(applicationForm());
  }

  function applicationForm(): HTMLElement {
    const displayName = input("displayName", { maxlength: "40" });
    const statement = el("textarea", { name: "statement", rows: "5", maxlength: "2000" });
    const result = el("div", {});
    const form = el(
      "form",
      { class: "card" },
      el("h2", { class: "tight" }, "Apply to sell"),
      el(
        "p",
        { class: "muted" },
        "A moderator reviews what you intend to sell. We ask for nothing else: no identity documents, no company details.",
      ),
      field("Seller name", displayName, "Shown on your listings"),
      field("What will you sell?", statement),
      el("button", { class: "primary", type: "submit" }, "Submit application"),
      result,
    );
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      void api("/api/market/seller-applications", {
        method: "POST",
        body: { displayName: displayName.value, statement: statement.value },
      })
        .then(() => void load())
        .catch((error: Error) => clear(result).append(notice(error.message, "error")));
    });
    return form;
  }

  function newListingForm(displayName: string): HTMLElement {
    const title = input("title", { maxlength: "120" });
    const description = el("textarea", { name: "description", rows: "6", maxlength: "8000" });
    const category = input("category", { maxlength: "40", placeholder: "e.g. design, code, tutoring" });
    // XMR, and no currency to choose (ADR-0060). A text field rather than `type=number`:
    // a number input hands back a value the browser has already parsed as a float, which is
    // the one thing a price with twelve decimals must not pass through. The server parses
    // the string and says what is wrong with it.
    const price = input("price", { inputmode: "decimal", placeholder: "0.045", value: "0" });
    const kind = el(
      "select",
      { name: "kind" },
      el("option", { value: "digital_good" }, "digital good"),
      el("option", { value: "service" }, "service"),
      el("option", { value: "physical_good" }, "physical good"),
    );
    const result = el("div", {});
    const listings = el("div", { class: "grid" });

    const form = el(
      "form",
      { class: "card" },
      el("h2", { class: "tight" }, `Selling as ${displayName}`),
      field("Title", title),
      field("Description", description),
      field("Category", category),
      el("div", { class: "row" }, field("Price in XMR", price), field("Kind", kind)),
      el("button", { class: "primary spaced", type: "submit" }, "Publish listing"),
      result,
    );
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      void api("/api/market/listings", {
        method: "POST",
        body: {
          title: title.value,
          description: description.value,
          category: category.value,
          kind: (kind as HTMLSelectElement).value,
          // Sent as the string the seller typed: the server parses the decimals, so no
          // float ever stands between what was typed and what is stored.
          priceXmr: price.value.trim(),
        },
      })
        .then(() => {
          clear(result).append(notice("Listing published."));
          void loadMine();
        })
        .catch((error: Error) => clear(result).append(notice(error.message, "error")));
    });

    void loadMine();
    async function loadMine() {
      const { seller, listings: mine } = await api<{
        seller: { displayName: string };
        listings: Listing[];
      }>(`/api/market/sellers/${encodeURIComponent(state.account!.username)}`);
      clear(listings).append(el("h2", {}, `Listings by ${seller.displayName}`));
      for (const listing of mine) {
        listings.append(
          el(
            "div",
            { class: "card" },
            el("strong", {}, listing.title),
            el("div", { class: "price" }, formatPrice(listing.priceXmr)),
            el("div", { class: "muted mono" }, `listed ${listing.listedOn}`),
          ),
        );
      }
    }

    return el("div", {}, form, listings);
  }
}
