import { api } from "../api.ts";
import { clear, el, field, input, money, notice } from "../ui.ts";
import { state } from "../state.ts";
import { sendShippingDetails, startConversation } from "../messaging.ts";

interface Listing {
  id: string;
  title: string;
  description: string;
  category: string;
  kind: string;
  priceMinor: number;
  currency: string;
  seller: { username: string; displayName: string };
  listedOn: string;
  reviewCount: number;
  averageRating: number | null;
}

export function renderMarket(root: HTMLElement, navigate: (route: string) => void): void {
  clear(root);
  const results = el("div", { class: "grid" });
  const search = input("q", { placeholder: "Search listings…" });
  const status = el("div", {});

  root.append(
    el("h1", {}, "Marketplace"),
    el(
      "p",
      { class: "lede" },
      "Digital goods and online services. Orders carry no address and no payment identity — terms are agreed in the encrypted channel attached to each order.",
    ),
    el(
      "div",
      { class: "row" },
      search,
      el("button", { onclick: () => void load() }, "Search"),
      el("button", { class: "ghost", onclick: () => navigate("#/sell") }, "Sell here"),
    ),
    status,
    results,
  );
  search.addEventListener("keydown", (event) => {
    if ((event as KeyboardEvent).key === "Enter") void load();
  });
  void load();

  async function load() {
    clear(status).append(el("p", { class: "muted" }, "Loading…"));
    const query = search.value.trim() ? `?q=${encodeURIComponent(search.value.trim())}` : "";
    const { listings } = await api<{ listings: Listing[] }>(`/api/market/listings${query}`);
    clear(status);
    clear(results);
    if (listings.length === 0) results.append(el("p", { class: "muted" }, "Nothing listed yet."));
    for (const listing of listings) results.append(card(listing));
  }

  function card(listing: Listing): HTMLElement {
    const buy = el("button", { class: "primary" }, "Order");
    const message = el("button", { class: "ghost" }, "Message seller");
    const local = el("div", {});
    buy.addEventListener("click", () => {
      // A physical order needs an address. It is collected here and sent through the order's
      // encrypted channel — the API call below carries the listing id and nothing else.
      const details =
        listing.kind === "physical_good"
          ? window.prompt("Delivery address (encrypted for the seller; the server never sees it)")
          : null;
      if (listing.kind === "physical_good" && !details?.trim()) return;
      buy.disabled = true;
      void api<{ id: string; channel: string }>("/api/market/orders", {
        method: "POST",
        body: { listingId: listing.id },
      })
        .then(async (order) => {
          await startConversation(listing.seller.username);
          if (details?.trim()) {
            await sendShippingDetails(listing.seller.username, order.channel, order.id, details.trim());
          }
          clear(local).append(notice(`Order ${order.id.slice(0, 8)} placed — see Orders.`));
        })
        .catch((error: Error) => clear(local).append(notice(error.message, "error")))
        .finally(() => {
          buy.disabled = false;
        });
    });
    message.addEventListener("click", () => {
      void startConversation(listing.seller.username).then(() => navigate("#/chat"));
    });

    return el(
      "article",
      { class: "card" },
      el("h2", { style: "margin-top:0" }, listing.title),
      el(
        "div",
        { class: "row" },
        el("span", { class: "price" }, money(listing.priceMinor, listing.currency)),
        el("span", { class: "tag" }, KIND_LABELS[listing.kind] ?? listing.kind),
        el("span", { class: "tag" }, listing.category),
      ),
      el("p", { class: "muted" }, listing.description.slice(0, 220)),
      el(
        "div",
        { class: "row muted mono" },
        el("span", {}, `by ${listing.seller.displayName} (@${listing.seller.username})`),
        el(
          "span",
          {},
          listing.averageRating === null
            ? "no reviews yet"
            : `★ ${listing.averageRating} (${listing.reviewCount})`,
        ),
      ),
      el("div", { class: "row" }, state.account ? buy : el("span", { class: "muted" }, "sign in to order"), message),
      local,
    );
  }
}

const KIND_LABELS: Record<string, string> = {
  digital_good: "digital good",
  service: "service",
  physical_good: "physical good",
};

export function renderSell(root: HTMLElement): void {
  clear(root);
  const status = el("div", {});
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
      el("h2", { style: "margin-top:0" }, "Apply to sell"),
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
    const price = input("price", { type: "number", min: "0", step: "0.01", value: "0" });
    const currency = el(
      "select",
      { name: "currency" },
      ...["USD", "EUR", "XMR", "BTC"].map((code) => el("option", { value: code }, code)),
    );
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
      el("h2", { style: "margin-top:0" }, `Selling as ${displayName}`),
      field("Title", title),
      field("Description", description),
      field("Category", category),
      el("div", { class: "row" }, field("Price", price), field("Currency", currency), field("Kind", kind)),
      el("button", { class: "primary", type: "submit", style: "margin-top:14px" }, "Publish listing"),
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
          currency: (currency as HTMLSelectElement).value,
          priceMinor: Math.round(Number(price.value) * 100),
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
            el("div", { class: "price" }, money(listing.priceMinor, listing.currency)),
            el("div", { class: "muted mono" }, `listed ${listing.listedOn}`),
          ),
        );
      }
    }

    return el("div", {}, form, listings);
  }
}
