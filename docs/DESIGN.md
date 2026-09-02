# Design system

## The position

A quiet, dense, typographic interface — the register of a well-made tool. No terminal green,
no Matrix rain, no glow, no gradient buttons, no decorative motion. The reasoning is not
taste: a product that asks people to trust it with private conversations and then dresses as
a hacker film is telling them it is a costume. Restraint is the argument.

What was studied and deliberately *not* copied: Apple's typographic calm and generous
leading; Linear's density and keyboard-first restraint; Stripe's hierarchy in dense data;
Vercel's monochrome discipline; the plain, document-like layouts of the serious privacy
tools. What we took from them is a *standard*, not a look. Symvolon's own signature is
narrower: two brand colours and their tints, hairline borders instead of shadows,
monospace reserved for things that are literally machine data, and a single bright surface
per screen — the primary action.

Everything below is enforced by `test/design.test.ts`, not just described here.

## Tokens

All tokens live at the top of `src/client/styles/app.css`. Component CSS references
**semantic** tokens only (`--surface`, `--text-muted`, `--border-strong`); the palette
(`--ink-600`, `--paper-200`) appears nowhere below the token block, and view code contains
no colour at all.

| Group | Tokens |
| --- | --- |
| Palette | `--ink-900…200`, `--paper-100…400`, `--grey-500…700`, `--state-*` |
| Surfaces | `--bg`, `--bg-sunken`, `--surface`, `--surface-raised`, `--surface-hover`, `--input-bg` |
| Text | `--text`, `--text-muted`, `--text-faint`, `--accent`, `--accent-text` |
| Lines | `--border`, `--border-strong`, `--border-width` |
| State | `--danger`, `--danger-surface`, `--warn`, `--ok`, `--focus` |
| Depth | `--shadow-sm`, `--shadow-md`, `--shadow-lg`, `--scrim` |
| Type | `--font-sans`, `--font-mono`, `--text-xs…2xl`, `--leading-*`, `--tracking-*` |
| Space | `--space-1…8` (4 px grid) |
| Radius | `--radius-sm` 6, `--radius-md` 10, `--radius-lg` 14, `--radius-pill` |
| Controls | `--control-height` 34, `--control-pad-*`, `--input-pad-*` |
| Motion | `--ease`, `--duration-fast` 90 ms, `--duration` 160 ms |

**Typography.** System faces only — SF, Segoe, Roboto, whatever the machine renders best.
A web font is a request that identifies a reader, and there is no third-party request in
this client at all. The scale is a 1.200 minor third from 15 px, rounded to whole pixels.
Monospace is not decoration: it means *this is machine data* — a key, a fingerprint, a
price, an identifier, a recovery word.

**Spacing.** One 4 px grid. The only values off it are the control paddings, which are
tokens of their own because a 34 px control with 8 px of vertical padding reads soft.

## Components

`button` (`primary`, `ghost`, `danger`, `small`, `icon`, `loading`), `input` / `textarea` /
`select` with `.field` + label + hint, `.card` (`.interactive`), `.panel`, `.tag`
(`ok`/`warn`/`danger`), `.notice` (`error`/`ok`), `.toast`, `.state` (empty and error),
`.skeleton`, `.spinner`, `table` inside `.table-wrap`, native `dialog`, `header.top` with
inline brand mark and theme control, `.chat`, `.messages`, `.phrase`, `pre.block`.

Three rules that keep it consistent:

1. **Every asynchronous surface has three states.** `skeleton()` while loading — the shape
   of what is coming, not a spinner over a void — `emptyState()` when there is nothing,
   with the one action that changes that, and `errorState()` with a retry. They are
   functions in `src/client/ui.ts`, so no view improvises its own blank rectangle.
2. **Destructive questions use `confirmDialog()`**, a native `<dialog>`: focus trapping,
   Escape and the backdrop are the platform's, and every line we do not write cannot be
   wrong. `window.confirm` is gone from the client.
3. **No inline styles.** `style-src 'self'` carries no `'unsafe-inline'`, so the browser
   *silently drops* a `style` attribute — a real bug this rewrite found and fixed. Utility
   classes replaced them, and the linter (`inline-style`) rejects new ones.

## Dark and light

One system, two token sets — not two designs. `:root` is dark; `[data-theme="light"]` swaps
the semantic tokens; `@media (prefers-color-scheme: light)` applies the same light set to
anyone who has expressed no preference. The header control cycles **system → dark → light**,
and system is the default, because a reader who set their machine to light at sunrise did
not mean "except this one site". The choice is stored in `localStorage` and never on the
server: a theme preference server-side is one more column that describes a person.

The test asserts that all three blocks define exactly the same token names. A token missing
from one of them is a component that keeps its dark value on a light desktop.

## Motion

Two durations, one easing curve, five animations in the whole stylesheet: the button
spinner, the skeleton shimmer, the toast entrance, the dialog entrance, and the shared
spin. Each explains a state change. `prefers-reduced-motion: reduce` removes all of them —
there is nothing in this interface that is worth overriding that request for.

## Accessibility (point 40)

Not a pass at the end; a property of the helpers every view is built from.

- **Semantic HTML first.** Navigation is `<nav aria-label="Primary">` with links (history,
  middle-click, link lists), pages start with one `<h1>`, data is a `<table>` with `<thead>`
  and `scope="col"`, questions are `<dialog>` with `<form method="dialog">`. ARIA appears
  only where HTML has no word for it: `role="log"` on the message history, `aria-pressed` on
  the buyer/seller toggle, `aria-expanded` on the address reveal.
- **Every control has a name.** `field()` associates the label (`for`/`id`) and wires the
  hint with `aria-describedby`; controls without a visible label carry `aria-label`. The
  browser pass checks the page for controls that have neither.
- **Keyboard.** A skip link is the first tab stop. A hash navigation moves focus to the new
  `<h1>` (`announce()`), so a screen reader hears the page change and the keyboard starts at
  the content, not on a button from the previous view. Dialogs trap and return focus
  natively; Escape cancels, Enter submits.
- **No `window.prompt`/`confirm`/`alert`.** They have no label, no hint and no styling. The
  lint rule `browser-prompt` refuses them; `formDialog()` and `confirmDialog()` replace them.
- **Contrast is computed, not assumed.** `test/design.test.ts` resolves every text token
  against every surface token in both themes and fails below 4.5:1. The first run of that
  test failed: `--text-faint` was 3.65–4.35 and the light theme's `--danger` 3.66. Both were
  fixed by adding palette steps, not by weakening the rule.
- **Visible focus** everywhere (`:focus-visible`, 2 px ring in a token colour); a focused
  heading shows no ring because it is a landing point, not a control. Toasts are a
  `role="status"` live region; nothing else is live — the whole app used to be, which reads
  every render aloud.

## Mobile first (point 41)

Breakpoints: 640 px (phone), 860 px (tablet), and the content width of 1120 px. Everything
below is in the stylesheet's responsive section and asserted by `test/design.test.ts`.

- **Navigation** becomes a fixed bar along the bottom under 640 px, every destination
  visible, under the thumb. (Six labels do not fit beside the brand at 360 px, and a strip
  that scrolls with its scrollbar hidden looks like three.) The header loses its
  `backdrop-filter` there, because that property makes it the containing block for fixed
  descendants.
- **Tables stack.** `table()` puts each column's name on its cells (`data-label`); below
  640 px the header row disappears and each row is a labelled block.
- **Messaging is the screen** on a phone: the conversation list is a strip above, the
  history scrolls in its own box, and the composer is a `<form>` that sticks above the
  navigation bar. Inputs are 16 px so iOS does not zoom into them.
- **Touch targets** are 44 px on coarse pointers (`@media (pointer: coarse)` raises
  `--control-height`); the browser pass lists any visible control shorter than that.
- **Checked in a real browser**, not only in CSS: Chromium at 360 × 740 with touch and at
  1280 × 800, both themes, the whole path from registration through ordering, text delivery,
  dispute and moderation. That pass is what found the bottom bar pinned to the header and the
  skeleton widths silently dropped by the style-src policy.
