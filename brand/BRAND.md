# Symvolon — identity

## The name

*σύμβολον* (symbolon): a token broken deliberately in two. Each party kept one half; the
halves fitted together were the proof that both belonged to the same agreement. It is the
origin of the word "symbol", and it is a precise description of two things this platform
does — a handshake where two key halves prove each other, and a marketplace where two
strangers need proof before they trade.

## The mark

One token. One cut, at 38°. The halves slid a little out of true, because a split token is
only a proof once someone puts it back together.

| File | Use |
| --- | --- |
| `symvolon-mark.svg` | Default. Ink on light backgrounds. |
| `symvolon-mark-inverse.svg` | Paper on dark backgrounds. |
| `symvolon-icon.svg` | App icon, favicon, launcher. Dark. |
| `symvolon-icon-light.svg` | App icon on a dark surface that needs a light tile. |

Rules, in order of how badly breaking them hurts:

1. **Never add text to the mark.** The wordmark is the word set in type next to it, never
   inside it.
2. **Never recolour the halves separately.** Two colours turn a cut token into a pie chart.
3. **Clear space**: at least 25% of the mark's width on every side.
4. **Minimum size**: 16 px. It was drawn to survive that; below it, use the icon tile.
5. **Do not rotate, skew, outline, add a gradient, or add a shadow.** The offset between
   the halves is the only movement the mark needs.

## Colour

| Token | Value | Use |
| --- | --- | --- |
| Ink | `#0B0D10` | The mark, text, dark surfaces. Not pure black — pure black reads as a hole on OLED. |
| Paper | `#F5F4F0` | Light surfaces, the mark on dark. Slightly warm, so long reading sessions do not glare. |

Interface tints, all derived from the two, so the product can be dark without being loud:

| Token | Value | Use |
| --- | --- | --- |
| Surface | `#14171C` | Cards and panels on ink |
| Surface raised | `#1A1E24` | Inputs, secondary buttons |
| Line | `#272C34` | Borders and dividers |
| Muted text | `#9AA1AB` | Secondary copy |
| Danger | `#E0837A` | Destructive actions only |

Paper is the only bright surface in the interface, and it is reserved for the single
primary action on a screen. No neon, no glow, no terminal green: a security product that
dresses as one is asking to be doubted.

Two colours are the whole palette. A privacy product that shouts in five accent colours is
lying about what it is. Anything else needed later (a state colour for an error, a muted
grey for secondary text) is a tint of these two, added to this file first.

## Voice

Plain, specific, and never overclaiming. The product's own README refuses to say
"anonymous" or "unbreakable"; marketing copy does not get a different standard. Say what
the system does, name what it does not do, and let `docs/THREAT_MODEL.md` carry the weight.
