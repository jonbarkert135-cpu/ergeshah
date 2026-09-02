/**
 * Theme: one design system, two token sets (`src/client/styles/app.css`).
 *
 * Three states, not two. "System" is the default and means *follow the operating system*,
 * which is the only correct default — a reader who set their machine to light at sunrise
 * did not mean "except this one site". The two explicit choices are an override.
 *
 * The choice lives in `localStorage`, never on the server: a theme preference stored
 * server-side is one more column that describes a person, and this project does not keep
 * those (`docs/PRIVACY.md`).
 */
export type Theme = "system" | "dark" | "light";

const STORAGE_KEY = "symvolon.theme";
const ORDER: Theme[] = ["system", "dark", "light"];

export function currentTheme(): Theme {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === "dark" || stored === "light") return stored;
  } catch {
    // Private-mode storage denials are not an error worth telling anyone about.
  }
  return "system";
}

/**
 * Called once from the entry module, before the first render. There is deliberately no
 * inline script in the shell to do it earlier: an inline script needs a Content-Security
 * -Policy loophole, and a few milliseconds of the system theme is a much smaller price
 * than `unsafe-inline` (`src/server/security.ts`).
 */
export function applyTheme(theme: Theme = currentTheme()): void {
  const root = document.documentElement;
  if (theme === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", theme);
}

export function setTheme(theme: Theme): void {
  try {
    if (theme === "system") localStorage.removeItem(STORAGE_KEY);
    else localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    // Still apply it for this session.
  }
  applyTheme(theme);
}

/** What the toggle does: system → dark → light → system. */
export function nextTheme(from: Theme = currentTheme()): Theme {
  return ORDER[(ORDER.indexOf(from) + 1) % ORDER.length]!;
}

export function themeLabel(theme: Theme): string {
  return theme === "system" ? "System theme" : theme === "dark" ? "Dark theme" : "Light theme";
}
