const DAY_MS = 24 * 60 * 60 * 1000;

/** Unix day number. Used wherever an exact timestamp would be gratuitous metadata. */
export function today(now = Date.now()): number {
  return Math.floor(now / DAY_MS);
}

export function dayToIsoDate(day: number): string {
  return new Date(day * DAY_MS).toISOString().slice(0, 10);
}
