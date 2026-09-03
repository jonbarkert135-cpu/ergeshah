/**
 * Timing noise (MD-2, ADR-0085), as two pure functions so they can be tested without a
 * clock, a browser or a server.
 *
 * Both take the randomness they use, rather than reaching for it: the client passes bytes
 * from libsodium's CSPRNG, and a test passes whatever it wants to assert about the edges.
 */

/**
 * A poll interval that is not the same every time. A fixed ten-second cadence is a
 * signature — it identifies this client among others on the same network, and it makes the
 * gap between a send and the next fetch predictable to anyone who can watch both. The
 * spread is deliberately wide (±40%) and the floor is deliberately not zero: noise that
 * approaches zero is a client that hammers the service.
 */
export function jitteredInterval(baseMs: number, unit: number): number {
  const clamped = Math.min(Math.max(unit, 0), 1);
  return Math.round(baseMs * (0.6 + clamped * 0.8));
}

/**
 * A delivery delay in whole quantisation steps (fifteen seconds). Quantised because a
 * delay of 3.471 seconds identifies the client that produced it, and never zero when the
 * feature is on: a delay that is sometimes nothing is a delay an observer can wait out.
 */
export function delayStepsSeconds(maxSeconds: number, unit: number, step = 15): number {
  const steps = Math.floor(maxSeconds / step);
  if (steps < 1) return 0;
  const clamped = Math.min(Math.max(unit, 0), 0.999_999);
  return (1 + Math.floor(clamped * steps)) * step;
}
