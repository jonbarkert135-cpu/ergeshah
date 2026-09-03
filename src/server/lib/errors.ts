export class HttpError extends Error {
  readonly statusCode: number;
  readonly code: string;
  /**
   * Extra fields merged into the JSON body. It exists for one case: an error the client
   * is expected to *act* on rather than show, and which therefore has to carry what the
   * next attempt needs (the proof-of-work challenge). Anything here is sent to whoever
   * made the request, so it holds instructions, never internals.
   */
  readonly details?: Record<string, unknown>;

  constructor(
    statusCode: number,
    code: string,
    message: string,
    details?: Record<string, unknown>,
  ) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
  }
}

export const badRequest = (message: string, code = "bad_request") =>
  new HttpError(400, code, message);
export const unauthorized = (message = "authentication required") =>
  new HttpError(401, "unauthorized", message);
export const forbidden = (message = "not allowed") => new HttpError(403, "forbidden", message);
export const notFound = (message = "not found") => new HttpError(404, "not_found", message);
export const conflict = (message: string, code = "conflict") => new HttpError(409, code, message);
export const tooManyRequests = (message = "rate limit exceeded") =>
  new HttpError(429, "rate_limited", message);
/**
 * 428 Precondition Required: the request is fine, it just has not paid yet. The body
 * carries the challenge to solve, so a client that understands this answer needs no extra
 * round trip and no separate endpoint (ADR-0039).
 */
export const proofOfWorkRequired = (pow: Record<string, unknown>, message: string) =>
  new HttpError(428, "pow_required", message, { pow });

/**
 * A constraint the database refused: unique, foreign key or check. Since migration 007
 * these are a deliberate second line of defence, not bugs, so a route may translate one
 * into the 409 it would have raised had its own check won the race.
 */
export function isConstraintViolation(error: unknown): boolean {
  const failure = error as { errcode?: number; code?: string; message?: string };
  // node:sqlite exposes the extended result code, whose low byte is SQLITE_CONSTRAINT (19):
  // 1555 unique, 787 foreign key, 275 check. pg exposes SQLSTATE class 23 for the same three.
  return (
    (typeof failure?.errcode === "number" && (failure.errcode & 0xff) === 19) ||
    (typeof failure?.code === "string" && failure.code.startsWith("23"))
  );
}

/** `await orConflict(db.run(...), conflict("..."))`: the race loser gets the same answer as the check. */
export async function orConflict<T>(action: Promise<T>, instead: HttpError): Promise<T> {
  try {
    return await action;
  } catch (error) {
    if (isConstraintViolation(error)) throw instead;
    throw error;
  }
}
