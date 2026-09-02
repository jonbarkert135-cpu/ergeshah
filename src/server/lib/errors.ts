export class HttpError extends Error {
  readonly statusCode: number;
  readonly code: string;

  constructor(statusCode: number, code: string, message: string) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
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
