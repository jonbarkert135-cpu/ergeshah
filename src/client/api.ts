/** Thin fetch wrapper: same-origin only, CSRF token attached, no third-party anything. */
import { sodiumReady } from "../shared/crypto/sodium.ts";
import { solveProofOfWork } from "../shared/pow.ts";

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  /** Present on a 428: the challenge whose solution this request needs. */
  readonly pow?: { challenge: string; mac: string; bits: number };

  constructor(
    status: number,
    code: string,
    message: string,
    pow?: { challenge: string; mac: string; bits: number },
  ) {
    super(message);
    this.status = status;
    this.code = code;
    this.pow = pow;
  }
}

function csrfToken(): string {
  const match = document.cookie.match(/(?:^|;\s*)csrf=([^;]+)/);
  return match ? decodeURIComponent(match[1] as string) : "";
}

/**
 * The server answers 428 on the account endpoints with a puzzle instead of a CAPTCHA
 * (point 71). Solving it is the client's job and nobody's business: no iframe, no third
 * party, no image to squint at. It costs a fraction of a second, so it is handled here
 * rather than shown to the user — the sign-in button simply takes slightly longer.
 */
async function solve(challenge: { challenge: string; mac: string; bits: number }) {
  const sodium = await sodiumReady();
  return {
    challenge: challenge.challenge,
    mac: challenge.mac,
    nonce: solveProofOfWork(challenge.challenge, challenge.bits, (input) =>
      sodium.crypto_hash_sha256(input),
    ),
  };
}

export async function api<T>(
  path: string,
  options: { method?: string; body?: unknown } = {},
): Promise<T> {
  try {
    return await send<T>(path, options);
  } catch (error) {
    // One retry, and only for the one code that means "this is solvable". A second 428
    // would be a server that never accepts the answer, and retrying that forever is how a
    // client becomes the load it was supposed to prevent.
    if (!(error instanceof ApiError) || error.code !== "pow_required" || !error.pow) throw error;
    const body = (options.body ?? {}) as Record<string, unknown>;
    return await send<T>(path, { ...options, body: { ...body, pow: await solve(error.pow) } });
  }
}

async function send<T>(
  path: string,
  options: { method?: string; body?: unknown } = {},
): Promise<T> {
  const method = options.method ?? "GET";
  const response = await fetch(path, {
    method,
    credentials: "same-origin",
    referrerPolicy: "no-referrer",
    headers: {
      // Only declare a JSON body when there is one: an empty body with a JSON
      // content-type is a parse error, not a request.
      ...(options.body === undefined ? {} : { "content-type": "application/json" }),
      ...(method === "GET" ? {} : { "x-csrf-token": csrfToken() }),
    },
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  const text = await response.text();
  let data: Record<string, unknown> = {};
  if (text) {
    try {
      data = JSON.parse(text) as Record<string, unknown>;
    } catch {
      // The API always answers JSON; anything else means a proxy or captive portal is
      // answering for it, which the user needs to be told rather than shown a parse error.
      throw new ApiError(response.status, "unexpected_response", "unexpected response from the server");
    }
  }
  if (!response.ok) {
    throw new ApiError(
      response.status,
      String(data.error ?? "error"),
      String(data.message ?? "request failed"),
      data.pow as { challenge: string; mac: string; bits: number } | undefined,
    );
  }
  return data as T;
}
