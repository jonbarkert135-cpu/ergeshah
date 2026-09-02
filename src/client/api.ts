/** Thin fetch wrapper: same-origin only, CSRF token attached, no third-party anything. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

function csrfToken(): string {
  const match = document.cookie.match(/(?:^|;\s*)csrf=([^;]+)/);
  return match ? decodeURIComponent(match[1] as string) : "";
}

export async function api<T>(
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
    );
  }
  return data as T;
}
