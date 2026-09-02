# API

- [`../API.md`](../API.md) — every endpoint: method, path, authentication, rate-limit
  bucket and purpose, plus the conventions (JSON, cookies, CSRF, error shape) and a list of
  what the API deliberately does not have.
- [`../ENVIRONMENT.md`](../ENVIRONMENT.md#rate_limits) — the buckets those endpoints name.
- [`../ARCHITECTURE.md`](../ARCHITECTURE.md#request-lifecycle) — what happens to a request
  between the proxy and the handler.

**Code:** `src/server/routes/` (auth, keys, messages, notifications, market, deliveries,
moderation, static), `src/server/lib/validate.ts` (every value that reaches SQL passes
through it), `src/client/api.ts` (the only place the client talks to it).

**Kept honest by:** `test/docs.test.ts` walks Fastify's route table and fails if an endpoint
exists that `API.md` does not document — or if `API.md` documents one that no longer
exists; `test/authorization.test.ts` calls every route anonymously; `test/security.test.ts`
sweeps every unsafe route without a CSRF token.
