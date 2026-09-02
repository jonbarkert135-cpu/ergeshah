/**
 * Serves the client. Assets are read once at boot into memory from an explicit list —
 * there is no filesystem path derived from a request anywhere in this server, so path
 * traversal is not "mitigated", it is impossible.
 */
import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { FastifyInstance } from "fastify";

const PUBLIC_DIR = join(dirname(fileURLToPath(import.meta.url)), "../../../public");

const ASSETS: Array<{ route: string; file: string; type: string }> = [
  { route: "/assets/app.js", file: "app.js", type: "application/javascript; charset=utf-8" },
  { route: "/assets/app.css", file: "app.css", type: "text/css; charset=utf-8" },
  { route: "/assets/sodium.js", file: "sodium.js", type: "application/javascript; charset=utf-8" },
  { route: "/favicon.svg", file: "favicon.svg", type: "image/svg+xml" },
  // The digests of everything above, so a reader can build this repository and compare
  // one file instead of diffing a megabyte of JavaScript (docs/AUDIT.md).
  { route: "/build.txt", file: "BUILD.txt", type: "text/plain; charset=utf-8" },
];

export async function registerStaticRoutes(app: FastifyInstance): Promise<void> {
  const shellPath = join(PUBLIC_DIR, "index.html");
  const shell = existsSync(shellPath)
    ? readFileSync(shellPath, "utf8")
    : "<!doctype html><title>Symvolon</title><p>Client not built. Run <code>npm run build</code>.</p>";
  app.decorate("appShell", shell);

  app.get("/", async (_request, reply) => reply.type("text/html; charset=utf-8").send(shell));

  for (const asset of ASSETS) {
    const path = join(PUBLIC_DIR, asset.file);
    if (!existsSync(path)) continue;
    const body = readFileSync(path);
    app.get(asset.route, async (_request, reply) => reply.type(asset.type).send(body));
  }

  /** Liveness/readiness for the reverse proxy and for `docker compose` health checks. */
  app.get("/healthz", async (_request, reply) => {
    try {
      await app.db.get("SELECT 1 AS ok");
      return { status: "ok" };
    } catch {
      return reply.status(503).send({ status: "degraded" });
    }
  });
}
