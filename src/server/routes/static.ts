/**
 * Serves the client. Everything is read once at boot from an explicit directory listing —
 * there is no filesystem path derived from a request anywhere in this server, so path
 * traversal is not "mitigated", it is impossible: a request either matches a route string
 * registered at startup or it does not exist.
 *
 * Two performance properties live here, both of which are ordinary web hygiene that this
 * project had been missing (ADR-0027):
 *
 * - **Content-addressed assets.** `app-<hash>.js` changes name whenever it changes bytes,
 *   so it can be cached for a year and a deployment can never serve a stale mix.
 * - **Pre-compressed bodies.** The build writes `.br` and `.gz` next to each asset, so the
 *   server spends no CPU per request and can afford the slowest, smallest brotli setting.
 */
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

const PUBLIC_DIR = join(dirname(fileURLToPath(import.meta.url)), "../../../public");

const TYPES: Record<string, string> = {
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".txt": "text/plain; charset=utf-8",
};

interface Asset {
  identity: Buffer;
  brotli: Buffer | null;
  gzip: Buffer | null;
  type: string;
  /** Content-addressed names never change meaning, so they are cacheable forever. */
  immutable: boolean;
}

function load(path: string, type: string, immutable: boolean): Asset {
  const compressed = (extension: string) =>
    existsSync(`${path}${extension}`) ? readFileSync(`${path}${extension}`) : null;
  return {
    identity: readFileSync(path),
    brotli: compressed(".br"),
    gzip: compressed(".gz"),
    type,
    immutable,
  };
}

/** Picks the smallest encoding the client said it understands. */
function send(request: FastifyRequest, reply: FastifyReply, asset: Asset): FastifyReply {
  const accepted = String(request.headers["accept-encoding"] ?? "");
  reply
    .type(asset.type)
    .header("vary", "accept-encoding")
    .header(
      "cache-control",
      asset.immutable ? "public, max-age=31536000, immutable" : "no-store",
    );
  if (asset.brotli && /\bbr\b/.test(accepted)) {
    return reply.header("content-encoding", "br").send(asset.brotli);
  }
  if (asset.gzip && /\bgzip\b/.test(accepted)) {
    return reply.header("content-encoding", "gzip").send(asset.gzip);
  }
  return reply.send(asset.identity);
}

export async function registerStaticRoutes(app: FastifyInstance): Promise<void> {
  const shellPath = join(PUBLIC_DIR, "index.html");
  const built = existsSync(shellPath);
  const shell = built
    ? load(shellPath, "text/html; charset=utf-8", false)
    : {
        identity: Buffer.from(
          "<!doctype html><title>Symvolon</title><p>Client not built. Run <code>npm run build</code>.</p>",
        ),
        brotli: null,
        gzip: null,
        type: "text/html; charset=utf-8",
        immutable: false,
      };
  app.decorate("appShell", shell.identity.toString("utf8"));

  app.get("/", async (request, reply) => send(request, reply, shell));

  const assetsDir = join(PUBLIC_DIR, "assets");
  const names = existsSync(assetsDir)
    ? readdirSync(assetsDir).filter((name) => !name.endsWith(".br") && !name.endsWith(".gz"))
    : [];
  for (const name of names) {
    const extension = name.slice(name.lastIndexOf("."));
    const asset = load(join(assetsDir, name), TYPES[extension] ?? "application/octet-stream", true);
    app.get(`/assets/${name}`, async (request, reply) => send(request, reply, asset));
  }

  for (const [route, file, immutable] of [
    ["/favicon.svg", "favicon.svg", true],
    // The digests of everything above, so a reader can build this repository and compare
    // one file instead of diffing a megabyte of JavaScript (docs/AUDIT.md).
    ["/build.txt", "BUILD.txt", false],
  ] as const) {
    const path = join(PUBLIC_DIR, file);
    if (!existsSync(path)) continue;
    const extension = file.slice(file.lastIndexOf("."));
    const asset = load(path, TYPES[extension] ?? "application/octet-stream", immutable);
    app.get(route, async (request, reply) => send(request, reply, asset));
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
