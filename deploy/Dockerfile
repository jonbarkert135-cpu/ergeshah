# One stage builds the client, one runs the server. No compilers or package managers
# survive into the runtime image.
#
# Both stages are pinned by digest rather than by the `node:22-bookworm-slim` tag, so the
# image that passed CI is the image that runs. The tag is written above each digest so a
# human can see what is being pinned and refresh it deliberately:
#   docker buildx imagetools inspect node:22-bookworm-slim

# node:22-bookworm-slim
FROM node@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5 AS build
WORKDIR /app
COPY package.json package-lock.json .npmrc ./
# .npmrc sets ignore-scripts=true: no package in the tree runs code during installation.
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
COPY scripts ./scripts
ENV NODE_ENV=production
RUN npm run build:client && npm prune --omit=dev

# node:22-bookworm-slim
FROM node@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5 AS runtime
ENV NODE_ENV=production
WORKDIR /app
RUN mkdir -p /app/data && chown -R node:node /app
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/public ./public
COPY --chown=node:node package.json ./
COPY --chown=node:node src ./src
# Unprivileged from here down. The compose file also runs the container read-only with
# every capability dropped, so this process cannot write to its own code or regain root.
USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "--experimental-strip-types", "--disable-warning=ExperimentalWarning", "src/server/main.ts"]
