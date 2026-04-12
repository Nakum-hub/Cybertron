# --- Stage 1: Install dependencies ---
FROM node:22-alpine AS deps

WORKDIR /srv/cybertron/backend

COPY app/backend/package*.json ./
RUN npm ci --omit=dev --no-audit --no-fund

# --- Stage 2: Production image ---
FROM node:22-alpine

WORKDIR /srv/cybertron/backend

RUN apk add --no-cache su-exec

COPY --from=deps /srv/cybertron/backend/node_modules ./node_modules
COPY app/backend/ ./
COPY app/backend/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh && \
    mkdir -p /srv/cybertron/uploads && \
    chown -R node:node /srv/cybertron/backend /srv/cybertron/uploads

ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=8001

USER node

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost:8001/v1/system/readiness || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]

CMD ["node", "server.js"]
