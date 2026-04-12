FROM node:22-alpine AS build

WORKDIR /srv/cybertron/frontend

COPY app/frontend/package*.json ./
RUN npm ci --no-audit --no-fund

COPY app/frontend/ ./
RUN npm run build:full

# ── Default: HTTP-only (port 8080) ──
FROM nginxinc/nginx-unprivileged:1.27-alpine AS default

COPY app/frontend/nginx/default.conf /etc/nginx/conf.d/default.conf
COPY --from=build --chown=101:101 /srv/cybertron/frontend/dist/ /usr/share/nginx/html/

EXPOSE 8080

CMD ["nginx", "-g", "daemon off;"]

# ── TLS: HTTPS (port 8443) with HTTP→HTTPS redirect on 8080 ──
FROM nginxinc/nginx-unprivileged:1.27-alpine AS tls

COPY app/frontend/nginx/default-tls.conf /etc/nginx/conf.d/default.conf
COPY --from=build --chown=101:101 /srv/cybertron/frontend/dist/ /usr/share/nginx/html/

EXPOSE 8080 8443

CMD ["nginx", "-g", "daemon off;"]
