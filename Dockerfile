FROM node:24-bookworm AS build

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY index.html vite.config.js ./
COPY public ./public
COPY src ./src
RUN npm run build

FROM node:24-bookworm AS runtime

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=3100 \
    SNORT_JSON_LOG=/data/alerts.jsonl \
    MAXMIND_DATABASE_PATH=/geoip/GeoLite2-City.mmdb

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --chown=node:node server ./server
COPY --chown=node:node --from=build /app/dist ./dist
RUN mkdir -p /data /geoip && chown node:node /data /geoip

USER node
EXPOSE 3100
CMD ["node", "server/server.mjs"]
