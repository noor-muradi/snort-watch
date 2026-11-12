FROM node:20-alpine AS build

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY index.html vite.config.js ./
COPY src ./src
RUN npm run build

FROM node:20-alpine AS runtime

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=3100 \
    SNORT_JSON_LOG=/data/alerts.jsonl

WORKDIR /app
COPY --chown=node:node server ./server
COPY --chown=node:node --from=build /app/dist ./dist
RUN mkdir -p /data && chown node:node /data

USER node
EXPOSE 3100
CMD ["node", "server/server.mjs"]
