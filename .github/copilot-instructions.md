# Project guidelines

## Project

Snort Watch is a local React console and Node.js API for Snort 2 alerts, with a fast-alert-to-NDJSON bridge and custom-rule management. The containerized deployment is under development; see [README.md](../README.md) and track milestones in [PLAN.md](../PLAN.md).

## Key files

- `src/App.jsx`, `src/RulesPanel.jsx`, `src/style.css`: dashboard UI and styles.
- `server/server.mjs`: alerts API and static UI server.
- `server/snort-fast-bridge.mjs`, `server/snort-fast.js`: alert ingestion and normalization.
- `server/rules-manager.mjs`, `server/snort-supervisor.mjs`: rule validation, GPLv2 Community Rules, and supervised Snort lifecycle.
- `server/server.mjs`, `server/rules-api-proxy.mjs`: alert API, static console, and private rules API proxy.
- `compose.yaml`, `Dockerfile`, `snort.Dockerfile`: console, bridge, and Snort sensor containers.
- `scripts/`, `systemd/`: host installer and systemd integration.
- `test/`: Node.js test suite.

## Working agreements

- Preserve least privilege. Do not use `privileged: true`, mount the Docker socket, or run systemd in an application container.
- Make Snort capture capabilities and host-network requirements explicit; add permissions only when verified necessary.
- Keep local logs and generated data out of source control; `data/` is intentionally ignored.
- Match existing JavaScript/JSX style, add focused tests, and update the README for user-visible or deployment changes.
- Use the maintained Node.js 24 image tag for project containers.
- Before every minor-release push, update `CHANGELOG.md` with shipped changes and `PLAN.md` with completed and remaining work.
- Before finishing, run `npm test` and `npm run build` for application changes.

## Commands

- Install dependencies: `npm ci`
- Run tests: `npm test`
- Build UI: `npm run build`
- Run local stack: `docker compose up --build -d`
