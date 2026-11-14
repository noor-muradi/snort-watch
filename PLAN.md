# Development plan

**Goal:** Run Snort and Snort Watch as a secure, container-based IDS stack. Keep the UI, alert ingestion, and rule management usable through Compose.

## Status

- [x] Create `feature/containerized-snort` from the initial release.
- [x] Choose Snort 2.9.20 from Ubuntu 24.04 packages and Node.js 24 images.
- [x] Choose Linux host networking with explicit interface and protected-network settings.
- [x] Choose persistent log/rule volumes and a private Unix socket for rule management.
- [x] Rename the Compose UI service from `dashboard` to `console`.
- [x] Build the Snort sensor, bridge, and console images and validate Snort's configuration.
- [x] Validate Compose startup, console APIs, private rules API, Snort startup, and sensor log access.
- [x] Verify an actual Snort alert is normalized by the bridge and displayed in the console.
- [x] Run automated coverage for rule validation, alert conversion, supervisor lifecycle, and retention.
- [ ] Complete live packet-capture, rule rollback, persistence, and least-privilege checks.
- [x] Document the Compose setup and required sensor configuration.
- [ ] Verify the complete stack from a clean deployment.
- [x] Choose deployment environment configuration for retention; implement 30-day alert retention and daily/size-based Snort log rotation with 7-day archive retention.
- [ ] Validate alert/log retention against a running Compose stack.
- [x] Remove alert-count and file-size caps from API/UI retrieval so the UI can query all retained alert history.
- [x] Add inclusive start/end date filters for alerts in the UI.
- [x] Automatically download/update a MaxMind GeoLite2 City database at console startup and show an English-labeled alert-count heatmap below the alerts panel; verified with valid credentials.
- [x] Add a persistent dark/light basemap toggle and verify map loading, resizing, and theme switching without a manual page reload.
- [ ] Add pie charts below the map for top source IPs, destination IPs, and ports.

## Constraints

- Do not run systemd inside the Snort container or use `privileged: true`.
- Match the host service's `NET_RAW` and `NET_ADMIN` capabilities initially; reassess `NET_ADMIN` after packet-capture testing.
- Do not mount the Docker socket. Keep configuration and data in explicit volumes.
- Keep the UI/API unprivileged and local by default.
- Snort containers still share the host kernel. Host networking may be needed for interface capture; it does not provide visibility into unrelated switched-LAN traffic.
- Keep this work on the feature branch until the complete stack and migration path are verified.

## Current implementation

Compose defines a Linux host-networked `sensor`, a `bridge`, and a local-only `console`. Alert and raw Snort log retention are configurable through `.env`; defaults keep normalized alerts for 30 days and rotate raw logs daily or at 100 MiB, retaining archives for 7 days. The API returns all retained alert records and the console filters by an inclusive date range. Automated tests pass; live retention behavior still needs Compose validation. Rule rollback and packet-capture validation remain.

See [README.md](./README.md) for setup instructions and [CHANGELOG.md](./CHANGELOG.md) for progress.
