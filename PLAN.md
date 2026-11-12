# Development plan

**Goal:** Run Snort and Snort Watch as a secure, container-based IDS stack. Keep the UI, alert ingestion, and rule management usable through Compose.

## Status

- [x] Create `feature/containerized-snort` from the initial release.
- [x] Choose Snort 2.9.20 from Ubuntu 24.04 packages and Node.js 24 images.
- [x] Choose Linux host networking with explicit interface and protected-network settings.
- [x] Choose persistent log/rule volumes and a private Unix socket for rule management.
- [x] Rename the Compose UI service from `dashboard` to `console`.
- [x] Build the Snort sensor, bridge, and console images; validate Snort's configuration without starting capture.
- [x] Validate Compose startup, console APIs, private rules API, Snort startup, and sensor log access.
- [ ] Verify an actual Snort alert is normalized by the bridge and displayed in the console.
- [ ] Verify rule validation, rollback, and supervised Snort restarts.
- [ ] Test packet capture, rule validation/rollback, persistence, restarts, and least privilege.
- [ ] Verify a clean Compose deployment and finish setup documentation.
- [ ] Define alert/log retention, comparing container environment configuration with a UI setting; prefer a safe, documented default.
- [ ] Remove the alert-count cap from API/UI retrieval so the UI can query the full alert history.
- [ ] Add a date-range filter for alerts in the UI.

## Constraints

- Do not run systemd inside the Snort container or use `privileged: true`.
- Match the host service's `NET_RAW` and `NET_ADMIN` capabilities initially; reassess `NET_ADMIN` after packet-capture testing.
- Do not mount the Docker socket. Keep configuration and data in explicit volumes.
- Keep the UI/API unprivileged and local by default.
- Snort containers still share the host kernel. Host networking may be needed for interface capture; it does not provide visibility into unrelated switched-LAN traffic.
- Keep this work on the feature branch until the complete stack and migration path are verified.

## Current implementation

Compose defines a Linux host-networked `sensor`, a `bridge`, and a local-only `console`. Image builds, Compose configuration, Snort config validation, app tests, UI build, and API probes pass. Actual alert forwarding, rule changes/rollback, and capture validation remain.

See [README.md](./README.md) for setup instructions and [CHANGELOG.md](./CHANGELOG.md) for progress.
