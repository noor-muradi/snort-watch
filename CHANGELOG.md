# Changelog

## v0.3.0 — 2026-11-14

- Removed alert-count and file-size caps from API/UI alert retrieval.
- Added inclusive date-range filtering to the alert list.
- Fixed the production container build so the UI logo is included in the static assets.
- Added startup-managed MaxMind GeoLite2 downloads and a public-IP alert-count heatmap below the alert list.
- Switched the heatmap to a vector basemap with English-only labels where English names are available.
- Added a persistent dark/light basemap toggle and fixed map initialization, resizing, and theme changes without requiring a page reload.
- Added coverage for unbounded alert history, date filtering, MaxMind geolocation, and English map labels.
- Added a future dashboard feature to the plan: pie charts for top source IPs, destination IPs, and ports.

## v0.2.0 — 2026-11-13

- Added configurable 30-day retention for normalized alerts and daily/100 MiB rotation for Snort logs, with 7-day archive retention.
- Added ingestion timestamps to new alerts so retention does not depend on Snort's yearless local timestamps.
- Added automated coverage for age-based alert pruning and Snort log rotation/archive expiry.
- Reused the Snort Watch UI logo in the README.
- Verified 31 tests, production build, Compose configuration, container image builds, and Snort configuration.

## v0.1.0 — 2026-11-13

- Added a containerized Snort 2.9.20 sensor using Ubuntu 24.04 and Node.js 24.
- Added Compose `sensor`, `bridge`, and `console` services with persistent volumes and least-privilege capabilities.
- Added supervised Snort lifecycle management and a private Unix-socket rules API proxy.
- Added focused supervisor/proxy tests and documented the Compose deployment.
- Verified the test suite, production build, Compose configuration, Node.js 24 images, and Snort configuration.
- Clarified that the recommended Compose setup packages Snort and does not require installing it on the Ubuntu host.

## v0.0.1

- Published the initial development release with the alert dashboard, Snort fast-alert bridge, and host-based rule management.
