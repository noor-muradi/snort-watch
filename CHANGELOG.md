# Changelog

## Unreleased — `feature/containerized-snort`

- Added the Ubuntu 24.04 Snort 2.9.20 sensor image and Node.js 24 runtime.
- Added Compose `sensor`, `bridge`, and `console` services with separate persistent volumes and least-privilege capabilities.
- Added sensor-side Snort supervision and a private Unix-socket rule-manager API proxy.
- Set sensor log-volume permissions for bridge access and retained least-privilege container settings.
- Added supervisor and Unix-socket proxy tests, and documented the Compose deployment.
- Verified tests, production build, Compose configuration, Node.js 24 images, and Snort 2.9.20 configuration.

## v0.0.1

- Published the initial development release with the alert dashboard, Snort fast-alert bridge, and host-based rule management.
