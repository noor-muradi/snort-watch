# Snort Watch

A lightweight Snort 2 IDS stack with a React console for alerts and rule management. A Node.js bridge converts Snort fast-alert lines to NDJSON.

This project was developed with assistance from AI tools. The project maintainer reviews and is responsible for the code, documentation, and release decisions.

> **Snort 2 vs. Snort 3:** Snort Watch currently packages Snort 2.9.20. Snort 2's `alert_fast` output is converted to JSONL by the bridge; this is not Snort 3's native JSON logger.

## Run with Docker Compose

The recommended deployment runs Snort, the alert bridge, and the console as containers. **You do not need to install Snort directly on the host.** Docker Engine and the Docker Compose plugin are required. The sensor uses Linux host networking to capture on a host interface.

1. Copy the sample configuration and edit it for the host:

   ```bash
   cp .env.example .env
   ```

   Set `SNORT_INTERFACE` to the Linux interface the sensor should monitor, and `SNORT_HOME_NET` to the protected network in CIDR notation. Choose an active interface and the network you intend to protect.

2. Validate and start the stack:

   ```bash
   docker compose config --quiet
   docker compose up --build -d
   docker compose ps
   docker compose logs --tail=50
   ```

The sensor image is based on Ubuntu 24.04 and uses its Snort 2.9.20 package plus the Node.js 24 runtime. It runs without systemd or `privileged` mode and drops all capabilities except `NET_RAW` and `NET_ADMIN`. If another Snort process is already capturing on the selected interface, stop it before starting the container sensor.

Open the console at **http://127.0.0.1:3100**. Check service health and recent alerts with:

```bash
curl http://127.0.0.1:3100/api/health
curl 'http://127.0.0.1:3100/api/alerts?limit=20'
```

Host networking lets the sensor capture on the selected host interface, but does not expose traffic switched between other devices. Monitoring that traffic requires a network TAP or switch mirror.

## Alerts and stored data

The sensor writes fast alerts to a shared `snort-logs` volume. The bridge reads them, converts recognized entries to JSONL, and appends them to `alerts-data`; the console reads that data read-only. Managed Snort rules are stored separately in `snort-rules`.

Alert history persists in the `alerts-data` volume and currently has no automatic time- or size-based retention. Restarting containers does not clear it. To stop the stack while keeping data:

```bash
docker compose down
```

To delete all Compose volumes, including alert history, Snort logs, and managed rules:

```bash
docker compose down --volumes
```

## Manage rules

Select **Rules** in the console to create custom alert rules or manage the official GPLv2 Snort Community Rules. The guided creator builds and previews a rule; **Save** validates it against Snort's configuration and applies it. Invalid changes are rejected, and failed Snort restarts restore the previous rule files.

The sensor-side rule manager is supervised with Snort. It is not exposed on a network port; the console reaches it through a private Unix socket shared by the two containers.

The Community Rules panel downloads the official archive from Snort and validates its contents and license. Only the community rules, license, and author credits are retained; VRT Certified Rules and the archive's `snort.conf` are not installed. Community signatures are under [GPLv2](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html); see the [Snort Community Rules page](https://www.snort.org/downloads/#rule-downloads).

## Local development

Node.js 20+ and npm are required for local application development. This mode does not install or run Snort. Point the bridge at an existing Snort fast-alert file if you want to test alert ingestion:

Run the long-lived bridge, API, and development server in separate terminals:

```bash
npm ci
npm test
npm run bridge
npm run api
npm run dev
```

Set `SNORT_FAST_LOG` and `SNORT_JSON_LOG` to select the bridge input and JSONL output paths. The process running the bridge must be able to read the input file. For example:

```bash
SNORT_FAST_LOG=/path/to/snort.alert.fast SNORT_JSON_LOG=/path/to/alerts.jsonl npm run bridge
```

## Dashboard behavior

- The console refreshes every five seconds and filters by severity. Search covers messages, signatures, IP addresses, ports, and protocols.
- The alert table shows 10 rows per page by default, with 10, 25, 50, or 100 rows per page.
- Priority 1/2/3 maps to Critical/High/Medium; priority 4 or above maps to Low. Alerts without priority are shown as “No priority.”
- The API returns at most the latest 2,000 records and scans no more than 8 MiB of the JSONL file per request.
- The bridge follows file rotation and truncation and emits one JSON object per recognized fast-alert line.
- Fast-alert conversion preserves the metadata available in that format; it cannot provide packet fields Snort did not log.

The console shows no alerts until traffic matches an enabled Snort rule. If the feed is unexpectedly empty, check `docker compose ps`, the sensor and bridge logs, and the health and alerts endpoints above.

## Security

Compose publishes the console only on localhost. Do not expose port `3100` to untrusted networks or reverse-proxy it without adding authentication and an authorization model. The sensor uses host networking and packet-capture capabilities; review the interface and protected-network values before startup.

## License

Snort Watch source code and documentation are licensed under the [MIT License](./LICENSE). GPLv2 Community Rules are downloaded separately from the official Snort source and are not included in this repository.
