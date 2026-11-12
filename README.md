# Snort Watch

A lightweight React dashboard for Snort IDS alerts. Snort stays on the Ubuntu host; a small Node bridge converts Snort 2 fast-alert lines to NDJSON, and the dashboard displays those records.

## Development disclosure

This project was developed with assistance from AI tools. The project maintainer reviews and is responsible for the code, documentation, and release decisions.

> **Snort 2 vs Snort 3:** This project targets Snort 2.x (tested with Snort 2.9.20). The Snort 2 package used here does not provide Snort 3's native JSON logger, so the bridge converts the existing `alert_fast` output. For Snort 3, use its native `alert_json` logger instead.

## 1. Install Snort on Ubuntu

Install the Ubuntu package and identify the interface that should be monitored:

```bash
sudo apt update
sudo apt install -y snort
snort -V
ip -brief link
ip -brief address
```

During package setup, select the monitored network range if prompted. Otherwise, edit `/etc/snort/snort.conf` and set `HOME_NET` to the actual protected network (for example, `192.168.1.0/24`); avoid leaving it as `any` on a real sensor. Check that the selected interface exists and is up:

```bash
ip route get 1.1.1.1
```

The interface shown after `dev` is a common choice for monitoring outbound traffic. For a network sensor, select the interface connected to the traffic you intend to inspect.

The Snort configuration must enable fast alert output. In `/etc/snort/snort.conf`, ensure there is one active line:

```conf
output alert_fast: snort.alert.fast
```

Do not add a duplicate if the line already exists. The systemd service below passes `-l /var/log/snort`, so this relative filename is written to `/var/log/snort/snort.alert.fast`.

## 2. Create the Snort systemd service

The Ubuntu package may provide a service already. Inspect it before creating another unit:

```bash
systemctl cat snort
getent passwd snort
```

Use the package's `snort` service account where available. If this is a custom installation without that account, create a restricted account:

```bash
sudo adduser --system --no-create-home --group snort
```

Create a log directory that allows the Snort user to write alerts and gives the `adm` group read access for the Docker bridge. The setgid bit keeps new files in the `adm` group, and the unit's umask prevents world-readable logs:

```bash
sudo install -d -o snort -g adm -m 2750 /var/log/snort
```

Create `/etc/systemd/system/snort.service` (or adapt the existing unit/drop-in) with the correct interface in `ExecStart`. Replace `<INTERFACE_NAME>` below with the interface selected above; do not use the placeholder literally:

```ini
[Unit]
Description=Snort IDS
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=snort
Group=snort
UMask=0007
ExecStart=/usr/sbin/snort -i INTERFACE_NAME -c /etc/snort/snort.conf -l /var/log/snort
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s
KillMode=control-group

[Install]
WantedBy=multi-user.target
```

Do **not** add `-D` or `-A fast` to `ExecStart`: systemd must supervise Snort in the foreground, and the active `output alert_fast` line in `snort.conf` chooses the alert filename watched by the bridge. The capabilities above allow packet capture without running Snort as root.

If you already have `/etc/systemd/system/snort.service`, you can use the provided drop-in instead. Edit its `INTERFACE_NAME` placeholder to match your interface before installing:

```bash
sudo install -D -m 0644 systemd/snort.service.d/override.conf /etc/systemd/system/snort.service.d/override.conf
sudo systemctl daemon-reload
sudo systemctl reset-failed snort
sudo systemctl enable --now snort
systemctl status snort --no-pager
```

After Snort has created the alert file, make sure it is readable by `adm` but not by all local users:

```bash
sudo chown snort:adm /var/log/snort/snort.alert.fast
sudo chmod 0640 /var/log/snort/snort.alert.fast
sudo systemctl restart snort
sudo journalctl -u snort -n 30 --no-pager
```

Confirm the service reports `active (running)` and the startup log says `Commencing packet processing`. Snort only writes alert records when traffic matches an enabled rule; an empty log can be normal.

## 3. Run locally (without Docker)

Requires Node.js 20+ and npm:

```bash
npm ci
npm test
```

Start each process in a separate terminal:

```bash
npm run bridge
npm run api
npm run dev
```

Open the Vite URL (normally `http://127.0.0.1:5173`). The bridge watches new entries in `/var/log/snort/snort.alert.fast` and writes NDJSON to `data/alerts.jsonl`. It skips existing entries at startup by default. To import the file from its beginning, run `SNORT_BRIDGE_FROM_START=1 npm run bridge`.

To select non-default paths, set matching values for the bridge and API:

```bash
SNORT_FAST_LOG=/path/to/snort.alert.fast SNORT_JSON_LOG=/path/to/alerts.jsonl npm run bridge
SNORT_JSON_LOG=/path/to/alerts.jsonl npm run api
```

The account running the bridge must be able to read Snort's fast-alert file. Do not make IDS logs world-readable.

## 4. Run the dashboard and bridge with Docker Compose

Docker Engine and the Docker Compose plugin are required. Snort itself remains a host service; Compose mounts its log directory **read-only** into the bridge container. The dashboard is published only on localhost.

Check Docker and the host `adm` group ID:

```bash
docker --version
docker compose version
getent group adm
```

Build and start both containers. Set the actual host group ID from `getent group adm` so the non-root bridge can read Snort's `0640 snort:adm` alert log:

```bash
export SNORT_LOG_GID="$(getent group adm | cut -d: -f3)"
docker compose up --build -d
docker compose ps
docker compose logs --tail=50
```

Open **http://127.0.0.1:3100**. Check API health and recent alerts with:

```bash
curl http://127.0.0.1:3100/api/health
curl 'http://127.0.0.1:3100/api/alerts?limit=20'
```

To use a different host log directory, set `SNORT_LOG_DIR` before starting Compose; that directory is mounted read-only at `/snort-logs` and must contain `snort.alert.fast`:

```bash
export SNORT_LOG_DIR=/path/to/snort/logs
docker compose up --build -d
```

Compose stores converted alerts in the named `alerts-data` volume shared between the bridge and dashboard. The container runs as the unprivileged `node` user, drops Linux capabilities, and exposes the UI/API on `127.0.0.1` only. To stop the containers while retaining alert history:

```bash
docker compose down
```

To also delete the stored alert history, explicitly remove the volume:

```bash
docker compose down --volumes
```

## 5. Manage custom rules from the UI

The **Rules** tab shows saved and draft custom rules in a collapsible list that is hidden by default. The guided rule-creation panel is also collapsed by default; expand **Create an alert rule** when you want to build a new signature. Its **Snort alert signatures** editor is available as an option at the bottom of the expanded creator. The Community Rules management panel is below the guided creator and collapsed by default as well. Hover over the `!` information mark to see how validation and Snort restarts work. The tab edits only `/var/lib/snort-watch/ui-managed.rules`; it does not replace `/etc/snort/rules/local.rules`. Only custom `alert` signatures are accepted. Each update is syntax-checked against the full Snort config before it is applied. On validation failure, the previous contents are restored. On success, the host Snort service is restarted to load the new rules.

Install the host-side rule manager once (Node.js 20+ must be installed on Ubuntu). If Node.js was installed with `nvm`, pass the current shell's executable path through `sudo`; the installer copies that Node binary into `/opt/snort-watch` for systemd:

```bash
sudo env PATH="$PATH" sh scripts/install-rules-manager.sh
```

The installer creates a restricted `snort-rules` account, adds separate includes for custom rules and community rules to Snort's `local.rules`, and runs the rule manager as a host systemd service bound to `127.0.0.1:3101`. It grants that account only two passwordless root commands: testing the Snort configuration and restarting the `snort` service. The UI container is not given access to Snort's configuration, systemd, or host privileges.

Rebuild/restart the UI after pulling an update:

```bash
export SNORT_LOG_GID="$(getent group adm | cut -d: -f3)"
docker compose up --build -d
```

Open **http://127.0.0.1:3100**, select **Rules**, and use **Create an alert rule** to choose a traffic type, networks, ports, direction, alert description, and severity. The UI previews a generated rule and assigns a SID automatically. Select the single **Save** button to validate and load it immediately; the creator shows green success feedback or red failure feedback. Guided rule creation does not create a draft. Advanced users can open the raw rule editor at the bottom of the creator panel.

Generated and saved custom rules appear in a readable list. Removing a rule marks the changes as a draft; **Save changes** in the list validates and applies the removal. The save button is disabled when there are no pending edits. Raw editor changes are saved with the same button.

### Official GPLv2 Community Rules

The Community Rules panel downloads the official Snort Community Rules archive from `snort.org`. It extracts only `community-rules/community.rules`, its GPLv2 license, and the AUTHORS credits; VRT Certified Rules and the archive's `snort.conf` are never installed. The rules remain in a separate managed file, `/var/lib/snort-watch/community-active.rules`, with the downloaded copy, license, and author credits retained separately. The installer adds a stable include for the active file.

Use **Install & enable** to download, validate, and apply the rules. **Update rules** fetches the latest archive and preserves whether rules are enabled or disabled. You can disable the active rules while retaining the download, re-enable them later, or remove the downloaded copy. Every operation validates Snort's full configuration before restarting the service; failed validation restores the previous files. The archive is fetched over HTTPS only from the official Snort endpoint and its expected Snort-hosted redirect, with redirect, archive-size, path, license, and rule-content checks.

The official community signatures are distributed under GNU GPLv2. See the [GPLv2 license](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html) and the [Snort Community Rules download page](https://www.snort.org/downloads/#rule-downloads). Enabling the set can add hundreds of detections; review alert volume and local configuration before enabling it on a production sensor.

The equivalent manual syntax for a high-priority ICMP echo rule is:

```text
alert icmp any any -> $HOME_NET any (msg:"Ping to home network"; itype:8; priority:2; sid:9000000; rev:1;)
```

The rule-manager API is loopback-only and accepts browser mutations only from the local dashboard/development origins. Keep the UI local: do not expose ports `3100` or `3101` to untrusted networks or reverse-proxy them without adding authentication and an explicit authorization model. To inspect manager health/logs:

```bash
systemctl status snort-rules-manager --no-pager
sudo journalctl -u snort-rules-manager -n 50 --no-pager
```

## License

Snort Watch source code and documentation are licensed under the [MIT License](./LICENSE). GPLv2 Community Rules are downloaded separately from the official Snort source and are not included in this repository; their license and author credits should be retained when installing them.

## Dashboard behavior

- The dashboard refreshes every five seconds and supports filtering by severity and searching messages, signatures, IPs, ports, and protocols.
- The alert table shows 10 rows per page by default, with numbered pagination and a rows-per-page selector (10, 25, 50, or 100). The selected Alerts/Rules tab is retained when the page is reloaded in the same browser tab.
- The Rules tab can edit, validate, and apply custom Snort alert rules when the local host rule-manager service is installed.
- Priority 1/2/3 maps to Critical/High/Medium; priority 4 or above maps to Low. Alerts without priority are shown as “No priority.”
- The API returns at most the latest 2,000 records and scans no more than 8 MiB of the JSONL file per request.
- The bridge follows file rotation and truncation and emits one JSON object per recognized fast-alert line.
- Fast-alert conversion preserves the metadata available in that format; it cannot provide packet fields Snort did not log.

If all counters show zero, first check `systemctl status snort`, the bridge logs, and `/api/alerts`. Counters represent detections, not total traffic, so they remain zero until packets match an enabled Snort rule.
