#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this installer with sudo." >&2
  exit 1
fi

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
local_rules=/etc/snort/rules/local.rules
managed_dir=/var/lib/snort-watch
managed_rules=$managed_dir/ui-managed.rules
community_rules=$managed_dir/community-active.rules
sudoers_tmp=$(mktemp)
trap 'rm -f "$sudoers_tmp"' EXIT HUP INT TERM

node_bin=${NODE_BIN:-"$(command -v node || true)"}
if [ -z "$node_bin" ] || [ ! -x "$node_bin" ]; then
  echo "Node.js 20+ is required. If installed with nvm, run:" >&2
  echo "  sudo env PATH=\"$PATH\" sh scripts/install-rules-manager.sh" >&2
  exit 1
fi
node_major=$("$node_bin" --version | sed 's/^v//' | cut -d. -f1)
if [ "$node_major" -lt 20 ]; then
  echo "Node.js 20+ is required; found $("$node_bin" --version)." >&2
  exit 1
fi
command -v visudo >/dev/null 2>&1 || {
  echo "visudo is required to validate the restricted sudoers entry." >&2
  exit 1
}
getent passwd snort >/dev/null || {
  echo "The Snort service account 'snort' is missing. Install Snort first." >&2
  exit 1
}
grep -Eq '^[[:space:]]*include[[:space:]]+\$RULE_PATH/local\.rules([[:space:]]|$)' /etc/snort/snort.conf || {
  echo "/etc/snort/snort.conf must include \$RULE_PATH/local.rules." >&2
  exit 1
}

if ! getent passwd snort-rules >/dev/null; then
  useradd --system --no-create-home --home-dir /nonexistent \
    --shell /usr/sbin/nologin --gid snort snort-rules
fi

install -d -o snort-rules -g snort -m 0750 "$managed_dir"
if [ ! -e "$managed_rules" ]; then
  printf '# Managed by Snort Watch. Add one alert rule per line.\n' > "$managed_rules"
fi
chown snort-rules:snort "$managed_rules"
chmod 0640 "$managed_rules"

if [ ! -e "$community_rules" ]; then
  printf '# Snort Watch managed GPLv2 community rules. Install from the Rules UI.\n' > "$community_rules"
fi
chown snort-rules:snort "$community_rules"
chmod 0640 "$community_rules"

if ! grep -Fxq 'include /var/lib/snort-watch/ui-managed.rules' "$local_rules"; then
  printf '\n# Snort Watch managed alert rules\ninclude /var/lib/snort-watch/ui-managed.rules\n' >> "$local_rules"
fi

if ! grep -Fxq 'include /var/lib/snort-watch/community-active.rules' "$local_rules"; then
  printf '\n# Snort Watch official GPLv2 community rules\ninclude /var/lib/snort-watch/community-active.rules\n' >> "$local_rules"
fi

install -d -o root -g root -m 0755 /opt/snort-watch/server /opt/snort-watch/bin
install -o root -g root -m 0755 "$node_bin" /opt/snort-watch/bin/node
install -o root -g root -m 0644 \
  "$project_root/server/rules-manager.mjs" \
  /opt/snort-watch/server/rules-manager.mjs
install -o root -g root -m 0644 \
  "$project_root/systemd/snort-rules-manager.service" \
  /etc/systemd/system/snort-rules-manager.service

install -o root -g root -m 0440 \
  "$project_root/systemd/snort-rules-manager.sudoers" "$sudoers_tmp"
visudo -c -f "$sudoers_tmp"
install -o root -g root -m 0440 "$sudoers_tmp" \
  /etc/sudoers.d/snort-rules-manager

systemctl daemon-reload
systemctl restart snort

if ! runuser -u snort-rules -- \
  sudo -n /usr/sbin/snort -T -c /etc/snort/snort.conf; then
  echo "Snort config validation failed; inspect the Snort output before enabling the UI manager." >&2
  exit 1
fi

systemctl enable --now snort-rules-manager.service
systemctl restart snort-rules-manager.service
systemctl --no-pager --full status snort-rules-manager.service
