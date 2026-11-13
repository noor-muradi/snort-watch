FROM node:24-bookworm AS node-runtime

FROM ubuntu:24.04

ARG SNORT_PACKAGE_VERSION=2.9.20-0+deb11u1ubuntu1
ENV DEBIAN_FRONTEND=noninteractive \
    SNORT_CONFIG=/etc/snort/snort.conf \
    SNORT_BIN=/usr/sbin/snort \
    SNORT_MANAGED_RULES=/var/lib/snort-watch/ui-managed.rules \
    SNORT_COMMUNITY_RULES=/var/lib/snort-watch/community-active.rules \
    SNORT_COMMUNITY_DOWNLOAD=/var/lib/snort-watch/community-download.rules \
    SNORT_COMMUNITY_STATE=/var/lib/snort-watch/community-state.json \
    SNORT_COMMUNITY_LICENSE=/var/lib/snort-watch/community-license.txt \
    SNORT_COMMUNITY_AUTHORS=/var/lib/snort-watch/community-authors.txt \
    SNORT_CONTROLLER_MODE=container \
    RULES_API_SOCKET=/run/snort-watch/rules-manager.sock \
    RULES_API_ALLOWED_ORIGINS=http://127.0.0.1:3100,http://localhost:3100

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      "snort=${SNORT_PACKAGE_VERSION}" \
      iproute2 \
      libatomic1 \
      ca-certificates \
      tar \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/log/snort /var/lib/snort-watch /run/snort-watch \
    && chown root:1000 /var/log/snort \
    && chmod 2750 /var/log/snort \
    && printf '\ninclude /var/lib/snort-watch/ui-managed.rules\ninclude /var/lib/snort-watch/community-active.rules\n' \
      >> /etc/snort/snort.conf \
    && printf '# Managed by Snort Watch. Add one alert rule per line.\n' \
      > /var/lib/snort-watch/ui-managed.rules \
    && printf '# Snort Watch managed GPLv2 community rules. Install from the Rules UI.\n' \
      > /var/lib/snort-watch/community-active.rules

COPY --from=node-runtime /usr/local/bin/node /usr/local/bin/node
COPY server/alert-retention.mjs server/rules-manager.mjs server/snort-log-retention.mjs server/snort-supervisor.mjs /opt/snort-watch/server/

RUN node --version \
    && snort -V

EXPOSE 3101
CMD ["node", "/opt/snort-watch/server/rules-manager.mjs"]
