#!/usr/bin/env bash

set -euo pipefail

SITE_NAME="messis.ads-ai.in"
SITE_FILE="/etc/apache2/sites-available/${SITE_NAME}.conf"
BACKUP_ROOT="/opt/messis/deploy/backups/PATCH-DEPLOY-002"

a2dissite "${SITE_NAME}.conf" 2>/dev/null || true

LATEST_BACKUP="$(
    find "${BACKUP_ROOT}" \
        -maxdepth 1 \
        -type f \
        -name "${SITE_NAME}.conf.*.bak" \
        -printf '%T@ %p\n' \
        2>/dev/null \
        | sort -nr \
        | head -n 1 \
        | cut -d' ' -f2-
)"

if [[ -n "${LATEST_BACKUP}" && -f "${LATEST_BACKUP}" ]]; then
    cp -a \
        "${LATEST_BACKUP}" \
        "${SITE_FILE}"

    chmod 0644 "${SITE_FILE}"
    chown root:root "${SITE_FILE}"

    a2ensite "${SITE_NAME}.conf"
else
    rm -f "${SITE_FILE}"
fi

apachectl configtest
systemctl reload apache2

echo "PATCH-DEPLOY-002 ROLLBACK: COMPLETED"
