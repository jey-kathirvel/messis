#!/usr/bin/env bash

set -euo pipefail

SERVICE_NAME="messis.service"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}"
BACKUP_ROOT="/opt/messis/deploy/backups/PATCH-DEPLOY-001"

systemctl disable --now "${SERVICE_NAME}" 2>/dev/null || true

LATEST_BACKUP="$(
    find "${BACKUP_ROOT}" \
        -maxdepth 1 \
        -type f \
        -name "${SERVICE_NAME}.*.bak" \
        -printf '%T@ %p\n' \
        2>/dev/null \
        | sort -nr \
        | head -n 1 \
        | cut -d' ' -f2-
)"

if [[ -n "${LATEST_BACKUP}" && -f "${LATEST_BACKUP}" ]]; then
    cp -a \
        "${LATEST_BACKUP}" \
        "${SERVICE_FILE}"

    systemctl daemon-reload
    systemctl enable --now "${SERVICE_NAME}"
else
    rm -f "${SERVICE_FILE}"
    systemctl daemon-reload
    systemctl reset-failed
fi

echo "PATCH-DEPLOY-001 ROLLBACK: COMPLETED"
