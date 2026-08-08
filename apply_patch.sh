#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="${MESSIS_PROJECT_DIR:-/opt/messis}"
STAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="${PROJECT_DIR}/backups/MESSIS-UX-GLASS-001-${STAMP}"

cd "${PROJECT_DIR}"
mkdir -p "${BACKUP_DIR}"
tar -czf "${BACKUP_DIR}/application-files.tgz" app/templates app/static/css app/static/pwa/mobile-shell.css
git rev-parse HEAD > "${BACKUP_DIR}/git-head.txt"
PYTHONPATH=. .venv/bin/python scripts/backup_messis_ux_glass_001.py "${BACKUP_DIR}/database.dump"

.venv/bin/python -m compileall -q app
PYTHONPATH=. .venv/bin/python tests/validate_garden_glass_theme.py
systemctl restart messis.service
systemctl is-active --quiet messis.service
healthy=0
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if curl -fsS http://127.0.0.1:8080/health >/dev/null; then
        healthy=1
        break
    fi
    sleep 1
done
if [ "${healthy}" -ne 1 ]; then
    echo "Messis health endpoint did not become ready within 10 seconds" >&2
    exit 1
fi

echo "MESSIS-UX-GLASS-001 applied successfully; backup: ${BACKUP_DIR}"
