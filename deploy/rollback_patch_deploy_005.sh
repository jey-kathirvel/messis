#!/usr/bin/env bash

set -euo pipefail

DOMAIN="messis.ads-ai.in"
BACKUP_DIR="/opt/messis/deploy/backups/PATCH-DEPLOY-005"

SERVICE_SOURCE="${BACKUP_DIR}/messis.service.before"
HTTP_SOURCE="${BACKUP_DIR}/messis.ads-ai.in.conf.before"
SSL_SOURCE="${BACKUP_DIR}/messis.ads-ai.in-le-ssl.conf.before"
SECURITY_SOURCE="${BACKUP_DIR}/apache-security.conf.before"

SERVICE_TARGET="/etc/systemd/system/messis.service"
HTTP_TARGET="/etc/apache2/sites-available/messis.ads-ai.in.conf"
SSL_TARGET="/etc/apache2/sites-available/messis.ads-ai.in-le-ssl.conf"
SECURITY_TARGET="/etc/apache2/conf-available/security.conf"

if [[ -f "${SERVICE_SOURCE}" ]]; then
    cp -a "${SERVICE_SOURCE}" "${SERVICE_TARGET}"
fi

if [[ -f "${HTTP_SOURCE}" ]]; then
    cp -a "${HTTP_SOURCE}" "${HTTP_TARGET}"
fi

if [[ -f "${SSL_SOURCE}" ]]; then
    cp -a "${SSL_SOURCE}" "${SSL_TARGET}"
fi

if [[ -f "${SECURITY_SOURCE}" ]]; then
    cp -a "${SECURITY_SOURCE}" "${SECURITY_TARGET}"
fi

systemctl daemon-reload
apachectl configtest

systemctl restart messis.service
systemctl restart apache2

systemctl is-active --quiet messis.service
systemctl is-active --quiet apache2

echo "PATCH-DEPLOY-005 ROLLBACK: PASSED"
