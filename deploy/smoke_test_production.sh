#!/usr/bin/env bash

set -euo pipefail

DOMAIN="messis.ads-ai.in"
APP_PORT="8080"

systemctl is-active --quiet messis.service
systemctl is-active --quiet apache2
systemctl is-active --quiet postgresql

curl \
    --fail \
    --silent \
    --show-error \
    --max-time 15 \
    "http://127.0.0.1:${APP_PORT}/" \
    >/dev/null

ROOT_STATUS="$(
    curl \
        --silent \
        --show-error \
        --output /dev/null \
        --write-out '%{http_code}' \
        --max-time 20 \
        "https://${DOMAIN}/"
)"

DASHBOARD_STATUS="$(
    curl \
        --silent \
        --show-error \
        --output /dev/null \
        --write-out '%{http_code}' \
        --max-time 20 \
        "https://${DOMAIN}/dashboard"
)"

case "${ROOT_STATUS}" in
    200|301|302|303|307|308)
        ;;
    *)
        exit 1
        ;;
esac

case "${DASHBOARD_STATUS}" in
    200|301|302|303|307|308|401|403)
        ;;
    *)
        exit 1
        ;;
esac

openssl x509 \
    -in "/etc/letsencrypt/live/${DOMAIN}/cert.pem" \
    -checkend 604800 \
    -noout

echo "MESSIS PRODUCTION SMOKE TEST: PASSED"
