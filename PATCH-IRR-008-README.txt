PATCH-IRR-008 — Weather Intelligence

Adds Open-Meteo daily forecast ingestion, deterministic zone-level irrigation
advice, water-volume adjustments, schedule delay/reduction acceptance, weather
alerts, an owner-scoped dashboard, and a date-filtered intelligence report.

Deployment: run ./apply_patch.sh from /opt/messis.
The script creates application and PostgreSQL backups, applies idempotent
indexes, validates the patch, restarts messis.service, and checks /health.
