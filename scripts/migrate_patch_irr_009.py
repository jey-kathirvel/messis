"""Idempotent indexes for PATCH-IRR-009 alert operations."""
from sqlalchemy import inspect, text
from app.database import engine


def main() -> None:
    if "irrigation_alerts" not in inspect(engine).get_table_names():
        raise SystemExit("irrigation_alerts is missing; deploy PATCH-IRR-001 first")
    with engine.begin() as connection:
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_irrigation_alert_owner_status_severity ON irrigation_alerts (owner_id, status, severity)"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_irrigation_alert_owner_type_created ON irrigation_alerts (owner_id, alert_type, created_at)"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_irrigation_alert_owner_due ON irrigation_alerts (owner_id, due_at)"))
    print("PATCH-IRR-009 migration: PASSED")


if __name__ == "__main__": main()
