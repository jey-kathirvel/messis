"""Additive production migration for PATCH-IRR-005."""
from sqlalchemy import inspect, text

from app.database import engine


COLUMNS = {
    "recurrence_type": "VARCHAR(20) NOT NULL DEFAULT 'none'",
    "recurrence_interval": "INTEGER NOT NULL DEFAULT 1",
    "recurrence_end_date": "DATE NULL",
    "recurrence_group_id": "VARCHAR(64) NULL",
}


def main() -> None:
    inspector = inspect(engine)
    if "irrigation_schedules" not in inspector.get_table_names():
        raise SystemExit("irrigation_schedules table is missing; deploy PATCH-IRR-001 first")
    existing = {column["name"] for column in inspector.get_columns("irrigation_schedules")}
    with engine.begin() as connection:
        for name, definition in COLUMNS.items():
            if name not in existing:
                connection.execute(text(f"ALTER TABLE irrigation_schedules ADD COLUMN {name} {definition}"))
                print(f"added irrigation_schedules.{name}")
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_irrigation_schedules_recurrence_end_date ON irrigation_schedules (recurrence_end_date)"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_irrigation_schedules_recurrence_group_id ON irrigation_schedules (recurrence_group_id)"))
    print("PATCH-IRR-005 migration: PASSED")


if __name__ == "__main__":
    main()
