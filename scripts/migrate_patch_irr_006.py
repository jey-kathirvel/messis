"""Additive production migration for PATCH-IRR-006."""
from sqlalchemy import inspect, text

from app.database import engine


COLUMNS = {
    "status": "VARCHAR(30) NOT NULL DEFAULT 'in_progress'",
    "paused_at": "TIMESTAMP WITH TIME ZONE NULL",
    "total_paused_minutes": "INTEGER NOT NULL DEFAULT 0",
    "supervisor_approved_by": "INTEGER NULL REFERENCES users(id) ON DELETE SET NULL",
    "supervisor_notes": "TEXT NULL",
}


def main() -> None:
    inspector = inspect(engine)
    if "irrigation_executions" not in inspector.get_table_names():
        raise SystemExit("irrigation_executions table is missing; deploy PATCH-IRR-001 first")
    existing = {column["name"] for column in inspector.get_columns("irrigation_executions")}
    with engine.begin() as connection:
        for name, definition in COLUMNS.items():
            if name not in existing:
                connection.execute(text(f"ALTER TABLE irrigation_executions ADD COLUMN {name} {definition}"))
                print(f"added irrigation_executions.{name}")
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_irrigation_executions_status ON irrigation_executions (status)"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_irrigation_executions_supervisor_approved_by ON irrigation_executions (supervisor_approved_by)"))
    print("PATCH-IRR-006 migration: PASSED")


if __name__ == "__main__":
    main()
