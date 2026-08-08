"""Additive production migration for PATCH-IRR-007."""
from sqlalchemy import inspect, text

from app.database import engine
from app.models import FertilizerStockMovement


COLUMNS = {
    "status": "VARCHAR(30) NOT NULL DEFAULT 'planned'",
    "approval_notes": "TEXT NULL",
    "completed_at": "TIMESTAMP WITH TIME ZONE NULL",
    "worker_remarks": "TEXT NULL",
    "stock_deducted": "BOOLEAN NOT NULL DEFAULT FALSE",
}


def main() -> None:
    inspector = inspect(engine)
    if "fertigation_plans" not in inspector.get_table_names():
        raise SystemExit("fertigation_plans table is missing; deploy PATCH-IRR-001 first")
    existing = {column["name"] for column in inspector.get_columns("fertigation_plans")}
    with engine.begin() as connection:
        for name, definition in COLUMNS.items():
            if name not in existing:
                connection.execute(text(f"ALTER TABLE fertigation_plans ADD COLUMN {name} {definition}"))
                print(f"added fertigation_plans.{name}")
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_fertigation_plans_status ON fertigation_plans (status)"))
    FertilizerStockMovement.__table__.create(bind=engine, checkfirst=True)
    print("PATCH-IRR-007 migration: PASSED")


if __name__ == "__main__":
    main()
