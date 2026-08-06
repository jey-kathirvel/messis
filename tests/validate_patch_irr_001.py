"""PATCH-IRR-001 source and SQLAlchemy metadata validation."""
from pathlib import Path

from app.database import Base
import app.models  # noqa: F401 - registers all model tables


EXPECTED_TABLES = {
    "irrigation_zones",
    "water_sources",
    "irrigation_pumps",
    "irrigation_plans",
    "irrigation_schedules",
    "irrigation_executions",
    "fertilizer_products",
    "fertigation_plans",
    "fertigation_plan_items",
    "weather_irrigation_recommendations",
    "soil_moisture_readings",
    "water_meter_readings",
    "irrigation_alerts",
    "irrigation_attachments",
}

OWNER_SCOPED_TABLES = EXPECTED_TABLES
FARM_SCOPED_TABLES = EXPECTED_TABLES - {"fertilizer_products"}


def main() -> None:
    source = Path("app/models.py").read_text(encoding="utf-8")
    assert "# PATCH-IRR-001: SMART IRRIGATION & FERTIGATION DATABASE FOUNDATION" in source

    actual_tables = set(Base.metadata.tables)
    missing = EXPECTED_TABLES - actual_tables
    assert not missing, f"Missing irrigation tables: {sorted(missing)}"

    for table_name in OWNER_SCOPED_TABLES:
        assert "owner_id" in Base.metadata.tables[table_name].columns, table_name

    for table_name in FARM_SCOPED_TABLES:
        assert "farm_id" in Base.metadata.tables[table_name].columns, table_name

    assert Base.metadata.tables["irrigation_zones"].c.owner_id.index
    assert Base.metadata.tables["irrigation_schedules"].c.scheduled_date.index
    assert Base.metadata.tables["irrigation_alerts"].c.status.index
    assert Base.metadata.tables["weather_irrigation_recommendations"].c.user_decision.index

    print("PATCH-IRR-001 DATABASE FOUNDATION: PASSED")


if __name__ == "__main__":
    main()
