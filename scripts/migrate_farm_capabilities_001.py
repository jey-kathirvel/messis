"""Idempotent schema and legacy assignment migration for FARM-CAP-001."""
from sqlalchemy import inspect, select

from app.agro_framework import assign_legacy_farms, seed_agro_framework
from app.database import SessionLocal, engine
from app.models import Farm, FarmOperationalProfile, FarmTemplateAssignment


def main() -> None:
    FarmOperationalProfile.__table__.create(bind=engine, checkfirst=True)
    with SessionLocal() as db:
        seed_agro_framework(db)
        assigned = assign_legacy_farms(db)
        # Use explicit scalar subqueries for compatibility with supported
        # SQLAlchemy/database versions.
        farms = len(db.scalars(select(Farm.id)).all())
        assignments = len(db.scalars(select(FarmTemplateAssignment.id)).all())
        profiles = len(db.scalars(select(FarmOperationalProfile.id)).all())
    tables = set(inspect(engine).get_table_names())
    if "farm_operational_profiles" not in tables:
        raise SystemExit("FARM-CAP-001 failed: operational profile table is missing")
    if assignments != farms or profiles != farms:
        raise SystemExit(
            "FARM-CAP-001 failed: every farm must have one assignment and profile "
            f"(farms={farms}, assignments={assignments}, profiles={profiles})"
        )
    print(
        "FARM-CAP-001 migration: PASSED "
        f"(legacy_assigned={assigned}, farms={farms})"
    )


if __name__ == "__main__":
    main()
