
# PATCH-UAT-FIX-003: refuse unsafe database configuration before execution.
from scripts.test_database_safety import load_safe_test_database
_MESSIS_SAFE_TEST_DATABASE = load_safe_test_database()

import ast
from datetime import date
from decimal import Decimal
from pathlib import Path

from sqlalchemy import inspect

from app.database import Base, engine
from app.models import (
    CoconutTree,
    Farm,
    TreeActivity,
)


EXPECTED_COLUMNS = {
    "id",
    "farm_id",
    "tree_id",
    "activity_type",
    "activity_date",
    "status",
    "title",
    "description",
    "quantity",
    "unit",
    "cost",
    "performed_by",
    "next_due_date",
    "notes",
    "created_at",
    "updated_at",
}


def validate_source() -> None:
    source = Path(
        "app/models.py"
    ).read_text()

    ast.parse(source)

    assert (
        "# PATCH-005B.1: TREE ACTIVITY MODEL"
        in source
    )

    required = {
        "class TreeActivity(Base):",
        '__tablename__ = "tree_activities"',
        "activity_type:",
        "activity_date:",
        "next_due_date:",
        "performed_by:",
        "ondelete=\"CASCADE\"",
        "ix_tree_activities_farm_tree_date",
        "ix_tree_activities_type_status",
        "ix_tree_activities_next_due_date",
    }

    missing = {
        item
        for item in required
        if item not in source
    }

    assert not missing, (
        f"Missing source content: {sorted(missing)}"
    )


def validate_model_metadata() -> None:
    table = TreeActivity.__table__

    assert table.name == "tree_activities"

    columns = set(
        table.columns.keys()
    )

    assert columns == EXPECTED_COLUMNS, {
        "missing": sorted(
            EXPECTED_COLUMNS - columns
        ),
        "unexpected": sorted(
            columns - EXPECTED_COLUMNS
        ),
    }

    assert (
        table.c.id.primary_key
        is True
    )

    assert (
        table.c.farm_id.nullable
        is False
    )

    assert (
        table.c.tree_id.nullable
        is False
    )

    assert (
        table.c.activity_type.nullable
        is False
    )

    assert (
        table.c.activity_date.nullable
        is False
    )

    assert (
        table.c.title.nullable
        is False
    )

    assert (
        table.c.status.nullable
        is False
    )


def validate_foreign_keys() -> None:
    farm_target = next(
        iter(
            TreeActivity.__table__
            .c.farm_id.foreign_keys
        )
    ).target_fullname

    tree_target = next(
        iter(
            TreeActivity.__table__
            .c.tree_id.foreign_keys
        )
    ).target_fullname

    assert farm_target == (
        f"{Farm.__tablename__}.id"
    )

    assert tree_target == (
        f"{CoconutTree.__tablename__}.id"
    )


def validate_indexes() -> None:
    indexes = {
        index.name
        for index in TreeActivity
        .__table__.indexes
    }

    required_indexes = {
        "ix_tree_activities_farm_tree_date",
        "ix_tree_activities_type_status",
        "ix_tree_activities_next_due_date",
    }

    assert required_indexes.issubset(
        indexes
    ), {
        "missing": sorted(
            required_indexes - indexes
        ),
    }


def validate_instance() -> None:
    activity = TreeActivity(
        farm_id=1,
        tree_id=1,
        activity_type="irrigation",
        activity_date=date(
            2026,
            7,
            31,
        ),
        status="completed",
        title="Morning irrigation",
        description=(
            "Applied irrigation to the root zone."
        ),
        quantity=Decimal(
            "40.000"
        ),
        unit="litres",
        cost=Decimal(
            "25.00"
        ),
        performed_by="Farm Worker",
        next_due_date=date(
            2026,
            8,
            2,
        ),
        notes="Soil moisture checked.",
    )

    assert activity.farm_id == 1
    assert activity.tree_id == 1
    assert (
        activity.activity_type
        == "irrigation"
    )
    assert (
        activity.title
        == "Morning irrigation"
    )
    assert (
        activity.quantity
        == Decimal("40.000")
    )
    assert (
        activity.cost
        == Decimal("25.00")
    )


def validate_database_table() -> None:
    Base.metadata.create_all(
        bind=engine
    )

    inspector = inspect(
        engine
    )

    assert inspector.has_table(
        "tree_activities"
    )

    database_columns = {
        column["name"]
        for column in inspector.get_columns(
            "tree_activities"
        )
    }

    assert EXPECTED_COLUMNS.issubset(
        database_columns
    ), {
        "missing": sorted(
            EXPECTED_COLUMNS
            - database_columns
        ),
    }


def main() -> None:
    validate_source()
    validate_model_metadata()
    validate_foreign_keys()
    validate_indexes()
    validate_instance()
    validate_database_table()

    print(
        "PATCH-005B.1 SOURCE: PASSED"
    )
    print(
        "PATCH-005B.1 MODEL METADATA: PASSED"
    )
    print(
        "PATCH-005B.1 FOREIGN KEYS: PASSED"
    )
    print(
        "PATCH-005B.1 INDEXES: PASSED"
    )
    print(
        "PATCH-005B.1 INSTANCE: PASSED"
    )
    print(
        "PATCH-005B.1 DATABASE TABLE: PASSED"
    )
    print(
        "PATCH-005B.1 TREE ACTIVITY MODEL: PASSED"
    )
    print(
        "PATCH-005B.1: PASSED"
    )


if __name__ == "__main__":
    main()
