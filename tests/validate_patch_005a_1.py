from sqlalchemy import inspect
from sqlalchemy.orm import configure_mappers

from app.database import Base, engine
from app.models import CoconutTree, Farm


EXPECTED_COLUMNS = {
    "id",
    "farm_id",
    "tree_code",
    "tree_name",
    "qr_code_id",
    "variety",
    "planting_date",
    "block_name",
    "row_number",
    "position_number",
    "health_status",
    "height_m",
    "canopy_diameter_m",
    "trunk_girth_cm",
    "remarks",
    "is_active",
    "created_at",
    "updated_at",
}


def main() -> None:
    configure_mappers()

    assert CoconutTree.__tablename__ == "coconut_trees"
    assert Farm.coconut_trees.property.mapper.class_ is CoconutTree
    assert CoconutTree.farm.property.mapper.class_ is Farm
    assert Farm.coconut_trees.property.back_populates == "farm"
    assert CoconutTree.farm.property.back_populates == "coconut_trees"

    metadata_table = Base.metadata.tables.get("coconut_trees")
    assert metadata_table is not None

    metadata_columns = set(metadata_table.columns.keys())
    missing_metadata_columns = EXPECTED_COLUMNS - metadata_columns
    assert not missing_metadata_columns, (
        "Missing metadata columns: "
        f"{sorted(missing_metadata_columns)}"
    )

    farm_fk = next(
        foreign_key
        for foreign_key in metadata_table.c.farm_id.foreign_keys
    )

    assert farm_fk.target_fullname == "farms.id"
    assert farm_fk.ondelete == "CASCADE"

    unique_constraints = {
        constraint.name
        for constraint in metadata_table.constraints
        if constraint.name
    }

    assert (
        "uq_coconut_trees_farm_tree_code"
        in unique_constraints
    )

    Base.metadata.create_all(bind=engine)

    inspector = inspect(engine)
    assert "coconut_trees" in inspector.get_table_names()

    database_columns = {
        column["name"]
        for column in inspector.get_columns("coconut_trees")
    }

    missing_database_columns = EXPECTED_COLUMNS - database_columns
    assert not missing_database_columns, (
        "Missing database columns: "
        f"{sorted(missing_database_columns)}"
    )

    foreign_keys = inspector.get_foreign_keys("coconut_trees")
    assert any(
        foreign_key["referred_table"] == "farms"
        and foreign_key["constrained_columns"] == ["farm_id"]
        and foreign_key["referred_columns"] == ["id"]
        for foreign_key in foreign_keys
    )

    unique_constraints = inspector.get_unique_constraints(
        "coconut_trees"
    )

    assert any(
        constraint.get("name")
        == "uq_coconut_trees_farm_tree_code"
        and set(constraint.get("column_names", []))
        == {"farm_id", "tree_code"}
        for constraint in unique_constraints
    )

    print("PATCH-005A.1 MODEL: PASSED")
    print("PATCH-005A.1 RELATIONSHIP: PASSED")
    print("PATCH-005A.1 DATABASE TABLE: PASSED")
    print("PATCH-005A.1 VALIDATION: PASSED")


if __name__ == "__main__":
    main()
