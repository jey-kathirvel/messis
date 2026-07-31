import ast
import csv
import io
from pathlib import Path

from app.main import (
    COCONUT_TREE_IMPORT_TEMPLATE_HEADERS,
    COCONUT_TREE_IMPORT_TEMPLATE_ROWS,
    app,
    generate_coconut_tree_import_template_csv,
    templates,
)


ROUTE_PATH = (
    "/farms/{farm_id}/trees/import-template.csv"
)

IMPORT_TEMPLATE = Path(
    "app/templates/trees/import.html"
)


EXPECTED_HEADERS = [
    "tree_code",
    "tree_name",
    "variety",
    "health_status",
    "planting_date",
    "block_name",
    "row_number",
    "position_number",
    "qr_code_id",
    "height_m",
    "canopy_diameter_m",
    "trunk_girth_cm",
    "remarks",
    "is_active",
]


def validate_source() -> None:
    source = Path("app/main.py").read_text()

    ast.parse(source)

    assert (
        "# PATCH-005A.10: COCONUT TREE CSV TEMPLATE DOWNLOAD"
        in source
    )

    required_source = {
        "COCONUT_TREE_IMPORT_TEMPLATE_HEADERS",
        "COCONUT_TREE_IMPORT_TEMPLATE_ROWS",
        "def generate_coconut_tree_import_template_csv(",
        "def download_coconut_tree_import_template(",
        '"coconut_tree.import_template_downloaded"',
        '"X-Content-Type-Options": "nosniff"',
        "coconut-tree-import-template.csv",
    }

    missing = {
        item
        for item in required_source
        if item not in source
    }

    assert not missing, (
        f"Missing source content: {sorted(missing)}"
    )


def validate_route() -> None:
    routes = [
        route
        for route in app.routes
        if getattr(route, "path", None) == ROUTE_PATH
        and "GET" in getattr(route, "methods", set())
    ]

    assert len(routes) == 1

    assert (
        routes[0].name
        == "download_coconut_tree_import_template"
    )


def validate_template_constants() -> None:
    assert (
        COCONUT_TREE_IMPORT_TEMPLATE_HEADERS
        == EXPECTED_HEADERS
    )

    assert len(
        COCONUT_TREE_IMPORT_TEMPLATE_ROWS
    ) == 2

    for row in COCONUT_TREE_IMPORT_TEMPLATE_ROWS:
        assert len(row) == len(EXPECTED_HEADERS)


def validate_generated_csv() -> None:
    content = (
        generate_coconut_tree_import_template_csv()
    )

    assert content.startswith("\ufeff")

    parsed_rows = list(
        csv.reader(
            io.StringIO(
                content.removeprefix("\ufeff")
            )
        )
    )

    assert len(parsed_rows) == 3
    assert parsed_rows[0] == EXPECTED_HEADERS

    assert parsed_rows[1][0] == "CTN-001"
    assert parsed_rows[1][2] == "Tall"
    assert parsed_rows[1][3] == "Healthy"
    assert parsed_rows[1][13] == "Yes"

    assert parsed_rows[2][0] == "CTN-002"
    assert parsed_rows[2][2] == "Dwarf"
    assert (
        parsed_rows[2][3]
        == "Needs Attention"
    )


def validate_import_compatibility() -> None:
    generated_headers = set(
        COCONUT_TREE_IMPORT_TEMPLATE_HEADERS
    )

    required_headers = {
        "tree_code",
        "variety",
        "health_status",
    }

    assert required_headers.issubset(
        generated_headers
    )

    assert generated_headers == {
        "tree_code",
        "tree_name",
        "variety",
        "health_status",
        "planting_date",
        "block_name",
        "row_number",
        "position_number",
        "qr_code_id",
        "height_m",
        "canopy_diameter_m",
        "trunk_girth_cm",
        "remarks",
        "is_active",
    }


def validate_template() -> None:
    assert IMPORT_TEMPLATE.is_file()

    content = IMPORT_TEMPLATE.read_text()

    required_content = {
        "Download CSV Template",
        "Download Example",
        "/trees/import-template.csv",
        "Dates must use YYYY-MM-DD format.",
        "Use the downloadable template",
    }

    missing = {
        item
        for item in required_content
        if item not in content
    }

    assert not missing, (
        f"Missing template content: {sorted(missing)}"
    )

    assert templates.get_template(
        "trees/import.html"
    )


def main() -> None:
    validate_source()
    validate_route()
    validate_template_constants()
    validate_generated_csv()
    validate_import_compatibility()
    validate_template()

    print("PATCH-005A.10 SOURCE: PASSED")
    print("PATCH-005A.10 ROUTE: PASSED")
    print("PATCH-005A.10 CONSTANTS: PASSED")
    print("PATCH-005A.10 GENERATED CSV: PASSED")
    print("PATCH-005A.10 IMPORT COMPATIBILITY: PASSED")
    print("PATCH-005A.10 TEMPLATE: PASSED")
    print("PATCH-005A.10 CSV TEMPLATE DOWNLOAD: PASSED")
    print("PATCH-005A.10: PASSED")


if __name__ == "__main__":
    main()
