
# PATCH-UAT-FIX-003: refuse unsafe database configuration before execution.
from scripts.test_database_safety import load_safe_test_database
_MESSIS_SAFE_TEST_DATABASE = load_safe_test_database()

import ast
from pathlib import Path

from app.main import (
    COCONUT_TREE_IMPORT_MAX_ROWS,
    COCONUT_TREE_IMPORT_REQUIRED_HEADERS,
    app,
    coconut_tree_import_payload,
    normalize_coconut_tree_import_header,
    parse_import_boolean,
    templates,
)


IMPORT_ROUTE = "/farms/{farm_id}/trees/import"
IMPORT_TEMPLATE = Path(
    "app/templates/trees/import.html"
)
LIST_TEMPLATE = Path(
    "app/templates/trees/list.html"
)


def validate_source() -> None:
    source = Path("app/main.py").read_text()

    ast.parse(source)

    assert (
        "# PATCH-005A.9: COCONUT TREE CSV IMPORT"
        in source
    )

    required_source = {
        "COCONUT_TREE_IMPORT_REQUIRED_HEADERS",
        "COCONUT_TREE_IMPORT_OPTIONAL_HEADERS",
        "COCONUT_TREE_IMPORT_MAX_ROWS = 1000",
        "def normalize_coconut_tree_import_header(",
        "def parse_import_boolean(",
        "def coconut_tree_import_payload(",
        "def render_coconut_tree_import_page(",
        "def coconut_tree_import_page(",
        "async def import_coconut_trees_csv(",
        "csv.DictReader(",
        "db.add_all(trees)",
        '"coconut_tree.imported"',
    }

    missing = {
        item
        for item in required_source
        if item not in source
    }

    assert not missing, (
        f"Missing source content: {sorted(missing)}"
    )


def validate_routes() -> None:
    routes = {
        (
            method,
            getattr(route, "path", ""),
        )
        for route in app.routes
        for method in getattr(
            route,
            "methods",
            set(),
        )
    }

    assert ("GET", IMPORT_ROUTE) in routes
    assert ("POST", IMPORT_ROUTE) in routes


def validate_helpers() -> None:
    assert (
        normalize_coconut_tree_import_header(
            "Tree Code"
        )
        == "tree_code"
    )

    assert parse_import_boolean("Yes") is True
    assert parse_import_boolean("active") is True
    assert parse_import_boolean("1") is True
    assert parse_import_boolean("No") is False
    assert parse_import_boolean("inactive") is False
    assert parse_import_boolean("0") is False
    assert parse_import_boolean("") is True

    try:
        parse_import_boolean("invalid")
    except ValueError:
        pass
    else:
        raise AssertionError(
            "Invalid boolean value was accepted."
        )

    payload = coconut_tree_import_payload(
        {
            "tree_code": " CTN-001 ",
            "variety": " Tall ",
            "health_status": " Healthy ",
            "is_active": "Yes",
        }
    )

    assert payload["tree_code"] == "CTN-001"
    assert payload["variety"] == "Tall"
    assert payload["health_status"] == "Healthy"
    assert payload["is_active"] is True

    assert COCONUT_TREE_IMPORT_MAX_ROWS == 1000

    assert COCONUT_TREE_IMPORT_REQUIRED_HEADERS == {
        "tree_code",
        "variety",
        "health_status",
    }


def validate_templates() -> None:
    assert IMPORT_TEMPLATE.is_file()
    assert LIST_TEMPLATE.is_file()

    import_content = IMPORT_TEMPLATE.read_text()
    list_content = LIST_TEMPLATE.read_text()

    required_import_content = {
        'name="csv_file"',
        'enctype="multipart/form-data"',
        "Validate and Import",
        "Required Columns",
        "Optional Columns",
        "CSV Example",
        "tree_code,tree_name,variety",
    }

    missing = {
        item
        for item in required_import_content
        if item not in import_content
    }

    assert not missing, (
        f"Missing import template content: {sorted(missing)}"
    )

    assert (
        'href="/farms/{{ farm.id }}/trees/import"'
        in list_content
    )

    assert "Import CSV" in list_content

    assert templates.get_template(
        "trees/import.html"
    )

    assert templates.get_template(
        "trees/list.html"
    )


def main() -> None:
    validate_source()
    validate_routes()
    validate_helpers()
    validate_templates()

    print("PATCH-005A.9 SOURCE: PASSED")
    print("PATCH-005A.9 ROUTES: PASSED")
    print("PATCH-005A.9 HELPERS: PASSED")
    print("PATCH-005A.9 TEMPLATES: PASSED")
    print("PATCH-005A.9 CSV IMPORT: PASSED")
    print("PATCH-005A.9: PASSED")


if __name__ == "__main__":
    main()
