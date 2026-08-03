
# PATCH-UAT-FIX-003: refuse unsafe database configuration before execution.
from scripts.test_database_safety import load_safe_test_database
_MESSIS_SAFE_TEST_DATABASE = load_safe_test_database()

import ast
from pathlib import Path

from app.main import (
    COCONUT_TREE_BULK_ACTIONS,
    app,
    normalize_coconut_tree_ids,
    templates,
)


ROUTE_PATH = (
    "/farms/{farm_id}/trees/bulk-update"
)

BULK_TEMPLATE = Path(
    "app/templates/trees/bulk_update.html"
)

LIST_TEMPLATE = Path(
    "app/templates/trees/list.html"
)


def validate_source() -> None:
    source = Path("app/main.py").read_text()

    ast.parse(source)

    assert (
        "# PATCH-005A.11: COCONUT TREE BULK UPDATE"
        in source
    )

    required_source = {
        "COCONUT_TREE_BULK_ACTIONS",
        "def normalize_coconut_tree_ids(",
        "def render_coconut_tree_bulk_update_page(",
        "def coconut_tree_bulk_update_page(",
        "async def bulk_update_coconut_trees(",
        '"coconut_tree.bulk_updated"',
        'selected_action == "set_health_status"',
        'selected_action == "activate"',
        'selected_action == "deactivate"',
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
    installed_routes = {
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

    assert ("GET", ROUTE_PATH) in installed_routes
    assert ("POST", ROUTE_PATH) in installed_routes


def validate_actions() -> None:
    assert COCONUT_TREE_BULK_ACTIONS == {
        "set_health_status",
        "activate",
        "deactivate",
    }


def validate_tree_ids() -> None:
    assert normalize_coconut_tree_ids(
        ["1", "2", "2", "invalid", "-1", "0", 3]
    ) == [1, 2, 3]

    assert normalize_coconut_tree_ids([]) == []

    assert normalize_coconut_tree_ids(
        [" 10 ", None, "11"]
    ) == [10, 11]


def validate_templates() -> None:
    assert BULK_TEMPLATE.is_file()
    assert LIST_TEMPLATE.is_file()

    bulk_content = BULK_TEMPLATE.read_text()
    list_content = LIST_TEMPLATE.read_text()

    required_bulk_content = {
        'name="tree_ids"',
        'name="bulk_action"',
        'name="health_status"',
        "Change health status",
        "Activate selected trees",
        "Deactivate selected trees",
        "Select all",
        "selectedCount",
    }

    missing = {
        item
        for item in required_bulk_content
        if item not in bulk_content
    }

    assert not missing, (
        f"Missing bulk template content: {sorted(missing)}"
    )

    assert (
        "/trees/bulk-update"
        in list_content
    )

    assert "Bulk Update" in list_content

    assert templates.get_template(
        "trees/bulk_update.html"
    )

    assert templates.get_template(
        "trees/list.html"
    )


def main() -> None:
    validate_source()
    validate_routes()
    validate_actions()
    validate_tree_ids()
    validate_templates()

    print("PATCH-005A.11 SOURCE: PASSED")
    print("PATCH-005A.11 ROUTES: PASSED")
    print("PATCH-005A.11 ACTIONS: PASSED")
    print("PATCH-005A.11 TREE IDS: PASSED")
    print("PATCH-005A.11 TEMPLATES: PASSED")
    print("PATCH-005A.11 BULK UPDATE: PASSED")
    print("PATCH-005A.11: PASSED")


if __name__ == "__main__":
    main()
