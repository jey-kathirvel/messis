
# PATCH-UAT-FIX-003: refuse unsafe database configuration before execution.
from scripts.test_database_safety import load_safe_test_database
_MESSIS_SAFE_TEST_DATABASE = load_safe_test_database()

import ast
from pathlib import Path

from app.main import (
    app,
    coconut_tree_form_values,
    templates,
)
from app.models import CoconutTree


EXPECTED_ROUTES = {
    ("GET", "/farms/{farm_id}/trees/new"),
    ("POST", "/farms/{farm_id}/trees/new"),
    ("GET", "/farms/{farm_id}/trees/{tree_id}/edit"),
    ("POST", "/farms/{farm_id}/trees/{tree_id}/edit"),
}


def validate_source() -> None:
    source = Path("app/main.py").read_text()
    ast.parse(source)

    assert (
        "# PATCH-005A.4: COCONUT TREE ADD AND EDIT FORMS"
        in source
    )

    required_functions = {
        "def coconut_tree_form_values(",
        "async def coconut_tree_form_payload(",
        "def render_coconut_tree_form(",
        "def new_coconut_tree_page(",
        "async def create_coconut_tree_from_form(",
        "def edit_coconut_tree_page(",
        "async def update_coconut_tree_from_form(",
    }

    missing = {
        item
        for item in required_functions
        if item not in source
    }

    assert not missing, (
        f"Missing functions: {sorted(missing)}"
    )


def validate_routes() -> None:
    installed_routes = {
        (method, getattr(route, "path", ""))
        for route in app.routes
        for method in getattr(route, "methods", set())
    }

    missing_routes = EXPECTED_ROUTES - installed_routes

    assert not missing_routes, (
        f"Missing routes: {sorted(missing_routes)}"
    )


def validate_form_defaults() -> None:
    values = coconut_tree_form_values()

    assert values["tree_code"] == ""
    assert values["variety"] == "Tall"
    assert values["health_status"] == "Healthy"
    assert values["is_active"] is True


def validate_form_tree_values() -> None:
    tree = CoconutTree(
        farm_id=1,
        tree_code="CTN-101",
        tree_name="Test Tree",
        variety="Hybrid",
        health_status="Diseased",
        is_active=False,
    )

    values = coconut_tree_form_values(tree)

    assert values["tree_code"] == "CTN-101"
    assert values["tree_name"] == "Test Tree"
    assert values["variety"] == "Hybrid"
    assert values["health_status"] == "Diseased"
    assert values["is_active"] is False


def validate_templates() -> None:
    form_path = Path("app/templates/trees/form.html")
    list_path = Path("app/templates/trees/list.html")

    assert form_path.is_file()
    assert list_path.is_file()

    form_content = form_path.read_text()
    list_content = list_path.read_text()

    required_form_content = {
        'name="tree_code"',
        'name="tree_name"',
        'name="qr_code_id"',
        'name="variety"',
        'name="planting_date"',
        'name="block_name"',
        'name="row_number"',
        'name="position_number"',
        'name="health_status"',
        'name="height_m"',
        'name="canopy_diameter_m"',
        'name="trunk_girth_cm"',
        'name="remarks"',
        'name="is_active"',
        "Add Coconut Tree",
        "Save Changes",
    }

    missing_form_content = {
        item
        for item in required_form_content
        if item not in form_content
    }

    assert not missing_form_content, (
        "Missing form content: "
        f"{sorted(missing_form_content)}"
    )

    assert (
        'href="/farms/{{ farm.id }}/trees/new"'
        in list_content
    )

    assert (
        'href="/farms/{{ farm.id }}/trees/{{ tree.id }}/edit"'
        in list_content
    )

    assert templates.get_template("trees/form.html")
    assert templates.get_template("trees/list.html")


def main() -> None:
    validate_source()
    validate_routes()
    validate_form_defaults()
    validate_form_tree_values()
    validate_templates()

    print("PATCH-005A.4 SOURCE: PASSED")
    print("PATCH-005A.4 ROUTES: PASSED")
    print("PATCH-005A.4 FORM VALUES: PASSED")
    print("PATCH-005A.4 TEMPLATES: PASSED")
    print("PATCH-005A.4 ADD/EDIT FORMS: PASSED")
    print("PATCH-005A.4: PASSED")


if __name__ == "__main__":
    main()
