
# PATCH-UAT-FIX-003: refuse unsafe database configuration before execution.
from scripts.test_database_safety import load_safe_test_database
_MESSIS_SAFE_TEST_DATABASE = load_safe_test_database()

import ast
from pathlib import Path

from app.main import app, templates


ROUTE_PATH = "/farms/{farm_id}/trees"
TEMPLATE_PATH = Path("app/templates/trees/list.html")


def validate_python_source() -> None:
    source = Path("app/main.py").read_text()
    ast.parse(source)

    assert (
        "# PATCH-005A.3: COCONUT TREE LIST UI"
        in source
    )

    assert "def coconut_tree_list_page(" in source
    assert 'name="trees/list.html"' in source
    assert "require_owned_farm(" in source


def validate_route() -> None:
    matching_routes = [
        route
        for route in app.routes
        if getattr(route, "path", None) == ROUTE_PATH
        and "GET" in getattr(route, "methods", set())
    ]

    assert len(matching_routes) == 1
    assert matching_routes[0].name == "coconut_tree_list_page"


def validate_template() -> None:
    assert TEMPLATE_PATH.is_file()

    content = TEMPLATE_PATH.read_text()

    required_content = {
        "Coconut Tree Master",
        "Registered Coconut Trees",
        "{{ tree.tree_code }}",
        "{{ tree.variety }}",
        "{{ tree.health_status }}",
        "{% for tree in trees %}",
        "{% if trees %}",
    }

    missing = {
        item
        for item in required_content
        if item not in content
    }

    assert not missing, (
        f"Missing template content: {sorted(missing)}"
    )

    template = templates.get_template("trees/list.html")
    assert template is not None


def main() -> None:
    validate_python_source()
    validate_route()
    validate_template()

    print("PATCH-005A.3 SOURCE: PASSED")
    print("PATCH-005A.3 ROUTE: PASSED")
    print("PATCH-005A.3 TEMPLATE: PASSED")
    print("PATCH-005A.3 TREE LIST UI: PASSED")
    print("PATCH-005A.3: PASSED")


if __name__ == "__main__":
    main()
