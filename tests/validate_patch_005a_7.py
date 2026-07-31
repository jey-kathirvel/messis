import ast
from pathlib import Path

from app.main import app, templates


ROUTE_PATH = "/farms/{farm_id}/trees"
TEMPLATE_PATH = Path("app/templates/trees/list.html")


def validate_source() -> None:
    source = Path("app/main.py").read_text()
    ast.parse(source)

    assert (
        "# PATCH-005A.7: COCONUT TREE SEARCH FILTER AND PAGINATION"
        in source
    )

    required_source = {
        "query_text = request.query_params.get(",
        "variety_filter = request.query_params.get(",
        "health_filter = request.query_params.get(",
        "activity_filter = request.query_params.get(",
        "func.count(CoconutTree.id)",
        "CoconutTree.tree_code.ilike(",
        "CoconutTree.tree_name.ilike(",
        "CoconutTree.qr_code_id.ilike(",
        ".offset(offset)",
        ".limit(page_size)",
        '"filtered_count": filtered_count',
        '"total_pages": total_pages',
        '"pagination_start": pagination_start',
        '"pagination_end": pagination_end',
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
    assert routes[0].name == "coconut_tree_list_page"


def validate_template() -> None:
    assert TEMPLATE_PATH.is_file()

    content = TEMPLATE_PATH.read_text()

    required_content = {
        'name="q"',
        'name="variety"',
        'name="health_status"',
        'name="activity"',
        'name="page_size"',
        "Apply Filters",
        "Clear Filters",
        "No matching coconut trees",
        "{{ pagination_start }}",
        "{{ pagination_end }}",
        "{{ filtered_count }}",
        "Page {{ page }} of {{ total_pages }}",
        "Previous",
        "Next",
        "| urlencode",
    }

    missing = {
        item
        for item in required_content
        if item not in content
    }

    assert not missing, (
        f"Missing template content: {sorted(missing)}"
    )

    assert templates.get_template("trees/list.html")


def main() -> None:
    validate_source()
    validate_route()
    validate_template()

    print("PATCH-005A.7 SOURCE: PASSED")
    print("PATCH-005A.7 ROUTE: PASSED")
    print("PATCH-005A.7 TEMPLATE: PASSED")
    print("PATCH-005A.7 SEARCH/FILTER/PAGINATION: PASSED")
    print("PATCH-005A.7: PASSED")


if __name__ == "__main__":
    main()
