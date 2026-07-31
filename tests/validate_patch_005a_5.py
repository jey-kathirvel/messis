import ast
from datetime import date
from pathlib import Path

from app.main import (
    app,
    calculate_tree_age,
    templates,
)


ROUTE_PATH = "/farms/{farm_id}/trees/{tree_id}"
DETAIL_TEMPLATE = Path("app/templates/trees/detail.html")
LIST_TEMPLATE = Path("app/templates/trees/list.html")


def validate_source() -> None:
    source = Path("app/main.py").read_text()
    ast.parse(source)

    assert (
        "# PATCH-005A.5: COCONUT TREE DETAIL PAGE"
        in source
    )

    assert "def calculate_tree_age(" in source
    assert "def coconut_tree_detail_page(" in source
    assert 'name="trees/detail.html"' in source
    assert "require_owned_farm(" in source
    assert "require_owned_coconut_tree(" in source


def validate_route() -> None:
    matches = [
        route
        for route in app.routes
        if getattr(route, "path", None) == ROUTE_PATH
        and "GET" in getattr(route, "methods", set())
    ]

    assert len(matches) == 1
    assert matches[0].name == "coconut_tree_detail_page"


def validate_age_calculation() -> None:
    assert calculate_tree_age(None) is None

    today = date.today()

    current_month_tree = date(
        today.year,
        today.month,
        1,
    )

    age = calculate_tree_age(current_month_tree)

    assert age is not None
    assert age["total_months"] >= 0
    assert age["years"] >= 0
    assert 0 <= age["months"] <= 11

    future_date = date(
        today.year + 1,
        today.month,
        min(today.day, 28),
    )

    assert calculate_tree_age(future_date) is None


def validate_templates() -> None:
    assert DETAIL_TEMPLATE.is_file()
    assert LIST_TEMPLATE.is_file()

    detail_content = DETAIL_TEMPLATE.read_text()
    list_content = LIST_TEMPLATE.read_text()

    required_detail_content = {
        "{{ tree.tree_code }}",
        "{{ tree.variety }}",
        "{{ tree.health_status }}",
        "{{ tree.block_name",
        "{{ tree.row_number",
        "{{ tree.position_number",
        "{{ tree.height_m",
        "{{ tree.canopy_diameter_m",
        "{{ tree.trunk_girth_cm",
        "{{ tree.remarks",
        "Tree Information",
        "Farm Position",
        "Measurements",
        "Record Details",
        "Edit Coconut Tree",
    }

    missing_detail_content = {
        item
        for item in required_detail_content
        if item not in detail_content
    }

    assert not missing_detail_content, (
        "Missing detail template content: "
        f"{sorted(missing_detail_content)}"
    )

    detail_link = (
        'href="/farms/{{ farm.id }}/trees/{{ tree.id }}"'
    )

    assert detail_link in list_content

    assert templates.get_template("trees/detail.html")
    assert templates.get_template("trees/list.html")


def main() -> None:
    validate_source()
    validate_route()
    validate_age_calculation()
    validate_templates()

    print("PATCH-005A.5 SOURCE: PASSED")
    print("PATCH-005A.5 ROUTE: PASSED")
    print("PATCH-005A.5 TREE AGE: PASSED")
    print("PATCH-005A.5 TEMPLATE: PASSED")
    print("PATCH-005A.5 TREE DETAIL PAGE: PASSED")
    print("PATCH-005A.5: PASSED")


if __name__ == "__main__":
    main()
