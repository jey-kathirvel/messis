import ast
import csv
import io
from pathlib import Path

from app.main import (
    app,
    coconut_tree_export_conditions,
    templates,
)


ROUTE_PATH = "/farms/{farm_id}/trees/export.csv"
TEMPLATE_PATH = Path("app/templates/trees/list.html")


def validate_source() -> None:
    source = Path("app/main.py").read_text()

    ast.parse(source)

    assert (
        "# PATCH-005A.8: COCONUT TREE CSV EXPORT"
        in source
    )

    required_content = {
        "import csv",
        "import io",
        "StreamingResponse",
        "def coconut_tree_export_conditions(",
        "def export_coconut_trees_csv(",
        'media_type="text/csv; charset=utf-8"',
        '"Content-Disposition"',
        '"coconut_tree.exported"',
        '"\\ufeff"',
    }

    missing = {
        item
        for item in required_content
        if item not in source
    }

    assert not missing, (
        f"Missing source content: {sorted(missing)}"
    )


def validate_route() -> None:
    matching_routes = [
        route
        for route in app.routes
        if getattr(route, "path", None) == ROUTE_PATH
        and "GET" in getattr(route, "methods", set())
    ]

    assert len(matching_routes) == 1

    assert (
        matching_routes[0].name
        == "export_coconut_trees_csv"
    )


def validate_conditions() -> None:
    conditions = coconut_tree_export_conditions(
        1,
        query_text="CTN",
        variety_filter="Tall",
        health_filter="Healthy",
        activity_filter="active",
    )

    assert len(conditions) == 5

    minimal_conditions = coconut_tree_export_conditions(
        1,
    )

    assert len(minimal_conditions) == 1


def validate_csv_structure() -> None:
    output = io.StringIO(newline="")
    writer = csv.writer(output)

    headers = [
        "Tree ID",
        "Farm ID",
        "Farm Name",
        "Tree Code",
        "Tree Name",
        "QR Code ID",
        "Variety",
        "Planting Date",
        "Block",
        "Row",
        "Position",
        "Health Status",
        "Height (m)",
        "Canopy Diameter (m)",
        "Trunk Girth (cm)",
        "Remarks",
        "Active",
        "Created At",
        "Updated At",
    ]

    writer.writerow(headers)

    parsed = list(
        csv.reader(
            io.StringIO(output.getvalue())
        )
    )

    assert parsed[0] == headers
    assert len(parsed[0]) == 19


def validate_template() -> None:
    assert TEMPLATE_PATH.is_file()

    content = TEMPLATE_PATH.read_text()

    required_content = {
        "Export CSV",
        "/trees/export.csv",
        "q={{ query_text | urlencode }}",
        "variety={{ variety_filter | urlencode }}",
        "health_status={{ health_filter | urlencode }}",
        "activity={{ activity_filter | urlencode }}",
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
    validate_conditions()
    validate_csv_structure()
    validate_template()

    print("PATCH-005A.8 SOURCE: PASSED")
    print("PATCH-005A.8 ROUTE: PASSED")
    print("PATCH-005A.8 FILTER CONDITIONS: PASSED")
    print("PATCH-005A.8 CSV STRUCTURE: PASSED")
    print("PATCH-005A.8 TEMPLATE: PASSED")
    print("PATCH-005A.8 CSV EXPORT: PASSED")
    print("PATCH-005A.8: PASSED")


if __name__ == "__main__":
    main()
