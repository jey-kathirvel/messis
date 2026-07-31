import ast
from pathlib import Path

from app.main import (
    COCONUT_TREE_LABEL_PAGE_SIZES,
    app,
    coconut_tree_label_conditions,
    coconut_tree_label_location,
    templates,
)


ROUTE_PATH = (
    "/farms/{farm_id}/trees/labels"
)

LABEL_TEMPLATE = Path(
    "app/templates/trees/labels.html"
)

LIST_TEMPLATE = Path(
    "app/templates/trees/list.html"
)


class DummyTree:
    block_name = "Block A"
    row_number = "R1"
    position_number = "P2"


class EmptyLocationTree:
    block_name = None
    row_number = ""
    position_number = None


def validate_source() -> None:
    source = Path("app/main.py").read_text()

    ast.parse(source)

    assert (
        "# PATCH-005A.12: COCONUT TREE PRINTABLE LABELS"
        in source
    )

    required_source = {
        "COCONUT_TREE_LABEL_PAGE_SIZES",
        "def coconut_tree_label_conditions(",
        "def coconut_tree_label_location(",
        "def coconut_tree_labels_page(",
        '"coconut_tree.labels_viewed"',
        'name="trees/labels.html"',
        '"pagination_start"',
        '"pagination_end"',
        '"total_pages"',
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
        if getattr(
            route,
            "path",
            None,
        ) == ROUTE_PATH
        and "GET" in getattr(
            route,
            "methods",
            set(),
        )
    ]

    assert len(routes) == 1

    assert (
        routes[0].name
        == "coconut_tree_labels_page"
    )


def validate_page_sizes() -> None:
    assert COCONUT_TREE_LABEL_PAGE_SIZES == {
        12,
        24,
        48,
        96,
    }


def validate_conditions() -> None:
    conditions = coconut_tree_label_conditions(
        1,
        query_text="CTN",
        variety_filter="Tall",
        health_filter="Healthy",
        activity_filter="active",
    )

    assert len(conditions) == 5

    default_conditions = (
        coconut_tree_label_conditions(1)
    )

    assert len(default_conditions) == 1


def validate_location() -> None:
    assert (
        coconut_tree_label_location(
            DummyTree()
        )
        == "Block A · R1 · P2"
    )

    assert (
        coconut_tree_label_location(
            EmptyLocationTree()
        )
        == ""
    )


def validate_templates() -> None:
    assert LABEL_TEMPLATE.is_file()
    assert LIST_TEMPLATE.is_file()

    label_content = LABEL_TEMPLATE.read_text()
    list_content = LIST_TEMPLATE.read_text()

    required_label_content = {
        "Printable Tree Labels",
        "Print Current Page",
        "window.print()",
        "tree-label",
        "label-grid",
        "@media print",
        "{{ tree.tree_code }}",
        "{{ tree.variety }}",
        "{{ tree.health_status }}",
        "QR Code ID",
        "Page {{ page }} of {{ total_pages }}",
    }

    missing = {
        item
        for item in required_label_content
        if item not in label_content
    }

    assert not missing, (
        f"Missing label template content: {sorted(missing)}"
    )

    assert (
        "/trees/labels"
        in list_content
    )

    assert "Print Labels" in list_content

    assert templates.get_template(
        "trees/labels.html"
    )

    assert templates.get_template(
        "trees/list.html"
    )


def main() -> None:
    validate_source()
    validate_route()
    validate_page_sizes()
    validate_conditions()
    validate_location()
    validate_templates()

    print("PATCH-005A.12 SOURCE: PASSED")
    print("PATCH-005A.12 ROUTE: PASSED")
    print("PATCH-005A.12 PAGE SIZES: PASSED")
    print("PATCH-005A.12 CONDITIONS: PASSED")
    print("PATCH-005A.12 LOCATION: PASSED")
    print("PATCH-005A.12 TEMPLATES: PASSED")
    print("PATCH-005A.12 PRINTABLE LABELS: PASSED")
    print("PATCH-005A.12: PASSED")


if __name__ == "__main__":
    main()
