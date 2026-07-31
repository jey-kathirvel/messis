import ast
from pathlib import Path

from app.main import app, templates


DELETE_ROUTE = (
    "POST",
    "/farms/{farm_id}/trees/{tree_id}/delete",
)

DETAIL_TEMPLATE = Path("app/templates/trees/detail.html")
LIST_TEMPLATE = Path("app/templates/trees/list.html")


def validate_source() -> None:
    source = Path("app/main.py").read_text()
    ast.parse(source)

    assert (
        "# PATCH-005A.6: COCONUT TREE DELETE UI"
        in source
    )

    assert (
        "async def delete_coconut_tree_from_form("
        in source
    )

    assert 'form.get("confirmation", "")' in source
    assert "confirmation != tree.tree_code" in source
    assert "db.delete(tree)" in source
    assert '"coconut_tree.deleted"' in source


def validate_route() -> None:
    routes = {
        (
            method,
            getattr(route, "path", ""),
        )
        for route in app.routes
        for method in getattr(route, "methods", set())
    }

    assert DELETE_ROUTE in routes


def validate_detail_template() -> None:
    assert DETAIL_TEMPLATE.is_file()

    content = DETAIL_TEMPLATE.read_text()

    required_content = {
        'name="confirmation"',
        'method="post"',
        '/delete"',
        "Permanently Delete Tree",
        "Delete Coconut Tree",
        "delete_error",
        "onsubmit=",
    }

    missing = {
        item
        for item in required_content
        if item not in content
    }

    assert not missing, (
        f"Missing detail template content: {sorted(missing)}"
    )

    assert templates.get_template("trees/detail.html")


def validate_list_template() -> None:
    assert LIST_TEMPLATE.is_file()

    content = LIST_TEMPLATE.read_text()

    assert 'request.query_params.get("success")' in content
    assert templates.get_template("trees/list.html")


def main() -> None:
    validate_source()
    validate_route()
    validate_detail_template()
    validate_list_template()

    print("PATCH-005A.6 SOURCE: PASSED")
    print("PATCH-005A.6 ROUTE: PASSED")
    print("PATCH-005A.6 DETAIL TEMPLATE: PASSED")
    print("PATCH-005A.6 LIST MESSAGE: PASSED")
    print("PATCH-005A.6 DELETE UI: PASSED")
    print("PATCH-005A.6: PASSED")


if __name__ == "__main__":
    main()
