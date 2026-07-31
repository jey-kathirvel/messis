import ast
from datetime import date, timedelta
from pathlib import Path

from app.main import (
    app,
    templates,
    tree_activity_is_overdue,
)
from app.models import TreeActivity


ACTIVITY_DETAIL_TEMPLATE = Path(
    "app/templates/tree_activities/detail.html"
)

ACTIVITY_LIST_TEMPLATE = Path(
    "app/templates/tree_activities/list.html"
)

TREE_DETAIL_TEMPLATE = Path(
    "app/templates/trees/detail.html"
)


def validate_source() -> None:
    source = Path(
        "app/main.py"
    ).read_text()

    ast.parse(source)

    required = {
        "# PATCH-005B.4: ACTIVITY DETAIL AND TREE SUMMARY",
        "def tree_activity_summary(",
        "def tree_activity_is_overdue(",
        "def tree_activity_detail_page(",
        "def tree_activity_summary_api(",
        '"tree_activity_summary":',
        '"tree_activity_is_overdue":',
    }

    missing = {
        item
        for item in required
        if item not in source
    }

    assert not missing, (
        f"Missing source content: {sorted(missing)}"
    )


def validate_overdue_helper() -> None:
    overdue = TreeActivity(
        activity_type="inspection",
        activity_date=date.today(),
        status="planned",
        title="Inspection",
        next_due_date=(
            date.today()
            - timedelta(days=1)
        ),
    )

    assert tree_activity_is_overdue(
        overdue
    )

    future = TreeActivity(
        activity_type="inspection",
        activity_date=date.today(),
        status="planned",
        title="Inspection",
        next_due_date=(
            date.today()
            + timedelta(days=1)
        ),
    )

    assert not tree_activity_is_overdue(
        future
    )

    cancelled = TreeActivity(
        activity_type="inspection",
        activity_date=date.today(),
        status="cancelled",
        title="Inspection",
        next_due_date=(
            date.today()
            - timedelta(days=1)
        ),
    )

    assert not tree_activity_is_overdue(
        cancelled
    )


def validate_routes() -> None:
    actual = {
        (
            method,
            getattr(
                route,
                "path",
                "",
            ),
            getattr(
                route,
                "name",
                "",
            ),
        )
        for route in app.routes
        for method in getattr(
            route,
            "methods",
            set(),
        )
    }

    assert (
        "GET",
        (
            "/farms/{farm_id}/trees/{tree_id}/"
            "activities/{activity_id}"
        ),
        "tree_activity_detail_page",
    ) in actual

    assert (
        "GET",
        (
            "/api/farms/{farm_id}/trees/{tree_id}/"
            "activities-summary"
        ),
        "tree_activity_summary_api",
    ) in actual


def validate_templates() -> None:
    assert ACTIVITY_DETAIL_TEMPLATE.is_file()
    assert ACTIVITY_LIST_TEMPLATE.is_file()
    assert TREE_DETAIL_TEMPLATE.is_file()

    detail_content = (
        ACTIVITY_DETAIL_TEMPLATE.read_text()
    )

    list_content = (
        ACTIVITY_LIST_TEMPLATE.read_text()
    )

    tree_content = (
        TREE_DETAIL_TEMPLATE.read_text()
    )

    assert "Tree Activity" in detail_content
    assert "Follow-up overdue" in detail_content
    assert "Edit Activity" in detail_content
    assert "Delete Activity" in detail_content

    assert "View Details" in list_content

    assert (
        "PATCH-005B.4: TREE ACTIVITY SUMMARY CARD"
        in tree_content
    )

    assert (
        "tree_activity_summary("
        in tree_content
    )

    assert (
        "activity_summary.total_count"
        in tree_content
    )

    assert (
        "activity_summary.overdue_count"
        in tree_content
    )

    assert (
        "activity_summary.next_due_activity"
        in tree_content
    )

    templates.get_template(
        "tree_activities/detail.html"
    )

    templates.get_template(
        "tree_activities/list.html"
    )

    templates.get_template(
        "trees/detail.html"
    )


def validate_globals() -> None:
    assert (
        "tree_activity_summary"
        in templates.env.globals
    )

    assert (
        "tree_activity_is_overdue"
        in templates.env.globals
    )


def main() -> None:
    validate_source()
    validate_overdue_helper()
    validate_routes()
    validate_templates()
    validate_globals()

    print(
        "PATCH-005B.4 SOURCE: PASSED"
    )
    print(
        "PATCH-005B.4 OVERDUE HELPER: PASSED"
    )
    print(
        "PATCH-005B.4 ROUTES: PASSED"
    )
    print(
        "PATCH-005B.4 TEMPLATES: PASSED"
    )
    print(
        "PATCH-005B.4 TEMPLATE GLOBALS: PASSED"
    )
    print(
        "PATCH-005B.4: PASSED"
    )


if __name__ == "__main__":
    main()
