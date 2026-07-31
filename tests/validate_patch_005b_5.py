
# PATCH-UAT-FIX-003: refuse unsafe database configuration before execution.
from scripts.test_database_safety import load_safe_test_database
_MESSIS_SAFE_TEST_DATABASE = load_safe_test_database()

import ast
from datetime import date
from pathlib import Path

from app.main import (
    TREE_ACTIVITY_STATUS_TRANSITIONS,
    app,
    normalize_tree_activity_status,
    templates,
    tree_activity_status_actions,
    tree_activity_status_transition_allowed,
    update_tree_activity_status,
)
from app.models import TreeActivity


LIST_TEMPLATE = Path(
    "app/templates/tree_activities/list.html"
)

DETAIL_TEMPLATE = Path(
    "app/templates/tree_activities/detail.html"
)


def activity_with_status(
    status: str,
) -> TreeActivity:
    return TreeActivity(
        farm_id=1,
        tree_id=1,
        activity_type="inspection",
        activity_date=date.today(),
        status=status,
        title="Tree inspection",
    )


def validate_source() -> None:
    source = Path(
        "app/main.py"
    ).read_text()

    ast.parse(source)

    required = {
        "# PATCH-005B.5: ACTIVITY STATUS WORKFLOW",
        "TREE_ACTIVITY_STATUS_TRANSITIONS",
        "def normalize_tree_activity_status(",
        "def tree_activity_status_transition_allowed(",
        "def tree_activity_status_actions(",
        "def update_tree_activity_status(",
        "async def tree_activity_status_submit(",
        "def tree_activity_status_api(",
        '"tree_activity.status_updated"',
        '"tree_activity_status_actions"',
    }

    missing = {
        item
        for item in required
        if item not in source
    }

    assert not missing, (
        f"Missing source content: {sorted(missing)}"
    )


def validate_transitions() -> None:
    assert (
        TREE_ACTIVITY_STATUS_TRANSITIONS[
            "planned"
        ]
        == {
            "in_progress",
            "completed",
            "cancelled",
        }
    )

    assert tree_activity_status_transition_allowed(
        "planned",
        "in_progress",
    )

    assert tree_activity_status_transition_allowed(
        "planned",
        "completed",
    )

    assert not tree_activity_status_transition_allowed(
        "completed",
        "cancelled",
    )

    assert tree_activity_status_transition_allowed(
        "completed",
        "planned",
    )

    assert (
        normalize_tree_activity_status(
            " Completed "
        )
        == "completed"
    )


def validate_status_update() -> None:
    activity = activity_with_status(
        "planned"
    )

    update_tree_activity_status(
        None,
        activity,
        "in_progress",
    )

    assert (
        activity.status
        == "in_progress"
    )

    update_tree_activity_status(
        None,
        activity,
        "completed",
    )

    assert (
        activity.status
        == "completed"
    )

    try:
        update_tree_activity_status(
            None,
            activity,
            "cancelled",
        )
    except ValueError:
        pass
    else:
        raise AssertionError(
            "Invalid status transition was accepted."
        )


def validate_actions() -> None:
    planned = activity_with_status(
        "planned"
    )

    planned_actions = {
        item["status"]
        for item in tree_activity_status_actions(
            planned
        )
    }

    assert planned_actions == {
        "in_progress",
        "completed",
        "cancelled",
    }

    completed = activity_with_status(
        "completed"
    )

    completed_actions = {
        item["status"]
        for item in tree_activity_status_actions(
            completed
        )
    }

    assert completed_actions == {
        "planned",
    }


def validate_routes() -> None:
    web_path = (
        "/farms/{farm_id}/trees/{tree_id}/"
        "activities/{activity_id}/status"
    )

    api_path = (
        "/api/farms/{farm_id}/trees/{tree_id}/"
        "activities/{activity_id}/status"
    )

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
        "POST",
        web_path,
        "tree_activity_status_submit",
    ) in actual

    assert (
        "PATCH",
        api_path,
        "tree_activity_status_api",
    ) in actual


def validate_templates() -> None:
    assert LIST_TEMPLATE.is_file()
    assert DETAIL_TEMPLATE.is_file()

    list_content = (
        LIST_TEMPLATE.read_text()
    )

    detail_content = (
        DETAIL_TEMPLATE.read_text()
    )

    assert (
        "PATCH-005B.5: LIST STATUS ACTIONS"
        in list_content
    )

    assert (
        "tree_activity_status_actions("
        in list_content
    )

    assert (
        'name="redirect_to"'
        in list_content
    )

    assert (
        "PATCH-005B.5: ACTIVITY STATUS ACTIONS"
        in detail_content
    )

    assert (
        "Update Activity Status"
        in detail_content
    )

    assert (
        "tree_activity_status_actions("
        in detail_content
    )

    templates.get_template(
        "tree_activities/list.html"
    )

    templates.get_template(
        "tree_activities/detail.html"
    )


def validate_globals() -> None:
    assert (
        "tree_activity_status_actions"
        in templates.env.globals
    )

    assert (
        "tree_activity_status_transition_allowed"
        in templates.env.globals
    )


def main() -> None:
    validate_source()
    validate_transitions()
    validate_status_update()
    validate_actions()
    validate_routes()
    validate_templates()
    validate_globals()

    print(
        "PATCH-005B.5 SOURCE: PASSED"
    )
    print(
        "PATCH-005B.5 STATUS TRANSITIONS: PASSED"
    )
    print(
        "PATCH-005B.5 STATUS UPDATE: PASSED"
    )
    print(
        "PATCH-005B.5 STATUS ACTIONS: PASSED"
    )
    print(
        "PATCH-005B.5 ROUTES: PASSED"
    )
    print(
        "PATCH-005B.5 TEMPLATES: PASSED"
    )
    print(
        "PATCH-005B.5 TEMPLATE GLOBALS: PASSED"
    )
    print(
        "PATCH-005B.5 ACTIVITY STATUS WORKFLOW: PASSED"
    )
    print(
        "PATCH-005B.5: PASSED"
    )


if __name__ == "__main__":
    main()
