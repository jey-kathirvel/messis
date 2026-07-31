import ast
from datetime import date
from decimal import Decimal
from pathlib import Path

from app.main import (
    TREE_ACTIVITY_STATUS_LABELS,
    TREE_ACTIVITY_TYPE_LABELS,
    app,
    templates,
    tree_activity_date_from_form,
    tree_activity_decimal_from_form,
    tree_activity_form_payload,
    tree_activity_form_values,
    tree_activity_status_label,
    tree_activity_status_style,
    tree_activity_type_label,
    tree_activity_type_style,
)


LIST_TEMPLATE = Path(
    "app/templates/tree_activities/list.html"
)

FORM_TEMPLATE = Path(
    "app/templates/tree_activities/form.html"
)

DETAIL_TEMPLATE = Path(
    "app/templates/trees/detail.html"
)


class FakeForm(dict):
    def get(
        self,
        key,
        default=None,
    ):
        return super().get(
            key,
            default,
        )


def valid_form():
    return FakeForm({
        "activity_type": "irrigation",
        "activity_date": "2026-07-31",
        "status": "completed",
        "title": "Morning irrigation",
        "description": "Watered root zone",
        "quantity": "40.500",
        "unit": "litres",
        "cost": "25.50",
        "performed_by": "Worker One",
        "next_due_date": "2026-08-02",
        "notes": "Soil moisture normal",
    })


def validate_source() -> None:
    source = Path(
        "app/main.py"
    ).read_text()

    ast.parse(source)

    assert (
        "# PATCH-005B.3: TREE ACTIVITY WEB UI"
        in source
    )

    required = {
        "def tree_activity_list_page(",
        "def tree_activity_create_page(",
        "async def tree_activity_create_submit(",
        "def tree_activity_edit_page(",
        "async def tree_activity_edit_submit(",
        "def tree_activity_delete_submit(",
        "def tree_activity_form_payload(",
        "def tree_activity_form_values(",
        "def tree_activity_type_label(",
        "def tree_activity_status_label(",
    }

    missing = {
        item
        for item in required
        if item not in source
    }

    assert not missing, (
        f"Missing source content: {sorted(missing)}"
    )


def validate_labels() -> None:
    assert (
        TREE_ACTIVITY_TYPE_LABELS[
            "irrigation"
        ]
        == "Irrigation"
    )

    assert (
        TREE_ACTIVITY_STATUS_LABELS[
            "in_progress"
        ]
        == "In Progress"
    )

    assert (
        tree_activity_type_label(
            "soil_testing"
        )
        == "Soil Testing"
    )

    assert (
        tree_activity_status_label(
            "completed"
        )
        == "Completed"
    )

    assert "blue" in (
        tree_activity_type_style(
            "irrigation"
        )
    )

    assert "emerald" in (
        tree_activity_status_style(
            "completed"
        )
    )


def validate_form_helpers() -> None:
    amount = (
        tree_activity_decimal_from_form(
            "25.567",
            "Cost",
            2,
        )
    )

    assert amount == Decimal(
        "25.57"
    )

    assert (
        tree_activity_decimal_from_form(
            "",
            "Cost",
            2,
        )
        is None
    )

    parsed_date = (
        tree_activity_date_from_form(
            "2026-07-31",
            "Activity date",
            required=True,
        )
    )

    assert parsed_date == date(
        2026,
        7,
        31,
    )

    payload = tree_activity_form_payload(
        valid_form()
    )

    assert (
        payload.activity_type
        == "irrigation"
    )

    assert payload.status == "completed"

    assert payload.quantity == Decimal(
        "40.500"
    )

    assert payload.cost == Decimal(
        "25.50"
    )

    values = tree_activity_form_values(
        form=valid_form()
    )

    assert (
        values["activity_date"]
        == "2026-07-31"
    )

    assert (
        values["title"]
        == "Morning irrigation"
    )


def validate_routes() -> None:
    base = (
        "/farms/{farm_id}/trees/"
        "{tree_id}/activities"
    )

    expected = {
        (
            "GET",
            base,
            "tree_activity_list_page",
        ),
        (
            "GET",
            base + "/new",
            "tree_activity_create_page",
        ),
        (
            "POST",
            base + "/new",
            "tree_activity_create_submit",
        ),
        (
            "GET",
            base + "/{activity_id}/edit",
            "tree_activity_edit_page",
        ),
        (
            "POST",
            base + "/{activity_id}/edit",
            "tree_activity_edit_submit",
        ),
        (
            "POST",
            base + "/{activity_id}/delete",
            "tree_activity_delete_submit",
        ),
    }

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

    missing = expected - actual

    assert not missing, (
        f"Missing routes: {sorted(missing)}"
    )


def validate_templates() -> None:
    assert LIST_TEMPLATE.is_file()
    assert FORM_TEMPLATE.is_file()
    assert DETAIL_TEMPLATE.is_file()

    list_content = (
        LIST_TEMPLATE.read_text()
    )

    form_content = (
        FORM_TEMPLATE.read_text()
    )

    detail_content = (
        DETAIL_TEMPLATE.read_text()
    )

    required_list = {
        "Tree Operations",
        "Add Activity",
        "Apply Filters",
        "activity.activity_type",
        "activity.activity_date",
        "activity.next_due_date",
        "tree_activity_type_label(",
        "tree_activity_status_style(",
        "Delete this activity?",
    }

    missing_list = {
        item
        for item in required_list
        if item not in list_content
    }

    assert not missing_list, (
        f"Missing list template content: "
        f"{sorted(missing_list)}"
    )

    required_form = {
        "Activity Information",
        'name="activity_type"',
        'name="activity_date"',
        'name="status"',
        'name="title"',
        'name="quantity"',
        'name="cost"',
        'name="performed_by"',
        'name="next_due_date"',
        "Save Activity",
        "Update Activity",
    }

    missing_form = {
        item
        for item in required_form
        if item not in form_content
    }

    assert not missing_form, (
        f"Missing form template content: "
        f"{sorted(missing_form)}"
    )

    assert (
        "Manage Tree Activities"
        in detail_content
    )

    templates.get_template(
        "tree_activities/list.html"
    )

    templates.get_template(
        "tree_activities/form.html"
    )

    templates.get_template(
        "trees/detail.html"
    )


def validate_template_globals() -> None:
    required = {
        "tree_activity_type_label",
        "tree_activity_status_label",
        "tree_activity_status_style",
        "tree_activity_type_style",
    }

    missing = {
        name
        for name in required
        if name not in templates.env.globals
    }

    assert not missing, (
        f"Missing template globals: "
        f"{sorted(missing)}"
    )


def main() -> None:
    validate_source()
    validate_labels()
    validate_form_helpers()
    validate_routes()
    validate_templates()
    validate_template_globals()

    print(
        "PATCH-005B.3 SOURCE: PASSED"
    )
    print(
        "PATCH-005B.3 LABELS AND STYLES: PASSED"
    )
    print(
        "PATCH-005B.3 FORM HELPERS: PASSED"
    )
    print(
        "PATCH-005B.3 WEB ROUTES: PASSED"
    )
    print(
        "PATCH-005B.3 TEMPLATES: PASSED"
    )
    print(
        "PATCH-005B.3 TEMPLATE GLOBALS: PASSED"
    )
    print(
        "PATCH-005B.3 TREE ACTIVITY WEB UI: PASSED"
    )
    print(
        "PATCH-005B.3: PASSED"
    )


if __name__ == "__main__":
    main()
