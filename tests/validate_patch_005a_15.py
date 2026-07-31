import ast
from datetime import date, datetime
from pathlib import Path

from app.main import (
    coconut_tree_age_details,
    coconut_tree_age_label,
    coconut_tree_maturity_status,
    coconut_tree_timeline,
    normalize_coconut_tree_date,
    templates,
)


class MatureTree:
    planting_date = date(
        2018,
        1,
        15,
    )

    variety = "Tall"

    created_at = datetime(
        2020,
        2,
        1,
        10,
        30,
    )

    updated_at = datetime(
        2024,
        5,
        10,
        8,
        15,
    )


class JuvenileTree:
    planting_date = date(
        2024,
        1,
        1,
    )

    variety = "Dwarf"

    created_at = None
    updated_at = None


class UnknownTree:
    planting_date = None
    variety = "Hybrid"
    created_at = None
    updated_at = None


def validate_source() -> None:
    source = Path(
        "app/main.py"
    ).read_text()

    ast.parse(source)

    assert (
        "# PATCH-005A.15: TREE AGE AND TEMPLATE HELPERS"
        in source
    )

    required = {
        "def normalize_coconut_tree_date(",
        "def coconut_tree_age_details(",
        "def coconut_tree_age_label(",
        "def coconut_tree_maturity_status(",
        "templates.env.globals.update({",
    }

    missing = {
        item
        for item in required
        if item not in source
    }

    assert not missing, (
        f"Missing source content: {sorted(missing)}"
    )


def validate_date_normalization() -> None:
    expected = date(
        2025,
        3,
        12,
    )

    assert normalize_coconut_tree_date(
        expected
    ) == expected

    assert normalize_coconut_tree_date(
        datetime(
            2025,
            3,
            12,
            9,
            30,
        )
    ) == expected

    assert normalize_coconut_tree_date(
        "2025-03-12"
    ) == expected

    assert normalize_coconut_tree_date(
        "invalid"
    ) is None

    assert normalize_coconut_tree_date(
        None
    ) is None


def validate_age_details() -> None:
    details = coconut_tree_age_details(
        MatureTree(),
        today=date(
            2026,
            7,
            31,
        ),
    )

    assert details["years"] == 8
    assert details["months"] == 6
    assert details["days"] == 16
    assert details["total_months"] == 102
    assert details["label"] == (
        "8 years 6 months"
    )

    unknown = coconut_tree_age_details(
        UnknownTree(),
        today=date(
            2026,
            7,
            31,
        ),
    )

    assert unknown["years"] is None
    assert unknown["total_months"] is None
    assert unknown["label"] == (
        "Planting date not recorded"
    )


def validate_age_label() -> None:
    label = coconut_tree_age_label(
        MatureTree()
    )

    assert isinstance(
        label,
        str,
    )

    assert label


def validate_maturity() -> None:
    assert coconut_tree_maturity_status(
        MatureTree()
    ) == "Mature"

    status = coconut_tree_maturity_status(
        JuvenileTree()
    )

    assert status in {
        "Juvenile",
        "Early Bearing",
    }

    assert coconut_tree_maturity_status(
        UnknownTree()
    ) == "Unknown"


def validate_timeline() -> None:
    events = coconut_tree_timeline(
        MatureTree()
    )

    assert len(events) == 3

    event_dates = [
        event["date"]
        for event in events
    ]

    assert event_dates == sorted(
        event_dates,
        reverse=True,
    )

    assert all(
        isinstance(
            event_date,
            date,
        )
        for event_date in event_dates
    )


def validate_template_globals() -> None:
    required_globals = {
        "coconut_tree_label_location",
        "coconut_tree_timeline",
        "coconut_tree_age_details",
        "coconut_tree_age_label",
        "coconut_tree_maturity_status",
    }

    missing = {
        helper_name
        for helper_name in required_globals
        if helper_name
        not in templates.env.globals
    }

    assert not missing, (
        f"Missing template globals: {sorted(missing)}"
    )


def validate_template() -> None:
    template_path = Path(
        "app/templates/trees/detail.html"
    )

    assert template_path.is_file()

    content = template_path.read_text()

    required = {
        "Tree Age & Maturity",
        "coconut_tree_age_details(tree)",
        "coconut_tree_maturity_status(tree)",
        "{{ tree_age.label }}",
        "Years",
        "Months",
        "Days",
    }

    missing = {
        item
        for item in required
        if item not in content
    }

    assert not missing, (
        f"Missing template content: {sorted(missing)}"
    )

    templates.get_template(
        "trees/detail.html"
    )


def main() -> None:
    validate_source()
    validate_date_normalization()
    validate_age_details()
    validate_age_label()
    validate_maturity()
    validate_timeline()
    validate_template_globals()
    validate_template()

    print("PATCH-005A.15 SOURCE: PASSED")
    print("PATCH-005A.15 DATE NORMALIZATION: PASSED")
    print("PATCH-005A.15 AGE DETAILS: PASSED")
    print("PATCH-005A.15 AGE LABEL: PASSED")
    print("PATCH-005A.15 MATURITY: PASSED")
    print("PATCH-005A.15 TIMELINE: PASSED")
    print("PATCH-005A.15 TEMPLATE GLOBALS: PASSED")
    print("PATCH-005A.15 TEMPLATE: PASSED")
    print("PATCH-005A.15: PASSED")


if __name__ == "__main__":
    main()
