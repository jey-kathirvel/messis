
# PATCH-UAT-FIX-003: refuse unsafe database configuration before execution.
from scripts.test_database_safety import load_safe_test_database
_MESSIS_SAFE_TEST_DATABASE = load_safe_test_database()

import ast
from datetime import date
from decimal import Decimal
from pathlib import Path

from pydantic import ValidationError

from app.main import (
    TREE_ACTIVITY_STATUSES,
    TREE_ACTIVITY_TYPES,
    TreeActivityCreatePayload,
    TreeActivityResponse,
    TreeActivityUpdatePayload,
    app,
    tree_activity_to_response,
)
from app.models import TreeActivity


BASE_PATH = (
    "/api/farms/{farm_id}/trees/"
    "{tree_id}/activities"
)


def validate_source() -> None:
    source = Path(
        "app/main.py"
    ).read_text()

    ast.parse(source)

    assert (
        "# PATCH-005B.2: TREE ACTIVITY CRUD BACKEND"
        in source
    )

    required = {
        "class TreeActivityCreatePayload(",
        "class TreeActivityUpdatePayload(",
        "class TreeActivityResponse(",
        "def require_owned_coconut_tree(",
        "def require_tree_activity(",
        "def list_tree_activities_api(",
        "def get_tree_activity_api(",
        "def create_tree_activity_api(",
        "def update_tree_activity_api(",
        "def delete_tree_activity_api(",
        '"tree_activity.created"',
        '"tree_activity.updated"',
        '"tree_activity.deleted"',
    }

    missing = {
        item
        for item in required
        if item not in source
    }

    assert not missing, (
        f"Missing source content: {sorted(missing)}"
    )


def validate_constants() -> None:
    expected_types = {
        "irrigation",
        "fertiliser",
        "manure",
        "pesticide",
        "disease_treatment",
        "pruning",
        "cleaning",
        "soil_testing",
        "inspection",
        "harvesting",
        "replacement",
        "other",
    }

    expected_statuses = {
        "planned",
        "in_progress",
        "completed",
        "cancelled",
    }

    assert set(
        TREE_ACTIVITY_TYPES
    ) == expected_types

    assert set(
        TREE_ACTIVITY_STATUSES
    ) == expected_statuses


def valid_payload():
    return {
        "activity_type": "Irrigation",
        "activity_date": date(
            2026,
            7,
            31,
        ),
        "status": "Completed",
        "title": " Morning irrigation ",
        "description": " Root-zone watering ",
        "quantity": Decimal(
            "40.000"
        ),
        "unit": " litres ",
        "cost": Decimal(
            "25.00"
        ),
        "performed_by": " Worker One ",
        "next_due_date": date(
            2026,
            8,
            2,
        ),
        "notes": " Soil moisture normal ",
    }


def validate_create_payload() -> None:
    payload = TreeActivityCreatePayload(
        **valid_payload()
    )

    assert (
        payload.activity_type
        == "irrigation"
    )

    assert payload.status == "completed"
    assert payload.title == "Morning irrigation"
    assert payload.unit == "litres"
    assert payload.performed_by == "Worker One"
    assert payload.quantity == Decimal("40.000")
    assert payload.cost == Decimal("25.00")


def validate_payload_rejections() -> None:
    invalid_type = valid_payload()
    invalid_type["activity_type"] = "invalid"

    try:
        TreeActivityCreatePayload(
            **invalid_type
        )
    except ValidationError:
        pass
    else:
        raise AssertionError(
            "Invalid activity type was accepted."
        )

    invalid_status = valid_payload()
    invalid_status["status"] = "unknown"

    try:
        TreeActivityCreatePayload(
            **invalid_status
        )
    except ValidationError:
        pass
    else:
        raise AssertionError(
            "Invalid status was accepted."
        )

    invalid_due_date = valid_payload()
    invalid_due_date["next_due_date"] = date(
        2026,
        7,
        30,
    )

    try:
        TreeActivityCreatePayload(
            **invalid_due_date
        )
    except ValidationError:
        pass
    else:
        raise AssertionError(
            "Invalid next due date was accepted."
        )


def validate_update_payload() -> None:
    payload = TreeActivityUpdatePayload(
        **valid_payload()
    )

    assert (
        payload.activity_type
        == "irrigation"
    )

    assert payload.status == "completed"


def validate_response_conversion() -> None:
    activity = TreeActivity(
        id=10,
        farm_id=1,
        tree_id=2,
        activity_type="irrigation",
        activity_date=date(
            2026,
            7,
            31,
        ),
        status="completed",
        title="Morning irrigation",
        description="Root-zone watering",
        quantity=Decimal(
            "40.000"
        ),
        unit="litres",
        cost=Decimal(
            "25.00"
        ),
        performed_by="Worker One",
        next_due_date=date(
            2026,
            8,
            2,
        ),
        notes="Soil moisture normal",
    )

    response = tree_activity_to_response(
        activity
    )

    assert isinstance(
        response,
        TreeActivityResponse,
    )

    assert response.id == 10
    assert response.farm_id == 1
    assert response.tree_id == 2
    assert (
        response.activity_type
        == "irrigation"
    )


def validate_routes() -> None:
    expected = {
        (
            "GET",
            BASE_PATH,
            "list_tree_activities_api",
        ),
        (
            "POST",
            BASE_PATH,
            "create_tree_activity_api",
        ),
        (
            "GET",
            BASE_PATH + "/{activity_id}",
            "get_tree_activity_api",
        ),
        (
            "PUT",
            BASE_PATH + "/{activity_id}",
            "update_tree_activity_api",
        ),
        (
            "DELETE",
            BASE_PATH + "/{activity_id}",
            "delete_tree_activity_api",
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


def validate_status_codes() -> None:
    route_map = {
        (
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
        ): route
        for route in app.routes
    }

    create_route = route_map[
        (
            BASE_PATH,
            "create_tree_activity_api",
        )
    ]

    delete_route = route_map[
        (
            BASE_PATH + "/{activity_id}",
            "delete_tree_activity_api",
        )
    ]

    assert (
        create_route.status_code
        == 201
    )

    assert (
        delete_route.status_code
        == 204
    )


def main() -> None:
    validate_source()
    validate_constants()
    validate_create_payload()
    validate_payload_rejections()
    validate_update_payload()
    validate_response_conversion()
    validate_routes()
    validate_status_codes()

    print(
        "PATCH-005B.2 SOURCE: PASSED"
    )
    print(
        "PATCH-005B.2 CONSTANTS: PASSED"
    )
    print(
        "PATCH-005B.2 PAYLOAD VALIDATION: PASSED"
    )
    print(
        "PATCH-005B.2 RESPONSE CONVERSION: PASSED"
    )
    print(
        "PATCH-005B.2 CRUD ROUTES: PASSED"
    )
    print(
        "PATCH-005B.2 STATUS CODES: PASSED"
    )
    print(
        "PATCH-005B.2 TREE ACTIVITY CRUD BACKEND: PASSED"
    )
    print(
        "PATCH-005B.2: PASSED"
    )


if __name__ == "__main__":
    main()
