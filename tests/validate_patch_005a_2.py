
# PATCH-UAT-FIX-003: refuse unsafe database configuration before execution.
from scripts.test_database_safety import load_safe_test_database
_MESSIS_SAFE_TEST_DATABASE = load_safe_test_database()

import ast
from datetime import date
from decimal import Decimal
from pathlib import Path

from app.main import (
    TREE_HEALTH_STATUSES,
    TREE_VARIETIES,
    app,
    validate_coconut_tree_payload,
)


EXPECTED_ROUTES = {
    ("GET", "/api/farms/{farm_id}/trees"),
    ("POST", "/api/farms/{farm_id}/trees"),
    ("GET", "/api/trees/{tree_id}"),
    ("PUT", "/api/trees/{tree_id}"),
    ("DELETE", "/api/trees/{tree_id}"),
}


def validate_source() -> None:
    source = Path("app/main.py").read_text()
    ast.parse(source)

    assert (
        "# PATCH-005A.2: COCONUT TREE CRUD BACKEND"
        in source
    )


def validate_routes() -> None:
    installed_routes: set[tuple[str, str]] = set()

    for route in app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", set())

        if not path:
            continue

        for method in methods:
            installed_routes.add((method, path))

    missing_routes = EXPECTED_ROUTES - installed_routes

    assert not missing_routes, (
        f"Missing routes: {sorted(missing_routes)}"
    )


def validate_constants() -> None:
    assert TREE_VARIETIES == {
        "Tall",
        "Dwarf",
        "Hybrid",
    }

    assert TREE_HEALTH_STATUSES == {
        "Healthy",
        "Needs Attention",
        "Diseased",
        "Removed",
    }


def validate_create_payload() -> None:
    values, errors = validate_coconut_tree_payload(
        {
            "tree_code": " ctn-001 ",
            "tree_name": " East Tree ",
            "qr_code_id": " QR-001 ",
            "variety": "hybrid",
            "planting_date": "2020-01-15",
            "block_name": " Block A ",
            "row_number": " R1 ",
            "position_number": " P1 ",
            "health_status": "needs attention",
            "height_m": "12.50",
            "canopy_diameter_m": "6.25",
            "trunk_girth_cm": "88.40",
            "remarks": " Productive tree ",
            "is_active": True,
        }
    )

    assert not errors
    assert values["tree_code"] == "CTN-001"
    assert values["tree_name"] == "East Tree"
    assert values["qr_code_id"] == "QR-001"
    assert values["variety"] == "Hybrid"
    assert values["planting_date"] == date(2020, 1, 15)
    assert values["health_status"] == "Needs Attention"
    assert values["height_m"] == Decimal("12.50")
    assert values["canopy_diameter_m"] == Decimal("6.25")
    assert values["trunk_girth_cm"] == Decimal("88.40")
    assert values["is_active"] is True


def validate_invalid_payloads() -> None:
    _, missing_code_errors = validate_coconut_tree_payload({})
    assert "tree_code" in missing_code_errors

    _, invalid_errors = validate_coconut_tree_payload(
        {
            "tree_code": "",
            "variety": "Unknown",
            "health_status": "Unknown",
            "planting_date": "2999-01-01",
            "height_m": "-1",
            "is_active": "yes",
            "unsupported": "value",
        }
    )

    expected_error_fields = {
        "tree_code",
        "variety",
        "health_status",
        "planting_date",
        "height_m",
        "is_active",
        "unknown_fields",
    }

    assert expected_error_fields <= set(invalid_errors)


def validate_partial_payload() -> None:
    values, errors = validate_coconut_tree_payload(
        {
            "health_status": "diseased",
            "remarks": "",
        },
        partial=True,
    )

    assert not errors
    assert values == {
        "health_status": "Diseased",
        "remarks": None,
    }


def main() -> None:
    validate_source()
    validate_routes()
    validate_constants()
    validate_create_payload()
    validate_invalid_payloads()
    validate_partial_payload()

    print("PATCH-005A.2 SOURCE: PASSED")
    print("PATCH-005A.2 ROUTES: PASSED")
    print("PATCH-005A.2 VALIDATION: PASSED")
    print("PATCH-005A.2 CRUD BACKEND: PASSED")
    print("PATCH-005A.2: PASSED")


if __name__ == "__main__":
    main()
