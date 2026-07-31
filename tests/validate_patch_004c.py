
from __future__ import annotations

# PATCH-UAT-FIX-003: refuse unsafe database configuration before execution.
from scripts.test_database_safety import load_safe_test_database
_MESSIS_SAFE_TEST_DATABASE = load_safe_test_database()


import re
import secrets
from pathlib import Path

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from sqlalchemy import delete, select

from app.database import SessionLocal
from app.main import app
from app.models import AuditLog, Farm, User

CREDENTIAL_FILE = Path(
    "/root/messis_initial_credentials.txt"
)


def load_credentials() -> tuple[str, str]:
    content = CREDENTIAL_FILE.read_text(
        encoding="utf-8",
    )

    user_match = re.search(
        r"(?:USER ID|USER_ID)\s*[:=]\s*([^\s]+)",
        content,
        re.IGNORECASE,
    )

    passcode_match = re.search(
        r"PASSCODE\s*[:=]\s*(\d{6})",
        content,
        re.IGNORECASE,
    )

    assert user_match is not None
    assert passcode_match is not None

    return (
        user_match.group(1).strip(),
        passcode_match.group(1).strip(),
    )


def cleanup(
    owner_id: int,
    farm_names: list[str],
) -> None:
    with SessionLocal() as db:
        farms = db.scalars(
            select(Farm).where(
                Farm.owner_id == owner_id,
                Farm.name.in_(farm_names),
            )
        ).all()

        for farm in farms:
            db.delete(farm)

        for farm_name in farm_names:
            db.execute(
                delete(AuditLog).where(
                    AuditLog.owner_id == owner_id,
                    AuditLog.detail.contains(farm_name),
                )
            )

        db.commit()


def main() -> None:
    routes = [
        route
        for route in app.routes
        if isinstance(route, APIRoute)
    ]

    farm_route_paths = [
        route.path
        for route in routes
        if route.path.startswith("/farms/")
    ]

    assert "/farms/analytics" in farm_route_paths
    assert "/farms/{farm_id}" in farm_route_paths

    assert (
        farm_route_paths.index("/farms/analytics")
        <
        farm_route_paths.index("/farms/{farm_id}")
    )

    login_user_id, passcode = load_credentials()
    suffix = secrets.token_hex(5)

    first_name = f"PATCH-004C North {suffix}"
    second_name = f"PATCH-004C South {suffix}"

    farm_names = [
        first_name,
        second_name,
    ]

    with SessionLocal() as db:
        owner = db.scalar(
            select(User).where(
                User.user_id == login_user_id,
            )
        )

        assert owner is not None
        owner_id = owner.id

    cleanup(
        owner_id=owner_id,
        farm_names=farm_names,
    )

    try:
        with TestClient(
            app,
            base_url="https://testserver",
        ) as client:
            unauthenticated_response = client.get(
                "/farms/analytics",
                follow_redirects=False,
            )

            assert unauthenticated_response.status_code in {
                302,
                303,
                307,
            }

            login_response = client.post(
                "/auth/login",
                data={
                    "user_id": login_user_id,
                    "passcode": passcode,
                },
                follow_redirects=False,
            )

            assert login_response.status_code == 303

            first_create = client.post(
                "/farms/new",
                data={
                    "name": first_name,
                    "location": "Bodinayakanur",
                    "acreage": "5",
                    "total_trees": "400",
                    "notes": "Analytics north farm",
                },
                follow_redirects=False,
            )

            assert first_create.status_code == 303

            second_create = client.post(
                "/farms/new",
                data={
                    "name": second_name,
                    "location": "Theni",
                    "acreage": "3",
                    "total_trees": "240",
                    "notes": "Analytics south farm",
                },
                follow_redirects=False,
            )

            assert second_create.status_code == 303

            list_response = client.get("/farms")

            assert list_response.status_code == 200
            assert 'href="/farms/analytics"' in (
                list_response.text
            )
            assert "Analytics" in list_response.text

            analytics_response = client.get(
                "/farms/analytics"
            )

            assert analytics_response.status_code == 200
            assert "Farm Analytics" in analytics_response.text
            assert first_name in analytics_response.text
            assert second_name in analytics_response.text
            assert "Bodinayakanur" in analytics_response.text
            assert "Theni" in analytics_response.text
            assert "treeChart" in analytics_response.text
            assert "acreageChart" in analytics_response.text
            assert "Chart" in analytics_response.text

            with SessionLocal() as db:
                owner_farms = db.scalars(
                    select(Farm).where(
                        Farm.owner_id == owner_id,
                    )
                ).all()

                expected_total_farms = len(owner_farms)
                expected_total_trees = sum(
                    int(farm.total_trees or 0)
                    for farm in owner_farms
                )

            assert str(expected_total_farms) in (
                analytics_response.text
            )
            assert str(expected_total_trees) in (
                analytics_response.text
            )

        print("FARM ANALYTICS ROUTE VALIDATION: PASSED")
        print("FARM ANALYTICS AUTH VALIDATION: PASSED")
        print("FARM ANALYTICS TOTALS VALIDATION: PASSED")
        print("FARM ANALYTICS LOCATION VALIDATION: PASSED")
        print("FARM ANALYTICS CHART VALIDATION: PASSED")
        print("FARM ANALYTICS BUTTON VALIDATION: PASSED")
        print("PATCH-004C: PASSED")
    finally:
        cleanup(
            owner_id=owner_id,
            farm_names=farm_names,
        )


if __name__ == "__main__":
    main()
