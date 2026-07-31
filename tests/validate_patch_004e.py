
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
    farm_routes = [
        route.path
        for route in app.routes
        if isinstance(route, APIRoute)
        and route.path.startswith("/farms/")
    ]

    assert "/farms/search" in farm_routes
    assert "/farms/{farm_id}" in farm_routes

    assert (
        farm_routes.index("/farms/search")
        <
        farm_routes.index("/farms/{farm_id}")
    )

    login_user_id, passcode = load_credentials()
    suffix = secrets.token_hex(5)

    alpha_name = f"PATCH-004E Alpha {suffix}"
    beta_name = f"PATCH-004E Beta {suffix}"

    farm_names = [
        alpha_name,
        beta_name,
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
                "/farms/search",
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

            alpha_create = client.post(
                "/farms/new",
                data={
                    "name": alpha_name,
                    "location": "Bodinayakanur",
                    "acreage": "8",
                    "total_trees": "640",
                    "notes": "Eastern coconut section",
                },
                follow_redirects=False,
            )

            assert alpha_create.status_code == 303

            beta_create = client.post(
                "/farms/new",
                data={
                    "name": beta_name,
                    "location": "Theni",
                    "acreage": "3",
                    "total_trees": "210",
                    "notes": "Western coconut section",
                },
                follow_redirects=False,
            )

            assert beta_create.status_code == 303

            list_response = client.get("/farms")

            assert list_response.status_code == 200
            assert 'href="/farms/search"' in (
                list_response.text
            )
            assert "Search" in list_response.text

            search_page = client.get(
                "/farms/search"
            )

            assert search_page.status_code == 200
            assert "Search and Filter Farms" in (
                search_page.text
            )
            assert alpha_name in search_page.text
            assert beta_name in search_page.text

            name_search = client.get(
                "/farms/search",
                params={
                    "q": "Alpha",
                },
            )

            assert name_search.status_code == 200
            assert alpha_name in name_search.text
            assert beta_name not in name_search.text

            location_search = client.get(
                "/farms/search",
                params={
                    "location": "Theni",
                },
            )

            assert location_search.status_code == 200
            assert beta_name in location_search.text
            assert alpha_name not in location_search.text

            notes_search = client.get(
                "/farms/search",
                params={
                    "q": "Eastern coconut",
                },
            )

            assert notes_search.status_code == 200
            assert alpha_name in notes_search.text
            assert beta_name not in notes_search.text

            no_result_search = client.get(
                "/farms/search",
                params={
                    "q": (
                        "NO-MATCH-"
                        + secrets.token_hex(8)
                    ),
                },
            )

            assert no_result_search.status_code == 200
            assert "No matching farms" in (
                no_result_search.text
            )

            sorted_search = client.get(
                "/farms/search",
                params={
                    "q": f"PATCH-004E",
                    "sort": "trees_desc",
                },
            )

            assert sorted_search.status_code == 200

            alpha_position = sorted_search.text.find(
                alpha_name
            )

            beta_position = sorted_search.text.find(
                beta_name
            )

            assert alpha_position != -1
            assert beta_position != -1
            assert alpha_position < beta_position

        print("FARM SEARCH ROUTE VALIDATION: PASSED")
        print("FARM SEARCH AUTH VALIDATION: PASSED")
        print("FARM SEARCH QUERY VALIDATION: PASSED")
        print("FARM LOCATION FILTER VALIDATION: PASSED")
        print("FARM NOTES SEARCH VALIDATION: PASSED")
        print("FARM SORT VALIDATION: PASSED")
        print("FARM EMPTY RESULT VALIDATION: PASSED")
        print("FARM SEARCH BUTTON VALIDATION: PASSED")
        print("PATCH-004E: PASSED")
    finally:
        cleanup(
            owner_id=owner_id,
            farm_names=farm_names,
        )


if __name__ == "__main__":
    main()
