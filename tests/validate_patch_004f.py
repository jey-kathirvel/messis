from __future__ import annotations

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
    names: list[str],
) -> None:
    with SessionLocal() as db:
        farms = db.scalars(
            select(Farm).where(
                Farm.owner_id == owner_id,
                Farm.name.in_(names),
            )
        ).all()

        for farm in farms:
            db.delete(farm)

        for name in names:
            db.execute(
                delete(AuditLog).where(
                    AuditLog.owner_id == owner_id,
                    AuditLog.detail.contains(name),
                )
            )

        db.commit()


def main() -> None:
    routes = [
        route
        for route in app.routes
        if isinstance(route, APIRoute)
    ]

    duplicate_routes = [
        route
        for route in routes
        if route.path
        == "/farms/{farm_id}/duplicate"
    ]

    assert len(duplicate_routes) == 1
    assert "POST" in duplicate_routes[0].methods

    login_user_id, passcode = load_credentials()
    suffix = secrets.token_hex(5)

    original_name = f"PATCH-004F Farm {suffix}"
    first_copy_name = f"Copy of {original_name}"
    second_copy_name = (
        f"Copy of {original_name} (2)"
    )

    cleanup_names = [
        original_name,
        first_copy_name,
        second_copy_name,
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
        names=cleanup_names,
    )

    try:
        with TestClient(
            app,
            base_url="https://testserver",
        ) as client:
            login_response = client.post(
                "/auth/login",
                data={
                    "user_id": login_user_id,
                    "passcode": passcode,
                },
                follow_redirects=False,
            )

            assert login_response.status_code == 303

            create_response = client.post(
                "/farms/new",
                data={
                    "name": original_name,
                    "location": "Bodinayakanur",
                    "acreage": "6.5",
                    "total_trees": "520",
                    "notes": "Duplicate validation farm",
                },
                follow_redirects=False,
            )

            assert create_response.status_code == 303

            with SessionLocal() as db:
                original = db.scalar(
                    select(Farm).where(
                        Farm.owner_id == owner_id,
                        Farm.name == original_name,
                    )
                )

                assert original is not None
                original_id = original.id

            detail_response = client.get(
                f"/farms/{original_id}"
            )

            assert detail_response.status_code == 200
            assert (
                f'action="/farms/{original_id}/duplicate"'
                in detail_response.text
            )
            assert "Duplicate Farm" in detail_response.text

            duplicate_response = client.post(
                f"/farms/{original_id}/duplicate",
                follow_redirects=False,
            )

            assert duplicate_response.status_code == 303
            assert duplicate_response.headers[
                "location"
            ].startswith("/farms/")

            with SessionLocal() as db:
                first_copy = db.scalar(
                    select(Farm).where(
                        Farm.owner_id == owner_id,
                        Farm.name == first_copy_name,
                    )
                )

                assert first_copy is not None
                assert first_copy.location == original.location
                assert str(first_copy.acreage) == str(
                    original.acreage
                )
                assert first_copy.total_trees == (
                    original.total_trees
                )
                assert first_copy.notes == original.notes

            second_duplicate_response = client.post(
                f"/farms/{original_id}/duplicate",
                follow_redirects=False,
            )

            assert (
                second_duplicate_response.status_code
                == 303
            )

            with SessionLocal() as db:
                second_copy = db.scalar(
                    select(Farm).where(
                        Farm.owner_id == owner_id,
                        Farm.name == second_copy_name,
                    )
                )

                assert second_copy is not None

            missing_response = client.post(
                "/farms/999999999/duplicate",
                follow_redirects=False,
            )

            assert missing_response.status_code == 404

        print("FARM DUPLICATE ROUTE VALIDATION: PASSED")
        print("FARM DUPLICATE BUTTON VALIDATION: PASSED")
        print("FARM DUPLICATE DATA VALIDATION: PASSED")
        print("FARM DUPLICATE NAME VALIDATION: PASSED")
        print("FARM DUPLICATE 404 VALIDATION: PASSED")
        print("PATCH-004F: PASSED")
    finally:
        cleanup(
            owner_id=owner_id,
            names=cleanup_names,
        )


if __name__ == "__main__":
    main()
