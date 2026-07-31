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
    farm_name: str,
) -> None:
    with SessionLocal() as db:
        farms = db.scalars(
            select(Farm).where(
                Farm.owner_id == owner_id,
                Farm.name == farm_name,
            )
        ).all()

        for farm in farms:
            db.delete(farm)

        db.execute(
            delete(AuditLog).where(
                AuditLog.owner_id == owner_id,
                AuditLog.detail.contains(farm_name),
            )
        )

        db.commit()


def main() -> None:
    matching_routes = [
        route
        for route in app.routes
        if isinstance(route, APIRoute)
        and route.path == "/farms/{farm_id}/print"
    ]

    assert len(matching_routes) == 1
    assert "GET" in matching_routes[0].methods

    login_user_id, passcode = load_credentials()
    suffix = secrets.token_hex(5)
    farm_name = f"PATCH-004G Print {suffix}"

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
        farm_name=farm_name,
    )

    try:
        with TestClient(
            app,
            base_url="https://testserver",
        ) as client:
            unauthenticated_response = client.get(
                "/farms/1/print",
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

            create_response = client.post(
                "/farms/new",
                data={
                    "name": farm_name,
                    "location": "Bodinayakanur",
                    "acreage": "5",
                    "total_trees": "400",
                    "notes": "Printable farm profile validation",
                },
                follow_redirects=False,
            )

            assert create_response.status_code == 303

            with SessionLocal() as db:
                farm = db.scalar(
                    select(Farm).where(
                        Farm.owner_id == owner_id,
                        Farm.name == farm_name,
                    )
                )

                assert farm is not None
                farm_id = farm.id

            detail_response = client.get(
                f"/farms/{farm_id}"
            )

            assert detail_response.status_code == 200
            assert (
                f'href="/farms/{farm_id}/print"'
                in detail_response.text
            )
            assert "Print Profile" in detail_response.text

            print_response = client.get(
                f"/farms/{farm_id}/print"
            )

            assert print_response.status_code == 200
            assert farm_name in print_response.text
            assert "Bodinayakanur" in print_response.text
            assert "400" in print_response.text
            assert "80.0" in print_response.text
            assert "Printable farm profile validation" in (
                print_response.text
            )
            assert "window.print()" in print_response.text
            assert "@media print" in print_response.text
            assert "Messis AI Farm Profile" in (
                print_response.text
            )

            missing_response = client.get(
                "/farms/999999999/print"
            )

            assert missing_response.status_code == 404

        print("FARM PRINT ROUTE VALIDATION: PASSED")
        print("FARM PRINT AUTH VALIDATION: PASSED")
        print("FARM PRINT BUTTON VALIDATION: PASSED")
        print("FARM PRINT CONTENT VALIDATION: PASSED")
        print("FARM PRINT DENSITY VALIDATION: PASSED")
        print("FARM PRINT 404 VALIDATION: PASSED")
        print("PATCH-004G: PASSED")
    finally:
        cleanup(
            owner_id=owner_id,
            farm_name=farm_name,
        )


if __name__ == "__main__":
    main()
