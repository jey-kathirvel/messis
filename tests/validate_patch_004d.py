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
    farm_routes = [
        route.path
        for route in app.routes
        if isinstance(route, APIRoute)
        and route.path.startswith("/farms/")
    ]

    assert "/farms/report" in farm_routes
    assert "/farms/{farm_id}" in farm_routes

    assert (
        farm_routes.index("/farms/report")
        <
        farm_routes.index("/farms/{farm_id}")
    )

    login_user_id, passcode = load_credentials()
    suffix = secrets.token_hex(5)
    farm_name = f"PATCH-004D Report {suffix}"

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
                "/farms/report",
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
                    "notes": "PATCH-004D report record",
                },
                follow_redirects=False,
            )

            assert create_response.status_code == 303

            list_response = client.get("/farms")

            assert list_response.status_code == 200
            assert 'href="/farms/report"' in (
                list_response.text
            )
            assert "Report" in list_response.text

            report_response = client.get(
                "/farms/report"
            )

            assert report_response.status_code == 200
            assert "Farm Portfolio Report" in (
                report_response.text
            )
            assert farm_name in report_response.text
            assert "Bodinayakanur" in report_response.text
            assert "400" in report_response.text
            assert "80.0" in report_response.text
            assert "Print Report" in report_response.text
            assert "window.print()" in report_response.text
            assert "@media print" in report_response.text

        print("FARM REPORT ROUTE VALIDATION: PASSED")
        print("FARM REPORT AUTH VALIDATION: PASSED")
        print("FARM REPORT CONTENT VALIDATION: PASSED")
        print("FARM REPORT CALCULATION VALIDATION: PASSED")
        print("FARM REPORT PRINT VALIDATION: PASSED")
        print("FARM REPORT BUTTON VALIDATION: PASSED")
        print("PATCH-004D: PASSED")
    finally:
        cleanup(
            owner_id=owner_id,
            farm_name=farm_name,
        )


if __name__ == "__main__":
    main()
