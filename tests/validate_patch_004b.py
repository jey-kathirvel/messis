from __future__ import annotations

import csv
import io
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
    routes = [
        route
        for route in app.routes
        if isinstance(route, APIRoute)
    ]

    assert any(
        route.path == "/farms/export.csv"
        and "GET" in route.methods
        for route in routes
    )

    login_user_id, passcode = load_credentials()
    farm_name = (
        f"PATCH-004B Export {secrets.token_hex(5)}"
    )

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
                "/farms/export.csv",
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
                    "location": (
                        "Bodinayakanur, Theni District"
                    ),
                    "acreage": "5.50",
                    "total_trees": "440",
                    "notes": (
                        "PATCH-004B CSV export "
                        "validation record."
                    ),
                },
                follow_redirects=False,
            )

            assert create_response.status_code == 303

            list_response = client.get("/farms")

            assert list_response.status_code == 200
            assert 'href="/farms/export.csv"' in (
                list_response.text
            )
            assert "Export CSV" in list_response.text

            export_response = client.get(
                "/farms/export.csv"
            )

            assert export_response.status_code == 200
            assert export_response.headers[
                "content-type"
            ].startswith("text/csv")

            disposition = export_response.headers.get(
                "content-disposition",
                "",
            )

            assert "attachment;" in disposition
            assert "messis_farms_" in disposition
            assert disposition.endswith('.csv"')

            rows = list(
                csv.DictReader(
                    io.StringIO(export_response.text)
                )
            )

            assert rows

            exported_farm = next(
                (
                    row
                    for row in rows
                    if row["Farm Name"] == farm_name
                ),
                None,
            )

            assert exported_farm is not None
            assert exported_farm["Location"] == (
                "Bodinayakanur, Theni District"
            )
            assert exported_farm["Acreage"] in {
                "5.50",
                "5.5",
                "5.500",
                "5.5000",
            }
            assert exported_farm["Total Trees"] == "440"
            assert exported_farm["Trees Per Acre"] == "80.0"
            assert exported_farm["Notes"] == (
                "PATCH-004B CSV export validation record."
            )
            assert exported_farm["Created At"]

        print("FARM CSV ROUTE VALIDATION: PASSED")
        print("FARM CSV AUTHENTICATION VALIDATION: PASSED")
        print("FARM CSV HEADER VALIDATION: PASSED")
        print("FARM CSV CONTENT VALIDATION: PASSED")
        print("FARM CSV CALCULATION VALIDATION: PASSED")
        print("FARM CSV BUTTON VALIDATION: PASSED")
        print("PATCH-004B: PASSED")
    finally:
        cleanup(
            owner_id=owner_id,
            farm_name=farm_name,
        )


if __name__ == "__main__":
    main()
