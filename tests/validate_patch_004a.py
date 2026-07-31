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
    routes = [
        route
        for route in app.routes
        if isinstance(route, APIRoute)
    ]

    assert any(
        route.path == "/farms/{farm_id}"
        and "GET" in route.methods
        for route in routes
    )

    user_id, passcode = load_credentials()
    farm_name = (
        f"PATCH-004A Detail {secrets.token_hex(5)}"
    )

    with SessionLocal() as db:
        owner = db.scalar(
            select(User).where(
                User.user_id == user_id,
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
            login_response = client.post(
                "/auth/login",
                data={
                    "user_id": user_id,
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
                    "total_trees": "420",
                    "notes": (
                        "PATCH-004A detail page "
                        "validation notes."
                    ),
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

            list_response = client.get("/farms")

            assert list_response.status_code == 200
            assert f'/farms/{farm_id}"' in (
                list_response.text
            )
            assert "View" in list_response.text

            detail_response = client.get(
                f"/farms/{farm_id}"
            )

            assert detail_response.status_code == 200
            assert farm_name in detail_response.text
            assert (
                "Bodinayakanur, Theni District"
                in detail_response.text
            )
            assert "5.50" in detail_response.text
            assert "420" in detail_response.text
            assert (
                "PATCH-004A detail page validation notes."
                in detail_response.text
            )
            assert (
                f'/farms/{farm_id}/edit'
                in detail_response.text
            )
            assert (
                f'/farms/{farm_id}/delete'
                in detail_response.text
            )

            missing_response = client.get(
                "/farms/999999999"
            )

            assert missing_response.status_code == 404

        print("FARM DETAIL ROUTE VALIDATION: PASSED")
        print("FARM DETAIL TEMPLATE VALIDATION: PASSED")
        print("FARM DETAIL DATA VALIDATION: PASSED")
        print("FARM DETAIL ACTION VALIDATION: PASSED")
        print("FARM DETAIL OWNER QUERY VALIDATION: PASSED")
        print("PATCH-004A: PASSED")
    finally:
        cleanup(
            owner_id=owner_id,
            farm_name=farm_name,
        )


if __name__ == "__main__":
    main()
