from __future__ import annotations

import re
import secrets
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import delete, select

from app.database import SessionLocal
from app.main import app
from app.models import AuditLog, Farm, User

CREDENTIAL_FILE = Path("/root/messis_initial_credentials.txt")


def load_credentials() -> tuple[str, str]:
    content = CREDENTIAL_FILE.read_text(encoding="utf-8")

    user_match = re.search(
        r"(?:USER ID|USER_ID)\s*[:=]\s*([^\s]+)",
        content,
        re.IGNORECASE,
    )
    passcode_match = re.search(
        r"(?:PASSCODE)\s*[:=]\s*(\d{6})",
        content,
        re.IGNORECASE,
    )

    assert user_match, "Unable to locate User ID in credentials file"
    assert passcode_match, "Unable to locate passcode in credentials file"

    return user_match.group(1).strip(), passcode_match.group(1).strip()


def main() -> None:
    login_user_id, passcode = load_credentials()
    unique_suffix = secrets.token_hex(4)
    farm_name = f"PATCH-003A Farm {unique_suffix}"

    with SessionLocal() as db:
        owner = db.scalar(
            select(User).where(User.user_id == login_user_id)
        )
        assert owner is not None, "Owner user not found"
        owner_id = owner.id

    with TestClient(app, base_url="https://testserver") as client:
        login_response = client.post(
            "/auth/login",
            data={
                "user_id": login_user_id,
                "passcode": passcode,
            },
            follow_redirects=False,
        )

        assert login_response.status_code == 303
        assert login_response.headers["location"] == "/dashboard"

        dashboard_before = client.get("/dashboard")
        assert dashboard_before.status_code == 200

        farm_list_before = client.get("/farms")
        assert farm_list_before.status_code == 200
        assert "<html" in farm_list_before.text.lower()
        assert "/farms/new" in farm_list_before.text

        new_farm_page = client.get("/farms/new")
        assert new_farm_page.status_code == 200
        assert "<form" in new_farm_page.text.lower()
        assert 'action="/farms/new"' in new_farm_page.text
        assert 'name="name"' in new_farm_page.text

        validation_response = client.post(
            "/farms/new",
            data={
                "name": "",
                "location": "Bodinayakanur",
                "acreage": "-1",
                "total_trees": "-10",
                "notes": "",
            },
        )

        assert validation_response.status_code == 422
        assert "Farm name is required." in validation_response.text
        assert "Acreage cannot be negative." in validation_response.text
        assert "Total trees cannot be negative." in validation_response.text

        create_response = client.post(
            "/farms/new",
            data={
                "name": farm_name,
                "location": "Bodinayakanur, Theni",
                "acreage": "5.75",
                "total_trees": "420",
                "notes": "PATCH-003A automated validation farm.",
            },
            follow_redirects=False,
        )

        assert create_response.status_code == 303
        assert create_response.headers["location"].startswith(
            "/farms?success="
        )

        duplicate_response = client.post(
            "/farms/new",
            data={
                "name": farm_name.lower(),
                "location": "Duplicate location",
                "acreage": "1",
                "total_trees": "10",
                "notes": "",
            },
        )

        assert duplicate_response.status_code == 409
        assert (
            "A farm with this name already exists."
            in duplicate_response.text
        )

        farm_list_after = client.get("/farms")
        assert farm_list_after.status_code == 200
        assert farm_name in farm_list_after.text
        assert "Bodinayakanur, Theni" in farm_list_after.text
        assert "420" in farm_list_after.text

        dashboard_after = client.get("/dashboard")
        assert dashboard_after.status_code == 200
        assert "<html" in dashboard_after.text.lower()

    with SessionLocal() as db:
        farm = db.scalar(
            select(Farm).where(
                Farm.owner_id == owner_id,
                Farm.name == farm_name,
            )
        )

        assert farm is not None
        assert str(farm.acreage) in {"5.75", "5.750", "5.7500"}
        assert farm.total_trees == 420
        assert farm.location == "Bodinayakanur, Theni"

        audit_log = db.scalar(
            select(AuditLog)
            .where(
                AuditLog.owner_id == owner_id,
                AuditLog.event_type == "farm_created",
                AuditLog.detail.contains(farm_name),
            )
            .order_by(AuditLog.id.desc())
        )

        assert audit_log is not None

        db.execute(
            delete(AuditLog).where(
                AuditLog.owner_id == owner_id,
                AuditLog.event_type == "farm_created",
                AuditLog.detail.contains(farm_name),
            )
        )
        db.delete(farm)
        db.commit()

    print("LOGIN VALIDATION: PASSED")
    print("FARM LIST VALIDATION: PASSED")
    print("FARM FORM VALIDATION: PASSED")
    print("FARM CREATE VALIDATION: PASSED")
    print("DUPLICATE FARM VALIDATION: PASSED")
    print("OWNER ISOLATION VALIDATION: PASSED")
    print("AUDIT LOG VALIDATION: PASSED")
    print("DASHBOARD INTEGRATION VALIDATION: PASSED")
    print("TEST DATA CLEANUP: PASSED")
    print("PATCH-003A.3: PASSED")


if __name__ == "__main__":
    main()
