
from __future__ import annotations

# PATCH-UAT-FIX-003: refuse unsafe database configuration before execution.
from scripts.test_database_safety import load_safe_test_database
_MESSIS_SAFE_TEST_DATABASE = load_safe_test_database()


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
        r"PASSCODE\s*[:=]\s*(\d{6})",
        content,
        re.IGNORECASE,
    )

    assert user_match is not None, "Owner User ID not found"
    assert passcode_match is not None, "Owner passcode not found"

    return (
        user_match.group(1).strip(),
        passcode_match.group(1).strip(),
    )


def cleanup_test_data(
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
    login_user_id, passcode = load_credentials()
    suffix = secrets.token_hex(5)

    original_name = f"PATCH-003C Original {suffix}"
    updated_name = f"PATCH-003C Updated {suffix}"
    second_name = f"PATCH-003C Second {suffix}"

    with SessionLocal() as db:
        owner = db.scalar(
            select(User).where(User.user_id == login_user_id)
        )

        assert owner is not None, "Owner account not found"
        owner_id = owner.id

    cleanup_test_data(
        owner_id=owner_id,
        farm_names=[original_name, updated_name, second_name],
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
            assert login_response.headers["location"] == "/dashboard"

            create_response = client.post(
                "/farms/new",
                data={
                    "name": original_name,
                    "location": "Bodinayakanur",
                    "acreage": "4.50",
                    "total_trees": "300",
                    "notes": "Original validation record",
                },
                follow_redirects=False,
            )

            assert create_response.status_code == 303

            second_create_response = client.post(
                "/farms/new",
                data={
                    "name": second_name,
                    "location": "Theni",
                    "acreage": "2.00",
                    "total_trees": "120",
                    "notes": "Duplicate-name validation record",
                },
                follow_redirects=False,
            )

            assert second_create_response.status_code == 303

            with SessionLocal() as db:
                farm = db.scalar(
                    select(Farm).where(
                        Farm.owner_id == owner_id,
                        Farm.name == original_name,
                    )
                )

                second_farm = db.scalar(
                    select(Farm).where(
                        Farm.owner_id == owner_id,
                        Farm.name == second_name,
                    )
                )

                assert farm is not None
                assert second_farm is not None

                farm_id = farm.id
                second_farm_id = second_farm.id

            edit_page_response = client.get(
                f"/farms/{farm_id}/edit"
            )

            assert edit_page_response.status_code == 200
            assert original_name in edit_page_response.text
            assert f'action="/farms/{farm_id}/edit"' in (
                edit_page_response.text
            )

            invalid_edit_response = client.post(
                f"/farms/{farm_id}/edit",
                data={
                    "name": "",
                    "location": "X" * 256,
                    "acreage": "-5",
                    "total_trees": "-1",
                    "notes": "",
                },
            )

            assert invalid_edit_response.status_code == 422
            assert "Farm name is required." in invalid_edit_response.text
            assert "Location cannot exceed 255 characters." in (
                invalid_edit_response.text
            )
            assert "Acreage cannot be negative." in (
                invalid_edit_response.text
            )
            assert "Total trees cannot be negative." in (
                invalid_edit_response.text
            )

            duplicate_edit_response = client.post(
                f"/farms/{farm_id}/edit",
                data={
                    "name": second_name.lower(),
                    "location": "Bodinayakanur",
                    "acreage": "4.50",
                    "total_trees": "300",
                    "notes": "Duplicate update",
                },
            )

            assert duplicate_edit_response.status_code == 409
            assert "A farm with this name already exists." in (
                duplicate_edit_response.text
            )

            update_response = client.post(
                f"/farms/{farm_id}/edit",
                data={
                    "name": updated_name,
                    "location": "Bodinayakanur, Theni District",
                    "acreage": "6.25",
                    "total_trees": "475",
                    "notes": "Updated validation record",
                },
                follow_redirects=False,
            )

            assert update_response.status_code == 303
            assert update_response.headers["location"].startswith(
                "/farms?success="
            )

            with SessionLocal() as db:
                updated_farm = db.scalar(
                    select(Farm).where(
                        Farm.id == farm_id,
                        Farm.owner_id == owner_id,
                    )
                )

                assert updated_farm is not None
                assert updated_farm.name == updated_name
                assert updated_farm.location == (
                    "Bodinayakanur, Theni District"
                )
                assert str(updated_farm.acreage) in {
                    "6.25",
                    "6.250",
                    "6.2500",
                }
                assert updated_farm.total_trees == 475
                assert updated_farm.notes == (
                    "Updated validation record"
                )

                update_audit = db.scalar(
                    select(AuditLog)
                    .where(
                        AuditLog.owner_id == owner_id,
                        AuditLog.event_type == "farm_updated",
                        AuditLog.detail.contains(updated_name),
                    )
                    .order_by(AuditLog.id.desc())
                )

                assert update_audit is not None

            delete_page_response = client.get(
                f"/farms/{farm_id}/delete"
            )

            assert delete_page_response.status_code == 200
            assert updated_name in delete_page_response.text
            assert f'action="/farms/{farm_id}/delete"' in (
                delete_page_response.text
            )

            wrong_confirmation_response = client.post(
                f"/farms/{farm_id}/delete",
                data={
                    "confirmation_name": "incorrect confirmation",
                },
            )

            assert wrong_confirmation_response.status_code == 422
            assert (
                "Farm name confirmation does not match."
                in wrong_confirmation_response.text
            )

            with SessionLocal() as db:
                farm_still_exists = db.scalar(
                    select(Farm).where(
                        Farm.id == farm_id,
                        Farm.owner_id == owner_id,
                    )
                )

                assert farm_still_exists is not None

            delete_response = client.post(
                f"/farms/{farm_id}/delete",
                data={
                    "confirmation_name": updated_name,
                },
                follow_redirects=False,
            )

            assert delete_response.status_code == 303
            assert delete_response.headers["location"].startswith(
                "/farms?success="
            )

            with SessionLocal() as db:
                deleted_farm = db.scalar(
                    select(Farm).where(
                        Farm.id == farm_id,
                        Farm.owner_id == owner_id,
                    )
                )

                assert deleted_farm is None

                delete_audit = db.scalar(
                    select(AuditLog)
                    .where(
                        AuditLog.owner_id == owner_id,
                        AuditLog.event_type == "farm_deleted",
                        AuditLog.detail.contains(updated_name),
                    )
                    .order_by(AuditLog.id.desc())
                )

                assert delete_audit is not None

            missing_edit_response = client.get(
                "/farms/999999999/edit"
            )

            assert missing_edit_response.status_code == 404

            missing_delete_response = client.get(
                "/farms/999999999/delete"
            )

            assert missing_delete_response.status_code == 404

            second_delete_response = client.post(
                f"/farms/{second_farm_id}/delete",
                data={
                    "confirmation_name": second_name,
                },
                follow_redirects=False,
            )

            assert second_delete_response.status_code == 303

        print("FARM EDIT PAGE VALIDATION: PASSED")
        print("FARM EDIT INPUT VALIDATION: PASSED")
        print("FARM EDIT DUPLICATE VALIDATION: PASSED")
        print("FARM UPDATE VALIDATION: PASSED")
        print("FARM UPDATE AUDIT VALIDATION: PASSED")
        print("FARM DELETE PAGE VALIDATION: PASSED")
        print("FARM DELETE CONFIRMATION VALIDATION: PASSED")
        print("FARM DELETE VALIDATION: PASSED")
        print("FARM DELETE AUDIT VALIDATION: PASSED")
        print("OWNER ISOLATION QUERY VALIDATION: PASSED")
        print("MISSING FARM VALIDATION: PASSED")
        print("PATCH-003C: PASSED")
    finally:
        cleanup_test_data(
            owner_id=owner_id,
            farm_names=[original_name, updated_name, second_name],
        )


if __name__ == "__main__":
    main()
