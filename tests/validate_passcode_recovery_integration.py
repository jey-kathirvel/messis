import os
import tempfile
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


database_file = Path(tempfile.gettempdir()) / "messis-passcode-recovery-test.db"
database_file.unlink(missing_ok=True)
os.environ["DATABASE_URL"] = f"sqlite:///{database_file.as_posix()}"
os.environ["SECRET_KEY"] = "passcode-recovery-integration-secret"
os.environ["APP_ENV"] = "development"
os.environ["PUBLIC_BASE_URL"] = "https://messis.example.test"
os.environ["SMTP_HOST"] = "smtp.example.test"
os.environ["SMTP_FROM_EMAIL"] = "no-reply@example.test"

from fastapi.testclient import TestClient
from sqlalchemy import select

import app.main as main_module
from app.database import SessionLocal
from app.main import app
from app.models import Farm, PasscodeResetToken, User
from app.security import hash_passcode, verify_passcode


def main() -> None:
    sent_messages: list[tuple[str, str]] = []
    main_module.send_passcode_reset_email = (
        lambda settings, recipient, reset_url: sent_messages.append((recipient, reset_url))
    )

    signup = {
        "username": "recovery-owner",
        "mobile_number": "9876543210",
        "email": "owner@example.test",
        "passcode": "246810",
        "confirm_passcode": "246810",
        "registration_code": "",
    }

    with TestClient(app, base_url="https://messis.example.test") as client:
        with SessionLocal() as db:
            legacy_user = User(
                user_id="legacy-owner",
                mobile_number="9876543220",
                display_name="Legacy Owner",
                passcode_hash=hash_passcode("112233"),
                role="owner",
                is_active=True,
            )
            db.add(legacy_user)
            db.flush()
            legacy_user_id = legacy_user.id
            db.add(Farm(owner_id=legacy_user.id, name="Legacy Preserved Farm", total_trees=77))
            db.commit()

        legacy_login = client.post(
            "/auth/login",
            data={"user_id": "legacy-owner", "passcode": "112233"},
            follow_redirects=False,
        )
        assert legacy_login.status_code == 303
        assert legacy_login.headers["location"].startswith("/account/recovery-email?next=")
        recovery_page = client.get(legacy_login.headers["location"])
        assert recovery_page.status_code == 200
        assert "Save and continue" in recovery_page.text
        saved_email = client.post(
            "/account/recovery-email",
            data={"email": "legacy@example.test", "next_path": "/dashboard"},
            follow_redirects=False,
        )
        assert saved_email.status_code == 303
        assert saved_email.headers["location"] == "/dashboard"
        with SessionLocal() as db:
            legacy_user = db.get(User, legacy_user_id)
            legacy_farm = db.scalar(select(Farm).where(Farm.owner_id == legacy_user_id))
            assert legacy_user.email == "legacy@example.test"
            assert legacy_farm.name == "Legacy Preserved Farm" and legacy_farm.total_trees == 77
            assert verify_passcode(legacy_user.passcode_hash, "112233")

        client.post("/auth/logout")
        created = client.post("/auth/set-passcode", data=signup, follow_redirects=False)
        assert created.status_code == 303

        duplicate = client.post(
            "/auth/set-passcode",
            data={**signup, "username": "another-owner", "mobile_number": "9876543211"},
        )
        assert duplicate.status_code == 400
        assert "email is already registered" in duplicate.text

        with SessionLocal() as db:
            user = db.scalar(select(User).where(User.user_id == signup["username"]))
            original_user_id = user.id
            db.add(Farm(owner_id=user.id, name="Preserved Farm", total_trees=42))
            db.commit()

        requested = client.post("/auth/forgot-passcode", data={"email": "OWNER@example.test"})
        assert requested.status_code == 200
        assert "If that email belongs" in requested.text
        assert len(sent_messages) == 1
        recipient, reset_url = sent_messages[0]
        assert recipient == "owner@example.test"
        token = parse_qs(urlsplit(reset_url).query)["token"][0]

        reset = client.post(
            "/auth/reset-passcode",
            data={
                "token": token,
                "new_passcode": "135790",
                "confirm_passcode": "135790",
            },
            follow_redirects=False,
        )
        assert reset.status_code == 303

        reused = client.get(f"/auth/reset-passcode?token={token}")
        assert reused.status_code == 400

    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.user_id == signup["username"]))
        farm = db.scalar(select(Farm).where(Farm.owner_id == user.id))
        token_record = db.scalar(select(PasscodeResetToken).where(PasscodeResetToken.user_id == user.id))
        assert user.id == original_user_id
        assert farm is not None and farm.name == "Preserved Farm" and farm.total_trees == 42
        assert not verify_passcode(user.passcode_hash, "246810")
        assert verify_passcode(user.passcode_hash, "135790")
        assert token_record.used_at is not None

    database_file.unlink(missing_ok=True)
    print("PASSCODE RECOVERY INTEGRATION: PASSED")


if __name__ == "__main__":
    main()
