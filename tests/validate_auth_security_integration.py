import secrets

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.database import Base, SessionLocal, engine
from app.main import app, settings
from app.models import AuditLog, User
from app.security import verify_passcode


def main() -> None:
    assert settings.app_env == "production"
    assert settings.signup_access_code
    Base.metadata.create_all(bind=engine)

    suffix = secrets.token_hex(4)
    origin = "https://testserver"
    valid_data = {
        "username": f"uat-{suffix}",
        "mobile_number": f"98765{int(suffix, 16) % 100000:05d}",
        "passcode": "246810",
        "confirm_passcode": "246810",
        "registration_code": settings.signup_access_code,
    }

    with TestClient(app, base_url=origin) as client:
        assert client.get("/auth/set-passcode").status_code == 200

        blocked = client.post("/auth/set-passcode", data=valid_data)
        assert blocked.status_code == 403

        invalid_code_data = {**valid_data, "registration_code": "invalid"}
        rejected = client.post(
            "/auth/set-passcode",
            data=invalid_code_data,
            headers={"Origin": origin, "X-Forwarded-For": "192.0.2.10"},
        )
        assert rejected.status_code == 400
        assert "Invalid registration code" in rejected.text

        created = client.post(
            "/auth/set-passcode",
            data=valid_data,
            headers={"Origin": origin, "X-Forwarded-For": "192.0.2.11"},
            follow_redirects=False,
        )
        assert created.status_code == 303
        assert created.headers["location"].startswith("/?success=")

    with SessionLocal() as session:
        user = session.scalar(select(User).where(User.user_id == valid_data["username"]))
        assert user is not None
        assert verify_passcode(user.passcode_hash, valid_data["passcode"])
        rejected_count = session.scalar(
            select(func.count(AuditLog.id)).where(
                AuditLog.event_type == "account_registration_rejected"
            )
        )
        assert rejected_count == 1

    print("PATCH-UAT-FIX-001 AUTH SECURITY INTEGRATION: PASSED")


if __name__ == "__main__":
    main()
