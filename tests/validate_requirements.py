from pathlib import Path


def main() -> None:
    requirements = Path("requirements.txt").read_text(encoding="utf-8").lower()
    required = {
        "sqlalchemy==2.0.43",
        "psycopg[binary]==3.2.9",
        "pydantic==2.13.4",
        "pydantic-settings==2.10.1",
        "argon2-cffi==25.1.0",
        "python-multipart==0.0.20",
        "qrcode==8.2",
        "pillow==12.3.0",
        "itsdangerous==2.2.0",
        "python-dotenv==1.1.1",
    }
    missing = {item for item in required if item not in requirements}
    assert not missing, sorted(missing)
    assert "alembic" not in requirements
    print("PATCH-UAT-FIX-002 REQUIREMENT SOURCE: PASSED")


if __name__ == "__main__":
    main()
