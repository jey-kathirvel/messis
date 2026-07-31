"""Safety controls for the Messis AI isolated test environment."""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit


class UnsafeTestDatabaseError(RuntimeError):
    """Raised before any unsafe test database connection is attempted."""


BLOCKED_DATABASES = {
    "messis_db",
    "postgres",
    "template0",
    "template1",
}

TEST_NAME_MARKERS = ("test", "testing", "pytest", "uat")


@dataclass(frozen=True)
class SafeTestDatabase:
    url: str
    scheme: str
    hostname: str
    port: int | None
    database: str

    @property
    def redacted_description(self) -> str:
        port = f":{self.port}" if self.port else ""
        return f"{self.scheme}://***@{self.hostname}{port}/{self.database}"


def _safe_error(message: str) -> UnsafeTestDatabaseError:
    return UnsafeTestDatabaseError(message)


def validate_test_database_url(
    database_url: str | None,
    environment: str | None,
) -> SafeTestDatabase:
    if environment != "test":
        raise _safe_error("MESSIS_ENV must be explicitly set to 'test'.")

    if not database_url or not database_url.strip():
        raise _safe_error("TEST_DATABASE_URL is required; production fallback is forbidden.")

    raw_url = database_url.strip()

    try:
        parsed = urlsplit(raw_url)
    except ValueError as exc:
        raise _safe_error("TEST_DATABASE_URL is not a valid database URL.") from exc

    scheme = parsed.scheme.lower()

    if scheme.startswith("sqlite"):
        raise _safe_error(
            "SQLite is forbidden for PostgreSQL integration regression tests."
        )

    if not (
        scheme.startswith("postgresql")
        or scheme.startswith("postgres")
    ):
        raise _safe_error("Only PostgreSQL is allowed for Messis integration tests.")

    database = unquote(parsed.path.lstrip("/")).strip().lower()

    if not database:
        raise _safe_error("The test database name cannot be determined.")

    if database in BLOCKED_DATABASES:
        raise _safe_error(f"Database '{database}' is protected and cannot be used by tests.")

    if not any(marker in database for marker in TEST_NAME_MARKERS):
        raise _safe_error(
            "The selected database name is ambiguous and does not identify itself as test-only."
        )

    hostname = (parsed.hostname or "").strip().lower()

    if not hostname:
        raise _safe_error("The test database hostname cannot be determined.")

    return SafeTestDatabase(
        url=raw_url,
        scheme=scheme,
        hostname=hostname,
        port=parsed.port,
        database=database,
    )


def load_safe_test_database() -> SafeTestDatabase:
    # Deliberately do not read DATABASE_URL. There is no production fallback.
    return validate_test_database_url(
        os.getenv("TEST_DATABASE_URL"),
        os.getenv("MESSIS_ENV"),
    )
