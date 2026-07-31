from __future__ import annotations

import pytest

from scripts.test_database_safety import (
    UnsafeTestDatabaseError,
    validate_test_database_url,
)


SAFE_URL = (
    "postgresql+psycopg://messis_test_user:"
    "super-secret-password@127.0.0.1:5432/messis_test_db"
)


@pytest.mark.parametrize("environment", [None, "", "production", "development"])
def test_requires_explicit_test_environment(environment):
    with pytest.raises(UnsafeTestDatabaseError):
        validate_test_database_url(SAFE_URL, environment)


def test_requires_test_database_url():
    with pytest.raises(UnsafeTestDatabaseError):
        validate_test_database_url(None, "test")


@pytest.mark.parametrize(
    "database",
    ["messis_db", "postgres", "template0", "template1"],
)
def test_rejects_protected_database_names(database):
    url = f"postgresql+psycopg://user:password@127.0.0.1:5432/{database}"
    with pytest.raises(UnsafeTestDatabaseError):
        validate_test_database_url(url, "test")


def test_rejects_sqlite():
    with pytest.raises(UnsafeTestDatabaseError):
        validate_test_database_url("sqlite:///messis_test.db", "test")


def test_rejects_ambiguous_database_name():
    with pytest.raises(UnsafeTestDatabaseError):
        validate_test_database_url(
            "postgresql+psycopg://user:password@127.0.0.1:5432/messis",
            "test",
        )


def test_accepts_clearly_named_postgresql_test_database():
    result = validate_test_database_url(SAFE_URL, "test")
    assert result.database == "messis_test_db"
    assert result.hostname == "127.0.0.1"


def test_error_does_not_disclose_password():
    password = "DO_NOT_DISCLOSE_THIS_PASSWORD"
    unsafe_url = (
        f"postgresql+psycopg://user:{password}"
        "@127.0.0.1:5432/messis_db"
    )

    with pytest.raises(UnsafeTestDatabaseError) as exc_info:
        validate_test_database_url(unsafe_url, "test")

    assert password not in str(exc_info.value)


def test_production_database_url_is_not_a_fallback(monkeypatch):
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+psycopg://prod:secret@127.0.0.1:5432/messis_db",
    )
    monkeypatch.delenv("TEST_DATABASE_URL", raising=False)
    monkeypatch.setenv("MESSIS_ENV", "test")

    from scripts.test_database_safety import load_safe_test_database

    with pytest.raises(UnsafeTestDatabaseError):
        load_safe_test_database()
