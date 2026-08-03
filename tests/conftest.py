"""Shared safety gate and PostgreSQL fixtures for Messis tests."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Generator

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.test_database_safety import (  # noqa: E402
    UnsafeTestDatabaseError,
    load_safe_test_database,
)


def pytest_sessionstart(session):
    """Stop before test collection can initialize a production DB connection."""
    del session

    try:
        safe_db = load_safe_test_database()
    except UnsafeTestDatabaseError as exc:
        raise pytest.UsageError(f"Messis test safety check failed: {exc}") from exc

    os.environ["DATABASE_URL"] = safe_db.url
    os.environ["MESSIS_DATABASE_URL"] = safe_db.url


@pytest.fixture(scope="session")
def safe_test_database():
    return load_safe_test_database()


@pytest.fixture(scope="session")
def test_engine(safe_test_database):
    from sqlalchemy import create_engine

    engine = create_engine(
        safe_test_database.url,
        pool_pre_ping=True,
        future=True,
    )

    try:
        with engine.connect() as connection:
            connection.exec_driver_sql("SELECT 1")
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def db_connection(test_engine):
    connection = test_engine.connect()
    transaction = connection.begin()

    try:
        yield connection
    finally:
        if transaction.is_active:
            transaction.rollback()
        connection.close()


@pytest.fixture
def db_session(db_connection):
    from sqlalchemy.orm import Session

    session = Session(
        bind=db_connection,
        join_transaction_mode="create_savepoint",
        expire_on_commit=False,
    )

    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def app_instance():
    try:
        from app.main import app
    except ImportError as exc:
        pytest.skip(f"Messis FastAPI application import unavailable: {exc}")

    return app


@pytest.fixture
def client(app_instance):
    from fastapi.testclient import TestClient

    with TestClient(app_instance) as test_client:
        yield test_client
