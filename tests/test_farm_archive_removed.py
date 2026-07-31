from pathlib import Path

from sqlalchemy import inspect

from app.database import engine
from app.models import Farm


def test_farm_model_has_no_archive_fields():
    columns = set(Farm.__table__.columns.keys())

    assert "is_active" not in columns
    assert "archived_at" not in columns
    assert "archive_reason" not in columns


def test_farms_table_has_no_archive_columns():
    columns = {
        column["name"]
        for column in inspect(engine).get_columns("farms")
    }

    assert "is_active" not in columns
    assert "archived_at" not in columns
    assert "archive_reason" not in columns


def test_existing_delete_workflow_remains_available():
    source = Path("app/main.py").read_text(
        encoding="utf-8"
    )

    assert '"/farms/{farm_id}/delete"' in source
    assert '"farm_deleted"' in source
