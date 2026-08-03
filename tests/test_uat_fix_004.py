from __future__ import annotations

import ast
from pathlib import Path


MAIN_PATH = Path("app/main.py")


def duplicate_function() -> tuple[str, ast.FunctionDef]:
    source = MAIN_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)

    for node in tree.body:
        if (
            isinstance(node, ast.FunctionDef)
            and node.name == "duplicate_farm"
        ):
            return source, node

    raise AssertionError("duplicate_farm was not found")


def function_source() -> str:
    source, function = duplicate_function()
    extracted = ast.get_source_segment(source, function)

    assert extracted is not None
    return extracted


def test_duplicate_farm_accepts_request():
    _, function = duplicate_function()
    arguments = [item.arg for item in function.args.args]

    assert "request" in arguments


def test_duplicate_farm_has_direct_audit_event():
    source = function_source()

    assert "audit(" in source
    assert '"farm_duplicated"' in source


def test_duplicate_audit_contains_source_and_destination():
    source = function_source()

    assert "source_farm.id" in source
    assert "source_farm.name" in source
    assert "duplicated_farm.id" in source
    assert "duplicated_farm.name" in source


def test_duplicate_flushes_before_audit():
    source = function_source()

    assert source.index("db.flush()") < source.index(
        '"farm_duplicated"'
    )


def test_duplicate_audit_occurs_before_commit():
    source = function_source()

    assert source.index('"farm_duplicated"') < source.index(
        "db.commit()"
    )


def test_duplicate_rolls_back_on_database_error():
    source = function_source()

    assert "except SQLAlchemyError:" in source
    assert "db.rollback()" in source


def test_duplicate_uses_single_commit_boundary():
    source = function_source()

    assert source.count("db.commit()") == 1
