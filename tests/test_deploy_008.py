from __future__ import annotations

import ast
from pathlib import Path

from app.version import APP_VERSION, RELEASE_NAME


MAIN_PATH = Path("app/main.py")


def test_authoritative_application_version():
    assert APP_VERSION == "0.5.1"


def test_authoritative_release_name():
    assert RELEASE_NAME == "v0.5.1-uat-hardened"


def test_version_module_imported_by_application():
    source = MAIN_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)

    imports = [
        node
        for node in tree.body
        if isinstance(node, ast.ImportFrom)
        and node.module == "app.version"
    ]

    assert imports

    imported_names = {
        alias.name
        for node in imports
        for alias in node.names
    }

    assert "APP_VERSION" in imported_names
    assert "RELEASE_NAME" in imported_names


def test_fastapi_uses_authoritative_version():
    source = MAIN_PATH.read_text(encoding="utf-8")

    assert "version=APP_VERSION" in source
    assert 'version="0.3.1"' not in source


def test_health_uses_authoritative_version():
    source = MAIN_PATH.read_text(encoding="utf-8")

    assert '"version": APP_VERSION' in source
    assert '"release": RELEASE_NAME' in source
    assert '"version": "0.3.1"' not in source
