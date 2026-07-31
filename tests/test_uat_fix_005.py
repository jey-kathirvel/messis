from __future__ import annotations

import ast
from pathlib import Path


MAIN_PATH = Path("app/main.py")
FAVICON_PATH = Path("app/static/favicon.svg")
ERROR_404_PATH = Path("app/templates/errors/404.html")
ERROR_500_PATH = Path("app/templates/errors/500.html")


def _main_source() -> str:
    return MAIN_PATH.read_text(encoding="utf-8")


def _function(name: str) -> ast.FunctionDef:
    tree = ast.parse(_main_source())

    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node

    raise AssertionError(f"{name} was not found")


def test_favicon_asset_exists():
    assert FAVICON_PATH.is_file()
    assert "<svg" in FAVICON_PATH.read_text(encoding="utf-8")


def test_favicon_route_exists():
    source = _main_source()
    function = _function("favicon")
    function_source = ast.get_source_segment(source, function)

    assert function_source is not None
    assert "FileResponse" in function_source
    assert "favicon.svg" in function_source
    assert "image/svg+xml" in function_source


def test_root_head_route_exists():
    source = _main_source()
    function = _function("login_head")
    function_source = ast.get_source_segment(source, function)

    assert function_source is not None
    assert "status_code=200" in function_source


def test_custom_error_templates_exist():
    assert ERROR_404_PATH.is_file()
    assert ERROR_500_PATH.is_file()


def test_404_handler_uses_custom_template():
    source = _main_source()
    function = _function("not_found_error")
    function_source = ast.get_source_segment(source, function)

    assert function_source is not None
    assert 'name="errors/404.html"' in function_source
    assert "status_code=404" in function_source


def test_500_handler_uses_custom_template():
    source = _main_source()
    function = _function("internal_server_error")
    function_source = ast.get_source_segment(source, function)

    assert function_source is not None
    assert 'name="errors/500.html"' in function_source
    assert "status_code=500" in function_source


def test_favicon_head_route_exists():
    source = _main_source()
    function = _function("favicon_head")
    function_source = ast.get_source_segment(source, function)

    assert function_source is not None
    assert "status_code=200" in function_source
    assert 'media_type="image/svg+xml"' in function_source
