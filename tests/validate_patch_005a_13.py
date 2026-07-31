import ast
from pathlib import Path

from app.main import (
    COCONUT_TREE_QR_BOX_SIZES,
    app,
    coconut_tree_qr_target_url,
    generate_coconut_tree_qr_png,
    templates,
)


ROUTE_PATH = (
    "/farms/{farm_id}/trees/{tree_id}/qr.png"
)

LABEL_TEMPLATE = Path(
    "app/templates/trees/labels.html"
)

DETAIL_TEMPLATE = Path(
    "app/templates/trees/detail.html"
)


class DummyBaseURL:
    def __str__(self) -> str:
        return "https://messis.example.com/"


class DummyRequest:
    base_url = DummyBaseURL()


def validate_source() -> None:
    source = Path("app/main.py").read_text()

    ast.parse(source)

    assert (
        "# PATCH-005A.13: COCONUT TREE QR CODE GENERATION"
        in source
    )

    required_source = {
        "COCONUT_TREE_QR_BOX_SIZES",
        "def coconut_tree_qr_target_url(",
        "def generate_coconut_tree_qr_png(",
        "def coconut_tree_qr_png(",
        '"coconut_tree.qr_generated"',
        '"image/png"',
        '"X-Content-Type-Options": "nosniff"',
    }

    missing = {
        item
        for item in required_source
        if item not in source
    }

    assert not missing, (
        f"Missing source content: {sorted(missing)}"
    )


def validate_route() -> None:
    routes = [
        route
        for route in app.routes
        if getattr(
            route,
            "path",
            None,
        ) == ROUTE_PATH
        and "GET" in getattr(
            route,
            "methods",
            set(),
        )
    ]

    assert len(routes) == 1
    assert routes[0].name == "coconut_tree_qr_png"


def validate_box_sizes() -> None:
    assert COCONUT_TREE_QR_BOX_SIZES == {
        4,
        6,
        8,
        10,
        12,
    }


def validate_target_url() -> None:
    result = coconut_tree_qr_target_url(
        DummyRequest(),
        15,
        125,
    )

    assert result == (
        "https://messis.example.com"
        "/farms/15/trees/125"
    )


def validate_png_generation() -> None:
    content = generate_coconut_tree_qr_png(
        "https://messis.example.com/farms/1/trees/2",
        box_size=6,
    )

    assert isinstance(content, bytes)
    assert len(content) > 100
    assert content.startswith(
        b"\x89PNG\r\n\x1a\n"
    )

    fallback_content = (
        generate_coconut_tree_qr_png(
            "TREE-001",
            box_size=999,
        )
    )

    assert fallback_content.startswith(
        b"\x89PNG\r\n\x1a\n"
    )

    try:
        generate_coconut_tree_qr_png("")
    except ValueError:
        pass
    else:
        raise AssertionError(
            "Empty QR values must be rejected."
        )


def validate_templates() -> None:
    assert LABEL_TEMPLATE.is_file()
    assert DETAIL_TEMPLATE.is_file()

    label_content = LABEL_TEMPLATE.read_text()
    detail_content = DETAIL_TEMPLATE.read_text()

    required_label_content = {
        "/qr.png?box_size=6",
        "QR code for {{ tree.tree_code }}",
        "Download QR",
        "download=true&box_size=10",
    }

    missing_label = {
        item
        for item in required_label_content
        if item not in label_content
    }

    assert not missing_label, (
        f"Missing label content: {sorted(missing_label)}"
    )

    assert "qr-pattern" not in label_content

    required_detail_content = {
        "Tree Identification",
        "QR Code",
        "Download QR Code",
        "/qr.png?box_size=8",
        "download=true&box_size=12",
    }

    missing_detail = {
        item
        for item in required_detail_content
        if item not in detail_content
    }

    assert not missing_detail, (
        f"Missing detail content: {sorted(missing_detail)}"
    )

    assert templates.get_template(
        "trees/labels.html"
    )

    assert templates.get_template(
        "trees/detail.html"
    )


def main() -> None:
    validate_source()
    validate_route()
    validate_box_sizes()
    validate_target_url()
    validate_png_generation()
    validate_templates()

    print("PATCH-005A.13 SOURCE: PASSED")
    print("PATCH-005A.13 ROUTE: PASSED")
    print("PATCH-005A.13 BOX SIZES: PASSED")
    print("PATCH-005A.13 TARGET URL: PASSED")
    print("PATCH-005A.13 PNG GENERATION: PASSED")
    print("PATCH-005A.13 TEMPLATES: PASSED")
    print("PATCH-005A.13 QR CODE GENERATION: PASSED")
    print("PATCH-005A.13: PASSED")


if __name__ == "__main__":
    main()
