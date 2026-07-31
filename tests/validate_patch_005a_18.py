import ast
from datetime import date
from pathlib import Path

from app.main import (
    app,
    coconut_tree_report_summary,
    templates,
)


ROUTE_PATH = (
    "/farms/{farm_id}/trees/{tree_id}/health-report"
)

REPORT_TEMPLATE = Path(
    "app/templates/trees/health_report.html"
)

DETAIL_TEMPLATE = Path(
    "app/templates/trees/detail.html"
)


class Tree:
    tree_code = "CT-001"
    variety = "Tall"
    health_status = "Healthy"
    is_active = True
    planting_date = date(
        2020,
        1,
        1,
    )
    block_name = "Block A"
    row_number = "R1"
    position_number = "P1"


def validate_source() -> None:
    source = Path(
        "app/main.py"
    ).read_text()

    ast.parse(source)

    assert (
        "# PATCH-005A.18: PRINTABLE TREE HEALTH REPORT"
        in source
    )

    required = {
        "def coconut_tree_report_summary(",
        "def coconut_tree_health_report_page(",
        '"coconut_tree.health_report_viewed"',
        'name="trees/health_report.html"',
        '"coconut_tree_report_summary"',
    }

    missing = {
        item
        for item in required
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

    assert (
        routes[0].name
        == "coconut_tree_health_report_page"
    )


def validate_summary() -> None:
    summary = coconut_tree_report_summary(
        Tree()
    )

    assert summary["tree_code"] == "CT-001"
    assert summary["variety"] == "Tall"
    assert summary["health_status"] == "Healthy"
    assert summary["is_active"] is True
    assert summary["location"] == (
        "Block A · R1 · P1"
    )
    assert summary["health_score"] == 90
    assert summary["health_label"] == "Excellent"
    assert summary["recommendation_count"] == 3
    assert len(summary["recommendations"]) == 3
    assert summary["maturity_status"] in {
        "Early Bearing",
        "Mature",
    }


def validate_template_globals() -> None:
    assert (
        "coconut_tree_report_summary"
        in templates.env.globals
    )


def validate_templates() -> None:
    assert REPORT_TEMPLATE.is_file()
    assert DETAIL_TEMPLATE.is_file()

    report_content = (
        REPORT_TEMPLATE.read_text()
    )

    detail_content = (
        DETAIL_TEMPLATE.read_text()
    )

    required_report = {
        "Coconut Tree Health Report",
        "Print Health Report",
        "window.print()",
        "report.health_score",
        "report.health_label",
        "report.recommendations",
        "report.maturity_status",
        "coconut_tree_priority_style(",
        "/qr.png?box_size=8",
        "@media print",
        "@page",
        "do not replace professional",
    }

    missing_report = {
        item
        for item in required_report
        if item not in report_content
    }

    assert not missing_report, (
        f"Missing report content: "
        f"{sorted(missing_report)}"
    )

    assert "Print Health Report" in detail_content
    assert "/health-report" in detail_content

    templates.get_template(
        "trees/health_report.html"
    )

    templates.get_template(
        "trees/detail.html"
    )


def main() -> None:
    validate_source()
    validate_route()
    validate_summary()
    validate_template_globals()
    validate_templates()

    print(
        "PATCH-005A.18 SOURCE: PASSED"
    )
    print(
        "PATCH-005A.18 ROUTE: PASSED"
    )
    print(
        "PATCH-005A.18 REPORT SUMMARY: PASSED"
    )
    print(
        "PATCH-005A.18 TEMPLATE GLOBALS: PASSED"
    )
    print(
        "PATCH-005A.18 TEMPLATES: PASSED"
    )
    print(
        "PATCH-005A.18 PRINTABLE HEALTH REPORT: PASSED"
    )
    print(
        "PATCH-005A.18: PASSED"
    )


if __name__ == "__main__":
    main()
