import ast
from pathlib import Path

from app.main import (
    coconut_tree_care_recommendations,
    coconut_tree_priority_style,
    templates,
)


class ExcellentTree:
    health_status = "Excellent"


class HealthyTree:
    health_status = "Healthy"


class FairTree:
    health_status = "Fair"


class PoorTree:
    health_status = "Poor"


class CriticalTree:
    health_status = "Critical"


def validate_source() -> None:
    source = Path(
        "app/main.py"
    ).read_text()

    ast.parse(source)

    assert (
        "# PATCH-005A.17: TREE CARE RECOMMENDATIONS"
        in source
    )

    required = {
        "def coconut_tree_care_recommendations(",
        "def coconut_tree_priority_style(",
        '"coconut_tree_care_recommendations"',
        '"coconut_tree_priority_style"',
        '"recommendations": recommendations',
        '"count": len(recommendations)',
    }

    missing = {
        item
        for item in required
        if item not in source
    }

    assert not missing, (
        f"Missing source content: {sorted(missing)}"
    )


def validate_recommendations() -> None:
    excellent = (
        coconut_tree_care_recommendations(
            ExcellentTree()
        )
    )

    assert excellent["health_score"] == 100
    assert excellent["count"] == 3

    assert {
        item["priority"]
        for item in excellent["recommendations"]
    } == {
        "Routine",
    }

    healthy = (
        coconut_tree_care_recommendations(
            HealthyTree()
        )
    )

    assert healthy["health_score"] == 90
    assert healthy["count"] == 3

    fair = coconut_tree_care_recommendations(
        FairTree()
    )

    assert fair["health_score"] == 60
    assert fair["count"] == 3

    assert {
        item["priority"]
        for item in fair["recommendations"]
    } == {
        "Attention",
    }

    poor = coconut_tree_care_recommendations(
        PoorTree()
    )

    assert poor["health_score"] == 40

    assert {
        item["priority"]
        for item in poor["recommendations"]
    } == {
        "Urgent",
    }

    critical = (
        coconut_tree_care_recommendations(
            CriticalTree()
        )
    )

    assert critical["health_score"] == 20

    assert {
        item["priority"]
        for item in critical["recommendations"]
    } == {
        "Critical",
    }


def validate_priority_styles() -> None:
    expected = {
        "Routine": "border-emerald-200",
        "Monitor": "border-sky-200",
        "Attention": "border-amber-200",
        "Urgent": "border-orange-200",
        "Critical": "border-red-200",
    }

    for priority, border in expected.items():
        style = coconut_tree_priority_style(
            priority
        )

        assert style["border"] == border
        assert style["badge"]
        assert style["icon"]

    fallback = coconut_tree_priority_style(
        "Unknown"
    )

    assert (
        fallback["border"]
        == "border-slate-200"
    )


def validate_template_globals() -> None:
    required_globals = {
        "coconut_tree_care_recommendations",
        "coconut_tree_priority_style",
    }

    missing = {
        name
        for name in required_globals
        if name not in templates.env.globals
    }

    assert not missing, (
        f"Missing template globals: {sorted(missing)}"
    )


def validate_template() -> None:
    path = Path(
        "app/templates/trees/detail.html"
    )

    assert path.is_file()

    content = path.read_text()

    required = {
        "Care Recommendations",
        "Recommended Next Actions",
        "coconut_tree_care_recommendations(tree)",
        "coconut_tree_priority_style(",
        "care_plan.recommendations",
        "recommendation.priority",
        "recommendation.title",
        "recommendation.description",
        "do not replace professional agricultural advice",
    }

    missing = {
        item
        for item in required
        if item not in content
    }

    assert not missing, (
        f"Missing template content: {sorted(missing)}"
    )

    templates.get_template(
        "trees/detail.html"
    )


def main() -> None:
    validate_source()
    validate_recommendations()
    validate_priority_styles()
    validate_template_globals()
    validate_template()

    print(
        "PATCH-005A.17 SOURCE: PASSED"
    )
    print(
        "PATCH-005A.17 RECOMMENDATIONS: PASSED"
    )
    print(
        "PATCH-005A.17 PRIORITY STYLES: PASSED"
    )
    print(
        "PATCH-005A.17 TEMPLATE GLOBALS: PASSED"
    )
    print(
        "PATCH-005A.17 TEMPLATE: PASSED"
    )
    print(
        "PATCH-005A.17: PASSED"
    )


if __name__ == "__main__":
    main()
