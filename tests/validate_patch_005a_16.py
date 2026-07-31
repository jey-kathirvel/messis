import ast
from pathlib import Path

from app.main import (
    coconut_tree_health_score,
    templates,
)


class Healthy:
    health_status="Healthy"


class Poor:
    health_status="Poor"


class Unknown:
    health_status=""


def validate():
    source=Path(
        "app/main.py"
    ).read_text()

    ast.parse(source)

    assert (
        "# PATCH-005A.16: TREE HEALTH SCORE"
        in source
    )

    assert (
        coconut_tree_health_score(
            Healthy()
        )["score"]==90
    )

    assert (
        coconut_tree_health_score(
            Poor()
        )["score"]==40
    )

    assert (
        coconut_tree_health_score(
            Unknown()
        )["score"]==75
    )

    template=Path(
        "app/templates/trees/detail.html"
    ).read_text()

    assert "Tree Health Score" in template
    assert "health.score" in template
    assert "stroke-dashoffset" in template

    assert (
        "coconut_tree_health_score"
        in templates.env.globals
    )

    templates.get_template(
        "trees/detail.html"
    )

    print(
        "PATCH-005A.16 SOURCE: PASSED"
    )
    print(
        "PATCH-005A.16 HEALTH SCORE: PASSED"
    )
    print(
        "PATCH-005A.16 TEMPLATE: PASSED"
    )
    print(
        "PATCH-005A.16: PASSED"
    )


if __name__=="__main__":
    validate()
