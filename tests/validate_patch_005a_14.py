import ast
from pathlib import Path

from app.main import (
    coconut_tree_timeline,
    templates,
)


class DummyTree:
    planting_date="2020-01-01"

    class DT:
        def date(self):
            return "2024-01-01"

    created_at=DT()
    updated_at=DT()
    variety="Tall"


def validate():
    source=Path("app/main.py").read_text()

    ast.parse(source)

    assert "# PATCH-005A.14: TREE TIMELINE" in source
    assert "def coconut_tree_timeline" in source

    events=coconut_tree_timeline(DummyTree())

    assert len(events) in {2, 3}

    titles = {
        event["title"]
        for event in events
    }

    assert "Tree Planted" in titles
    assert "Registered" in titles

    template=Path(
        "app/templates/trees/detail.html"
    ).read_text()

    assert "Tree Timeline" in template
    assert "No timeline events available." in template

    templates.get_template(
        "trees/detail.html"
    )

    print("PATCH-005A.14 SOURCE: PASSED")
    print("PATCH-005A.14 TIMELINE: PASSED")
    print("PATCH-005A.14 TEMPLATE: PASSED")
    print("PATCH-005A.14: PASSED")


if __name__=="__main__":
    validate()
