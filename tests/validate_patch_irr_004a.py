from pathlib import Path
from jinja2 import Environment

root = Path(__file__).resolve().parents[1]
template = root / "app/templates/irrigation/calculator.html"
layout = root / "app/templates/irrigation/layout.html"
css = root / "app/static/css/irrigation.css"

for path in (template, layout, css):
    assert path.exists(), f"Missing required file: {path}"

text = template.read_text(encoding="utf-8")
css_text = css.read_text(encoding="utf-8")
layout_text = layout.read_text(encoding="utf-8")

for marker in ("calc-layout", "calc-form-grid", "calc-result-card", "Calculate recommendation"):
    assert marker in text, f"Calculator UI marker missing: {marker}"
for marker in ("PATCH-IRR-004A", ".calc-layout", ".calc-result-card", "@media(max-width:720px)"):
    assert marker in css_text, f"Calculator CSS marker missing: {marker}"
assert "irrigation.css?v=006" in layout_text, "CSS cache version was not updated"

Environment().parse(text)
Environment().parse(layout_text)
print("PATCH-IRR-004A CALCULATOR UI/UX FIX: PASSED")
