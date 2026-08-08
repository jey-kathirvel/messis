from pathlib import Path

root = Path(__file__).resolve().parents[1]
route = (root / "app/irrigation_management.py").read_text()
template = (root / "app/templates/irrigation/calculator_history.html").read_text()
css = (root / "app/static/css/irrigation.css").read_text()
layout = (root / "app/templates/irrigation/layout.html").read_text()

checks = {
    "history route metrics": "PATCH-IRR-004B: premium history dashboard metrics" in route,
    "runtime aggregate": "estimated_runtime_minutes" in route and "runtime=runtime" in route,
    "trend payload": '"height": max(8' in route,
    "premium KPI grid": "history-kpis" in template,
    "trend chart": "water-chart" in template,
    "recommendation badges": "decision-badge" in template,
    "client-side search": "historySearch" in template,
    "responsive premium CSS": "PATCH-IRR-004B — Premium Calculator History Dashboard" in css,
    "cache version": "irrigation.css?v=006" in layout,
}
failed = [name for name, ok in checks.items() if not ok]
if failed:
    raise SystemExit("PATCH-IRR-004B validation failed: " + ", ".join(failed))
print("PATCH-IRR-004B PREMIUM CALCULATOR DASHBOARD UI: PASSED")
