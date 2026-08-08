"""Application-wide garden glassmorphism design-system coverage."""
from pathlib import Path


root = Path(__file__).resolve().parents[1]
theme = (root / "app/static/css/garden-glass.css").read_text(encoding="utf-8")
for marker in ("MESSIS-UX-GLASS-001", "--glass-surface", "backdrop-filter", "prefers-reduced-transparency", ".sidebar", "table", "input,select,textarea", ".messis-mobile-navigation", ".topbar .page-title strong", ".weather-summary-panel", ".topbar{padding-right:190px"):
    assert marker in theme, marker
for relative in ("app/static/css/app.css", "app/static/css/agri-theme.css", "app/static/pwa/mobile-shell.css"):
    text = (root / relative).read_text(encoding="utf-8")
    assert "garden-glass.css?v=003" in "\n".join(text.splitlines()[:3]), relative
for relative in ("app/templates/errors/404.html", "app/templates/errors/500.html", "app/templates/reminders/popup.html", "app/templates/setup/dynamic_fields.html"):
    assert "garden-glass.css?v=003" in (root / relative).read_text(encoding="utf-8"), relative
for path in (root / "app/templates").rglob("*.html"):
    text = path.read_text(encoding="utf-8")
    if "<html" not in text.lower():
        continue
    covered = "extends" in text and "base.html" in text or any(marker in text for marker in ("app.css", "agri-theme.css", "mobile-shell.css", "garden-glass.css"))
    assert covered, f"Full-page template is outside the garden-glass style chain: {path.relative_to(root)}"
print("MESSIS GARDEN GLASSMORPHISM THEME: PASSED")
