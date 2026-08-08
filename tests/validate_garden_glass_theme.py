"""Application-wide garden glassmorphism design-system coverage."""
from pathlib import Path


root = Path(__file__).resolve().parents[1]
theme = (root / "app/static/css/garden-glass.css").read_text(encoding="utf-8")
subpages = (root / "app/static/css/messis-subpages.css").read_text(encoding="utf-8")
base = (root / "app/templates/base.html").read_text(encoding="utf-8")
dashboard = (root / "app/templates/dashboard/business.html").read_text(encoding="utf-8")
for marker in ("MESSIS-UX-HEADER-001", "height:54px", ".messis-nav-icon-button", "position:sticky"):
    assert marker in subpages, marker
assert "messis-subpages.css?v=001c" in base
assert 'aria-label="Go back"' in base and 'aria-label="Back to dashboard"' in base
assert 'class="messis-nav-icon"' in base and "<svg" in base
assert ".messis-page-toolbar .messis-nav-icon-button" in subpages
for marker in ("PATCH-WEATHER-001D", ".weather-day-card strong", ".weather-advisory-mini p"):
    assert marker in dashboard, marker
for marker in ("MESSIS-UX-GLASS-001", "--glass-surface", "backdrop-filter", "prefers-reduced-transparency", ".sidebar", "table", "input,select,textarea", ".messis-mobile-navigation", ".topbar .page-title strong", ".weather-summary-panel", ".topbar{padding-right:190px", ".pwa-install-button.visible"):
    assert marker in theme, marker
for relative in ("app/static/css/app.css", "app/static/css/agri-theme.css", "app/static/pwa/mobile-shell.css"):
    text = (root / relative).read_text(encoding="utf-8")
    assert "garden-glass.css?v=004" in "\n".join(text.splitlines()[:3]), relative
for relative in ("app/templates/errors/404.html", "app/templates/errors/500.html", "app/templates/reminders/popup.html", "app/templates/setup/dynamic_fields.html"):
    assert "garden-glass.css?v=004" in (root / relative).read_text(encoding="utf-8"), relative
dashboard = (root / "app/templates/dashboard/business.html").read_text(encoding="utf-8")
assert 'aria-label="Install Messis AI app"' in dashboard and "pwa-install-icon" in dashboard
for path in (root / "app/templates").rglob("*.html"):
    text = path.read_text(encoding="utf-8")
    if "<html" not in text.lower():
        continue
    covered = "extends" in text and "base.html" in text or any(marker in text for marker in ("app.css", "agri-theme.css", "mobile-shell.css", "garden-glass.css"))
    assert covered, f"Full-page template is outside the garden-glass style chain: {path.relative_to(root)}"
print("MESSIS GARDEN GLASSMORPHISM THEME: PASSED")
