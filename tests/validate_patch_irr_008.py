"""PATCH-IRR-008 weather adapter, decision rules, routes and templates."""
from datetime import date
from decimal import Decimal
from pathlib import Path

from jinja2 import Environment

from app.irrigation_management import router
from app.services.irrigation_weather import build_irrigation_advice


root = Path(__file__).resolve().parents[1]
business_menu = (root / "app/templates/dashboard/business.html").read_text(encoding="utf-8")
mobile_menu = (root / "app/templates/base.html").read_text(encoding="utf-8")
assert 'href="/irrigation/weather"' in business_menu and "Weather Intelligence" in business_menu
assert 'href="/irrigation/weather"' in mobile_menu
for relative in ("weather_dashboard.html", "weather_report.html"):
    path = root / "app/templates/irrigation" / relative
    assert path.is_file(), relative
    Environment().parse(path.read_text(encoding="utf-8"))

paths = {route.path for route in router.routes}
required = {
    "/irrigation/weather",
    "/irrigation/weather/refresh",
    "/irrigation/weather/{recommendation_id}/decision",
    "/irrigation/weather/report",
}
assert not (required - paths), sorted(required - paths)

heavy_rain = build_irrigation_advice(
    {"date": date.today().isoformat(), "rain_mm": 18, "rain_probability": 85},
    Decimal("1000"),
    "drip",
)
assert heavy_rain.recommendation == "delay_irrigation"
assert heavy_rain.adjustment_percent == Decimal("-100")
assert heavy_rain.recommended_litres == Decimal("0.00")
assert heavy_rain.severity == "high"

hot = build_irrigation_advice(
    {"date": date.today().isoformat(), "temperature_max": 39, "et0": 6.2},
    Decimal("1000"),
    "drip",
)
assert hot.recommendation == "increase_water"
assert hot.recommended_litres == Decimal("1200.00")

normal = build_irrigation_advice(
    {"date": date.today().isoformat(), "temperature_max": 28, "humidity_mean": 60},
    Decimal("1000"),
    "drip",
)
assert normal.recommendation == "proceed"
assert normal.recommended_litres == Decimal("1000.00")

print("PATCH-IRR-008 WEATHER INTELLIGENCE: PASSED")
