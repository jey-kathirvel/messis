"""Open-Meteo forecast adapter and deterministic irrigation recommendation rules."""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_UP
import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


PROVIDER = "Open-Meteo"
PROVIDER_URL = "https://api.open-meteo.com/v1/forecast"


def decimal_value(value: object) -> Decimal:
    try:
        return Decimal(str(value or 0)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except Exception:
        return Decimal("0.00")


def fetch_daily_forecast(latitude: float, longitude: float, forecast_days: int = 10) -> list[dict[str, object]]:
    if not -90 <= latitude <= 90 or not -180 <= longitude <= 180:
        raise ValueError("Invalid weather coordinates.")
    if not 1 <= forecast_days <= 16:
        raise ValueError("Forecast days must be between 1 and 16.")
    parameters = {
        "latitude": f"{latitude:.6f}", "longitude": f"{longitude:.6f}", "timezone": "auto",
        "forecast_days": str(forecast_days),
        "daily": ",".join(("temperature_2m_max", "temperature_2m_min", "relative_humidity_2m_mean",
            "precipitation_sum", "rain_sum", "precipitation_probability_max", "wind_speed_10m_max",
            "et0_fao_evapotranspiration", "weather_code")),
    }
    request = Request(PROVIDER_URL + "?" + urlencode(parameters), headers={"Accept":"application/json", "User-Agent":"Messis-AI/0.5"})
    try:
        with urlopen(request, timeout=12) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        raise RuntimeError(f"Weather provider returned HTTP {exc.code}.") from exc
    except (URLError, TimeoutError) as exc:
        raise RuntimeError("Weather provider is unavailable.") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RuntimeError("Weather provider returned invalid data.") from exc
    if payload.get("error"):
        raise RuntimeError(str(payload.get("reason") or "Weather provider error."))
    daily = dict(payload.get("daily") or {}); dates = list(daily.get("time") or [])
    rows = []
    for index, forecast_date in enumerate(dates):
        def at(name: str):
            values = list(daily.get(name) or [])
            return values[index] if index < len(values) else None
        rows.append({"date": forecast_date, "temperature_max": at("temperature_2m_max"),
            "temperature_min": at("temperature_2m_min"), "humidity_mean": at("relative_humidity_2m_mean"),
            "precipitation_mm": at("precipitation_sum"), "rain_mm": at("rain_sum"),
            "rain_probability": at("precipitation_probability_max"), "wind_speed_max": at("wind_speed_10m_max"),
            "et0_mm": at("et0_fao_evapotranspiration"), "weather_code": at("weather_code"),
            "latitude": latitude, "longitude": longitude, "provider": PROVIDER})
    return rows


@dataclass(frozen=True)
class IrrigationAdvice:
    recommendation: str
    adjustment_percent: Decimal
    recommended_litres: Decimal | None
    reason: str
    severity: str


def build_irrigation_advice(forecast: dict[str, object], base_litres: Decimal | None,
                            irrigation_method: str | None = None) -> IrrigationAdvice:
    rain = max(decimal_value(forecast.get("rain_mm")), decimal_value(forecast.get("precipitation_mm")))
    probability = decimal_value(forecast.get("rain_probability")); temperature = decimal_value(forecast.get("temperature_max"))
    humidity = decimal_value(forecast.get("humidity_mean")); wind = decimal_value(forecast.get("wind_speed_max")); et0 = decimal_value(forecast.get("et0_mm"))
    method = (irrigation_method or "other").lower()
    if rain >= Decimal("15") or probability >= Decimal("80"):
        recommendation, adjustment, reason, severity = "delay_irrigation", Decimal("-100"), "Heavy rain is likely; delay irrigation and reassess field moisture.", "high"
    elif rain >= Decimal("7.5") or probability >= Decimal("60"):
        recommendation, adjustment, reason, severity = "reduce_water", Decimal("-50"), "Meaningful rainfall is forecast; reduce planned irrigation by half.", "medium"
    elif wind >= Decimal("35") and method in ("sprinkler", "micro_sprinkler"):
        recommendation, adjustment, reason, severity = "delay_irrigation", Decimal("-100"), "Strong wind will reduce sprinkler distribution efficiency.", "high"
    elif temperature >= Decimal("38") or et0 >= Decimal("6"):
        recommendation, adjustment, reason, severity = "increase_water", Decimal("20"), "High heat or evapotranspiration is increasing crop water demand.", "medium"
    elif temperature >= Decimal("35") or et0 >= Decimal("4.5") or (humidity > 0 and humidity <= Decimal("35")):
        recommendation, adjustment, reason, severity = "increase_water", Decimal("10"), "Warm or dry conditions justify a moderate water increase.", "low"
    else:
        recommendation, adjustment, reason, severity = "proceed", Decimal("0"), "Forecast conditions support the current irrigation plan.", "info"
    recommended = None
    if base_litres is not None:
        recommended = max(Decimal("0"), base_litres * (Decimal("1") + adjustment / Decimal("100"))).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return IrrigationAdvice(recommendation, adjustment, recommended, reason, severity)
