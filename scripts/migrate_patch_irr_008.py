"""Idempotent indexes for PATCH-IRR-008 weather intelligence."""
from sqlalchemy import inspect, text
from app.database import engine


def main() -> None:
    if "weather_irrigation_recommendations" not in inspect(engine).get_table_names():
        raise SystemExit("weather_irrigation_recommendations is missing; deploy PATCH-IRR-001 first")
    with engine.begin() as connection:
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_weather_irr_owner_forecast ON weather_irrigation_recommendations (owner_id, forecast_date)"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_weather_irr_zone_forecast ON weather_irrigation_recommendations (zone_id, forecast_date)"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_weather_irr_decision_forecast ON weather_irrigation_recommendations (user_decision, forecast_date)"))
    print("PATCH-IRR-008 migration: PASSED")


if __name__=="__main__": main()
