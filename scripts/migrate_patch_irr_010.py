"""Idempotent reporting indexes and schema assertions for PATCH-IRR-010."""
from sqlalchemy import inspect, text
from app.database import engine


def main() -> None:
    required = {"irrigation_schedules", "irrigation_executions", "pump_runtime_logs", "fertigation_plans", "weather_irrigation_recommendations", "irrigation_alerts"}
    missing = required - set(inspect(engine).get_table_names())
    if missing: raise SystemExit("Missing irrigation tables: " + ", ".join(sorted(missing)))
    statements = (
        "CREATE INDEX IF NOT EXISTS ix_irr_schedule_owner_farm_zone_date ON irrigation_schedules (owner_id, farm_id, zone_id, scheduled_date)",
        "CREATE INDEX IF NOT EXISTS ix_irr_execution_owner_schedule_status ON irrigation_executions (owner_id, schedule_id, status)",
        "CREATE INDEX IF NOT EXISTS ix_pump_runtime_owner_farm_date ON pump_runtime_logs (owner_id, farm_id, run_date)",
        "CREATE INDEX IF NOT EXISTS ix_fertigation_owner_farm_zone_date ON fertigation_plans (owner_id, farm_id, zone_id, planned_date)",
        "CREATE INDEX IF NOT EXISTS ix_weather_owner_farm_zone_date ON weather_irrigation_recommendations (owner_id, farm_id, zone_id, forecast_date)",
        "CREATE INDEX IF NOT EXISTS ix_alert_owner_farm_zone_created ON irrigation_alerts (owner_id, farm_id, zone_id, created_at)",
    )
    with engine.begin() as connection:
        for statement in statements: connection.execute(text(statement))
    print("PATCH-IRR-010 migration and schema hardening: PASSED")


if __name__ == "__main__": main()
