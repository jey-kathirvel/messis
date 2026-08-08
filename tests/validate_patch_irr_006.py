"""PATCH-IRR-006 routes, templates, model and field lifecycle validation."""
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

from jinja2 import Environment
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from starlette.requests import Request

from app.database import Base
from app.irrigation_management import (_elapsed_minutes, execution_approve, execution_complete,
    execution_pause, execution_resume, execution_start)
from app.main import app
from app.models import AuditLog, Farm, IrrigationAlert, IrrigationExecution, IrrigationPump, IrrigationSchedule, IrrigationZone, PumpRuntimeLog, User


root = Path(__file__).resolve().parents[1]
for relative in (
    "app/templates/irrigation/execution_dashboard.html",
    "app/templates/irrigation/execution_field.html",
    "app/templates/irrigation/execution_report.html",
):
    path = root / relative
    assert path.is_file(), relative
    Environment().parse(path.read_text(encoding="utf-8"))

paths = {getattr(route, "path", None) for route in app.routes}
required = {
    "/irrigation/executions", "/irrigation/executions/report",
    "/irrigation/schedules/{schedule_id}/execute", "/irrigation/schedules/{schedule_id}/execute/start",
    "/irrigation/executions/{execution_id}/pause", "/irrigation/executions/{execution_id}/resume",
    "/irrigation/executions/{execution_id}/complete", "/irrigation/executions/{execution_id}/approve",
}
assert not (required - paths), sorted(required - paths)

columns = Base.metadata.tables["irrigation_executions"].columns
for name in ("status", "paused_at", "total_paused_minutes", "supervisor_approved_by", "supervisor_notes"):
    assert name in columns, name

now = datetime.now(timezone.utc)
assert _elapsed_minutes(now - timedelta(minutes=42), now, 7) == 35

engine = create_engine("sqlite+pysqlite:///:memory:")
Base.metadata.create_all(engine)
with Session(engine) as db:
    user = User(user_id="irr006", display_name="Owner", passcode_hash="x"); db.add(user); db.flush()
    farm = Farm(owner_id=user.id, name="Farm"); db.add(farm); db.flush()
    zone = IrrigationZone(owner_id=user.id, farm_id=farm.id, name="Zone", irrigation_method="drip"); db.add(zone); db.flush()
    pump = IrrigationPump(owner_id=user.id, farm_id=farm.id, name="Pump", status="available"); db.add(pump); db.flush()
    schedule = IrrigationSchedule(owner_id=user.id, farm_id=farm.id, zone_id=zone.id, pump_id=pump.id,
        scheduled_date=date.today(), scheduled_start_time="06:00", planned_litres=Decimal("5000"),
        estimated_duration_minutes=60, status="planned")
    db.add(schedule); db.commit()
    request = Request({"type":"http", "method":"POST", "path":"/test", "headers":[], "client":("127.0.0.1", 1)})
    execution_start(schedule.id, request, "1000", "8000", "Opening OK", user, db)
    execution = db.query(IrrigationExecution).filter_by(schedule_id=schedule.id).one()
    assert execution.status == "in_progress" and schedule.status == "in_progress" and pump.status == "running"
    execution_pause(execution.id, request, user, db); assert execution.status == "paused"
    execution_resume(execution.id, request, user, db); assert execution.status == "in_progress"
    execution_complete(execution.id, request, "5800", "3000", "", "50", "100", "Completed", "on", "on", user, db)
    assert execution.status == "completed" and execution.actual_water_litres == Decimal("4800")
    assert schedule.status == "completed" and pump.status == "faulty" and zone.last_irrigation_date == date.today()
    assert db.query(PumpRuntimeLog).filter_by(pump_id=pump.id).count() == 1
    assert db.query(IrrigationAlert).filter_by(schedule_id=schedule.id).count() == 1
    execution_approve(execution.id, request, "Reviewed", user, db)
    assert execution.status == "approved" and execution.supervisor_approved_by == user.id
    assert db.query(AuditLog).filter_by(owner_id=user.id).count() == 5

print("PATCH-IRR-006 IRRIGATION EXECUTION & FIELD OPERATIONS: PASSED")
