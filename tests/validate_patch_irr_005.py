"""PATCH-IRR-005 source, route, recurrence and conflict validation."""
from datetime import date
from pathlib import Path

from jinja2 import Environment
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.database import Base
from app.irrigation_management import _recurring_dates, _schedule_conflicts
from app.main import app
from app.models import Farm, IrrigationSchedule, IrrigationZone, User


root = Path(__file__).resolve().parents[1]
required_files = (
    "app/templates/irrigation/schedule_calendar.html",
    "app/templates/irrigation/schedule_form.html",
    "app/templates/irrigation/schedule_report.html",
    "scripts/migrate_patch_irr_005.py",
)
for relative in required_files:
    path = root / relative
    assert path.is_file(), f"Missing {relative}"
    if path.suffix == ".html":
        Environment().parse(path.read_text(encoding="utf-8"))

paths = {getattr(route, "path", None) for route in app.routes}
required_paths = {
    "/irrigation/schedules", "/irrigation/schedules/new",
    "/irrigation/schedules/{schedule_id}/edit", "/irrigation/schedules/{schedule_id}/status",
    "/irrigation/schedules/{schedule_id}/delete", "/irrigation/schedules/report",
}
assert not (required_paths - paths), sorted(required_paths - paths)

columns = Base.metadata.tables["irrigation_schedules"].columns
for name in ("recurrence_type", "recurrence_interval", "recurrence_end_date", "recurrence_group_id"):
    assert name in columns, name

assert _recurring_dates(date(2026, 8, 8), "daily", 2, date(2026, 8, 12)) == [date(2026, 8, 8), date(2026, 8, 10), date(2026, 8, 12)]
assert _recurring_dates(date(2026, 1, 31), "monthly", 1, date(2026, 3, 31)) == [date(2026, 1, 31), date(2026, 2, 28), date(2026, 3, 31)]

engine = create_engine("sqlite+pysqlite:///:memory:")
Base.metadata.create_all(engine)
with Session(engine) as db:
    user = User(user_id="irr005", display_name="Owner", passcode_hash="x")
    db.add(user); db.flush()
    farm = Farm(owner_id=user.id, name="Farm")
    db.add(farm); db.flush()
    zone = IrrigationZone(owner_id=user.id, farm_id=farm.id, name="Zone", irrigation_method="drip")
    db.add(zone); db.flush()
    db.add(IrrigationSchedule(owner_id=user.id, farm_id=farm.id, zone_id=zone.id,
        scheduled_date=date(2026, 8, 8), scheduled_start_time="09:00", estimated_duration_minutes=60,
        assigned_worker="Kumar", status="planned"))
    db.commit()
    conflicts = _schedule_conflicts(db, user.id, scheduled_date=date(2026, 8, 8), start_time="09:30",
        duration=45, zone_id=zone.id, pump_id=None, assigned_worker="kumar")
    assert conflicts and "zone" in conflicts[0] and "worker" in conflicts[0]
    no_conflict = _schedule_conflicts(db, user.id, scheduled_date=date(2026, 8, 8), start_time="10:00",
        duration=30, zone_id=zone.id, pump_id=None, assigned_worker="Kumar")
    assert not no_conflict

print("PATCH-IRR-005 SMART IRRIGATION SCHEDULER & CALENDAR: PASSED")
