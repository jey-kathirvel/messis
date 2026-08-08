"""PATCH-IRR-010 reporting, navigation, tenant isolation and aggregation validation."""
from datetime import date
from decimal import Decimal
from pathlib import Path

from jinja2 import Environment
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.database import Base
from app.irrigation_management import _irrigation_report_data, irrigation_consolidated_csv, router
from app.models import Farm, IrrigationExecution, IrrigationSchedule, IrrigationZone, User


root = Path(__file__).resolve().parents[1]
template = root / "app/templates/irrigation/consolidated_report.html"
assert template.is_file(); Environment().parse(template.read_text(encoding="utf-8"))
for relative in ("app/templates/dashboard/business.html", "app/templates/base.html", "app/templates/irrigation/layout.html"):
    assert 'href="/irrigation/reports"' in (root / relative).read_text(encoding="utf-8")
paths = {route.path for route in router.routes}
assert {"/irrigation/reports", "/irrigation/reports/export.csv"} <= paths

engine = create_engine("sqlite+pysqlite:///:memory:"); Base.metadata.create_all(engine)
with Session(engine) as db:
    owner = User(user_id="irr010", display_name="Owner", passcode_hash="x")
    other = User(user_id="irr010-other", display_name="Other", passcode_hash="x"); db.add_all((owner, other)); db.flush()
    farm = Farm(owner_id=owner.id, name="Report Farm"); hidden_farm = Farm(owner_id=other.id, name="Hidden Farm"); db.add_all((farm, hidden_farm)); db.flush()
    zone = IrrigationZone(owner_id=owner.id, farm_id=farm.id, name="North", irrigation_method="drip")
    hidden_zone = IrrigationZone(owner_id=other.id, farm_id=hidden_farm.id, name="Hidden", irrigation_method="drip"); db.add_all((zone, hidden_zone)); db.flush()
    schedule = IrrigationSchedule(owner_id=owner.id, farm_id=farm.id, zone_id=zone.id, scheduled_date=date.today(), planned_litres=Decimal("1000"), status="completed")
    hidden_schedule = IrrigationSchedule(owner_id=other.id, farm_id=hidden_farm.id, zone_id=hidden_zone.id, scheduled_date=date.today(), planned_litres=Decimal("9000"), status="completed"); db.add_all((schedule, hidden_schedule)); db.flush()
    db.add_all((IrrigationExecution(owner_id=owner.id, farm_id=farm.id, schedule_id=schedule.id, status="completed", actual_water_litres=Decimal("800")), IrrigationExecution(owner_id=other.id, farm_id=hidden_farm.id, schedule_id=hidden_schedule.id, status="completed", actual_water_litres=Decimal("8000")))); db.commit()
    data = _irrigation_report_data(db, owner, date.today().isoformat(), date.today().isoformat(), None, None)
    assert data["metrics"]["schedules"] == 1 and data["metrics"]["planned"] == Decimal("1000")
    assert data["metrics"]["actual"] == Decimal("800") and data["metrics"]["saved"] == Decimal("200")
    assert all(row[2].owner_id == owner.id for row in data["schedules"])
    response = irrigation_consolidated_csv(date.today().isoformat(), date.today().isoformat(), None, None, owner, db)
    body = response.body.decode("utf-8")
    assert response.media_type.startswith("text/csv") and "Report Farm" in body and "Hidden Farm" not in body
    assert response.headers["cache-control"] == "private, no-store"

print("PATCH-IRR-010 REPORTS & PRODUCTION HARDENING: PASSED")
