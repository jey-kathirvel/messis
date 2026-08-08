"""PATCH-IRR-009 routes, templates, navigation and alert rule lifecycle."""
from datetime import date, timedelta
from decimal import Decimal
from pathlib import Path

from jinja2 import Environment
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.database import Base
from app.irrigation_management import _generate_irrigation_alerts, router
from app.models import Farm, IrrigationAlert, IrrigationPump, IrrigationSchedule, IrrigationZone, User, WaterSource


root = Path(__file__).resolve().parents[1]
for relative in ("alerts_dashboard.html", "alerts_report.html"):
    path = root / "app/templates/irrigation" / relative
    assert path.is_file(), relative
    Environment().parse(path.read_text(encoding="utf-8"))
for relative in ("app/templates/dashboard/business.html", "app/templates/base.html", "app/templates/irrigation/layout.html"):
    assert 'href="/irrigation/alerts"' in (root / relative).read_text(encoding="utf-8")

paths = {route.path for route in router.routes}
required = {"/irrigation/alerts", "/irrigation/alerts/generate", "/irrigation/alerts/{alert_id}/status", "/irrigation/alerts/report"}
assert not (required - paths), sorted(required - paths)

engine = create_engine("sqlite+pysqlite:///:memory:"); Base.metadata.create_all(engine)
with Session(engine) as db:
    user = User(user_id="irr009", display_name="Owner", passcode_hash="x"); db.add(user); db.flush()
    farm = Farm(owner_id=user.id, name="Alert Farm"); db.add(farm); db.flush()
    zone = IrrigationZone(owner_id=user.id, farm_id=farm.id, name="North", irrigation_method="drip"); db.add(zone); db.flush()
    db.add(IrrigationSchedule(owner_id=user.id, farm_id=farm.id, zone_id=zone.id, scheduled_date=date.today()-timedelta(days=1), status="planned"))
    db.add(WaterSource(owner_id=user.id, farm_id=farm.id, name="Tank", source_type="tank", capacity_litres=Decimal("1000"), current_level_litres=Decimal("100")))
    db.add(IrrigationPump(owner_id=user.id, farm_id=farm.id, name="Pump", status="faulty")); db.commit()
    created = _generate_irrigation_alerts(db, user); db.commit()
    assert created == 3
    assert db.query(IrrigationAlert).filter_by(owner_id=user.id).count() == 3
    assert {row.alert_type for row in db.query(IrrigationAlert).all()} == {"schedule_overdue", "low_water_source", "pump_attention"}
    assert _generate_irrigation_alerts(db, user) == 0

print("PATCH-IRR-009 IRRIGATION ALERTS & NOTIFICATIONS: PASSED")
