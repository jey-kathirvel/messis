from __future__ import annotations

from calendar import monthrange
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from urllib.parse import quote
from uuid import uuid4

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.services.water_calculator import calculate_water
from app.models import (AuditLog, Farm, IrrigationAlert, IrrigationEquipment, IrrigationExecution, IrrigationPump, IrrigationSchedule, IrrigationZone, PumpMaintenanceRecord, PumpRuntimeLog, User, WaterSource, WaterRequirementCalculation)

router = APIRouter(tags=["Irrigation Management"])
templates = Jinja2Templates(directory=Path(__file__).resolve().parent / "templates")

IRRIGATION_METHODS = ("drip", "sprinkler", "flood", "furrow", "micro_sprinkler", "manual_hose", "rain_fed", "other")
WATER_SOURCE_TYPES = ("borewell", "open_well", "farm_pond", "canal", "river", "rainwater_tank", "municipal", "tanker", "other")
AREA_UNITS = ("acre", "hectare", "cent", "sq_m")
AVAILABILITY_STATUSES = ("available", "limited", "unavailable", "maintenance")
WATER_QUALITY_STATUSES = ("good", "acceptable", "needs_treatment", "not_tested")
PUMP_TYPES = ("submersible", "centrifugal", "monoblock", "solar", "diesel", "booster", "other")
POWER_SOURCES = ("electricity", "solar", "diesel", "petrol", "hybrid", "other")
PUMP_STATUSES = ("available", "running", "idle", "maintenance", "faulty", "offline")
EQUIPMENT_TYPES = ("filter", "fertigation_tank", "valve", "pressure_gauge", "flow_meter", "automation_controller", "pipe", "sprinkler", "drip_unit", "other")
EQUIPMENT_STATUSES = ("available", "in_use", "maintenance", "faulty", "retired")
SERVICE_TYPES = ("inspection", "preventive", "repair", "oil_change", "bearing_change", "electrical", "overhaul", "other")
SCHEDULE_STATUSES = ("planned", "confirmed", "in_progress", "completed", "postponed", "cancelled")
RECURRENCE_TYPES = ("none", "daily", "weekly", "monthly")


def current_irrigation_user(request: Request, db: Session = Depends(get_db)) -> User:
    user_id = request.session.get("user_id")
    if not isinstance(user_id, int):
        raise HTTPException(status_code=401, detail="Authentication required")
    user = db.get(User, user_id)
    if not user or not user.is_active:
        request.session.clear()
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def _text(value: str | None) -> str | None:
    value = (value or "").strip()
    return value or None


def _decimal(value: str | None, label: str, *, allow_zero: bool = True) -> Decimal | None:
    value = (value or "").strip()
    if not value:
        return None
    try:
        number = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError(f"{label} must be a valid number.") from exc
    if number < 0 or (not allow_zero and number == 0):
        raise ValueError(f"{label} must be greater than{' or equal to' if allow_zero else ''} zero.")
    return number


def _integer(value: str | None, label: str, *, allow_zero: bool = True) -> int | None:
    value = (value or "").strip()
    if not value:
        return None
    try:
        number = int(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be a whole number.") from exc
    if number < 0 or (not allow_zero and number == 0):
        raise ValueError(f"{label} must be greater than{' or equal to' if allow_zero else ''} zero.")
    return number


def _date(value: str | None, label: str) -> date | None:
    value = (value or "").strip()
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be a valid date.") from exc


def _farm(db: Session, owner_id: int, farm_id: int) -> Farm:
    farm = db.scalar(select(Farm).where(Farm.id == farm_id, Farm.owner_id == owner_id))
    if not farm:
        raise HTTPException(status_code=404, detail="Farm not found")
    return farm


def _zone(db: Session, owner_id: int, zone_id: int) -> IrrigationZone:
    zone = db.scalar(select(IrrigationZone).where(IrrigationZone.id == zone_id, IrrigationZone.owner_id == owner_id))
    if not zone:
        raise HTTPException(status_code=404, detail="Irrigation zone not found")
    return zone


def _source(db: Session, owner_id: int, source_id: int) -> WaterSource:
    source = db.scalar(select(WaterSource).where(WaterSource.id == source_id, WaterSource.owner_id == owner_id))
    if not source:
        raise HTTPException(status_code=404, detail="Water source not found")
    return source


def _ctx(request: Request, user: User, **extra):
    return {"request": request, "current_user": user, "success_message": request.query_params.get("success"), "error_message": request.query_params.get("error"), **extra}


def _schedule(db: Session, owner_id: int, schedule_id: int) -> IrrigationSchedule:
    schedule = db.scalar(select(IrrigationSchedule).where(IrrigationSchedule.id == schedule_id, IrrigationSchedule.owner_id == owner_id))
    if not schedule:
        raise HTTPException(status_code=404, detail="Irrigation schedule not found")
    return schedule


def _execution(db: Session, owner_id: int, execution_id: int) -> IrrigationExecution:
    execution = db.scalar(select(IrrigationExecution).where(IrrigationExecution.id == execution_id, IrrigationExecution.owner_id == owner_id))
    if not execution:
        raise HTTPException(status_code=404, detail="Irrigation execution not found")
    return execution


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _elapsed_minutes(started_at: datetime | None, ended_at: datetime | None, paused_minutes: int = 0) -> int:
    if not started_at or not ended_at:
        return 0
    elapsed = int((_aware(ended_at) - _aware(started_at)).total_seconds() // 60) - paused_minutes
    return max(0, elapsed)


def _irrigation_audit(db: Session, request: Request, user: User, event: str, detail: str) -> None:
    forwarded = request.headers.get("x-forwarded-for")
    ip_address = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else None)
    db.add(AuditLog(owner_id=user.id, event_type=event, ip_address=ip_address, detail=detail))


def _clock(value: str | None, label: str) -> str | None:
    value = (value or "").strip()
    if not value:
        return None
    try:
        return time.fromisoformat(value).strftime("%H:%M")
    except ValueError as exc:
        raise ValueError(f"{label} must be a valid time.") from exc


def _schedule_minutes(schedule: IrrigationSchedule) -> tuple[int, int]:
    start = schedule.scheduled_start_time or "00:00"
    hour, minute = (int(part) for part in start.split(":")[:2])
    start_minutes = hour * 60 + minute
    return start_minutes, start_minutes + (schedule.estimated_duration_minutes or 0)


def _schedule_conflicts(db: Session, owner_id: int, *, scheduled_date: date, start_time: str | None,
                        duration: int | None, zone_id: int, pump_id: int | None,
                        assigned_worker: str | None, exclude_id: int | None = None) -> list[str]:
    probe = IrrigationSchedule(scheduled_start_time=start_time, estimated_duration_minutes=duration)
    probe_start, probe_end = _schedule_minutes(probe)
    stmt = select(IrrigationSchedule).where(
        IrrigationSchedule.owner_id == owner_id,
        IrrigationSchedule.scheduled_date == scheduled_date,
        IrrigationSchedule.status.not_in(("cancelled", "completed")),
    )
    if exclude_id:
        stmt = stmt.where(IrrigationSchedule.id != exclude_id)
    conflicts: list[str] = []
    worker_key = (assigned_worker or "").strip().casefold()
    for item in db.scalars(stmt):
        item_start, item_end = _schedule_minutes(item)
        overlaps = probe_start < item_end and item_start < probe_end
        if not overlaps:
            continue
        resources = []
        if item.zone_id == zone_id:
            resources.append("zone")
        if pump_id and item.pump_id == pump_id:
            resources.append("pump")
        if worker_key and (item.assigned_worker or "").strip().casefold() == worker_key:
            resources.append("worker")
        if resources:
            conflicts.append(f"Schedule #{item.id} overlaps for {', '.join(resources)}.")
    return conflicts


def _recurring_dates(start: date, recurrence_type: str, interval: int, end: date | None) -> list[date]:
    if recurrence_type == "none":
        return [start]
    if not end:
        raise ValueError("Recurrence end date is required for recurring schedules.")
    if end < start:
        raise ValueError("Recurrence end date cannot be before the start date.")
    dates: list[date] = []
    current = start
    monthly_step = 0
    while current <= end and len(dates) < 366:
        dates.append(current)
        if recurrence_type == "daily":
            current += timedelta(days=interval)
        elif recurrence_type == "weekly":
            current += timedelta(days=7 * interval)
        else:
            monthly_step += interval
            month_index = start.month - 1 + monthly_step
            year = start.year + month_index // 12
            month = month_index % 12 + 1
            current = date(year, month, min(start.day, monthrange(year, month)[1]))
    if len(dates) >= 366 and current <= end:
        raise ValueError("Recurring schedules are limited to 366 occurrences.")
    return dates


@router.get("/irrigation", response_class=HTMLResponse)
def irrigation_dashboard(request: Request, user: User = Depends(current_irrigation_user), db: Session = Depends(get_db)):
    zones = db.scalar(select(func.count(IrrigationZone.id)).where(IrrigationZone.owner_id == user.id)) or 0
    sources = db.scalar(select(func.count(WaterSource.id)).where(WaterSource.owner_id == user.id)) or 0
    pumps = db.scalar(select(func.count(IrrigationPump.id)).where(IrrigationPump.owner_id == user.id)) or 0
    faulty_pumps = db.scalar(select(func.count(IrrigationPump.id)).where(IrrigationPump.owner_id == user.id, IrrigationPump.status.in_(("faulty", "maintenance", "offline")))) or 0
    equipment = db.scalar(select(func.count(IrrigationEquipment.id)).where(IrrigationEquipment.owner_id == user.id, IrrigationEquipment.is_active.is_(True))) or 0
    active_zones = db.scalar(select(func.count(IrrigationZone.id)).where(IrrigationZone.owner_id == user.id, IrrigationZone.is_active.is_(True))) or 0
    total_capacity = db.scalar(select(func.coalesce(func.sum(WaterSource.capacity_litres), 0)).where(WaterSource.owner_id == user.id, WaterSource.is_active.is_(True))) or 0
    due = list(db.scalars(select(IrrigationZone).where(IrrigationZone.owner_id == user.id, IrrigationZone.is_active.is_(True), IrrigationZone.next_irrigation_date.is_not(None)).order_by(IrrigationZone.next_irrigation_date).limit(8)))
    return templates.TemplateResponse(request=request, name="irrigation/dashboard.html", context=_ctx(request,user,page_title="Irrigation Management",zones=zones,sources=sources,active_zones=active_zones,total_capacity=total_capacity,due=due,pumps=pumps,faulty_pumps=faulty_pumps,equipment=equipment))


@router.get("/irrigation/zones", response_class=HTMLResponse)
def zone_list(request: Request, farm_id: int | None = None, user: User = Depends(current_irrigation_user), db: Session = Depends(get_db)):
    stmt = select(IrrigationZone, Farm).join(Farm, Farm.id == IrrigationZone.farm_id).where(IrrigationZone.owner_id == user.id, Farm.owner_id == user.id)
    if farm_id is not None:
        _farm(db, user.id, farm_id); stmt = stmt.where(IrrigationZone.farm_id == farm_id)
    rows = list(db.execute(stmt.order_by(IrrigationZone.is_active.desc(), IrrigationZone.name)).all())
    farms = list(db.scalars(select(Farm).where(Farm.owner_id == user.id).order_by(Farm.name)))
    return templates.TemplateResponse(request=request,name="irrigation/zones_list.html",context=_ctx(request,user,page_title="Irrigation Zones",rows=rows,farms=farms,selected_farm_id=farm_id))


@router.get("/irrigation/zones/new", response_class=HTMLResponse)
def zone_new(request: Request, farm_id: int | None = None, user: User = Depends(current_irrigation_user), db: Session = Depends(get_db)):
    farms=list(db.scalars(select(Farm).where(Farm.owner_id==user.id).order_by(Farm.name)))
    return templates.TemplateResponse(request=request,name="irrigation/zone_form.html",context=_ctx(request,user,page_title="Add Irrigation Zone",zone=None,farms=farms,selected_farm_id=farm_id,methods=IRRIGATION_METHODS,area_units=AREA_UNITS))


@router.post("/irrigation/zones/new")
def zone_create(request: Request, farm_id: int=Form(...), name: str=Form(...), crop_name: str=Form(""), crop_variety: str=Form(""), growth_stage: str=Form(""), plant_count: str=Form("0"), area_value: str=Form(""), area_unit: str=Form("acre"), soil_type: str=Form(""), irrigation_method: str=Form("drip"), recommended_litres_per_plant: str=Form(""), recommended_interval_days: str=Form(""), last_irrigation_date: str=Form(""), next_irrigation_date: str=Form(""), notes: str=Form(""), is_active: str|None=Form(None), user: User=Depends(current_irrigation_user), db: Session=Depends(get_db)):
    try:
        _farm(db,user.id,farm_id)
        clean_name=(name or "").strip()
        if not clean_name: raise ValueError("Zone name is required.")
        if irrigation_method not in IRRIGATION_METHODS: raise ValueError("Invalid irrigation method.")
        if area_unit not in AREA_UNITS: raise ValueError("Invalid area unit.")
        zone=IrrigationZone(owner_id=user.id,farm_id=farm_id,name=clean_name,crop_name=_text(crop_name),crop_variety=_text(crop_variety),growth_stage=_text(growth_stage),plant_count=_integer(plant_count,"Plant count") or 0,area_value=_decimal(area_value,"Area"),area_unit=area_unit,soil_type=_text(soil_type),irrigation_method=irrigation_method,recommended_litres_per_plant=_decimal(recommended_litres_per_plant,"Recommended litres per plant"),recommended_interval_days=_integer(recommended_interval_days,"Recommended interval"),last_irrigation_date=_date(last_irrigation_date,"Last irrigation date"),next_irrigation_date=_date(next_irrigation_date,"Next irrigation date"),notes=_text(notes),is_active=is_active=="on")
        db.add(zone); db.commit()
    except (ValueError,IntegrityError) as exc:
        db.rollback(); message="A zone with this name already exists for the selected farm." if isinstance(exc,IntegrityError) else str(exc)
        return RedirectResponse(f"/irrigation/zones/new?error={quote(message)}&farm_id={farm_id}",status_code=303)
    return RedirectResponse("/irrigation/zones?success="+quote("Irrigation zone created successfully."),status_code=303)


@router.get("/irrigation/zones/{zone_id}/edit", response_class=HTMLResponse)
def zone_edit(zone_id:int,request:Request,user:User=Depends(current_irrigation_user),db:Session=Depends(get_db)):
    zone=_zone(db,user.id,zone_id); farms=list(db.scalars(select(Farm).where(Farm.owner_id==user.id).order_by(Farm.name)))
    return templates.TemplateResponse(request=request,name="irrigation/zone_form.html",context=_ctx(request,user,page_title="Edit Irrigation Zone",zone=zone,farms=farms,selected_farm_id=zone.farm_id,methods=IRRIGATION_METHODS,area_units=AREA_UNITS))


@router.post("/irrigation/zones/{zone_id}/edit")
def zone_update(zone_id:int,request:Request,farm_id:int=Form(...),name:str=Form(...),crop_name:str=Form(""),crop_variety:str=Form(""),growth_stage:str=Form(""),plant_count:str=Form("0"),area_value:str=Form(""),area_unit:str=Form("acre"),soil_type:str=Form(""),irrigation_method:str=Form("drip"),recommended_litres_per_plant:str=Form(""),recommended_interval_days:str=Form(""),last_irrigation_date:str=Form(""),next_irrigation_date:str=Form(""),notes:str=Form(""),is_active:str|None=Form(None),user:User=Depends(current_irrigation_user),db:Session=Depends(get_db)):
    zone=_zone(db,user.id,zone_id)
    try:
        _farm(db,user.id,farm_id); clean_name=(name or "").strip()
        if not clean_name: raise ValueError("Zone name is required.")
        if irrigation_method not in IRRIGATION_METHODS or area_unit not in AREA_UNITS: raise ValueError("Invalid irrigation configuration.")
        zone.farm_id=farm_id; zone.name=clean_name; zone.crop_name=_text(crop_name); zone.crop_variety=_text(crop_variety); zone.growth_stage=_text(growth_stage); zone.plant_count=_integer(plant_count,"Plant count") or 0; zone.area_value=_decimal(area_value,"Area"); zone.area_unit=area_unit; zone.soil_type=_text(soil_type); zone.irrigation_method=irrigation_method; zone.recommended_litres_per_plant=_decimal(recommended_litres_per_plant,"Recommended litres per plant"); zone.recommended_interval_days=_integer(recommended_interval_days,"Recommended interval"); zone.last_irrigation_date=_date(last_irrigation_date,"Last irrigation date"); zone.next_irrigation_date=_date(next_irrigation_date,"Next irrigation date"); zone.notes=_text(notes); zone.is_active=is_active=="on"; db.commit()
    except (ValueError,IntegrityError) as exc:
        db.rollback(); message="A zone with this name already exists for the selected farm." if isinstance(exc,IntegrityError) else str(exc)
        return RedirectResponse(f"/irrigation/zones/{zone_id}/edit?error={quote(message)}",status_code=303)
    return RedirectResponse("/irrigation/zones?success="+quote("Irrigation zone updated successfully."),status_code=303)


@router.post("/irrigation/zones/{zone_id}/delete")
def zone_delete(zone_id:int,user:User=Depends(current_irrigation_user),db:Session=Depends(get_db)):
    zone=_zone(db,user.id,zone_id)
    try: db.delete(zone); db.commit()
    except IntegrityError: db.rollback(); return RedirectResponse("/irrigation/zones?error="+quote("Zone cannot be deleted because irrigation records depend on it. Mark it inactive instead."),status_code=303)
    return RedirectResponse("/irrigation/zones?success="+quote("Irrigation zone deleted."),status_code=303)


@router.get("/irrigation/water-sources", response_class=HTMLResponse)
def source_list(request:Request,farm_id:int|None=None,user:User=Depends(current_irrigation_user),db:Session=Depends(get_db)):
    stmt=select(WaterSource,Farm).join(Farm,Farm.id==WaterSource.farm_id).where(WaterSource.owner_id==user.id,Farm.owner_id==user.id)
    if farm_id is not None: _farm(db,user.id,farm_id); stmt=stmt.where(WaterSource.farm_id==farm_id)
    rows=list(db.execute(stmt.order_by(WaterSource.is_active.desc(),WaterSource.name)).all()); farms=list(db.scalars(select(Farm).where(Farm.owner_id==user.id).order_by(Farm.name)))
    return templates.TemplateResponse(request=request,name="irrigation/sources_list.html",context=_ctx(request,user,page_title="Water Sources",rows=rows,farms=farms,selected_farm_id=farm_id))


@router.get("/irrigation/water-sources/new", response_class=HTMLResponse)
def source_new(request:Request,farm_id:int|None=None,user:User=Depends(current_irrigation_user),db:Session=Depends(get_db)):
    farms=list(db.scalars(select(Farm).where(Farm.owner_id==user.id).order_by(Farm.name)))
    return templates.TemplateResponse(request=request,name="irrigation/source_form.html",context=_ctx(request,user,page_title="Add Water Source",source=None,farms=farms,selected_farm_id=farm_id,source_types=WATER_SOURCE_TYPES,availability_statuses=AVAILABILITY_STATUSES,quality_statuses=WATER_QUALITY_STATUSES))


@router.post("/irrigation/water-sources/new")
def source_create(request:Request,farm_id:int=Form(...),name:str=Form(...),source_type:str=Form(...),capacity_litres:str=Form(""),current_level_litres:str=Form(""),flow_rate_lpm:str=Form(""),water_quality_status:str=Form("not_tested"),last_quality_test_date:str=Form(""),availability_status:str=Form("available"),notes:str=Form(""),is_active:str|None=Form(None),user:User=Depends(current_irrigation_user),db:Session=Depends(get_db)):
    try:
        _farm(db,user.id,farm_id); clean_name=(name or "").strip()
        if not clean_name: raise ValueError("Water source name is required.")
        if source_type not in WATER_SOURCE_TYPES or availability_status not in AVAILABILITY_STATUSES or water_quality_status not in WATER_QUALITY_STATUSES: raise ValueError("Invalid water source configuration.")
        capacity=_decimal(capacity_litres,"Capacity"); level=_decimal(current_level_litres,"Current level")
        if capacity is not None and level is not None and level>capacity: raise ValueError("Current water level cannot exceed capacity.")
        source=WaterSource(owner_id=user.id,farm_id=farm_id,name=clean_name,source_type=source_type,capacity_litres=capacity,current_level_litres=level,flow_rate_lpm=_decimal(flow_rate_lpm,"Flow rate"),water_quality_status=water_quality_status,last_quality_test_date=_date(last_quality_test_date,"Quality test date"),availability_status=availability_status,notes=_text(notes),is_active=is_active=="on")
        db.add(source); db.commit()
    except (ValueError,IntegrityError) as exc:
        db.rollback(); message="A water source with this name already exists for the selected farm." if isinstance(exc,IntegrityError) else str(exc)
        return RedirectResponse(f"/irrigation/water-sources/new?error={quote(message)}&farm_id={farm_id}",status_code=303)
    return RedirectResponse("/irrigation/water-sources?success="+quote("Water source created successfully."),status_code=303)


@router.get("/irrigation/water-sources/{source_id}/edit", response_class=HTMLResponse)
def source_edit(source_id:int,request:Request,user:User=Depends(current_irrigation_user),db:Session=Depends(get_db)):
    source=_source(db,user.id,source_id); farms=list(db.scalars(select(Farm).where(Farm.owner_id==user.id).order_by(Farm.name)))
    return templates.TemplateResponse(request=request,name="irrigation/source_form.html",context=_ctx(request,user,page_title="Edit Water Source",source=source,farms=farms,selected_farm_id=source.farm_id,source_types=WATER_SOURCE_TYPES,availability_statuses=AVAILABILITY_STATUSES,quality_statuses=WATER_QUALITY_STATUSES))


@router.post("/irrigation/water-sources/{source_id}/edit")
def source_update(source_id:int,request:Request,farm_id:int=Form(...),name:str=Form(...),source_type:str=Form(...),capacity_litres:str=Form(""),current_level_litres:str=Form(""),flow_rate_lpm:str=Form(""),water_quality_status:str=Form("not_tested"),last_quality_test_date:str=Form(""),availability_status:str=Form("available"),notes:str=Form(""),is_active:str|None=Form(None),user:User=Depends(current_irrigation_user),db:Session=Depends(get_db)):
    source=_source(db,user.id,source_id)
    try:
        _farm(db,user.id,farm_id); clean_name=(name or "").strip()
        if not clean_name: raise ValueError("Water source name is required.")
        if source_type not in WATER_SOURCE_TYPES or availability_status not in AVAILABILITY_STATUSES or water_quality_status not in WATER_QUALITY_STATUSES: raise ValueError("Invalid water source configuration.")
        capacity=_decimal(capacity_litres,"Capacity"); level=_decimal(current_level_litres,"Current level")
        if capacity is not None and level is not None and level>capacity: raise ValueError("Current water level cannot exceed capacity.")
        source.farm_id=farm_id; source.name=clean_name; source.source_type=source_type; source.capacity_litres=capacity; source.current_level_litres=level; source.flow_rate_lpm=_decimal(flow_rate_lpm,"Flow rate"); source.water_quality_status=water_quality_status; source.last_quality_test_date=_date(last_quality_test_date,"Quality test date"); source.availability_status=availability_status; source.notes=_text(notes); source.is_active=is_active=="on"; db.commit()
    except (ValueError,IntegrityError) as exc:
        db.rollback(); message="A water source with this name already exists for the selected farm." if isinstance(exc,IntegrityError) else str(exc)
        return RedirectResponse(f"/irrigation/water-sources/{source_id}/edit?error={quote(message)}",status_code=303)
    return RedirectResponse("/irrigation/water-sources?success="+quote("Water source updated successfully."),status_code=303)


@router.post("/irrigation/water-sources/{source_id}/delete")
def source_delete(source_id:int,user:User=Depends(current_irrigation_user),db:Session=Depends(get_db)):
    source=_source(db,user.id,source_id)
    pump_count=db.scalar(select(func.count(IrrigationPump.id)).where(IrrigationPump.owner_id==user.id,IrrigationPump.water_source_id==source.id)) or 0
    if pump_count: return RedirectResponse("/irrigation/water-sources?error="+quote("Water source is linked to a pump. Remove the link or mark the source inactive."),status_code=303)
    try: db.delete(source); db.commit()
    except IntegrityError: db.rollback(); return RedirectResponse("/irrigation/water-sources?error="+quote("Water source cannot be deleted because irrigation records depend on it. Mark it inactive instead."),status_code=303)
    return RedirectResponse("/irrigation/water-sources?success="+quote("Water source deleted."),status_code=303)



def _pump(db: Session, owner_id: int, pump_id: int) -> IrrigationPump:
    pump = db.scalar(select(IrrigationPump).where(IrrigationPump.id == pump_id, IrrigationPump.owner_id == owner_id))
    if not pump:
        raise HTTPException(status_code=404, detail="Pump not found")
    return pump


def _equipment(db: Session, owner_id: int, equipment_id: int) -> IrrigationEquipment:
    item = db.scalar(select(IrrigationEquipment).where(IrrigationEquipment.id == equipment_id, IrrigationEquipment.owner_id == owner_id))
    if not item:
        raise HTTPException(status_code=404, detail="Equipment not found")
    return item


@router.get("/irrigation/pumps", response_class=HTMLResponse)
def pump_list(request: Request, farm_id: int | None = None, user: User = Depends(current_irrigation_user), db: Session = Depends(get_db)):
    stmt = select(IrrigationPump, Farm, WaterSource).join(Farm, Farm.id == IrrigationPump.farm_id).outerjoin(WaterSource, WaterSource.id == IrrigationPump.water_source_id).where(IrrigationPump.owner_id == user.id, Farm.owner_id == user.id)
    if farm_id is not None:
        _farm(db, user.id, farm_id); stmt = stmt.where(IrrigationPump.farm_id == farm_id)
    rows = list(db.execute(stmt.order_by(IrrigationPump.name)).all())
    farms = list(db.scalars(select(Farm).where(Farm.owner_id == user.id).order_by(Farm.name)))
    return templates.TemplateResponse(request=request, name="irrigation/pumps_list.html", context=_ctx(request,user,page_title="Pumps",rows=rows,farms=farms,selected_farm_id=farm_id))


@router.get("/irrigation/pumps/new", response_class=HTMLResponse)
def pump_new(request: Request, farm_id: int | None = None, user: User = Depends(current_irrigation_user), db: Session = Depends(get_db)):
    farms=list(db.scalars(select(Farm).where(Farm.owner_id==user.id).order_by(Farm.name)))
    sources=list(db.scalars(select(WaterSource).where(WaterSource.owner_id==user.id).order_by(WaterSource.name)))
    return templates.TemplateResponse(request=request,name="irrigation/pump_form.html",context=_ctx(request,user,page_title="Add Pump",pump=None,farms=farms,sources=sources,selected_farm_id=farm_id,pump_types=PUMP_TYPES,power_sources=POWER_SOURCES,statuses=PUMP_STATUSES))


@router.post("/irrigation/pumps/new")
def pump_create(farm_id:int=Form(...),water_source_id:str=Form(""),name:str=Form(...),pump_type:str=Form(""),horsepower:str=Form(""),flow_rate_lpm:str=Form(""),power_source:str=Form(""),operating_cost_per_hour:str=Form(""),installation_date:str=Form(""),last_service_date:str=Form(""),next_service_date:str=Form(""),status:str=Form("available"),fault_details:str=Form(""),user:User=Depends(current_irrigation_user),db:Session=Depends(get_db)):
    try:
        _farm(db,user.id,farm_id); clean=(name or "").strip()
        if not clean: raise ValueError("Pump name is required.")
        if pump_type and pump_type not in PUMP_TYPES: raise ValueError("Invalid pump type.")
        if power_source and power_source not in POWER_SOURCES: raise ValueError("Invalid power source.")
        if status not in PUMP_STATUSES: raise ValueError("Invalid pump status.")
        source_id=_integer(water_source_id,"Water source")
        if source_id:
            src=_source(db,user.id,source_id)
            if src.farm_id != farm_id: raise ValueError("Water source must belong to the selected farm.")
        pump=IrrigationPump(owner_id=user.id,farm_id=farm_id,water_source_id=source_id,name=clean,pump_type=_text(pump_type),horsepower=_decimal(horsepower,"Horsepower"),flow_rate_lpm=_decimal(flow_rate_lpm,"Flow rate"),power_source=_text(power_source),operating_cost_per_hour=_decimal(operating_cost_per_hour,"Operating cost"),installation_date=_date(installation_date,"Installation date"),last_service_date=_date(last_service_date,"Last service date"),next_service_date=_date(next_service_date,"Next service date"),status=status,fault_details=_text(fault_details))
        db.add(pump); db.commit()
    except (ValueError,IntegrityError) as exc:
        db.rollback(); msg="A pump with this name already exists for the selected farm." if isinstance(exc,IntegrityError) else str(exc)
        return RedirectResponse(f"/irrigation/pumps/new?error={quote(msg)}&farm_id={farm_id}",status_code=303)
    return RedirectResponse("/irrigation/pumps?success="+quote("Pump created successfully."),status_code=303)


@router.get("/irrigation/pumps/{pump_id}/edit", response_class=HTMLResponse)
def pump_edit(pump_id:int,request:Request,user:User=Depends(current_irrigation_user),db:Session=Depends(get_db)):
    pump=_pump(db,user.id,pump_id); farms=list(db.scalars(select(Farm).where(Farm.owner_id==user.id).order_by(Farm.name))); sources=list(db.scalars(select(WaterSource).where(WaterSource.owner_id==user.id).order_by(WaterSource.name)))
    return templates.TemplateResponse(request=request,name="irrigation/pump_form.html",context=_ctx(request,user,page_title="Edit Pump",pump=pump,farms=farms,sources=sources,selected_farm_id=pump.farm_id,pump_types=PUMP_TYPES,power_sources=POWER_SOURCES,statuses=PUMP_STATUSES))


@router.post("/irrigation/pumps/{pump_id}/edit")
def pump_update(pump_id:int,farm_id:int=Form(...),water_source_id:str=Form(""),name:str=Form(...),pump_type:str=Form(""),horsepower:str=Form(""),flow_rate_lpm:str=Form(""),power_source:str=Form(""),operating_cost_per_hour:str=Form(""),installation_date:str=Form(""),last_service_date:str=Form(""),next_service_date:str=Form(""),status:str=Form("available"),fault_details:str=Form(""),user:User=Depends(current_irrigation_user),db:Session=Depends(get_db)):
    pump=_pump(db,user.id,pump_id)
    try:
        _farm(db,user.id,farm_id); clean=(name or "").strip()
        if not clean: raise ValueError("Pump name is required.")
        if pump_type and pump_type not in PUMP_TYPES or power_source and power_source not in POWER_SOURCES or status not in PUMP_STATUSES: raise ValueError("Invalid pump configuration.")
        source_id=_integer(water_source_id,"Water source")
        if source_id:
            src=_source(db,user.id,source_id)
            if src.farm_id != farm_id: raise ValueError("Water source must belong to the selected farm.")
        pump.farm_id=farm_id; pump.water_source_id=source_id; pump.name=clean; pump.pump_type=_text(pump_type); pump.horsepower=_decimal(horsepower,"Horsepower"); pump.flow_rate_lpm=_decimal(flow_rate_lpm,"Flow rate"); pump.power_source=_text(power_source); pump.operating_cost_per_hour=_decimal(operating_cost_per_hour,"Operating cost"); pump.installation_date=_date(installation_date,"Installation date"); pump.last_service_date=_date(last_service_date,"Last service date"); pump.next_service_date=_date(next_service_date,"Next service date"); pump.status=status; pump.fault_details=_text(fault_details); db.commit()
    except (ValueError,IntegrityError) as exc:
        db.rollback(); msg="A pump with this name already exists for the selected farm." if isinstance(exc,IntegrityError) else str(exc)
        return RedirectResponse(f"/irrigation/pumps/{pump_id}/edit?error={quote(msg)}",status_code=303)
    return RedirectResponse("/irrigation/pumps?success="+quote("Pump updated successfully."),status_code=303)


@router.post("/irrigation/pumps/{pump_id}/delete")
def pump_delete(pump_id:int,user:User=Depends(current_irrigation_user),db:Session=Depends(get_db)):
    pump=_pump(db,user.id,pump_id)
    deps=(db.scalar(select(func.count(IrrigationEquipment.id)).where(IrrigationEquipment.owner_id==user.id,IrrigationEquipment.pump_id==pump.id)) or 0)+(db.scalar(select(func.count(PumpMaintenanceRecord.id)).where(PumpMaintenanceRecord.owner_id==user.id,PumpMaintenanceRecord.pump_id==pump.id)) or 0)+(db.scalar(select(func.count(PumpRuntimeLog.id)).where(PumpRuntimeLog.owner_id==user.id,PumpRuntimeLog.pump_id==pump.id)) or 0)
    if deps: return RedirectResponse("/irrigation/pumps?error="+quote("Pump has equipment, maintenance or runtime records. Mark it offline instead."),status_code=303)
    try: db.delete(pump); db.commit()
    except IntegrityError: db.rollback(); return RedirectResponse("/irrigation/pumps?error="+quote("Pump cannot be deleted because irrigation records depend on it."),status_code=303)
    return RedirectResponse("/irrigation/pumps?success="+quote("Pump deleted."),status_code=303)


@router.get("/irrigation/equipment", response_class=HTMLResponse)
def equipment_list(request:Request,farm_id:int|None=None,user:User=Depends(current_irrigation_user),db:Session=Depends(get_db)):
    stmt=select(IrrigationEquipment,Farm,IrrigationPump).join(Farm,Farm.id==IrrigationEquipment.farm_id).outerjoin(IrrigationPump,IrrigationPump.id==IrrigationEquipment.pump_id).where(IrrigationEquipment.owner_id==user.id,Farm.owner_id==user.id)
    if farm_id is not None: _farm(db,user.id,farm_id); stmt=stmt.where(IrrigationEquipment.farm_id==farm_id)
    rows=list(db.execute(stmt.order_by(IrrigationEquipment.name)).all()); farms=list(db.scalars(select(Farm).where(Farm.owner_id==user.id).order_by(Farm.name)))
    return templates.TemplateResponse(request=request,name="irrigation/equipment_list.html",context=_ctx(request,user,page_title="Irrigation Equipment",rows=rows,farms=farms,selected_farm_id=farm_id))


@router.get("/irrigation/equipment/new", response_class=HTMLResponse)
def equipment_new(request:Request,farm_id:int|None=None,user:User=Depends(current_irrigation_user),db:Session=Depends(get_db)):
    farms=list(db.scalars(select(Farm).where(Farm.owner_id==user.id).order_by(Farm.name))); zones=list(db.scalars(select(IrrigationZone).where(IrrigationZone.owner_id==user.id).order_by(IrrigationZone.name))); pumps=list(db.scalars(select(IrrigationPump).where(IrrigationPump.owner_id==user.id).order_by(IrrigationPump.name)))
    return templates.TemplateResponse(request=request,name="irrigation/equipment_form.html",context=_ctx(request,user,page_title="Add Equipment",item=None,farms=farms,zones=zones,pumps=pumps,selected_farm_id=farm_id,types=EQUIPMENT_TYPES,statuses=EQUIPMENT_STATUSES))


@router.post("/irrigation/equipment/new")
def equipment_create(farm_id:int=Form(...),zone_id:str=Form(""),pump_id:str=Form(""),name:str=Form(...),equipment_type:str=Form(...),manufacturer:str=Form(""),model_number:str=Form(""),serial_number:str=Form(""),installation_date:str=Form(""),purchase_cost:str=Form(""),status:str=Form("available"),last_service_date:str=Form(""),next_service_date:str=Form(""),notes:str=Form(""),is_active:str|None=Form(None),user:User=Depends(current_irrigation_user),db:Session=Depends(get_db)):
    try:
        _farm(db,user.id,farm_id); clean=(name or "").strip()
        if not clean: raise ValueError("Equipment name is required.")
        if equipment_type not in EQUIPMENT_TYPES or status not in EQUIPMENT_STATUSES: raise ValueError("Invalid equipment configuration.")
        zid=_integer(zone_id,"Zone"); pid=_integer(pump_id,"Pump")
        if zid and _zone(db,user.id,zid).farm_id!=farm_id: raise ValueError("Zone must belong to the selected farm.")
        if pid and _pump(db,user.id,pid).farm_id!=farm_id: raise ValueError("Pump must belong to the selected farm.")
        item=IrrigationEquipment(owner_id=user.id,farm_id=farm_id,zone_id=zid,pump_id=pid,name=clean,equipment_type=equipment_type,manufacturer=_text(manufacturer),model_number=_text(model_number),serial_number=_text(serial_number),installation_date=_date(installation_date,"Installation date"),purchase_cost=_decimal(purchase_cost,"Purchase cost"),status=status,last_service_date=_date(last_service_date,"Last service date"),next_service_date=_date(next_service_date,"Next service date"),notes=_text(notes),is_active=is_active=="on")
        db.add(item); db.commit()
    except (ValueError,IntegrityError) as exc:
        db.rollback(); msg="Equipment with this name already exists for the selected farm." if isinstance(exc,IntegrityError) else str(exc)
        return RedirectResponse(f"/irrigation/equipment/new?error={quote(msg)}&farm_id={farm_id}",status_code=303)
    return RedirectResponse("/irrigation/equipment?success="+quote("Equipment created successfully."),status_code=303)


@router.get("/irrigation/pumps/{pump_id}/maintenance", response_class=HTMLResponse)
def maintenance_list(pump_id:int,request:Request,user:User=Depends(current_irrigation_user),db:Session=Depends(get_db)):
    pump=_pump(db,user.id,pump_id); rows=list(db.scalars(select(PumpMaintenanceRecord).where(PumpMaintenanceRecord.owner_id==user.id,PumpMaintenanceRecord.pump_id==pump.id).order_by(PumpMaintenanceRecord.service_date.desc())))
    return templates.TemplateResponse(request=request,name="irrigation/maintenance.html",context=_ctx(request,user,page_title=f"{pump.name} Maintenance",pump=pump,rows=rows,service_types=SERVICE_TYPES))


@router.post("/irrigation/pumps/{pump_id}/maintenance")
def maintenance_create(pump_id:int,service_date:str=Form(...),service_type:str=Form(...),technician:str=Form(""),cost:str=Form(""),next_service_date:str=Form(""),work_performed:str=Form(""),parts_replaced:str=Form(""),notes:str=Form(""),user:User=Depends(current_irrigation_user),db:Session=Depends(get_db)):
    pump=_pump(db,user.id,pump_id)
    try:
        if service_type not in SERVICE_TYPES: raise ValueError("Invalid service type.")
        sd=_date(service_date,"Service date")
        if not sd: raise ValueError("Service date is required.")
        nxt=_date(next_service_date,"Next service date")
        if nxt and nxt<sd: raise ValueError("Next service date cannot be before service date.")
        row=PumpMaintenanceRecord(owner_id=user.id,farm_id=pump.farm_id,pump_id=pump.id,service_date=sd,service_type=service_type,technician=_text(technician),cost=_decimal(cost,"Cost"),next_service_date=nxt,work_performed=_text(work_performed),parts_replaced=_text(parts_replaced),notes=_text(notes)); db.add(row); pump.last_service_date=sd; pump.next_service_date=nxt; db.commit()
    except ValueError as exc:
        db.rollback(); return RedirectResponse(f"/irrigation/pumps/{pump_id}/maintenance?error={quote(str(exc))}",status_code=303)
    return RedirectResponse(f"/irrigation/pumps/{pump_id}/maintenance?success="+quote("Maintenance record added."),status_code=303)


@router.get("/irrigation/pumps/{pump_id}/runtime", response_class=HTMLResponse)
def runtime_list(pump_id:int,request:Request,user:User=Depends(current_irrigation_user),db:Session=Depends(get_db)):
    pump=_pump(db,user.id,pump_id); rows=list(db.scalars(select(PumpRuntimeLog).where(PumpRuntimeLog.owner_id==user.id,PumpRuntimeLog.pump_id==pump.id).order_by(PumpRuntimeLog.run_date.desc()).limit(100)))
    total_minutes=db.scalar(select(func.coalesce(func.sum(PumpRuntimeLog.runtime_minutes),0)).where(PumpRuntimeLog.owner_id==user.id,PumpRuntimeLog.pump_id==pump.id)) or 0
    return templates.TemplateResponse(request=request,name="irrigation/runtime.html",context=_ctx(request,user,page_title=f"{pump.name} Runtime",pump=pump,rows=rows,total_minutes=total_minutes))


@router.post("/irrigation/pumps/{pump_id}/runtime")
def runtime_create(pump_id:int,run_date:str=Form(...),runtime_minutes:str=Form(...),energy_kwh:str=Form(""),fuel_litres:str=Form(""),water_pumped_litres:str=Form(""),operating_cost:str=Form(""),notes:str=Form(""),user:User=Depends(current_irrigation_user),db:Session=Depends(get_db)):
    pump=_pump(db,user.id,pump_id)
    try:
        rd=_date(run_date,"Run date"); minutes=_integer(runtime_minutes,"Runtime",allow_zero=False)
        if not rd or not minutes: raise ValueError("Run date and runtime are required.")
        row=PumpRuntimeLog(owner_id=user.id,farm_id=pump.farm_id,pump_id=pump.id,run_date=rd,runtime_minutes=minutes,energy_kwh=_decimal(energy_kwh,"Energy"),fuel_litres=_decimal(fuel_litres,"Fuel"),water_pumped_litres=_decimal(water_pumped_litres,"Water pumped"),operating_cost=_decimal(operating_cost,"Operating cost"),notes=_text(notes)); db.add(row); db.commit()
    except ValueError as exc:
        db.rollback(); return RedirectResponse(f"/irrigation/pumps/{pump_id}/runtime?error={quote(str(exc))}",status_code=303)
    return RedirectResponse(f"/irrigation/pumps/{pump_id}/runtime?success="+quote("Runtime log added."),status_code=303)


# PATCH-IRR-005: SMART IRRIGATION SCHEDULER & CALENDAR
def _scheduler_options(db: Session, owner_id: int):
    farms = list(db.scalars(select(Farm).where(Farm.owner_id == owner_id).order_by(Farm.name)))
    zones = list(db.scalars(select(IrrigationZone).where(IrrigationZone.owner_id == owner_id, IrrigationZone.is_active.is_(True)).order_by(IrrigationZone.name)))
    sources = list(db.scalars(select(WaterSource).where(WaterSource.owner_id == owner_id, WaterSource.is_active.is_(True)).order_by(WaterSource.name)))
    pumps = list(db.scalars(select(IrrigationPump).where(IrrigationPump.owner_id == owner_id).order_by(IrrigationPump.name)))
    return farms, zones, sources, pumps


@router.get("/irrigation/schedules", response_class=HTMLResponse)
def schedule_calendar(request: Request, month: str | None = None, farm_id: int | None = None,
                      user: User = Depends(current_irrigation_user), db: Session = Depends(get_db)):
    try:
        month_start = datetime.strptime(month, "%Y-%m").date().replace(day=1) if month else date.today().replace(day=1)
    except ValueError:
        month_start = date.today().replace(day=1)
    next_month = (month_start.replace(day=28) + timedelta(days=4)).replace(day=1)
    month_end = next_month - timedelta(days=1)
    stmt = select(IrrigationSchedule, IrrigationZone, Farm, IrrigationPump).join(
        IrrigationZone, IrrigationZone.id == IrrigationSchedule.zone_id
    ).join(Farm, Farm.id == IrrigationSchedule.farm_id).outerjoin(
        IrrigationPump, IrrigationPump.id == IrrigationSchedule.pump_id
    ).where(
        IrrigationSchedule.owner_id == user.id,
        IrrigationZone.owner_id == user.id,
        Farm.owner_id == user.id,
        IrrigationSchedule.scheduled_date.between(month_start, month_end),
    )
    if farm_id:
        _farm(db, user.id, farm_id)
        stmt = stmt.where(IrrigationSchedule.farm_id == farm_id)
    rows = list(db.execute(stmt.order_by(IrrigationSchedule.scheduled_date, IrrigationSchedule.scheduled_start_time)).all())
    by_day: dict[int, list] = {}
    for row in rows:
        by_day.setdefault(row[0].scheduled_date.day, []).append(row)
    leading = month_start.weekday()
    cells = [None] * leading + list(range(1, month_end.day + 1))
    while len(cells) % 7:
        cells.append(None)
    weeks = [cells[index:index + 7] for index in range(0, len(cells), 7)]
    farms, zones, sources, pumps = _scheduler_options(db, user.id)
    today = date.today()
    upcoming = [row for row in rows if row[0].scheduled_date >= today and row[0].status not in ("completed", "cancelled")][:8]
    counts = {status: sum(1 for row in rows if row[0].status == status) for status in SCHEDULE_STATUSES}
    return templates.TemplateResponse(request=request, name="irrigation/schedule_calendar.html", context=_ctx(
        request, user, page_title="Irrigation Scheduler", rows=rows, by_day=by_day, weeks=weeks,
        month_start=month_start, previous_month=(month_start - timedelta(days=1)).strftime("%Y-%m"),
        next_month=next_month.strftime("%Y-%m"), farms=farms, zones=zones, sources=sources,
        pumps=pumps, selected_farm_id=farm_id, upcoming=upcoming, counts=counts, today=today,
    ))


@router.get("/irrigation/schedules/new", response_class=HTMLResponse)
def schedule_new(request: Request, zone_id: int | None = None, scheduled_date: str | None = None,
                 user: User = Depends(current_irrigation_user), db: Session = Depends(get_db)):
    farms, zones, sources, pumps = _scheduler_options(db, user.id)
    selected_zone = _zone(db, user.id, zone_id) if zone_id else None
    return templates.TemplateResponse(request=request, name="irrigation/schedule_form.html", context=_ctx(
        request, user, page_title="Create Irrigation Schedule", schedule=None, farms=farms, zones=zones,
        sources=sources, pumps=pumps, selected_zone=selected_zone, selected_date=scheduled_date or date.today().isoformat(),
        statuses=SCHEDULE_STATUSES, recurrence_types=RECURRENCE_TYPES,
    ))


@router.post("/irrigation/schedules/new")
def schedule_create(farm_id: int = Form(...), zone_id: int = Form(...), water_source_id: str = Form(""),
                    pump_id: str = Form(""), scheduled_date: str = Form(...), scheduled_start_time: str = Form(""),
                    planned_litres: str = Form(""), estimated_duration_minutes: str = Form(""),
                    assigned_worker: str = Form(""), status: str = Form("planned"), instructions: str = Form(""),
                    recurrence_type: str = Form("none"), recurrence_interval: str = Form("1"),
                    recurrence_end_date: str = Form(""), fertigation_required: str | None = Form(None),
                    user: User = Depends(current_irrigation_user), db: Session = Depends(get_db)):
    try:
        _farm(db, user.id, farm_id)
        zone = _zone(db, user.id, zone_id)
        if zone.farm_id != farm_id:
            raise ValueError("Zone must belong to the selected farm.")
        source_id = _integer(water_source_id, "Water source")
        source = _source(db, user.id, source_id) if source_id else None
        selected_pump_id = _integer(pump_id, "Pump")
        pump = _pump(db, user.id, selected_pump_id) if selected_pump_id else None
        if source and source.farm_id != farm_id:
            raise ValueError("Water source must belong to the selected farm.")
        if pump and pump.farm_id != farm_id:
            raise ValueError("Pump must belong to the selected farm.")
        if status not in SCHEDULE_STATUSES or recurrence_type not in RECURRENCE_TYPES:
            raise ValueError("Invalid scheduler configuration.")
        start_date = _date(scheduled_date, "Scheduled date")
        if not start_date:
            raise ValueError("Scheduled date is required.")
        start_time = _clock(scheduled_start_time, "Start time")
        duration = _integer(estimated_duration_minutes, "Estimated duration", allow_zero=False)
        if not start_time or not duration:
            raise ValueError("Start time and estimated duration are required.")
        interval = _integer(recurrence_interval, "Recurrence interval", allow_zero=False) or 1
        end_date = _date(recurrence_end_date, "Recurrence end date")
        dates = _recurring_dates(start_date, recurrence_type, interval, end_date)
        worker = _text(assigned_worker)
        conflicts: list[str] = []
        for occurrence in dates:
            conflicts.extend(_schedule_conflicts(db, user.id, scheduled_date=occurrence, start_time=start_time,
                duration=duration, zone_id=zone_id, pump_id=selected_pump_id, assigned_worker=worker))
        if conflicts:
            alert = IrrigationAlert(owner_id=user.id, farm_id=farm_id, zone_id=zone_id, alert_type="schedule_conflict",
                severity="warning", title="Irrigation scheduling conflict", message=" ".join(conflicts[:5]), status="open")
            db.add(alert); db.commit()
            raise ValueError("Conflict detected: " + " ".join(conflicts[:3]))
        group_id = uuid4().hex if len(dates) > 1 else None
        for occurrence in dates:
            db.add(IrrigationSchedule(owner_id=user.id, farm_id=farm_id, zone_id=zone_id,
                water_source_id=source_id, pump_id=selected_pump_id, scheduled_date=occurrence,
                scheduled_start_time=start_time, planned_litres=_decimal(planned_litres, "Planned litres"),
                estimated_duration_minutes=duration, assigned_worker=worker, status=status,
                instructions=_text(instructions), recurrence_type=recurrence_type, recurrence_interval=interval,
                recurrence_end_date=end_date, recurrence_group_id=group_id,
                fertigation_required=fertigation_required == "on"))
        db.commit()
    except (ValueError, IntegrityError) as exc:
        if not (isinstance(exc, ValueError) and str(exc).startswith("Conflict detected:")):
            db.rollback()
        return RedirectResponse("/irrigation/schedules/new?error=" + quote(str(exc)), status_code=303)
    return RedirectResponse("/irrigation/schedules?success=" + quote(f"Created {len(dates)} irrigation schedule(s)."), status_code=303)


@router.get("/irrigation/schedules/{schedule_id}/edit", response_class=HTMLResponse)
def schedule_edit(schedule_id: int, request: Request, user: User = Depends(current_irrigation_user), db: Session = Depends(get_db)):
    schedule = _schedule(db, user.id, schedule_id)
    farms, zones, sources, pumps = _scheduler_options(db, user.id)
    return templates.TemplateResponse(request=request, name="irrigation/schedule_form.html", context=_ctx(
        request, user, page_title="Edit Irrigation Schedule", schedule=schedule, farms=farms, zones=zones,
        sources=sources, pumps=pumps, selected_zone=_zone(db, user.id, schedule.zone_id), selected_date=None,
        statuses=SCHEDULE_STATUSES, recurrence_types=RECURRENCE_TYPES,
    ))


@router.post("/irrigation/schedules/{schedule_id}/edit")
def schedule_update(schedule_id: int, farm_id: int = Form(...), zone_id: int = Form(...), water_source_id: str = Form(""),
                    pump_id: str = Form(""), scheduled_date: str = Form(...), scheduled_start_time: str = Form(""),
                    planned_litres: str = Form(""), estimated_duration_minutes: str = Form(""), assigned_worker: str = Form(""),
                    status: str = Form("planned"), instructions: str = Form(""), fertigation_required: str | None = Form(None),
                    user: User = Depends(current_irrigation_user), db: Session = Depends(get_db)):
    item = _schedule(db, user.id, schedule_id)
    try:
        _farm(db, user.id, farm_id); zone = _zone(db, user.id, zone_id)
        if zone.farm_id != farm_id or status not in SCHEDULE_STATUSES:
            raise ValueError("Invalid farm, zone or status.")
        source_id = _integer(water_source_id, "Water source"); pump_id_value = _integer(pump_id, "Pump")
        if source_id and _source(db, user.id, source_id).farm_id != farm_id:
            raise ValueError("Water source must belong to the selected farm.")
        if pump_id_value and _pump(db, user.id, pump_id_value).farm_id != farm_id:
            raise ValueError("Pump must belong to the selected farm.")
        day = _date(scheduled_date, "Scheduled date"); start = _clock(scheduled_start_time, "Start time")
        duration = _integer(estimated_duration_minutes, "Estimated duration", allow_zero=False)
        if not day or not start or not duration:
            raise ValueError("Date, start time and duration are required.")
        worker = _text(assigned_worker)
        conflicts = _schedule_conflicts(db, user.id, scheduled_date=day, start_time=start, duration=duration,
            zone_id=zone_id, pump_id=pump_id_value, assigned_worker=worker, exclude_id=item.id)
        if conflicts:
            raise ValueError("Conflict detected: " + " ".join(conflicts[:3]))
        item.farm_id=farm_id; item.zone_id=zone_id; item.water_source_id=source_id; item.pump_id=pump_id_value
        item.scheduled_date=day; item.scheduled_start_time=start; item.planned_litres=_decimal(planned_litres,"Planned litres")
        item.estimated_duration_minutes=duration; item.assigned_worker=worker; item.status=status
        item.instructions=_text(instructions); item.fertigation_required=fertigation_required == "on"; db.commit()
    except (ValueError, IntegrityError) as exc:
        db.rollback(); return RedirectResponse(f"/irrigation/schedules/{schedule_id}/edit?error=" + quote(str(exc)), status_code=303)
    return RedirectResponse("/irrigation/schedules?success=" + quote("Schedule updated."), status_code=303)


@router.post("/irrigation/schedules/{schedule_id}/status")
def schedule_status(schedule_id: int, status: str = Form(...), user: User = Depends(current_irrigation_user), db: Session = Depends(get_db)):
    item = _schedule(db, user.id, schedule_id)
    if status not in SCHEDULE_STATUSES:
        raise HTTPException(status_code=400, detail="Invalid schedule status")
    item.status = status; db.commit()
    return RedirectResponse("/irrigation/schedules?success=" + quote("Schedule status updated."), status_code=303)


@router.post("/irrigation/schedules/{schedule_id}/delete")
def schedule_delete(schedule_id: int, series: str | None = Form(None), user: User = Depends(current_irrigation_user), db: Session = Depends(get_db)):
    item = _schedule(db, user.id, schedule_id)
    if series == "on" and item.recurrence_group_id:
        items = list(db.scalars(select(IrrigationSchedule).where(IrrigationSchedule.owner_id == user.id,
            IrrigationSchedule.recurrence_group_id == item.recurrence_group_id, IrrigationSchedule.scheduled_date >= item.scheduled_date)))
    else:
        items = [item]
    try:
        for row in items: db.delete(row)
        db.commit()
    except IntegrityError:
        db.rollback(); return RedirectResponse("/irrigation/schedules?error=" + quote("Schedule has dependent execution records and cannot be deleted."), status_code=303)
    return RedirectResponse("/irrigation/schedules?success=" + quote(f"Deleted {len(items)} schedule(s)."), status_code=303)


@router.get("/irrigation/schedules/report", response_class=HTMLResponse)
def schedule_report(request: Request, date_from: str | None = None, date_to: str | None = None,
                    user: User = Depends(current_irrigation_user), db: Session = Depends(get_db)):
    start = _date(date_from, "From date") if date_from else date.today().replace(day=1)
    end = _date(date_to, "To date") if date_to else date.today()
    rows = list(db.execute(select(IrrigationSchedule, IrrigationZone, Farm, IrrigationPump).join(
        IrrigationZone, IrrigationZone.id == IrrigationSchedule.zone_id).join(Farm, Farm.id == IrrigationSchedule.farm_id).outerjoin(
        IrrigationPump, IrrigationPump.id == IrrigationSchedule.pump_id).where(
        IrrigationSchedule.owner_id == user.id, IrrigationSchedule.scheduled_date.between(start, end),
        IrrigationZone.owner_id == user.id, Farm.owner_id == user.id).order_by(IrrigationSchedule.scheduled_date)).all())
    total_litres = sum((row[0].planned_litres or Decimal("0") for row in rows), Decimal("0"))
    total_minutes = sum((row[0].estimated_duration_minutes or 0 for row in rows))
    return templates.TemplateResponse(request=request, name="irrigation/schedule_report.html", context=_ctx(
        request, user, page_title="Irrigation Schedule Report", rows=rows, start=start, end=end,
        total_litres=total_litres, total_minutes=total_minutes,
        completed=sum(1 for row in rows if row[0].status == "completed"),
    ))


# PATCH-IRR-006: IRRIGATION EXECUTION & FIELD OPERATIONS
def _execution_rows(db: Session, owner_id: int):
    return select(IrrigationExecution, IrrigationSchedule, IrrigationZone, Farm, IrrigationPump).join(
        IrrigationSchedule, IrrigationSchedule.id == IrrigationExecution.schedule_id
    ).join(IrrigationZone, IrrigationZone.id == IrrigationSchedule.zone_id).join(
        Farm, Farm.id == IrrigationSchedule.farm_id
    ).outerjoin(IrrigationPump, IrrigationPump.id == IrrigationSchedule.pump_id).where(
        IrrigationExecution.owner_id == owner_id, IrrigationSchedule.owner_id == owner_id,
        IrrigationZone.owner_id == owner_id, Farm.owner_id == owner_id,
    )


@router.get("/irrigation/executions", response_class=HTMLResponse)
def execution_dashboard(request: Request, user: User = Depends(current_irrigation_user), db: Session = Depends(get_db)):
    rows = list(db.execute(_execution_rows(db, user.id).order_by(IrrigationExecution.created_at.desc()).limit(250)).all())
    active = [row for row in rows if row[0].status in ("in_progress", "paused")]
    completed = [row for row in rows if row[0].status in ("completed", "approved")]
    water = sum((row[0].actual_water_litres or Decimal("0") for row in completed), Decimal("0"))
    issues = sum(1 for row in rows if row[0].leakage_reported or row[0].pump_issue_reported)
    pending_approval = sum(1 for row in rows if row[0].status == "completed" and not row[0].supervisor_approved_at)
    return templates.TemplateResponse(request=request, name="irrigation/execution_dashboard.html", context=_ctx(
        request, user, page_title="Irrigation Field Operations", rows=rows, active=active,
        completed=completed[:20], water=water, issues=issues, pending_approval=pending_approval,
    ))


@router.get("/irrigation/executions/report", response_class=HTMLResponse)
def execution_report(request: Request, date_from: str | None = None, date_to: str | None = None,
                     user: User = Depends(current_irrigation_user), db: Session = Depends(get_db)):
    try:
        start = _date(date_from, "From date") if date_from else date.today().replace(day=1)
        end = _date(date_to, "To date") if date_to else date.today()
        if start and end and end < start:
            raise ValueError("To date cannot be before from date.")
    except ValueError as exc:
        start = date.today().replace(day=1); end = date.today(); error = str(exc)
    else:
        error = None
    stmt = _execution_rows(db, user.id).where(IrrigationSchedule.scheduled_date.between(start, end))
    rows = list(db.execute(stmt.order_by(IrrigationSchedule.scheduled_date.desc())).all())
    planned_water = sum((row[1].planned_litres or Decimal("0") for row in rows), Decimal("0"))
    actual_water = sum((row[0].actual_water_litres or Decimal("0") for row in rows), Decimal("0"))
    planned_minutes = sum((row[1].estimated_duration_minutes or 0 for row in rows))
    actual_minutes = sum((row[0].actual_duration_minutes or 0 for row in rows))
    return templates.TemplateResponse(request=request, name="irrigation/execution_report.html", context=_ctx(
        request, user, page_title="Irrigation Execution Report", rows=rows, start=start, end=end,
        planned_water=planned_water, actual_water=actual_water, planned_minutes=planned_minutes,
        actual_minutes=actual_minutes, error_message=error,
    ))


@router.get("/irrigation/schedules/{schedule_id}/execute", response_class=HTMLResponse)
def execution_field_page(schedule_id: int, request: Request, user: User = Depends(current_irrigation_user), db: Session = Depends(get_db)):
    schedule = _schedule(db, user.id, schedule_id)
    zone = _zone(db, user.id, schedule.zone_id); farm = _farm(db, user.id, schedule.farm_id)
    pump = _pump(db, user.id, schedule.pump_id) if schedule.pump_id else None
    execution = db.scalar(select(IrrigationExecution).where(IrrigationExecution.owner_id == user.id, IrrigationExecution.schedule_id == schedule.id))
    return templates.TemplateResponse(request=request, name="irrigation/execution_field.html", context=_ctx(
        request, user, page_title="Field Irrigation", schedule=schedule, execution=execution,
        zone=zone, farm=farm, pump=pump, now=_utcnow(),
    ))


@router.post("/irrigation/schedules/{schedule_id}/execute/start")
def execution_start(schedule_id: int, request: Request, opening_meter_reading: str = Form(""),
                    opening_tank_level_litres: str = Form(""), worker_remarks: str = Form(""),
                    user: User = Depends(current_irrigation_user), db: Session = Depends(get_db)):
    schedule = _schedule(db, user.id, schedule_id)
    existing = db.scalar(select(IrrigationExecution).where(IrrigationExecution.owner_id == user.id, IrrigationExecution.schedule_id == schedule.id))
    if existing:
        return RedirectResponse(f"/irrigation/schedules/{schedule_id}/execute?error=" + quote("Execution already exists for this schedule."), status_code=303)
    if schedule.status in ("completed", "cancelled"):
        return RedirectResponse(f"/irrigation/schedules/{schedule_id}/execute?error=" + quote("Completed or cancelled schedules cannot be started."), status_code=303)
    try:
        execution = IrrigationExecution(owner_id=user.id, farm_id=schedule.farm_id, schedule_id=schedule.id,
            status="in_progress", started_at=_utcnow(), opening_meter_reading=_decimal(opening_meter_reading, "Opening meter reading"),
            opening_tank_level_litres=_decimal(opening_tank_level_litres, "Opening tank level"), worker_remarks=_text(worker_remarks))
        db.add(execution); schedule.status = "in_progress"
        if schedule.pump_id:
            _pump(db, user.id, schedule.pump_id).status = "running"
        _irrigation_audit(db, request, user, "irrigation_execution_started", f"schedule_id={schedule.id}")
        db.commit()
    except (ValueError, IntegrityError) as exc:
        db.rollback(); return RedirectResponse(f"/irrigation/schedules/{schedule_id}/execute?error=" + quote(str(exc)), status_code=303)
    return RedirectResponse(f"/irrigation/schedules/{schedule_id}/execute?success=" + quote("Irrigation started."), status_code=303)


@router.post("/irrigation/executions/{execution_id}/pause")
def execution_pause(execution_id: int, request: Request, user: User = Depends(current_irrigation_user), db: Session = Depends(get_db)):
    execution = _execution(db, user.id, execution_id)
    if execution.status != "in_progress":
        raise HTTPException(status_code=409, detail="Only active executions can be paused")
    execution.status = "paused"; execution.paused_at = _utcnow()
    _irrigation_audit(db, request, user, "irrigation_execution_paused", f"execution_id={execution.id}")
    db.commit()
    return RedirectResponse(f"/irrigation/schedules/{execution.schedule_id}/execute?success=" + quote("Irrigation paused."), status_code=303)


@router.post("/irrigation/executions/{execution_id}/resume")
def execution_resume(execution_id: int, request: Request, user: User = Depends(current_irrigation_user), db: Session = Depends(get_db)):
    execution = _execution(db, user.id, execution_id)
    if execution.status != "paused" or not execution.paused_at:
        raise HTTPException(status_code=409, detail="Only paused executions can be resumed")
    execution.total_paused_minutes += _elapsed_minutes(execution.paused_at, _utcnow())
    execution.paused_at = None; execution.status = "in_progress"
    _irrigation_audit(db, request, user, "irrigation_execution_resumed", f"execution_id={execution.id}")
    db.commit()
    return RedirectResponse(f"/irrigation/schedules/{execution.schedule_id}/execute?success=" + quote("Irrigation resumed."), status_code=303)


@router.post("/irrigation/executions/{execution_id}/complete")
def execution_complete(execution_id: int, request: Request, closing_meter_reading: str = Form(""),
                       closing_tank_level_litres: str = Form(""), actual_water_litres: str = Form(""),
                       actual_duration_minutes: str = Form(""), completion_percentage: str = Form("100"),
                       worker_remarks: str = Form(""), leakage_reported: str | None = Form(None),
                       pump_issue_reported: str | None = Form(None), user: User = Depends(current_irrigation_user),
                       db: Session = Depends(get_db)):
    execution = _execution(db, user.id, execution_id); schedule = _schedule(db, user.id, execution.schedule_id)
    if execution.status not in ("in_progress", "paused"):
        raise HTTPException(status_code=409, detail="Execution is not active")
    try:
        now = _utcnow(); paused = execution.total_paused_minutes
        if execution.status == "paused" and execution.paused_at:
            paused += _elapsed_minutes(execution.paused_at, now)
        closing_meter = _decimal(closing_meter_reading, "Closing meter reading")
        closing_tank = _decimal(closing_tank_level_litres, "Closing tank level")
        actual_water = _decimal(actual_water_litres, "Actual water")
        if execution.opening_meter_reading is not None and closing_meter is not None:
            if closing_meter < execution.opening_meter_reading:
                raise ValueError("Closing meter reading cannot be below the opening reading.")
            meter_water = closing_meter - execution.opening_meter_reading
            if actual_water is None:
                actual_water = meter_water
        if execution.opening_tank_level_litres is not None and closing_tank is not None and closing_tank > execution.opening_tank_level_litres:
            raise ValueError("Closing tank level cannot exceed the opening level.")
        if actual_water is None and execution.opening_tank_level_litres is not None and closing_tank is not None:
            actual_water = execution.opening_tank_level_litres - closing_tank
        percentage = _decimal(completion_percentage, "Completion percentage") or Decimal("0")
        if percentage > 100:
            raise ValueError("Completion percentage cannot exceed 100.")
        manual_duration = _integer(actual_duration_minutes, "Actual duration", allow_zero=False)
        execution.completed_at=now; execution.total_paused_minutes=paused; execution.paused_at=None
        execution.actual_duration_minutes=manual_duration or _elapsed_minutes(execution.started_at, now, paused)
        execution.closing_meter_reading=closing_meter; execution.closing_tank_level_litres=closing_tank
        execution.actual_water_litres=actual_water; execution.completion_percentage=percentage
        execution.worker_remarks=_text(worker_remarks) or execution.worker_remarks
        execution.leakage_reported=leakage_reported == "on"; execution.pump_issue_reported=pump_issue_reported == "on"
        execution.status="completed"; schedule.status="completed" if percentage >= 100 else "postponed"
        zone = _zone(db, user.id, schedule.zone_id); zone.last_irrigation_date = now.date()
        if zone.recommended_interval_days:
            zone.next_irrigation_date = now.date() + timedelta(days=zone.recommended_interval_days)
        if schedule.pump_id:
            pump = _pump(db, user.id, schedule.pump_id)
            pump.status = "faulty" if execution.pump_issue_reported else "available"
            if execution.actual_duration_minutes:
                db.add(PumpRuntimeLog(owner_id=user.id, farm_id=schedule.farm_id, pump_id=pump.id,
                    run_date=schedule.scheduled_date, runtime_minutes=execution.actual_duration_minutes,
                    water_pumped_litres=actual_water, notes=f"Generated from irrigation execution #{execution.id}"))
        issue_labels = []
        if execution.leakage_reported: issue_labels.append("leakage")
        if execution.pump_issue_reported: issue_labels.append("pump issue")
        if issue_labels:
            db.add(IrrigationAlert(owner_id=user.id, farm_id=schedule.farm_id, zone_id=schedule.zone_id,
                schedule_id=schedule.id, alert_type="execution_issue", severity="critical" if execution.pump_issue_reported else "warning",
                title="Irrigation execution issue", message=f"Execution #{execution.id}: {', '.join(issue_labels)} reported.", status="open"))
        _irrigation_audit(db, request, user, "irrigation_execution_completed", f"execution_id={execution.id}; completion={percentage}")
        db.commit()
    except (ValueError, IntegrityError) as exc:
        db.rollback(); return RedirectResponse(f"/irrigation/schedules/{schedule.id}/execute?error=" + quote(str(exc)), status_code=303)
    return RedirectResponse(f"/irrigation/schedules/{schedule.id}/execute?success=" + quote("Irrigation completed and recorded."), status_code=303)


@router.post("/irrigation/executions/{execution_id}/approve")
def execution_approve(execution_id: int, request: Request, supervisor_notes: str = Form(""),
                      user: User = Depends(current_irrigation_user), db: Session = Depends(get_db)):
    execution = _execution(db, user.id, execution_id)
    if execution.status not in ("completed", "approved"):
        raise HTTPException(status_code=409, detail="Only completed executions can be approved")
    execution.status="approved"; execution.supervisor_approved_by=user.id
    execution.supervisor_approved_at=_utcnow(); execution.supervisor_notes=_text(supervisor_notes)
    _irrigation_audit(db, request, user, "irrigation_execution_approved", f"execution_id={execution.id}")
    db.commit()
    return RedirectResponse(f"/irrigation/schedules/{execution.schedule_id}/execute?success=" + quote("Execution approved."), status_code=303)


# PATCH-IRR-004: SMART WATER REQUIREMENT CALCULATOR
@router.get("/irrigation/calculator", response_class=HTMLResponse)
def water_calculator_page(request:Request, zone_id:int|None=None, user:User=Depends(current_irrigation_user), db:Session=Depends(get_db)):
    zones=list(db.scalars(select(IrrigationZone).where(IrrigationZone.owner_id==user.id,IrrigationZone.is_active.is_(True)).order_by(IrrigationZone.name)))
    pumps=list(db.scalars(select(IrrigationPump).where(IrrigationPump.owner_id==user.id).order_by(IrrigationPump.name)))
    selected=_zone(db,user.id,zone_id) if zone_id else None
    return templates.TemplateResponse(request=request,name="irrigation/calculator.html",context=_ctx(request,user,page_title="Smart Water Calculator",zones=zones,pumps=pumps,selected_zone=selected,result=None))

@router.post("/irrigation/calculator", response_class=HTMLResponse)
def water_calculator_run(request:Request,zone_id:int=Form(...),pump_id:str=Form(""),plant_count:str=Form(...),litres_per_plant:str=Form(...),temperature_c:str=Form(""),humidity_percent:str=Form(""),rain_probability_percent:str=Form(""),expected_rain_mm:str=Form(""),notes:str=Form(""),user:User=Depends(current_irrigation_user),db:Session=Depends(get_db)):
    zones=list(db.scalars(select(IrrigationZone).where(IrrigationZone.owner_id==user.id,IrrigationZone.is_active.is_(True)).order_by(IrrigationZone.name)))
    pumps=list(db.scalars(select(IrrigationPump).where(IrrigationPump.owner_id==user.id).order_by(IrrigationPump.name)))
    try:
        zone=_zone(db,user.id,zone_id); pid=_integer(pump_id,"Pump"); pump=_pump(db,user.id,pid) if pid else None
        if pump and pump.farm_id!=zone.farm_id: raise ValueError("Pump must belong to the selected zone's farm.")
        count=_integer(plant_count,"Plant count",allow_zero=False); lpp=_decimal(litres_per_plant,"Litres per plant",allow_zero=False)
        result=calculate_water(plant_count=count or 0,litres_per_plant=lpp or Decimal("0"),soil_type=zone.soil_type,irrigation_method=zone.irrigation_method,pump_flow_lpm=pump.flow_rate_lpm if pump else None,pump_cost_per_hour=pump.operating_cost_per_hour if pump else None,temperature_c=_decimal(temperature_c,"Temperature"),humidity_percent=_decimal(humidity_percent,"Humidity"),rain_probability_percent=_decimal(rain_probability_percent,"Rain probability"),expected_rain_mm=_decimal(expected_rain_mm,"Expected rain"),area_value=zone.area_value)
        row=WaterRequirementCalculation(owner_id=user.id,farm_id=zone.farm_id,zone_id=zone.id,pump_id=pump.id if pump else None,calculation_date=date.today(),plant_count=count,base_litres_per_plant=lpp,base_water_litres=result.base_water_litres,soil_factor=result.soil_factor,irrigation_efficiency=result.irrigation_efficiency,temperature_c=_decimal(temperature_c,"Temperature"),humidity_percent=_decimal(humidity_percent,"Humidity"),rain_probability_percent=_decimal(rain_probability_percent,"Rain probability"),expected_rain_mm=_decimal(expected_rain_mm,"Expected rain"),weather_adjustment_percent=result.weather_adjustment_percent,effective_rain_litres=result.effective_rain_litres,final_water_litres=result.final_water_litres,water_saved_litres=result.water_saved_litres,estimated_runtime_minutes=result.estimated_runtime_minutes,estimated_operating_cost=result.estimated_operating_cost,recommendation=result.recommendation,recommendation_reason=result.reason,notes=_text(notes)); db.add(row); db.commit()
        return templates.TemplateResponse(request=request,name="irrigation/calculator.html",context=_ctx(request,user,page_title="Smart Water Calculator",zones=zones,pumps=pumps,selected_zone=zone,result=result))
    except ValueError as exc:
        db.rollback(); return templates.TemplateResponse(request=request,name="irrigation/calculator.html",context=_ctx(request,user,page_title="Smart Water Calculator",zones=zones,pumps=pumps,selected_zone=None,result=None,error_message=str(exc)),status_code=400)

@router.get("/irrigation/calculator/history", response_class=HTMLResponse)
def water_calculator_history(request:Request,user:User=Depends(current_irrigation_user),db:Session=Depends(get_db)):
    # PATCH-IRR-004B: premium history dashboard metrics and trend data.
    rows=list(db.execute(select(WaterRequirementCalculation,IrrigationZone,Farm).join(IrrigationZone,IrrigationZone.id==WaterRequirementCalculation.zone_id).join(Farm,Farm.id==WaterRequirementCalculation.farm_id).where(WaterRequirementCalculation.owner_id==user.id,IrrigationZone.owner_id==user.id,Farm.owner_id==user.id).order_by(WaterRequirementCalculation.created_at.desc()).limit(250)).all())
    total=db.scalar(select(func.coalesce(func.sum(WaterRequirementCalculation.final_water_litres),0)).where(WaterRequirementCalculation.owner_id==user.id)) or 0
    saved=db.scalar(select(func.coalesce(func.sum(WaterRequirementCalculation.water_saved_litres),0)).where(WaterRequirementCalculation.owner_id==user.id)) or 0
    runtime=db.scalar(select(func.coalesce(func.sum(WaterRequirementCalculation.estimated_runtime_minutes),0)).where(WaterRequirementCalculation.owner_id==user.id)) or 0
    cost=db.scalar(select(func.coalesce(func.sum(WaterRequirementCalculation.estimated_operating_cost),0)).where(WaterRequirementCalculation.owner_id==user.id)) or 0
    count=db.scalar(select(func.count(WaterRequirementCalculation.id)).where(WaterRequirementCalculation.owner_id==user.id)) or 0

    recent=list(reversed(rows[:12]))
    max_final=max((float(item[0].final_water_litres or 0) for item in recent),default=0) or 1
    trend=[{
        "label": item[0].calculation_date.strftime("%d %b"),
        "litres": float(item[0].final_water_litres or 0),
        "saved": float(item[0].water_saved_litres or 0),
        "height": max(8,round((float(item[0].final_water_litres or 0)/max_final)*100)),
    } for item in recent]

    return templates.TemplateResponse(request=request,name="irrigation/calculator_history.html",context=_ctx(request,user,page_title="Water Calculation History",rows=rows,total=total,saved=saved,runtime=runtime,cost=cost,count=count,trend=trend))
