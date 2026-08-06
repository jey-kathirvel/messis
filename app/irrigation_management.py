from __future__ import annotations

from datetime import date
from decimal import Decimal, InvalidOperation
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.services.water_calculator import calculate_water
from app.models import (Farm, IrrigationEquipment, IrrigationPump, IrrigationZone, PumpMaintenanceRecord, PumpRuntimeLog, User, WaterSource, WaterRequirementCalculation)

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
