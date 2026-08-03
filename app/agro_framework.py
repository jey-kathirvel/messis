"""Universal agriculture templates and first-login setup workflow."""
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import (
    Farm, FarmCategory, FarmFieldValue, FarmTemplate, FarmTemplateAssignment,
    FarmTemplateVersion, FarmType, TemplateField, User, UserSetupProfile,
)

router = APIRouter()
templates = Jinja2Templates(directory=Path(__file__).resolve().parent / "templates")

SEEDS = {
    "coconut": {"category": ("plantation", "Plantation Farming", "🌴"), "name": "Coconut", "icon": "🥥",
        "terms": {"production_unit": "Nuts", "production_event": "Harvest", "asset_count": "Trees", "cycle": "Harvest Cycle", "output": "Coconut Yield"},
        "fields": [("tree_count", "Tree count", "number", True, {"min": 0}), ("variety", "Coconut variety", "select", False, {}), ("irrigation_type", "Irrigation type", "select", True, {})]},
    "paddy": {"category": ("crop", "Crop Farming", "🌾"), "name": "Paddy", "icon": "🌾",
        "terms": {"production_unit": "Kilograms / Bags", "production_event": "Harvest", "asset_count": "Cultivated Area", "cycle": "Crop Season", "output": "Paddy Yield"},
        "fields": [("cultivated_area", "Cultivated area", "number", True, {"min": 0.01}), ("seed_variety", "Seed variety", "text", True, {}), ("season", "Crop season", "text", True, {})]},
    "dairy": {"category": ("dairy", "Dairy", "🐄"), "name": "Dairy", "icon": "🐄",
        "terms": {"production_unit": "Litres", "production_event": "Milking", "asset_count": "Cattle Count", "cycle": "Lactation Cycle", "output": "Milk Production"},
        "fields": [("cattle_count", "Cattle count", "number", True, {"min": 1}), ("breed", "Primary breed", "text", True, {}), ("daily_capacity", "Daily milk capacity", "number", False, {"min": 0})]},
}

FIELD_HELP = {
    "tree_count": "Number of coconut trees currently planted on this farm.",
    "variety": "Primary coconut variety grown on this farm.",
    "irrigation_type": "Main water source or irrigation method used for the crop.",
    "cultivated_area": "Area currently prepared or planted with paddy.",
    "seed_variety": "Name or code of the paddy seed variety used for this cycle.",
    "season": "Local crop season or production cycle, such as Kuruvai or Samba.",
    "cattle_count": "Total number of cattle managed as part of this dairy farm.",
    "breed": "Primary cattle breed, such as Jersey, HF, or a local breed.",
    "daily_capacity": "Expected total milk production per day in litres.",
}


def seed_agro_framework(db: Session) -> None:
    """Idempotently seed published Coconut, Paddy and Dairy template v1."""
    for code, spec in SEEDS.items():
        category_code, category_name, category_icon = spec["category"]
        category = db.scalar(select(FarmCategory).where(FarmCategory.code == category_code))
        if not category:
            category = FarmCategory(code=category_code, name=category_name, icon=category_icon)
            db.add(category); db.flush()
        farm_type = db.scalar(select(FarmType).where(FarmType.code == code))
        if not farm_type:
            farm_type = FarmType(category_id=category.id, code=code, name=spec["name"], icon=spec["icon"])
            db.add(farm_type); db.flush()
        template = db.scalar(select(FarmTemplate).where(FarmTemplate.template_code == f"{code}_v1"))
        if not template:
            template = FarmTemplate(template_code=f"{code}_v1", template_name=f"{spec['name']} Farm Template", farm_type_id=farm_type.id, description=f"System {spec['name']} template")
            db.add(template); db.flush()
        version = db.scalar(select(FarmTemplateVersion).where(FarmTemplateVersion.template_id == template.id, FarmTemplateVersion.version == 1))
        if not version:
            version = FarmTemplateVersion(template_id=template.id, version=1, status="PUBLISHED", terminology_json=spec["terms"], dashboard_widgets_json=["production", "expenses", "revenue", "activities"], published_at=datetime.now(timezone.utc))
            db.add(version); db.flush()
        for order, (key, label, kind, required, rules) in enumerate(spec["fields"], 1):
            if not db.scalar(select(TemplateField.id).where(TemplateField.template_version_id == version.id, TemplateField.field_key == key)):
                options = ["Tall", "Dwarf", "Hybrid"] if key == "variety" else (["Rainfed", "Canal", "Borewell", "Drip"] if key == "irrigation_type" else [])
                db.add(TemplateField(template_version_id=version.id, field_key=key, field_label=label, field_type=kind, is_required=required, validation_rules_json=rules, options_json=options, display_order=order))
    db.commit()


def signed_in_user(request: Request, db: Session = Depends(get_db)) -> User:
    user_id = request.session.get("user_id")
    user = db.get(User, user_id) if isinstance(user_id, int) else None
    if not user or not user.is_active:
        raise HTTPException(401, "Authentication required")
    return user


def _profile(db: Session, user: User) -> UserSetupProfile:
    profile = db.scalar(select(UserSetupProfile).where(UserSetupProfile.owner_id == user.id))
    if not profile:
        # Existing accounts pre-date the framework and must retain dashboard access.
        profile = UserSetupProfile(owner_id=user.id, status="COMPLETED", current_step=6, completed_at=datetime.now(timezone.utc))
        db.add(profile); db.commit(); db.refresh(profile)
    return profile


@router.get("/setup", response_class=HTMLResponse)
def setup_page(request: Request, user: User = Depends(signed_in_user), db: Session = Depends(get_db)):
    profile = _profile(db, user)
    if profile.status == "COMPLETED":
        return RedirectResponse("/dashboard", 303)
    categories = db.scalars(select(FarmCategory).where(FarmCategory.is_active.is_(True)).order_by(FarmCategory.name)).all()
    farm_types = db.scalars(select(FarmType).where(FarmType.is_active.is_(True)).order_by(FarmType.name)).all()
    return templates.TemplateResponse(request=request, name="setup/wizard.html", context={
        "page_title": "Set up your farm", "current_user": user, "profile": profile,
        "draft": profile.draft_json or {}, "categories": categories, "farm_types": farm_types,
        "wizard_mode": "first_farm",
        # First-login setup resumes only when a valid farm type was saved.
        "wizard_start_step": profile.current_step if (profile.draft_json or {}).get("farm_type_id") else 1,
    })


@router.get("/farms/setup", response_class=HTMLResponse)
def additional_farm_setup_page(request: Request, user: User = Depends(signed_in_user), db: Session = Depends(get_db)):
    profile = _profile(db, user)
    categories = db.scalars(select(FarmCategory).where(FarmCategory.is_active.is_(True)).order_by(FarmCategory.name)).all()
    farm_types = db.scalars(select(FarmType).where(FarmType.is_active.is_(True)).order_by(FarmType.name)).all()
    return templates.TemplateResponse(request=request, name="setup/wizard.html", context={
        "page_title": "Add a new farm", "current_user": user, "profile": profile,
        "draft": profile.draft_json or {}, "categories": categories, "farm_types": farm_types,
        "wizard_mode": "new_farm",
        # Add Farm is always a fresh navigation intent, even if a draft exists.
        "wizard_start_step": 1,
    })


@router.get("/api/v1/setup/status")
def setup_status(user: User = Depends(signed_in_user), db: Session = Depends(get_db)):
    p = _profile(db, user)
    return {"status": p.status, "current_step": p.current_step, "draft": p.draft_json}


@router.get("/api/v1/setup/categories")
def setup_categories(user: User = Depends(signed_in_user), db: Session = Depends(get_db)):
    return [{"id": x.id, "code": x.code, "name": x.name, "icon": x.icon} for x in db.scalars(select(FarmCategory).where(FarmCategory.is_active.is_(True))).all()]


@router.get("/api/v1/setup/farm-types")
def setup_farm_types(category_id: int | None = None, user: User = Depends(signed_in_user), db: Session = Depends(get_db)):
    query = select(FarmType).where(FarmType.is_active.is_(True))
    if category_id: query = query.where(FarmType.category_id == category_id)
    return [{"id": x.id, "category_id": x.category_id, "code": x.code, "name": x.name, "icon": x.icon} for x in db.scalars(query).all()]


@router.get("/api/v1/setup/templates")
def setup_templates(farm_type_id: int | None = None, user: User = Depends(signed_in_user), db: Session = Depends(get_db)):
    query = select(FarmTemplateVersion, FarmTemplate).join(FarmTemplate).where(FarmTemplateVersion.status == "PUBLISHED")
    if farm_type_id: query = query.where(FarmTemplate.farm_type_id == farm_type_id)
    return [{"id": version.id, "template_id": template.id, "code": template.template_code, "name": template.template_name, "version": version.version, "farm_type_id": template.farm_type_id} for version, template in db.execute(query).all()]


@router.post("/api/v1/setup/save-step")
async def save_step(request: Request, user: User = Depends(signed_in_user), db: Session = Depends(get_db)):
    payload = await request.json()
    p = _profile(db, user)
    new_farm_mode = payload.get("mode") == "new_farm"
    if p.status == "COMPLETED" and not new_farm_mode: raise HTTPException(409, "Setup is already complete")
    step = int(payload.get("step", p.current_step))
    if not 1 <= step <= 6: raise HTTPException(422, "Step must be between 1 and 6")
    p.draft_json = {**(p.draft_json or {}), **payload.get("data", {})}; p.current_step = min(step + 1, 6)
    if not new_farm_mode: p.status = "IN_PROGRESS"
    db.commit()
    return {"status": p.status, "current_step": p.current_step}


@router.post("/api/v1/setup/complete")
def complete_setup(farm_type_id: int = Form(...), farm_name: str = Form(...), location: str = Form(""), area: str = Form(...), user: User = Depends(signed_in_user), db: Session = Depends(get_db)):
    p = _profile(db, user)
    if p.status == "COMPLETED": return RedirectResponse("/dashboard", 303)
    ft = db.get(FarmType, farm_type_id)
    if not ft or not ft.is_active: raise HTTPException(422, "Invalid farm type")
    try: parsed_area = Decimal(area)
    except InvalidOperation: raise HTTPException(422, "Area must be a number")
    if parsed_area <= 0: raise HTTPException(422, "Area must be greater than zero")
    name = farm_name.strip()
    if not name: raise HTTPException(422, "Farm name is required")
    template = db.scalar(select(FarmTemplateVersion).join(FarmTemplate).where(FarmTemplate.farm_type_id == ft.id, FarmTemplateVersion.status == "PUBLISHED").order_by(FarmTemplateVersion.version.desc()))
    if not template: raise HTTPException(409, "No published template for this farm type")
    farm = Farm(owner_id=user.id, name=name, location=location.strip() or None, acreage=str(parsed_area), total_trees=0)
    db.add(farm); db.flush()
    db.add(FarmTemplateAssignment(farm_id=farm.id, owner_id=user.id, template_version_id=template.id))
    p.status = "COMPLETED"; p.current_step = 6; p.completed_at = datetime.now(timezone.utc); p.draft_json = {}
    db.commit()
    return RedirectResponse(f"/farms/{farm.id}", 303)


@router.post("/api/v1/setup/complete-json")
async def complete_setup_json(request: Request, user: User = Depends(signed_in_user), db: Session = Depends(get_db)):
    payload = await request.json()
    p = _profile(db, user)
    new_farm_mode = payload.get("mode") == "new_farm"
    if p.status == "COMPLETED" and not new_farm_mode:
        raise HTTPException(409, "Setup is already complete")
    try:
        farm_type_id = int(payload.get("farm_type_id"))
        parsed_area = Decimal(str(payload.get("area", "")))
    except (TypeError, ValueError, InvalidOperation):
        raise HTTPException(422, "Farm type and a valid area are required")
    ft = db.get(FarmType, farm_type_id)
    if not ft or not ft.is_active:
        raise HTTPException(422, "Invalid farm type")
    name = str(payload.get("farm_name", "")).strip()
    if not name or parsed_area <= 0:
        raise HTTPException(422, "Farm name and an area greater than zero are required")
    if db.scalar(select(Farm.id).where(Farm.owner_id == user.id, Farm.name == name)):
        raise HTTPException(409, "A farm with this name already exists")
    version = db.scalar(select(FarmTemplateVersion).join(FarmTemplate).where(
        FarmTemplate.farm_type_id == ft.id,
        FarmTemplateVersion.status == "PUBLISHED",
    ).order_by(FarmTemplateVersion.version.desc()))
    if not version:
        raise HTTPException(409, "No published template for this farm type")
    fields = db.scalars(select(TemplateField).where(
        TemplateField.template_version_id == version.id,
        TemplateField.is_active.is_(True),
    )).all()
    values = payload.get("dynamic_values") or {}
    errors: dict[str, str] = {}
    for field in fields:
        value = values.get(field.field_key)
        if field.is_required and value in (None, ""):
            errors[field.field_key] = "This field is required"
        if value not in (None, "") and field.field_type == "number":
            try:
                number = Decimal(str(value))
            except InvalidOperation:
                errors[field.field_key] = "Must be a number"
                continue
            minimum = field.validation_rules_json.get("min")
            if minimum is not None and number < Decimal(str(minimum)):
                errors[field.field_key] = f"Must be at least {minimum}"
    if errors:
        return JSONResponse({"detail": "Dynamic field validation failed", "errors": errors}, status_code=422)
    farm = Farm(
        owner_id=user.id, name=name, location=str(payload.get("location", "")).strip() or None,
        acreage=str(parsed_area), total_trees=int(values.get("tree_count") or 0),
        notes=str(payload.get("notes", "")).strip() or None,
    )
    db.add(farm); db.flush()
    db.add(FarmTemplateAssignment(farm_id=farm.id, owner_id=user.id, template_version_id=version.id))
    for field in fields:
        if field.field_key in values and values[field.field_key] not in (None, ""):
            db.add(FarmFieldValue(farm_id=farm.id, owner_id=user.id, template_field_id=field.id, value_json=values[field.field_key]))
    p.status = "COMPLETED"; p.current_step = 1 if new_farm_mode else 6
    if not p.completed_at: p.completed_at = datetime.now(timezone.utc)
    p.draft_json = {}
    db.commit()
    return {"status": "COMPLETED", "farm_id": farm.id, "redirect_url": f"/farms/{farm.id}"}


def _owned_assignment(farm_id: int, user: User, db: Session) -> FarmTemplateAssignment:
    assignment = db.scalar(select(FarmTemplateAssignment).where(FarmTemplateAssignment.farm_id == farm_id, FarmTemplateAssignment.owner_id == user.id))
    if not assignment: raise HTTPException(404, "Farm template not found")
    return assignment


def farm_template_context(db: Session, farm: Farm, owner_id: int) -> dict[str, Any]:
    """Return presentation metadata, with a Coconut fallback for legacy farms."""
    assignment = db.scalar(select(FarmTemplateAssignment).where(
        FarmTemplateAssignment.farm_id == farm.id,
        FarmTemplateAssignment.owner_id == owner_id,
    ))
    if not assignment:
        return {
            "assigned": False, "farm_type_code": "coconut", "farm_type_name": "Coconut",
            "icon": "🥥", "is_coconut": True,
            "terminology": SEEDS["coconut"]["terms"], "dynamic_fields": [],
            "asset_label": "Trees", "asset_value": farm.total_trees or 0,
        }
    version = db.get(FarmTemplateVersion, assignment.template_version_id)
    template = db.get(FarmTemplate, version.template_id)
    farm_type = db.get(FarmType, template.farm_type_id)
    fields = db.scalars(select(TemplateField).where(
        TemplateField.template_version_id == version.id,
        TemplateField.is_active.is_(True),
    ).order_by(TemplateField.display_order)).all()
    values = {row.template_field_id: row.value_json for row in db.scalars(select(FarmFieldValue).where(
        FarmFieldValue.farm_id == farm.id, FarmFieldValue.owner_id == owner_id,
    )).all()}
    dynamic = [{"key": field.field_key, "label": field.field_label, "value": values.get(field.id), "unit": field.unit_type} for field in fields]
    terms = version.terminology_json or {}
    asset_field = next((x for x in dynamic if x["key"] in {"tree_count", "cultivated_area", "cattle_count"}), None)
    return {
        "assigned": True, "farm_type_code": farm_type.code, "farm_type_name": farm_type.name,
        "icon": farm_type.icon or "🌱", "is_coconut": farm_type.code == "coconut",
        "terminology": terms, "dynamic_fields": dynamic,
        "asset_label": terms.get("asset_count", "Farm capacity"),
        "asset_value": asset_field["value"] if asset_field else "—",
    }


@router.get("/farms/{farm_id}/dynamic-fields", response_class=HTMLResponse)
def dynamic_fields_page(farm_id: int, request: Request, user: User = Depends(signed_in_user), db: Session = Depends(get_db)):
    farm = db.scalar(select(Farm).where(Farm.id == farm_id, Farm.owner_id == user.id))
    if not farm: raise HTTPException(404, "Farm not found")
    context = farm_template_context(db, farm, user.id)
    if not context["assigned"]:
        return RedirectResponse(f"/farms/{farm.id}/edit", 303)
    return templates.TemplateResponse(request=request, name="setup/dynamic_fields.html", context={
        "page_title": f"Configure {farm.name}", "current_user": user, "farm": farm,
        "farm_context": context,
    })


@router.get("/api/v1/templates/{template_id}/form")
def template_form(template_id: int, user: User = Depends(signed_in_user), db: Session = Depends(get_db)):
    version = db.get(FarmTemplateVersion, template_id)
    if not version or version.status != "PUBLISHED": raise HTTPException(404, "Template not found")
    fields = db.scalars(select(TemplateField).where(TemplateField.template_version_id == version.id, TemplateField.is_active.is_(True)).order_by(TemplateField.display_order)).all()
    return {"template_version_id": version.id, "terminology": version.terminology_json, "widgets": version.dashboard_widgets_json, "fields": [{"id": f.id, "key": f.field_key, "label": f.field_label, "type": f.field_type, "required": f.is_required, "options": f.options_json, "validation": f.validation_rules_json, "conditional": f.conditional_rules_json, "unit": f.unit_type, "help": f.help_text or FIELD_HELP.get(f.field_key, "Enter the value that applies to this farm.")} for f in fields]}


@router.get("/api/v1/farms/{farm_id}/dynamic-fields")
def farm_fields(farm_id: int, user: User = Depends(signed_in_user), db: Session = Depends(get_db)):
    a = _owned_assignment(farm_id, user, db)
    fields = db.scalars(select(TemplateField).where(TemplateField.template_version_id == a.template_version_id, TemplateField.is_active.is_(True)).order_by(TemplateField.display_order)).all()
    values = {v.template_field_id: v.value_json for v in db.scalars(select(FarmFieldValue).where(FarmFieldValue.farm_id == farm_id, FarmFieldValue.owner_id == user.id)).all()}
    return {"farm_id": farm_id, "template_version_id": a.template_version_id, "fields": [{"id": f.id, "key": f.field_key, "label": f.field_label, "type": f.field_type, "required": f.is_required, "value": values.get(f.id)} for f in fields]}


@router.get("/api/v1/farms/{farm_id}/dashboard/widgets")
def farm_dashboard_widgets(farm_id: int, user: User = Depends(signed_in_user), db: Session = Depends(get_db)):
    assignment = _owned_assignment(farm_id, user, db)
    version = db.get(FarmTemplateVersion, assignment.template_version_id)
    return {"farm_id": farm_id, "template_version_id": version.id, "widgets": version.dashboard_widgets_json, "terminology": version.terminology_json}


@router.put("/api/v1/farms/{farm_id}/dynamic-fields")
async def update_farm_fields(farm_id: int, request: Request, user: User = Depends(signed_in_user), db: Session = Depends(get_db)):
    a = _owned_assignment(farm_id, user, db); payload: dict[str, Any] = await request.json(); supplied = payload.get("values", {})
    fields = db.scalars(select(TemplateField).where(TemplateField.template_version_id == a.template_version_id, TemplateField.is_active.is_(True))).all()
    errors = {}
    for field in fields:
        value = supplied.get(field.field_key)
        if field.is_required and (value is None or value == ""): errors[field.field_key] = "This field is required"
        if value not in (None, "") and field.field_type == "number":
            try: number = Decimal(str(value))
            except InvalidOperation: errors[field.field_key] = "Must be a number"; continue
            minimum = field.validation_rules_json.get("min")
            if minimum is not None and number < Decimal(str(minimum)): errors[field.field_key] = f"Must be at least {minimum}"
    if errors: return JSONResponse({"errors": errors}, status_code=422)
    for field in fields:
        if field.field_key not in supplied: continue
        row = db.scalar(select(FarmFieldValue).where(FarmFieldValue.farm_id == farm_id, FarmFieldValue.template_field_id == field.id))
        if row: row.value_json = supplied[field.field_key]
        else: db.add(FarmFieldValue(farm_id=farm_id, owner_id=user.id, template_field_id=field.id, value_json=supplied[field.field_key]))
    db.commit()
    return {"status": "saved"}
